package fixes

import (
	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cloudtrailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
)

// ── cloudtrail-s3-dataevents-enabled ─────────────────────────────────────────
// Account-level fix: finds the first active multi-region trail and enables
// S3 data event logging for all buckets.

type cloudTrailS3DataEventsFix struct{ clients *awsdata.Clients }

func (f *cloudTrailS3DataEventsFix) CheckID() string {
	return "cloudtrail-s3-dataevents-enabled"
}
func (f *cloudTrailS3DataEventsFix) Description() string {
	return "Enable S3 data event logging on an active CloudTrail trail"
}
func (f *cloudTrailS3DataEventsFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *cloudTrailS3DataEventsFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *cloudTrailS3DataEventsFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	// Find an active trail to add S3 data event logging to
	trailsOut, err := f.clients.CloudTrail.ListTrails(fctx.Ctx, &cloudtrail.ListTrailsInput{})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "list trails: " + err.Error()
		return base
	}
	if len(trailsOut.Trails) == 0 {
		base.Status = fix.FixSkipped
		base.Message = "no CloudTrail trails found; create a trail first"
		return base
	}

	// Find first active logging trail
	var activeTrailArn string
	for _, t := range trailsOut.Trails {
		if t.TrailARN == nil {
			continue
		}
		st, err := f.clients.CloudTrail.GetTrailStatus(fctx.Ctx, &cloudtrail.GetTrailStatusInput{
			Name: t.TrailARN,
		})
		if err != nil || st.IsLogging == nil || !*st.IsLogging {
			continue
		}
		activeTrailArn = *t.TrailARN
		break
	}
	if activeTrailArn == "" {
		base.Status = fix.FixSkipped
		base.Message = "no actively logging trail found; start logging on a trail first"
		return base
	}

	// Get existing event selectors
	evOut, err := f.clients.CloudTrail.GetEventSelectors(fctx.Ctx, &cloudtrail.GetEventSelectorsInput{
		TrailName: aws.String(activeTrailArn),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get event selectors: " + err.Error()
		return base
	}

	// Check idempotency: is S3 data event logging already enabled?
	for _, sel := range evOut.EventSelectors {
		for _, dr := range sel.DataResources {
			if aws.ToString(dr.Type) == "AWS::S3::Object" {
				for _, v := range dr.Values {
					if v == "arn:aws:s3" || v == "arn:aws:s3:::" {
						base.Status = fix.FixSkipped
						base.Message = "S3 data events already enabled on trail " + activeTrailArn
						return base
					}
				}
			}
		}
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enable S3 data event logging (all buckets) on trail " + activeTrailArn}
		return base
	}

	// Add S3 data event selector — preserve existing selectors
	s3DataSelector := cloudtrailtypes.EventSelector{
		ReadWriteType:           cloudtrailtypes.ReadWriteTypeAll,
		IncludeManagementEvents: aws.Bool(false),
		DataResources: []cloudtrailtypes.DataResource{
			{
				Type:   aws.String("AWS::S3::Object"),
				Values: []string{"arn:aws:s3:::"},
			},
		},
	}

	existingSelectors := evOut.EventSelectors
	// Remove S3 data resource from existing selectors to avoid duplicates
	var cleanedSelectors []cloudtrailtypes.EventSelector
	for _, sel := range existingSelectors {
		var newDR []cloudtrailtypes.DataResource
		for _, dr := range sel.DataResources {
			if aws.ToString(dr.Type) != "AWS::S3::Object" {
				newDR = append(newDR, dr)
			}
		}
		sel.DataResources = newDR
		cleanedSelectors = append(cleanedSelectors, sel)
	}
	newSelectors := append(cleanedSelectors, s3DataSelector)

	_, err = f.clients.CloudTrail.PutEventSelectors(fctx.Ctx, &cloudtrail.PutEventSelectorsInput{
		TrailName:      aws.String(activeTrailArn),
		EventSelectors: newSelectors,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "put event selectors: " + err.Error()
		return base
	}
	base.Steps = []string{"enabled S3 data event logging (all buckets, read+write) on trail " + activeTrailArn}
	base.Status = fix.FixApplied
	return base
}
