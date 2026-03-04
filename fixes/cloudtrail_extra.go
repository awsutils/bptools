package fixes

import (
	"fmt"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cloudtrailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
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

// ── cloudtrail-all-read-s3-data-event-check / cloudtrail-all-write-s3-data-event-check ──

type cloudTrailS3AllDataEventsFix struct {
	checkID   string
	readWrite cloudtrailtypes.ReadWriteType
	clients   *awsdata.Clients
}

func (f *cloudTrailS3AllDataEventsFix) CheckID() string { return f.checkID }
func (f *cloudTrailS3AllDataEventsFix) Description() string {
	return fmt.Sprintf("Enable S3 %s data events on a multi-region CloudTrail trail", f.readWrite)
}
func (f *cloudTrailS3AllDataEventsFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *cloudTrailS3AllDataEventsFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *cloudTrailS3AllDataEventsFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	// Find an active multi-region trail
	trailsOut, err := f.clients.CloudTrail.ListTrails(fctx.Ctx, &cloudtrail.ListTrailsInput{})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "list trails: " + err.Error()
		return base
	}

	var activeTrailArn string
	for _, t := range trailsOut.Trails {
		if t.TrailARN == nil {
			continue
		}
		// Check if multi-region
		detail, derr := f.clients.CloudTrail.GetTrail(fctx.Ctx, &cloudtrail.GetTrailInput{Name: t.TrailARN})
		if derr != nil || detail.Trail == nil || detail.Trail.IsMultiRegionTrail == nil || !*detail.Trail.IsMultiRegionTrail {
			continue
		}
		st, serr := f.clients.CloudTrail.GetTrailStatus(fctx.Ctx, &cloudtrail.GetTrailStatusInput{Name: t.TrailARN})
		if serr != nil || st.IsLogging == nil || !*st.IsLogging {
			continue
		}
		activeTrailArn = *t.TrailARN
		break
	}
	if activeTrailArn == "" {
		base.Status = fix.FixSkipped
		base.Message = "no active multi-region trail found"
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

	// Idempotency: check if desired S3 data events already covered
	for _, sel := range evOut.EventSelectors {
		rwMatch := sel.ReadWriteType == cloudtrailtypes.ReadWriteTypeAll || sel.ReadWriteType == f.readWrite
		if !rwMatch {
			continue
		}
		for _, dr := range sel.DataResources {
			if aws.ToString(dr.Type) == "AWS::S3::Object" {
				for _, v := range dr.Values {
					if v == "arn:aws:s3" || v == "arn:aws:s3:::" {
						base.Status = fix.FixSkipped
						base.Message = fmt.Sprintf("S3 %s data events already enabled on trail %s", f.readWrite, activeTrailArn)
						return base
					}
				}
			}
		}
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable S3 %s data events on trail %s", f.readWrite, activeTrailArn)}
		return base
	}

	s3DataSelector := cloudtrailtypes.EventSelector{
		ReadWriteType:           f.readWrite,
		IncludeManagementEvents: aws.Bool(false),
		DataResources: []cloudtrailtypes.DataResource{
			{
				Type:   aws.String("AWS::S3::Object"),
				Values: []string{"arn:aws:s3:::"},
			},
		},
	}

	var cleanedSelectors []cloudtrailtypes.EventSelector
	for _, sel := range evOut.EventSelectors {
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
	base.Steps = []string{fmt.Sprintf("enabled S3 %s data events (all buckets) on multi-region trail %s", f.readWrite, activeTrailArn)}
	base.Status = fix.FixApplied
	return base
}

// ── cloudtrail-s3-bucket-public-access-prohibited ─────────────────────────────

type cloudTrailS3PublicAccessFix struct{ clients *awsdata.Clients }

func (f *cloudTrailS3PublicAccessFix) CheckID() string {
	return "cloudtrail-s3-bucket-public-access-prohibited"
}
func (f *cloudTrailS3PublicAccessFix) Description() string {
	return "Block public access on the S3 bucket used by CloudTrail"
}
func (f *cloudTrailS3PublicAccessFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *cloudTrailS3PublicAccessFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *cloudTrailS3PublicAccessFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	trailOut, err := f.clients.CloudTrail.GetTrail(fctx.Ctx, &cloudtrail.GetTrailInput{
		Name: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get trail: " + err.Error()
		return base
	}
	if trailOut.Trail == nil || trailOut.Trail.S3BucketName == nil || *trailOut.Trail.S3BucketName == "" {
		base.Status = fix.FixSkipped
		base.Message = "trail has no S3 bucket configured"
		return base
	}
	bucketName := *trailOut.Trail.S3BucketName

	pabOut, err := f.clients.S3.GetPublicAccessBlock(fctx.Ctx, &s3.GetPublicAccessBlockInput{
		Bucket: aws.String(bucketName),
	})
	if err == nil && pabOut.PublicAccessBlockConfiguration != nil {
		c := pabOut.PublicAccessBlockConfiguration
		if aws.ToBool(c.BlockPublicAcls) && aws.ToBool(c.IgnorePublicAcls) &&
			aws.ToBool(c.BlockPublicPolicy) && aws.ToBool(c.RestrictPublicBuckets) {
			base.Status = fix.FixSkipped
			base.Message = "public access already fully blocked on bucket " + bucketName
			return base
		}
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would block public access on S3 bucket %s (CloudTrail trail %s)", bucketName, resourceID)}
		return base
	}

	_, err = f.clients.S3.PutPublicAccessBlock(fctx.Ctx, &s3.PutPublicAccessBlockInput{
		Bucket: aws.String(bucketName),
		PublicAccessBlockConfiguration: &s3types.PublicAccessBlockConfiguration{
			BlockPublicAcls:       aws.Bool(true),
			IgnorePublicAcls:      aws.Bool(true),
			BlockPublicPolicy:     aws.Bool(true),
			RestrictPublicBuckets: aws.Bool(true),
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "put public access block on bucket " + bucketName + ": " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("blocked public access on S3 bucket %s (CloudTrail trail %s)", bucketName, resourceID)}
	base.Status = fix.FixApplied
	return base
}
