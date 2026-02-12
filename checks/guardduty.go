package checks

import (
	"os"
	"strconv"
	"strings"
	"time"

	"bptools/awsdata"
	"bptools/checker"

	"github.com/aws/aws-sdk-go-v2/aws"
	guardduty "github.com/aws/aws-sdk-go-v2/service/guardduty"
	guarddutytypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
)

// RegisterGuardDutyChecks registers GuardDuty checks.
func RegisterGuardDutyChecks(d *awsdata.Data) {
	// guardduty-enabled-centralized
	checker.Register(EnabledCheck(
		"guardduty-enabled-centralized",
		"This rule checks GuardDuty enabled centralized.",
		"guardduty",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			dets, err := d.GuardDutyDetectors.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for id, det := range dets {
				res = append(res, EnabledResource{ID: id, Enabled: det.Status == guarddutytypes.DetectorStatusEnabled})
			}
			return res, nil
		},
	))

	features := map[string]string{
		"guardduty-s3-protection-enabled":          "S3_DATA_EVENTS",
		"guardduty-eks-protection-audit-enabled":   "EKS_AUDIT_LOGS",
		"guardduty-eks-protection-runtime-enabled": "EKS_RUNTIME_MONITORING",
		"guardduty-ecs-protection-runtime-enabled": "ECS_RUNTIME_MONITORING",
		"guardduty-ec2-protection-runtime-enabled": "EC2_RUNTIME_MONITORING",
		"guardduty-lambda-protection-enabled":      "LAMBDA_NETWORK_LOGS",
		"guardduty-rds-protection-enabled":         "RDS_LOGIN_EVENTS",
		"guardduty-malware-protection-enabled":     "EBS_MALWARE_PROTECTION",
		"guardduty-runtime-monitoring-enabled":     "RUNTIME_MONITORING",
	}
	for id, feat := range features {
		cid := id
		f := feat
		checker.Register(EnabledCheck(
			cid,
			"This rule checks GuardDuty protection feature enabled.",
			"guardduty",
			d,
			func(d *awsdata.Data) ([]EnabledResource, error) {
				dets, err := d.GuardDutyDetectors.Get()
				if err != nil {
					return nil, err
				}
				var res []EnabledResource
				for id, det := range dets {
					enabled := false
					if det.Status == guarddutytypes.DetectorStatusEnabled {
						for _, ft := range det.Features {
							if string(ft.Name) == f {
								enabled = ft.Status == guarddutytypes.FeatureStatusEnabled
								break
							}
						}
					}
					res = append(res, EnabledResource{ID: id, Enabled: enabled})
				}
				return res, nil
			},
		))
	}

	// guardduty-non-archived-findings
	checker.Register(ConfigCheck(
		"guardduty-non-archived-findings",
		"This rule checks GuardDuty non-archived findings.",
		"guardduty",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			ids, err := d.GuardDutyDetectorIDs.Get()
			if err != nil {
				return nil, err
			}
			highDays := guarddutyThresholdDaysFromEnv("BPTOOLS_GUARDDUTY_HIGH_SEVERITY_MAX_AGE_DAYS", 7)
			mediumDays := guarddutyThresholdDaysFromEnv("BPTOOLS_GUARDDUTY_MEDIUM_SEVERITY_MAX_AGE_DAYS", 30)
			lowDays := guarddutyThresholdDaysFromEnv("BPTOOLS_GUARDDUTY_LOW_SEVERITY_MAX_AGE_DAYS", 90)
			var res []ConfigResource
			for _, id := range ids {
				highCount, err := guarddutyNonArchivedFindingsOlderThan(d, id, 7.0, 9.0, highDays)
				if err != nil {
					return nil, err
				}
				mediumCount, err := guarddutyNonArchivedFindingsOlderThan(d, id, 4.0, 7.0, mediumDays)
				if err != nil {
					return nil, err
				}
				lowCount, err := guarddutyNonArchivedFindingsOlderThan(d, id, 0.0, 4.0, lowDays)
				if err != nil {
					return nil, err
				}
				totalOld := highCount + mediumCount + lowCount
				ok := totalOld == 0
				res = append(res, ConfigResource{
					ID:      id,
					Passing: ok,
					Detail:  "Old non-archived findings high/medium/low: " + strconv.Itoa(highCount) + "/" + strconv.Itoa(mediumCount) + "/" + strconv.Itoa(lowCount),
				})
			}
			return res, nil
		},
	))
}

func guarddutyThresholdDaysFromEnv(envVar string, defaultValue int64) int64 {
	value := strings.TrimSpace(os.Getenv(envVar))
	if value == "" {
		return defaultValue
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil || n <= 0 {
		return defaultValue
	}
	return n
}

func guarddutyNonArchivedFindingsOlderThan(d *awsdata.Data, detectorID string, severityMin float64, severityMax float64, maxAgeDays int64) (int, error) {
	cutoffMillis := time.Now().Add(-time.Duration(maxAgeDays) * 24 * time.Hour).UnixMilli()
	minSeverity := int64(severityMin * 10)
	maxSeverity := int64(severityMax * 10)
	criteria := guarddutytypes.FindingCriteria{
		Criterion: map[string]guarddutytypes.Condition{
			"service.archived": {Equals: []string{"false"}},
			"updatedAt":        {LessThanOrEqual: &cutoffMillis},
			"severity": {
				GreaterThanOrEqual: &minSeverity,
				LessThan:           &maxSeverity,
			},
		},
	}
	count := 0
	var nextToken *string
	for {
		out, err := d.Clients.GuardDuty.ListFindings(d.Ctx, &guardduty.ListFindingsInput{
			DetectorId:      &detectorID,
			FindingCriteria: &criteria,
			MaxResults:      aws.Int32(50),
			NextToken:       nextToken,
		})
		if err != nil {
			return 0, err
		}
		count += len(out.FindingIds)
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}
	return count, nil
}
