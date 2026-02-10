package checks

import (
	"bptools/awsdata"
	"bptools/checker"

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
			counts, err := d.GuardDutyNonArchivedFindings.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for id, count := range counts {
				ok := count == 0
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "Non-archived findings count"})
			}
			return res, nil
		},
	))
}
