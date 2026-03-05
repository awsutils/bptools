package fixes

import (
	"bptools/awsdata"
	"bptools/fix"
)

func registerMultiBatch16(d *awsdata.Data) {
	_ = d

	if fix.Lookup("cloudwatch-alarm-action-check") == nil {
		fix.Register(&aliasFix{checkID: "cloudwatch-alarm-action-check", target: "cloudwatch-alarm-action-enabled-check"})
	}
	if fix.Lookup("cloudwatch-alarm-resource-check") == nil {
		fix.Register(&aliasFix{checkID: "cloudwatch-alarm-resource-check", target: "cloudwatch-alarm-action-enabled-check"})
	}
	if fix.Lookup("cloudwatch-alarm-settings-check") == nil {
		fix.Register(&aliasFix{checkID: "cloudwatch-alarm-settings-check", target: "cloudwatch-alarm-action-enabled-check"})
	}
	if fix.Lookup("codedeploy-auto-rollback-monitor-enabled") == nil {
		fix.Register(&aliasFix{checkID: "codedeploy-auto-rollback-monitor-enabled", target: "codedeploy-deployment-group-auto-rollback-enabled"})
	}
	if fix.Lookup("multi-region-cloudtrail-enabled") == nil {
		fix.Register(&aliasFix{checkID: "multi-region-cloudtrail-enabled", target: "cloudtrail-enabled"})
	}
	if fix.Lookup("cloudtrail-security-trail-enabled") == nil {
		fix.Register(&aliasFix{checkID: "cloudtrail-security-trail-enabled", target: "cloudtrail-enabled"})
	}
	if fix.Lookup("wafv2-rulegroup-logging-enabled") == nil {
		fix.Register(&aliasFix{checkID: "wafv2-rulegroup-logging-enabled", target: "wafv2-logging-enabled"})
	}
	if fix.Lookup("cloud-trail-cloud-watch-logs-enabled") == nil {
		fix.Register(&unsupportedFix{checkID: "cloud-trail-cloud-watch-logs-enabled", reason: "automatic CloudTrail CloudWatch Logs destination wiring is not safely inferable; configure log group and role explicitly"})
	}
	if fix.Lookup("cloud-trail-encryption-enabled") == nil {
		fix.Register(&unsupportedFix{checkID: "cloud-trail-encryption-enabled", reason: "trail key policy and KMS key selection require environment-specific constraints; apply manually"})
	}
	if fix.Lookup("cloudtrail-s3-bucket-access-logging") == nil {
		fix.Register(&unsupportedFix{checkID: "cloudtrail-s3-bucket-access-logging", reason: "trail bucket logging target cannot be chosen safely without organization log-archive policy"})
	}
}
