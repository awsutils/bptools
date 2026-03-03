package fixes

import (
	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/mq"
	mqtypes "github.com/aws/aws-sdk-go-v2/service/mq/types"
)

// ── mq-automatic-minor-version-upgrade-enabled / mq-auto-minor-version-upgrade-enabled ──

type mqAutoMinorVersionFix struct {
	checkID string
	clients *awsdata.Clients
}

func (f *mqAutoMinorVersionFix) CheckID() string     { return f.checkID }
func (f *mqAutoMinorVersionFix) Description() string { return "Enable auto minor version upgrade on MQ broker" }
func (f *mqAutoMinorVersionFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *mqAutoMinorVersionFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *mqAutoMinorVersionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.MQ.DescribeBroker(fctx.Ctx, &mq.DescribeBrokerInput{
		BrokerId: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe MQ broker: " + err.Error()
		return base
	}
	if out.AutoMinorVersionUpgrade != nil && *out.AutoMinorVersionUpgrade {
		base.Status = fix.FixSkipped
		base.Message = "auto minor version upgrade already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enable auto minor version upgrade on MQ broker " + resourceID}
		return base
	}

	_, err = f.clients.MQ.UpdateBroker(fctx.Ctx, &mq.UpdateBrokerInput{
		BrokerId:                aws.String(resourceID),
		AutoMinorVersionUpgrade: aws.Bool(true),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update MQ broker: " + err.Error()
		return base
	}
	base.Steps = []string{"enabled auto minor version upgrade on MQ broker " + resourceID}
	base.Status = fix.FixApplied
	return base
}

// ── mq-broker-general-logging-enabled ────────────────────────────────────────

type mqGeneralLoggingFix struct{ clients *awsdata.Clients }

func (f *mqGeneralLoggingFix) CheckID() string {
	return "mq-broker-general-logging-enabled"
}
func (f *mqGeneralLoggingFix) Description() string {
	return "Enable general logging on MQ broker"
}
func (f *mqGeneralLoggingFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *mqGeneralLoggingFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *mqGeneralLoggingFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.MQ.DescribeBroker(fctx.Ctx, &mq.DescribeBrokerInput{
		BrokerId: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe MQ broker: " + err.Error()
		return base
	}
	if out.Logs != nil && out.Logs.General != nil && *out.Logs.General {
		base.Status = fix.FixSkipped
		base.Message = "general logging already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enable general logging on MQ broker " + resourceID}
		return base
	}

	auditEnabled := out.Logs != nil && out.Logs.Audit != nil && *out.Logs.Audit
	_, err = f.clients.MQ.UpdateBroker(fctx.Ctx, &mq.UpdateBrokerInput{
		BrokerId: aws.String(resourceID),
		Logs: &mqtypes.Logs{
			General: aws.Bool(true),
			Audit:   aws.Bool(auditEnabled),
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update MQ broker: " + err.Error()
		return base
	}
	base.Steps = []string{"enabled general logging on MQ broker " + resourceID}
	base.Status = fix.FixApplied
	return base
}

// ── mq-cloudwatch-audit-logging-enabled / mq-cloudwatch-audit-log-enabled ───

type mqAuditLoggingFix struct {
	checkID string
	clients *awsdata.Clients
}

func (f *mqAuditLoggingFix) CheckID() string     { return f.checkID }
func (f *mqAuditLoggingFix) Description() string { return "Enable audit logging on MQ broker" }
func (f *mqAuditLoggingFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *mqAuditLoggingFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *mqAuditLoggingFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.MQ.DescribeBroker(fctx.Ctx, &mq.DescribeBrokerInput{
		BrokerId: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe MQ broker: " + err.Error()
		return base
	}
	if out.Logs != nil && out.Logs.Audit != nil && *out.Logs.Audit {
		base.Status = fix.FixSkipped
		base.Message = "audit logging already enabled"
		return base
	}
	// Only ActiveMQ supports audit logging — RabbitMQ does not
	if out.EngineType == mqtypes.EngineTypeRabbitmq {
		base.Status = fix.FixSkipped
		base.Message = "RabbitMQ does not support audit logging"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enable audit logging on MQ broker " + resourceID}
		return base
	}

	generalEnabled := out.Logs != nil && out.Logs.General != nil && *out.Logs.General
	_, err = f.clients.MQ.UpdateBroker(fctx.Ctx, &mq.UpdateBrokerInput{
		BrokerId: aws.String(resourceID),
		Logs: &mqtypes.Logs{
			General: aws.Bool(generalEnabled),
			Audit:   aws.Bool(true),
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update MQ broker: " + err.Error()
		return base
	}
	base.Steps = []string{"enabled audit logging on MQ broker " + resourceID}
	base.Status = fix.FixApplied
	return base
}
