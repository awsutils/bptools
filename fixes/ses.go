package fixes

import (
	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	sesv2types "github.com/aws/aws-sdk-go-v2/service/sesv2/types"
)

// ── ses-sending-tls-required ──────────────────────────────────────────────────

type sesTLSRequiredFix struct{ clients *awsdata.Clients }

func (f *sesTLSRequiredFix) CheckID() string     { return "ses-sending-tls-required" }
func (f *sesTLSRequiredFix) Description() string { return "Require TLS for SES configuration set delivery" }
func (f *sesTLSRequiredFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *sesTLSRequiredFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *sesTLSRequiredFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.SESv2.GetConfigurationSet(fctx.Ctx, &sesv2.GetConfigurationSetInput{
		ConfigurationSetName: aws.String(resourceID),
	})
	if err == nil && out.DeliveryOptions != nil && out.DeliveryOptions.TlsPolicy == sesv2types.TlsPolicyRequire {
		base.Status = fix.FixSkipped
		base.Message = "TLS policy already set to REQUIRE"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would set TLS policy to REQUIRE on SES configuration set " + resourceID}
		return base
	}

	_, err = f.clients.SESv2.PutConfigurationSetDeliveryOptions(fctx.Ctx, &sesv2.PutConfigurationSetDeliveryOptionsInput{
		ConfigurationSetName: aws.String(resourceID),
		TlsPolicy:            sesv2types.TlsPolicyRequire,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "put configuration set delivery options: " + err.Error()
		return base
	}
	base.Steps = []string{"set TLS policy to REQUIRE on SES configuration set " + resourceID}
	base.Status = fix.FixApplied
	return base
}
