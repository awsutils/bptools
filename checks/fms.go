package checks

import (
	"strings"

	"bptools/awsdata"
	"bptools/checker"

	fmstypes "github.com/aws/aws-sdk-go-v2/service/fms/types"
)

// RegisterFMSChecks registers Firewall Manager checks.
func RegisterFMSChecks(d *awsdata.Data) {
	checker.Register(ConfigCheck(
		"fms-shield-resource-policy-check",
		"This rule checks fms shield resource policy check.",
		"fms",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			policies, err := d.FMSPolicyDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for id, p := range policies {
				if p.SecurityServicePolicyData == nil || p.SecurityServicePolicyData.Type != fmstypes.SecurityServiceTypeShieldAdvanced {
					continue
				}
				ok := len(p.ResourceTypeList) > 0
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "Shield policy has resource types"})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"fms-webacl-resource-policy-check",
		"This rule checks fms webacl resource policy check.",
		"fms",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			policies, err := d.FMSPolicyDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for id, p := range policies {
				if p.SecurityServicePolicyData == nil {
					continue
				}
				if p.SecurityServicePolicyData.Type != fmstypes.SecurityServiceTypeWaf && p.SecurityServicePolicyData.Type != fmstypes.SecurityServiceTypeWafv2 {
					continue
				}
				ok := len(p.ResourceTypeList) > 0 && p.SecurityServicePolicyData.ManagedServiceData != nil && *p.SecurityServicePolicyData.ManagedServiceData != ""
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "WAF policy attached to resources"})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"fms-webacl-rulegroup-association-check",
		"This rule checks fms webacl rulegroup association check.",
		"fms",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			policies, err := d.FMSPolicyDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for id, p := range policies {
				if p.SecurityServicePolicyData == nil {
					continue
				}
				if p.SecurityServicePolicyData.Type != fmstypes.SecurityServiceTypeWaf && p.SecurityServicePolicyData.Type != fmstypes.SecurityServiceTypeWafv2 {
					continue
				}
				msd := ""
				if p.SecurityServicePolicyData.ManagedServiceData != nil {
					msd = *p.SecurityServicePolicyData.ManagedServiceData
				}
				ok := strings.Contains(strings.ToLower(msd), "rulegroup")
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "Rule group association found in managed service data"})
			}
			return res, nil
		},
	))
}
