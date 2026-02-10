package checks

import (
	"encoding/json"
	"fmt"

	"bptools/awsdata"
	"bptools/checker"
)

// RegisterEMRChecks registers EMR checks.
func RegisterEMRChecks(d *awsdata.Data) {
	checker.Register(EnabledCheck(
		"emr-block-public-access",
		"This rule checks EMR block public access.",
		"emr",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			cfg, err := d.EMRBlockPublicAccess.Get()
			if err != nil {
				return nil, err
			}
			enabled := cfg.BlockPublicSecurityGroupRules != nil && *cfg.BlockPublicSecurityGroupRules
			return []EnabledResource{{ID: "account", Enabled: enabled}}, nil
		},
	))

	checker.Register(EnabledCheck(
		"emr-kerberos-enabled",
		"This rule checks enabled state for EMR kerberos.",
		"emr",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			clusters, err := d.EMRClusterDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for id, c := range clusters {
				enabled := c.KerberosAttributes != nil
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"emr-master-no-public-ip",
		"This rule checks EMR master no public IP.",
		"emr",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			clusters, err := d.EMRClusterDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for id, c := range clusters {
				public := c.MasterPublicDnsName != nil && *c.MasterPublicDnsName != ""
				res = append(res, ConfigResource{ID: id, Passing: !public, Detail: fmt.Sprintf("Master public DNS set: %v", public)})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"emr-security-configuration-encryption-rest",
		"This rule checks EMR security configuration encryption rest.",
		"emr",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			configs, err := d.EMRSecurityConfigDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for name, cfg := range configs {
				ok := hasEMRConfigField(cfg.SecurityConfiguration, []string{"EncryptionConfiguration", "AtRestEncryptionConfiguration"})
				res = append(res, ConfigResource{ID: name, Passing: ok, Detail: "AtRestEncryptionConfiguration present"})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"emr-security-configuration-encryption-transit",
		"This rule checks EMR security configuration encryption transit.",
		"emr",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			configs, err := d.EMRSecurityConfigDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for name, cfg := range configs {
				ok := hasEMRConfigField(cfg.SecurityConfiguration, []string{"EncryptionConfiguration", "InTransitEncryptionConfiguration"})
				res = append(res, ConfigResource{ID: name, Passing: ok, Detail: "InTransitEncryptionConfiguration present"})
			}
			return res, nil
		},
	))
}

func hasEMRConfigField(raw *string, path []string) bool {
	if raw == nil || *raw == "" {
		return false
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(*raw), &m); err != nil {
		return false
	}
	cur := any(m)
	for _, p := range path {
		obj, ok := cur.(map[string]any)
		if !ok {
			return false
		}
		cur, ok = obj[p]
		if !ok {
			return false
		}
	}
	return true
}
