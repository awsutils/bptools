package checks

import (
	"encoding/json"
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/checker"

	emrtypes "github.com/aws/aws-sdk-go-v2/service/emr/types"
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
			onlySSH := emrPermittedRangesAreOnlySSH(cfg.PermittedPublicSecurityGroupRuleRanges)
			return []EnabledResource{{ID: "account", Enabled: enabled && onlySSH}}, nil
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
			securityConfigs, err := d.EMRSecurityConfigDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for id, c := range clusters {
				if emrClusterIsDeletedOrDeleting(c) {
					continue
				}
				enabled := false
				if c.SecurityConfiguration != nil && strings.TrimSpace(*c.SecurityConfiguration) != "" {
					if secCfg, ok := securityConfigs[*c.SecurityConfiguration]; ok {
						enabled = emrSecurityConfigHasKerberos(secCfg.SecurityConfiguration)
					}
				}
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
				if emrClusterIsDeletedOrDeleting(c) {
					continue
				}
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
				ok, found := emrConfigBoolField(cfg.SecurityConfiguration, []string{"EncryptionConfiguration", "EnableAtRestEncryption"})
				detail := "EnableAtRestEncryption missing or false"
				if found {
					detail = fmt.Sprintf("EnableAtRestEncryption: %v", ok)
				}
				res = append(res, ConfigResource{ID: name, Passing: ok, Detail: detail})
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
				ok, found := emrConfigBoolField(cfg.SecurityConfiguration, []string{"EncryptionConfiguration", "EnableInTransitEncryption"})
				detail := "EnableInTransitEncryption missing or false"
				if found {
					detail = fmt.Sprintf("EnableInTransitEncryption: %v", ok)
				}
				res = append(res, ConfigResource{ID: name, Passing: ok, Detail: detail})
			}
			return res, nil
		},
	))
}

func emrConfigBoolField(raw *string, path []string) (bool, bool) {
	if raw == nil || *raw == "" {
		return false, false
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(*raw), &m); err != nil {
		return false, false
	}
	cur := any(m)
	for _, p := range path {
		obj, ok := cur.(map[string]any)
		if !ok {
			return false, false
		}
		cur, ok = obj[p]
		if !ok {
			return false, false
		}
	}
	switch value := cur.(type) {
	case bool:
		return value, true
	case string:
		v := strings.ToLower(strings.TrimSpace(value))
		return v == "true" || v == "1" || v == "on" || v == "enabled", true
	default:
		return false, false
	}
}

func emrPermittedRangesAreOnlySSH(ranges []emrtypes.PortRange) bool {
	if len(ranges) == 0 {
		return true
	}
	for _, pr := range ranges {
		if pr.MinRange == nil || pr.MaxRange == nil {
			return false
		}
		if *pr.MinRange != 22 || *pr.MaxRange != 22 {
			return false
		}
	}
	return true
}

func emrSecurityConfigHasKerberos(raw *string) bool {
	if raw == nil || strings.TrimSpace(*raw) == "" {
		return false
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(*raw), &doc); err != nil {
		return false
	}
	authRaw, ok := doc["AuthenticationConfiguration"]
	if !ok {
		return false
	}
	auth, ok := authRaw.(map[string]any)
	if !ok {
		return false
	}
	kerberos, ok := auth["KerberosConfiguration"]
	if !ok {
		return false
	}
	k, ok := kerberos.(map[string]any)
	if !ok {
		return false
	}
	return len(k) > 0
}

func emrClusterIsDeletedOrDeleting(cluster emrtypes.Cluster) bool {
	if cluster.Status == nil {
		return false
	}
	state := strings.ToUpper(strings.TrimSpace(string(cluster.Status.State)))
	return strings.HasPrefix(state, "TERMINAT")
}
