package checks

import (
	"bptools/awsdata"
	"bptools/checker"
)

func RegisterAthenaChecks(d *awsdata.Data) {
	// athena-data-catalog-description
	checker.Register(DescriptionCheck(
		"athena-data-catalog-description",
		"This rule checks Athena data catalog description.",
		"athena",
		d,
		func(d *awsdata.Data) ([]DescriptionResource, error) {
			cats, err := d.AthenaDataCatalogs.Get()
			if err != nil {
				return nil, err
			}
			var res []DescriptionResource
			for _, c := range cats {
				id := "unknown"
				if c.Name != nil {
					id = *c.Name
				}
				res = append(res, DescriptionResource{ID: id, Description: c.Description})
			}
			return res, nil
		},
	))

	// athena-prepared-statement-description
	checker.Register(DescriptionCheck(
		"athena-prepared-statement-description",
		"This rule checks Athena prepared statement description.",
		"athena",
		d,
		func(d *awsdata.Data) ([]DescriptionResource, error) {
			stmts, err := d.AthenaPreparedStatements.Get()
			if err != nil {
				return nil, err
			}
			var res []DescriptionResource
			for _, s := range stmts {
				id := "unknown"
				if s.StatementName != nil {
					id = *s.StatementName
				}
				res = append(res, DescriptionResource{ID: id, Description: s.Description})
			}
			return res, nil
		},
	))

	// athena-workgroup-description
	checker.Register(DescriptionCheck(
		"athena-workgroup-description",
		"This rule checks Athena workgroup description.",
		"athena",
		d,
		func(d *awsdata.Data) ([]DescriptionResource, error) {
			wgs, err := d.AthenaWorkgroupDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []DescriptionResource
			for name, wg := range wgs {
				res = append(res, DescriptionResource{ID: name, Description: wg.Description})
			}
			return res, nil
		},
	))

	// athena-workgroup-encrypted-at-rest
	checker.Register(EncryptionCheck(
		"athena-workgroup-encrypted-at-rest",
		"This rule checks Athena workgroup encrypted at rest.",
		"athena",
		d,
		func(d *awsdata.Data) ([]EncryptionResource, error) {
			wgs, err := d.AthenaWorkgroupDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []EncryptionResource
			for name, wg := range wgs {
				encrypted := wg.Configuration != nil && wg.Configuration.ResultConfiguration != nil && wg.Configuration.ResultConfiguration.EncryptionConfiguration != nil
				res = append(res, EncryptionResource{ID: name, Encrypted: encrypted})
			}
			return res, nil
		},
	))

	// athena-workgroup-enforce-workgroup-configuration
	checker.Register(EnabledCheck(
		"athena-workgroup-enforce-workgroup-configuration",
		"This rule checks Athena workgroup enforce workgroup configuration.",
		"athena",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			wgs, err := d.AthenaWorkgroupDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for name, wg := range wgs {
				enabled := wg.Configuration != nil && wg.Configuration.EnforceWorkGroupConfiguration
				res = append(res, EnabledResource{ID: name, Enabled: enabled})
			}
			return res, nil
		},
	))

	// athena-workgroup-engine-version-auto-upgrade
	checker.Register(EnabledCheck(
		"athena-workgroup-engine-version-auto-upgrade",
		"This rule checks Athena workgroup engine version auto upgrade.",
		"athena",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			wgs, err := d.AthenaWorkgroupDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for name, wg := range wgs {
				enabled := wg.Configuration != nil && wg.Configuration.EngineVersion != nil && wg.Configuration.EngineVersion.SelectedEngineVersion != nil && wg.Configuration.EngineVersion.AutoUpgrade
				res = append(res, EnabledResource{ID: name, Enabled: enabled})
			}
			return res, nil
		},
	))

	// athena-workgroup-logging-enabled
	checker.Register(LoggingCheck(
		"athena-workgroup-logging-enabled",
		"This rule checks Athena workgroup logging enabled.",
		"athena",
		d,
		func(d *awsdata.Data) ([]LoggingResource, error) {
			wgs, err := d.AthenaWorkgroupDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []LoggingResource
			for name, wg := range wgs {
				logging := wg.Configuration != nil && wg.Configuration.PublishCloudWatchMetricsEnabled
				res = append(res, LoggingResource{ID: name, Logging: logging})
			}
			return res, nil
		},
	))

	// athena-workgroup-logging-enabled uses logging check; no extra rules here
}
