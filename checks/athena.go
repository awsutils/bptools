package checks

import (
	"fmt"

	"bptools/awsdata"
	"bptools/checker"

	"github.com/aws/aws-sdk-go-v2/service/athena"
)

func RegisterAthenaChecks(d *awsdata.Data) {
	// athena-data-catalog-description
	checker.Register(DescriptionCheck(
		"athena-data-catalog-description",
		"Checks if Amazon Athena data catalogs have a description. The rule is NON_COMPLIANT if configuration.Description does not exist.",
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
		"Checks if Amazon Athena prepared statements have a description. The rule is NON_COMPLIANT if configuration.Description does not exist.",
		"athena",
		d,
		func(d *awsdata.Data) ([]DescriptionResource, error) {
			workgroups, err := d.AthenaWorkgroups.Get()
			if err != nil {
				return nil, err
			}
			var res []DescriptionResource
			for _, wg := range workgroups {
				if wg.Name == nil {
					continue
				}
				listOut, err := d.Clients.Athena.ListPreparedStatements(d.Ctx, &athena.ListPreparedStatementsInput{WorkGroup: wg.Name})
				if err != nil {
					continue
				}
				for _, stmt := range listOut.PreparedStatements {
					id := fmt.Sprintf("%s:unknown", *wg.Name)
					if stmt.StatementName != nil {
						id = fmt.Sprintf("%s:%s", *wg.Name, *stmt.StatementName)
					}
					if stmt.StatementName == nil {
						res = append(res, DescriptionResource{ID: id, Description: nil})
						continue
					}
					getOut, err := d.Clients.Athena.GetPreparedStatement(d.Ctx, &athena.GetPreparedStatementInput{
						WorkGroup:     wg.Name,
						StatementName: stmt.StatementName,
					})
					if err != nil || getOut.PreparedStatement == nil {
						res = append(res, DescriptionResource{ID: id, Description: nil})
						continue
					}
					res = append(res, DescriptionResource{ID: id, Description: getOut.PreparedStatement.Description})
				}
			}
			return res, nil
		},
	))

	// athena-workgroup-description
	checker.Register(DescriptionCheck(
		"athena-workgroup-description",
		"Checks if Amazon Athena workgroups have a description. The rule is NON_COMPLIANT if configuration.Description does not exist or is an empty string.",
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
		"Checks if an Amazon Athena workgroup is encrypted at rest. The rule is NON_COMPLIANT if encryption of data at rest is not enabled for an Athena workgroup.",
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
		"Checks if Amazon Athena workgroups using Athena engine enforce workgroup configuration to override client-side settings. The rule is NON_COMPLIANT if configuration.WorkGroupConfiguration.EnforceWorkGroupConfiguration is false.",
		"athena",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			wgs, err := d.AthenaWorkgroupDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for name, wg := range wgs {
				enabled := wg.Configuration != nil && wg.Configuration.EnforceWorkGroupConfiguration != nil && *wg.Configuration.EnforceWorkGroupConfiguration
				res = append(res, EnabledResource{ID: name, Enabled: enabled})
			}
			return res, nil
		},
	))

	// athena-workgroup-engine-version-auto-upgrade
	checker.Register(EnabledCheck(
		"athena-workgroup-engine-version-auto-upgrade",
		"Checks if Amazon Athena workgroups using Athena engine are configured to auto upgrade. The rule is NON_COMPLIANT if configuration.WorkGroupConfiguration.EngineVersion.SelectedEngineVersion is not 'AUTO'.",
		"athena",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			wgs, err := d.AthenaWorkgroupDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for name, wg := range wgs {
				enabled := wg.Configuration != nil &&
					wg.Configuration.EngineVersion != nil &&
					wg.Configuration.EngineVersion.SelectedEngineVersion != nil &&
					*wg.Configuration.EngineVersion.SelectedEngineVersion == "AUTO"
				res = append(res, EnabledResource{ID: name, Enabled: enabled})
			}
			return res, nil
		},
	))

	// athena-workgroup-logging-enabled
	checker.Register(LoggingCheck(
		"athena-workgroup-logging-enabled",
		"Checks if Amazon Athena WorkGroup publishes usage metrics to Amazon CloudWatch. The rule is NON_COMPLIANT if an Amazon Athena WorkGroup 'PublishCloudWatchMetricsEnabled' is set to false.",
		"athena",
		d,
		func(d *awsdata.Data) ([]LoggingResource, error) {
			wgs, err := d.AthenaWorkgroupDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []LoggingResource
			for name, wg := range wgs {
				logging := wg.Configuration != nil && wg.Configuration.PublishCloudWatchMetricsEnabled != nil && *wg.Configuration.PublishCloudWatchMetricsEnabled
				res = append(res, LoggingResource{ID: name, Logging: logging})
			}
			return res, nil
		},
	))

	// athena-workgroup-logging-enabled uses logging check; no extra rules here
}
