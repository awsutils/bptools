package checks

import (
	"bptools/awsdata"
	"bptools/checker"
)

func RegisterTransferChecks(d *awsdata.Data) {
	// transfer-family-server-no-ftp
	checker.Register(ConfigCheck(
		"transfer-family-server-no-ftp",
		"This rule checks Transfer Family server no FTP.",
		"transfer",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			servers, err := d.TransferServerDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for id, s := range servers {
				ok := true
				for _, p := range s.Protocols {
					if p == "FTP" {
						ok = false
						break
					}
				}
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "Protocols exclude FTP"})
			}
			return res, nil
		},
	))

	// transfer-agreement-description + transfer-agreement-tagged
	checker.Register(DescriptionCheck(
		"transfer-agreement-description",
		"This rule checks Transfer agreement description.",
		"transfer",
		d,
		func(d *awsdata.Data) ([]DescriptionResource, error) {
			agrs, err := d.TransferAgreementDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []DescriptionResource
			for id, a := range agrs {
				res = append(res, DescriptionResource{ID: id, Description: a.Description})
			}
			return res, nil
		},
	))
	checker.Register(TaggedCheck(
		"transfer-agreement-tagged",
		"This rule checks Transfer agreement tagged.",
		"transfer",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			agrs, err := d.TransferAgreements.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.TransferTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, a := range agrs {
				if a.Arn == nil {
					continue
				}
				res = append(res, TaggedResource{ID: *a.Arn, Tags: tags[*a.Arn]})
			}
			return res, nil
		},
	))

	// transfer-certificate-description + transfer-certificate-tagged
	checker.Register(DescriptionCheck(
		"transfer-certificate-description",
		"This rule checks Transfer certificate description.",
		"transfer",
		d,
		func(d *awsdata.Data) ([]DescriptionResource, error) {
			certs, err := d.TransferCertificateDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []DescriptionResource
			for id, c := range certs {
				res = append(res, DescriptionResource{ID: id, Description: c.Description})
			}
			return res, nil
		},
	))
	checker.Register(TaggedCheck(
		"transfer-certificate-tagged",
		"This rule checks Transfer certificate tagged.",
		"transfer",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			certs, err := d.TransferCertificates.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.TransferTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, c := range certs {
				if c.Arn == nil {
					continue
				}
				res = append(res, TaggedResource{ID: *c.Arn, Tags: tags[*c.Arn]})
			}
			return res, nil
		},
	))

	// transfer-connector-logging-enabled + transfer-connector-tagged
	checker.Register(LoggingCheck(
		"transfer-connector-logging-enabled",
		"This rule checks Transfer connector logging enabled.",
		"transfer",
		d,
		func(d *awsdata.Data) ([]LoggingResource, error) {
			conns, err := d.TransferConnectorDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []LoggingResource
			for id, c := range conns {
				logging := c.LoggingRole != nil && *c.LoggingRole != ""
				res = append(res, LoggingResource{ID: id, Logging: logging})
			}
			return res, nil
		},
	))
	checker.Register(TaggedCheck(
		"transfer-connector-tagged",
		"This rule checks Transfer connector tagged.",
		"transfer",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			conns, err := d.TransferConnectors.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.TransferTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, c := range conns {
				if c.Arn == nil {
					continue
				}
				res = append(res, TaggedResource{ID: *c.Arn, Tags: tags[*c.Arn]})
			}
			return res, nil
		},
	))

	// transfer-profile-tagged
	checker.Register(TaggedCheck(
		"transfer-profile-tagged",
		"This rule checks Transfer profile tagged.",
		"transfer",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			profiles, err := d.TransferProfiles.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.TransferTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, p := range profiles {
				if p.Arn == nil {
					continue
				}
				res = append(res, TaggedResource{ID: *p.Arn, Tags: tags[*p.Arn]})
			}
			return res, nil
		},
	))

	// transfer-workflow-description + transfer-workflow-tagged
	checker.Register(DescriptionCheck(
		"transfer-workflow-description",
		"This rule checks Transfer workflow description.",
		"transfer",
		d,
		func(d *awsdata.Data) ([]DescriptionResource, error) {
			workflows, err := d.TransferWorkflowDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []DescriptionResource
			for id, w := range workflows {
				res = append(res, DescriptionResource{ID: id, Description: w.Description})
			}
			return res, nil
		},
	))
	checker.Register(TaggedCheck(
		"transfer-workflow-tagged",
		"This rule checks Transfer workflow tagged.",
		"transfer",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			workflows, err := d.TransferWorkflows.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.TransferTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, w := range workflows {
				if w.Arn == nil {
					continue
				}
				res = append(res, TaggedResource{ID: *w.Arn, Tags: tags[*w.Arn]})
			}
			return res, nil
		},
	))
}
