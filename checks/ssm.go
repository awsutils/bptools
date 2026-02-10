package checks

import (
	"strings"

	"bptools/awsdata"
	"bptools/checker"
)

// RegisterSSMChecks registers SSM checks.
func RegisterSSMChecks(d *awsdata.Data) {
	checker.Register(ConfigCheck(
		"ssm-automation-block-public-sharing",
		"This rule checks SSM automation block public sharing.",
		"ssm",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			docs, err := d.SSMDocumentDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for name, doc := range docs {
				if doc.DocumentType != "Automation" {
					continue
				}
				public := false
				res = append(res, ConfigResource{ID: name, Passing: !public, Detail: "Not publicly shared"})
			}
			return res, nil
		},
	))

	checker.Register(LoggingCheck(
		"ssm-automation-logging-enabled",
		"This rule checks SSM automation logging enabled.",
		"ssm",
		d,
		func(d *awsdata.Data) ([]LoggingResource, error) {
			contents, err := d.SSMDocumentContent.Get()
			if err != nil {
				return nil, err
			}
			var res []LoggingResource
			for name, body := range contents {
				logging := strings.Contains(body, "cloudWatchOutputConfig") || strings.Contains(body, "CloudWatchOutputConfig")
				res = append(res, LoggingResource{ID: name, Logging: logging})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"ssm-document-not-public",
		"This rule checks SSM document not public.",
		"ssm",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			docs, err := d.SSMDocumentDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for name, doc := range docs {
				public := doc.Owner == nil || *doc.Owner == "public"
				res = append(res, ConfigResource{ID: name, Passing: !public, Detail: "Owner not public"})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"ssm-document-tagged",
		"This rule checks tagging for SSM document exist.",
		"ssm",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			docs, err := d.SSMDocuments.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.SSMDocumentTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, doc := range docs {
				id := "unknown"
				if doc.Name != nil {
					id = *doc.Name
				}
				res = append(res, TaggedResource{ID: id, Tags: tags[id]})
			}
			return res, nil
		},
	))
}
