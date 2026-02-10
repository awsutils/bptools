package checks

import (
	"bptools/awsdata"
	"bptools/checker"
)

// RegisterIoTChecks registers IoT checks.
func RegisterIoTChecks(d *awsdata.Data) {
	checker.Register(EnabledCheck(
		"iot-authorizer-token-signing-enabled",
		"This rule checks IOT authorizer token signing enabled.",
		"iot",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			auths, err := d.IoTAuthorizerDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for name, a := range auths {
				enabled := a.SigningDisabled == nil || !*a.SigningDisabled
				res = append(res, EnabledResource{ID: name, Enabled: enabled})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"iot-job-template-tagged",
		"This rule checks tagging for IOT job template exist.",
		"iot",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			items, err := d.IoTJobTemplates.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.IoTJobTemplateTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, it := range items {
				id := "unknown"
				key := ""
				if it.JobTemplateArn != nil {
					id = *it.JobTemplateArn
					key = *it.JobTemplateArn
				} else if it.JobTemplateId != nil {
					id = *it.JobTemplateId
					key = *it.JobTemplateId
				}
				res = append(res, TaggedResource{ID: id, Tags: tags[key]})
			}
			return res, nil
		},
	))

	checker.Register(DescriptionCheck(
		"iot-provisioning-template-description",
		"This rule checks IOT provisioning template description.",
		"iot",
		d,
		func(d *awsdata.Data) ([]DescriptionResource, error) {
			templates, err := d.IoTProvisioningTemplateDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []DescriptionResource
			for name, t := range templates {
				has := t.Description != nil && *t.Description != ""
				res = append(res, DescriptionResource{ID: name, HasDescription: has})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"iot-provisioning-template-jitp",
		"This rule checks IOT provisioning template jitp.",
		"iot",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			templates, err := d.IoTProvisioningTemplateDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for name, t := range templates {
				ok := t.Enabled != nil && *t.Enabled
				res = append(res, ConfigResource{ID: name, Passing: ok, Detail: "Template enabled"})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"iot-provisioning-template-tagged",
		"This rule checks tagging for IOT provisioning template exist.",
		"iot",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			templates, err := d.IoTProvisioningTemplates.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.IoTProvisioningTemplateTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, t := range templates {
				id := "unknown"
				key := ""
				if t.TemplateArn != nil {
					id = *t.TemplateArn
					key = *t.TemplateArn
				} else if t.TemplateName != nil {
					id = *t.TemplateName
					key = *t.TemplateName
				}
				res = append(res, TaggedResource{ID: id, Tags: tags[key]})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"iot-scheduled-audit-tagged",
		"This rule checks tagging for IOT scheduled audit exist.",
		"iot",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			audits, err := d.IoTScheduledAudits.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.IoTScheduledAuditTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, a := range audits {
				id := "unknown"
				if a.ScheduledAuditArn != nil {
					id = *a.ScheduledAuditArn
				}
				res = append(res, TaggedResource{ID: id, Tags: tags[id]})
			}
			return res, nil
		},
	))
}
