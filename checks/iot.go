package checks

import (
	"bptools/awsdata"
	"bptools/checker"
)

// RegisterIoTChecks registers IoT checks.
func RegisterIoTChecks(d *awsdata.Data) {
	checker.Register(EnabledCheck(
		"iot-authorizer-token-signing-enabled",
		"Checks if an AWS IoT Core authorizer has not disabled the signing requirements for validating the token signature in an authorization request. The rule is NON_COMPLIANT if the authorizer has configuration.SigningDisabled set to True.",
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
		"Checks if AWS IoT job template resources resources have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
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
		"Checks if AWS IoT provisioning templates have a description. The rule is NON_COMPLIANT if configuration.Description does not exist or is an empty string.",
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
		"Checks if AWS IoT provisioning templates are using just-in-time provisioning (JITP). The rule is NON_COMPLIANT if configuration.TemplateType is not 'JITP'.",
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
		"Checks if AWS IoT provisioning templates have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
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
		"Checks if AWS IoT scheduled audits have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
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
