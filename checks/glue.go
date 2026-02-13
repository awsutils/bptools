package checks

import (
	"bptools/awsdata"
	"bptools/checker"
)

// RegisterGlueChecks registers Glue checks.
func RegisterGlueChecks(d *awsdata.Data) {
	checker.Register(LoggingCheck(
		"glue-job-logging-enabled",
		"Checks if an AWS Glue job has logging enabled. The rule is NON_COMPLIANT if an AWS Glue job does not have Amazon CloudWatch logs enabled.",
		"glue",
		d,
		func(d *awsdata.Data) ([]LoggingResource, error) {
			jobs, err := d.GlueJobs.Get()
			if err != nil {
				return nil, err
			}
			var res []LoggingResource
			for _, j := range jobs {
				id := "unknown"
				if j.Name != nil {
					id = *j.Name
				}
				logging := j.DefaultArguments != nil && j.DefaultArguments["--enable-continuous-cloudwatch-log"] != "false" && j.DefaultArguments["--enable-continuous-cloudwatch-log"] != "0"
				res = append(res, LoggingResource{ID: id, Logging: logging})
			}
			return res, nil
		},
	))

	checker.Register(EncryptionCheck(
		"glue-ml-transform-encrypted-at-rest",
		"Checks if an AWS Glue ML Transform has encryption at rest enabled. The rule is NON_COMPLIANT if `MLUserDataEncryptionMode` is set to `DISABLED`.",
		"glue",
		d,
		func(d *awsdata.Data) ([]EncryptionResource, error) {
			transforms, err := d.GlueMLTransforms.Get()
			if err != nil {
				return nil, err
			}
			var res []EncryptionResource
			for _, t := range transforms {
				id := "unknown"
				if t.TransformId != nil {
					id = *t.TransformId
				}
				encrypted := t.TransformEncryption != nil && t.TransformEncryption.MlUserDataEncryption != nil && t.TransformEncryption.MlUserDataEncryption.MlUserDataEncryptionMode != "DISABLED"
				res = append(res, EncryptionResource{ID: id, Encrypted: encrypted})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"glue-ml-transform-tagged",
		"Checks if AWS Glue machine learning transforms have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"glue",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			transforms, err := d.GlueMLTransforms.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.GlueMLTransformTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, t := range transforms {
				id := "unknown"
				if t.TransformId != nil {
					id = *t.TransformId
				}
				res = append(res, TaggedResource{ID: id, Tags: tags[id]})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"glue-spark-job-supported-version",
		"Checks if an AWS Glue Spark job is running on the specified minimum supported AWS Glue version. The rule is NON_COMPLIANT if the AWS Glue Spark job is not running on the minimum supported AWS Glue version that you specify.",
		"glue",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			jobs, err := d.GlueJobs.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, j := range jobs {
				id := "unknown"
				if j.Name != nil {
					id = *j.Name
				}
				ok := j.GlueVersion != nil && *j.GlueVersion != "0.9" && *j.GlueVersion != "1.0"
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "GlueVersion supported"})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"custom-schema-registry-policy-attached",
		"Checks if custom Amazon EventBridge schema registries have a resource policy attached. The rule is NON_COMPLIANT for custom schema registries without a resource policy attached.",
		"glue",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			regs, err := d.GlueRegistries.Get()
			if err != nil {
				return nil, err
			}
			policies, err := d.GlueRegistryPolicies.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, r := range regs {
				if r.RegistryName == nil || r.RegistryArn == nil {
					continue
				}
				if *r.RegistryName == "default" {
					continue
				}
				pol := policies[*r.RegistryArn]
				ok := pol != ""
				res = append(res, ConfigResource{ID: *r.RegistryArn, Passing: ok, Detail: "Registry policy attached"})
			}
			return res, nil
		},
	))
}
