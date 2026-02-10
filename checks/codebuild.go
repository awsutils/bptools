package checks

import (
	"strings"

	"bptools/awsdata"
	"bptools/checker"
)

// RegisterCodeBuildChecks registers CodeBuild checks.
func RegisterCodeBuildChecks(d *awsdata.Data) {
	checker.Register(EncryptionCheck(
		"codebuild-project-artifact-encryption",
		"This rule checks codebuild project artifact encryption.",
		"codebuild",
		d,
		func(d *awsdata.Data) ([]EncryptionResource, error) {
			projects, err := d.CodeBuildProjects.Get()
			if err != nil {
				return nil, err
			}
			var res []EncryptionResource
			for _, p := range projects {
				id := projectID(p.Name)
				encrypted := p.Artifacts != nil && (p.Artifacts.EncryptionDisabled == nil || !*p.Artifacts.EncryptionDisabled)
				res = append(res, EncryptionResource{ID: id, Encrypted: encrypted})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"codebuild-project-environment-privileged-check",
		"This rule checks configuration for codebuild project environment privileged.",
		"codebuild",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			projects, err := d.CodeBuildProjects.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, p := range projects {
				id := projectID(p.Name)
				priv := p.Environment != nil && p.Environment.PrivilegedMode != nil && *p.Environment.PrivilegedMode
				res = append(res, ConfigResource{ID: id, Passing: !priv, Detail: "PrivilegedMode disabled"})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"codebuild-project-envvar-awscred-check",
		"This rule checks configuration for codebuild project envvar awscred.",
		"codebuild",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			projects, err := d.CodeBuildProjects.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, p := range projects {
				id := projectID(p.Name)
				ok := true
				if p.Environment != nil {
					for _, ev := range p.Environment.EnvironmentVariables {
						name := ""
						if ev.Name != nil {
							name = strings.ToUpper(*ev.Name)
						}
						if name == "AWS_ACCESS_KEY_ID" || name == "AWS_SECRET_ACCESS_KEY" || name == "AWS_SESSION_TOKEN" {
							ok = false
							break
						}
					}
				}
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "No static AWS credential env vars"})
			}
			return res, nil
		},
	))

	checker.Register(LoggingCheck(
		"codebuild-project-logging-enabled",
		"This rule checks logging is enabled for codebuild project.",
		"codebuild",
		d,
		func(d *awsdata.Data) ([]LoggingResource, error) {
			projects, err := d.CodeBuildProjects.Get()
			if err != nil {
				return nil, err
			}
			var res []LoggingResource
			for _, p := range projects {
				id := projectID(p.Name)
				logging := false
				if p.LogsConfig != nil {
					if p.LogsConfig.CloudWatchLogs != nil && p.LogsConfig.CloudWatchLogs.Status != "DISABLED" {
						logging = true
					}
					if p.LogsConfig.S3Logs != nil && p.LogsConfig.S3Logs.Status != "DISABLED" {
						logging = true
					}
				}
				res = append(res, LoggingResource{ID: id, Logging: logging})
			}
			return res, nil
		},
	))

	checker.Register(EncryptionCheck(
		"codebuild-project-s3-logs-encrypted",
		"This rule checks codebuild project S3 logs encrypted.",
		"codebuild",
		d,
		func(d *awsdata.Data) ([]EncryptionResource, error) {
			projects, err := d.CodeBuildProjects.Get()
			if err != nil {
				return nil, err
			}
			var res []EncryptionResource
			for _, p := range projects {
				id := projectID(p.Name)
				encrypted := true
				if p.LogsConfig != nil && p.LogsConfig.S3Logs != nil && p.LogsConfig.S3Logs.Status != "DISABLED" {
					encrypted = p.LogsConfig.S3Logs.EncryptionDisabled == nil || !*p.LogsConfig.S3Logs.EncryptionDisabled
				}
				res = append(res, EncryptionResource{ID: id, Encrypted: encrypted})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"codebuild-project-source-repo-url-check",
		"This rule checks configuration for codebuild project source repo url.",
		"codebuild",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			projects, err := d.CodeBuildProjects.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, p := range projects {
				id := projectID(p.Name)
				ok := p.Source != nil && p.Source.Location != nil && *p.Source.Location != ""
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "Source location configured"})
			}
			return res, nil
		},
	))

	checker.Register(EncryptionCheck(
		"codebuild-report-group-encrypted-at-rest",
		"This rule checks encryption at rest for codebuild report group.",
		"codebuild",
		d,
		func(d *awsdata.Data) ([]EncryptionResource, error) {
			groups, err := d.CodeBuildReportGroupDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []EncryptionResource
			for arn, g := range groups {
				encrypted := true
				if g.ExportConfig != nil && g.ExportConfig.S3Destination != nil {
					encrypted = g.ExportConfig.S3Destination.EncryptionDisabled == nil || !*g.ExportConfig.S3Destination.EncryptionDisabled
				}
				res = append(res, EncryptionResource{ID: arn, Encrypted: encrypted})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"codebuild-report-group-tagged",
		"This rule checks tagging for codebuild report group exist.",
		"codebuild",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			groups, err := d.CodeBuildReportGroupDetails.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.CodeBuildReportGroupTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for arn := range groups {
				res = append(res, TaggedResource{ID: arn, Tags: tags[arn]})
			}
			return res, nil
		},
	))
}

func projectID(name *string) string {
	if name != nil {
		return *name
	}
	return "unknown"
}
