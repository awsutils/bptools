package checks

import (
	"fmt"
	"net/url"
	"strings"

	"bptools/awsdata"
	"bptools/checker"
)

// RegisterCodeBuildChecks registers CodeBuild checks.
func RegisterCodeBuildChecks(d *awsdata.Data) {
	checker.Register(EncryptionCheck(
		"codebuild-project-artifact-encryption",
		"Checks if an AWS CodeBuild project has encryption enabled for all of its artifacts. The rule is NON_COMPLIANT if 'encryptionDisabled' is set to 'true' for any primary or secondary (if present) artifact configurations.",
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
				if p.Artifacts != nil && p.Artifacts.EncryptionDisabled != nil && *p.Artifacts.EncryptionDisabled {
					encrypted = false
				}
				for _, art := range p.SecondaryArtifacts {
					if art.EncryptionDisabled != nil && *art.EncryptionDisabled {
						encrypted = false
						break
					}
				}
				res = append(res, EncryptionResource{ID: id, Encrypted: encrypted})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"codebuild-project-environment-privileged-check",
		"Checks if an AWS CodeBuild project environment has privileged mode enabled. The rule is NON_COMPLIANT for a CodeBuild project if ‘privilegedMode’ is set to ‘true’.",
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
		"Checks if the project contains environment variables AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY. The rule is NON_COMPLIANT when the project environment variables contains plaintext credentials.",
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
		"Checks if an AWS CodeBuild project environment has at least one log option enabled. The rule is NON_COMPLIANT if the status of all present log configurations is set to 'DISABLED'.",
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
		"Checks if a AWS CodeBuild project configured with Amazon S3 Logs has encryption enabled for its logs. The rule is NON_COMPLIANT if ‘encryptionDisabled’ is set to ‘true’ in a S3LogsConfig of a CodeBuild project.",
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
		"Checks if the Bitbucket source repository URL contains sign-in credentials or not. The rule is NON_COMPLIANT if the URL contains any sign-in information and COMPLIANT if it doesn't.",
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
				locations := map[string]string{}
				if p.Source != nil && p.Source.Location != nil {
					locations["primary"] = strings.TrimSpace(*p.Source.Location)
				}
				for idx, source := range p.SecondarySources {
					if source.Location == nil {
						continue
					}
					key := fmt.Sprintf("secondary[%d]", idx)
					locations[key] = strings.TrimSpace(*source.Location)
				}
				if len(locations) == 0 {
					res = append(res, ConfigResource{ID: id, Passing: true, Detail: "No source location URL configured"})
					continue
				}
				ok := true
				detail := "No embedded URL credentials"
				for sourceKey, location := range locations {
					if location == "" {
						continue
					}
					sourceOK, sourceDetail := codeBuildSourceURLHasNoEmbeddedCredentials(location)
					if !sourceOK {
						ok = false
						detail = fmt.Sprintf("%s: %s", sourceKey, sourceDetail)
						break
					}
				}
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: detail})
			}
			return res, nil
		},
	))

	checker.Register(EncryptionCheck(
		"codebuild-report-group-encrypted-at-rest",
		"Checks if an AWS CodeBuild report group has encryption at rest setting enabled. The rule is NON_COMPLIANT if 'EncryptionDisabled' is 'true'.",
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
		"Checks if AWS CodeBuild report groups have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
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

func codeBuildSourceURLHasNoEmbeddedCredentials(location string) (bool, string) {
	parsed, err := url.Parse(location)
	if err != nil {
		trimmed := strings.TrimSpace(location)
		if strings.Contains(trimmed, "@") && strings.Contains(trimmed, "://") {
			return false, "Source location appears to include embedded credentials"
		}
		return true, "Source location is not a URL"
	}
	if parsed.User != nil {
		username := parsed.User.Username()
		if username == "" {
			username = "<empty>"
		}
		return false, fmt.Sprintf("Embedded URL credentials detected for user %s", username)
	}
	return true, "No embedded URL credentials"
}
