package checks

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"bptools/awsdata"
	"bptools/checker"

	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
)

var eksRequiredControlPlaneLogTypes = map[ekstypes.LogType]bool{
	ekstypes.LogTypeApi:               true,
	ekstypes.LogTypeAudit:             true,
	ekstypes.LogTypeAuthenticator:     true,
	ekstypes.LogTypeControllerManager: true,
	ekstypes.LogTypeScheduler:         true,
}

func eksAllControlPlaneLogsEnabled(c ekstypes.Cluster) bool {
	if c.Logging == nil {
		return false
	}
	enabled := make(map[ekstypes.LogType]bool)
	for _, setup := range c.Logging.ClusterLogging {
		if setup.Enabled == nil || !*setup.Enabled {
			continue
		}
		for _, t := range setup.Types {
			enabled[t] = true
		}
	}
	for t := range eksRequiredControlPlaneLogTypes {
		if !enabled[t] {
			return false
		}
	}
	return true
}

func eksEncryptionConfigIncludesSecrets(c ekstypes.Cluster) bool {
	for _, cfg := range c.EncryptionConfig {
		for _, r := range cfg.Resources {
			if strings.EqualFold(string(r), "secrets") {
				return true
			}
		}
	}
	return false
}

func eksVersionParts(version string) (int, int, bool) {
	v := strings.TrimSpace(strings.TrimPrefix(version, "v"))
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return 0, 0, false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, false
	}
	minorDigits := ""
	for _, ch := range parts[1] {
		if ch >= '0' && ch <= '9' {
			minorDigits += string(ch)
		} else {
			break
		}
	}
	if minorDigits == "" {
		return 0, 0, false
	}
	minor, err := strconv.Atoi(minorDigits)
	if err != nil {
		return 0, 0, false
	}
	return major, minor, true
}

func eksVersionAtLeast(version, minVersion string) bool {
	maj, min, ok := eksVersionParts(version)
	if !ok {
		return false
	}
	reqMaj, reqMin, ok := eksVersionParts(minVersion)
	if !ok {
		return false
	}
	if maj != reqMaj {
		return maj > reqMaj
	}
	return min >= reqMin
}

func eksVersionInAllowedList(version string, allowed []string) bool {
	for _, v := range allowed {
		if strings.EqualFold(strings.TrimSpace(version), strings.TrimSpace(v)) {
			return true
		}
	}
	return false
}

func eksParseCSV(value string) []string {
	items := strings.Split(value, ",")
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func RegisterEKSChecks(d *awsdata.Data) {
	// eks-cluster-logging-enabled and eks-cluster-log-enabled
	checker.Register(LoggingCheck(
		"eks-cluster-logging-enabled",
		"Checks if an Amazon Elastic Kubernetes Service (Amazon EKS) cluster is configured with logging enabled. The rule is NON_COMPLIANT if logging for Amazon EKS clusters is not enabled for all log types.",
		"eks",
		d,
		func(d *awsdata.Data) ([]LoggingResource, error) {
			clusters, err := d.EKSClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []LoggingResource
			for name, c := range clusters {
				logging := eksAllControlPlaneLogsEnabled(c)
				res = append(res, LoggingResource{ID: name, Logging: logging})
			}
			return res, nil
		},
	))
	checker.Register(LoggingCheck(
		"eks-cluster-log-enabled",
		"Checks if an Amazon Elastic Kubernetes Service (Amazon EKS) cluster is configured with logging enabled. The rule is NON_COMPLIANT if logging for Amazon EKS clusters is not enabled or if logging is not enabled with the log type mentioned.",
		"eks",
		d,
		func(d *awsdata.Data) ([]LoggingResource, error) {
			clusters, err := d.EKSClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []LoggingResource
			for name, c := range clusters {
				logging := eksAllControlPlaneLogsEnabled(c)
				res = append(res, LoggingResource{ID: name, Logging: logging})
			}
			return res, nil
		},
	))

	// eks-endpoint-no-public-access
	checker.Register(ConfigCheck(
		"eks-endpoint-no-public-access",
		"Checks if the Amazon Elastic Kubernetes Service (Amazon EKS) endpoint is not publicly accessible. The rule is NON_COMPLIANT if the endpoint is publicly accessible.",
		"eks",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			clusters, err := d.EKSClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for name, c := range clusters {
				public := c.ResourcesVpcConfig != nil && c.ResourcesVpcConfig.EndpointPublicAccess
				res = append(res, ConfigResource{ID: name, Passing: !public, Detail: fmt.Sprintf("PublicAccess: %v", public)})
			}
			return res, nil
		},
	))

	// eks-secrets-encrypted + eks-cluster-secrets-encrypted
	checker.Register(EncryptionCheck(
		"eks-secrets-encrypted",
		"Checks if Amazon Elastic Kubernetes Service clusters are configured to have Kubernetes secrets encrypted using AWS Key Management Service (KMS) keys.",
		"eks",
		d,
		func(d *awsdata.Data) ([]EncryptionResource, error) {
			clusters, err := d.EKSClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []EncryptionResource
			for name, c := range clusters {
				encrypted := c.EncryptionConfig != nil && len(c.EncryptionConfig) > 0 && eksEncryptionConfigIncludesSecrets(c)
				res = append(res, EncryptionResource{ID: name, Encrypted: encrypted})
			}
			return res, nil
		},
	))
	checker.Register(EncryptionCheck(
		"eks-cluster-secrets-encrypted",
		"Checks if Amazon EKS clusters are configured to have Kubernetes secrets encrypted using AWS KMS. The rule is NON_COMPLIANT if an EKS cluster does not have an encryptionConfig resource or if encryptionConfig does not name secrets as a resource.",
		"eks",
		d,
		func(d *awsdata.Data) ([]EncryptionResource, error) {
			clusters, err := d.EKSClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []EncryptionResource
			for name, c := range clusters {
				encrypted := c.EncryptionConfig != nil && len(c.EncryptionConfig) > 0 && eksEncryptionConfigIncludesSecrets(c)
				res = append(res, EncryptionResource{ID: name, Encrypted: encrypted})
			}
			return res, nil
		},
	))

	// eks-addon-tagged
	checker.Register(TaggedCheck(
		"eks-addon-tagged",
		"Checks if Amazon EKS add-ons have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"eks",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			addons, err := d.EKSAddons.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, items := range addons {
				for _, a := range items {
					id := "unknown"
					if a.AddonArn != nil {
						id = *a.AddonArn
					}
					res = append(res, TaggedResource{ID: id, Tags: a.Tags})
				}
			}
			return res, nil
		},
	))

	// eks-fargate-profile-tagged
	checker.Register(TaggedCheck(
		"eks-fargate-profile-tagged",
		"Checks if Amazon EKS fargate profiles have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"eks",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			fps, err := d.EKSFargateProfiles.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, items := range fps {
				for _, fp := range items {
					id := "unknown"
					if fp.FargateProfileArn != nil {
						id = *fp.FargateProfileArn
					}
					res = append(res, TaggedResource{ID: id, Tags: fp.Tags})
				}
			}
			return res, nil
		},
	))

	// eks-cluster-supported-version + eks-cluster-oldest-supported-version
	checker.Register(ConfigCheck(
		"eks-cluster-supported-version",
		"Checks if an Amazon Elastic Kubernetes Service (EKS) cluster is running a supported Kubernetes version. This rule is NON_COMPLIANT if an EKS cluster is running an unsupported version (less than the parameter 'oldestVersionSupported').",
		"eks",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			clusters, err := d.EKSClusters.Get()
			if err != nil {
				return nil, err
			}
			allowedVersions := eksParseCSV(os.Getenv("BPTOOLS_EKS_SUPPORTED_VERSIONS"))
			minSupported := strings.TrimSpace(os.Getenv("BPTOOLS_EKS_MIN_SUPPORTED_VERSION"))
			var res []ConfigResource
			for name, c := range clusters {
				if c.Version == nil || *c.Version == "" {
					res = append(res, ConfigResource{ID: name, Passing: false, Detail: "Version missing"})
					continue
				}
				ok := false
				if len(allowedVersions) > 0 {
					ok = eksVersionInAllowedList(*c.Version, allowedVersions)
				} else if minSupported != "" {
					ok = eksVersionAtLeast(*c.Version, minSupported)
				} else {
					ok = true
				}
				res = append(res, ConfigResource{ID: name, Passing: ok, Detail: fmt.Sprintf("Version: %s", *c.Version)})
			}
			return res, nil
		},
	))
	checker.Register(ConfigCheck(
		"eks-cluster-oldest-supported-version",
		"Checks if an Amazon Elastic Kubernetes Service (EKS) cluster is running the oldest supported version. The rule is NON_COMPLIANT if an EKS cluster is running oldest supported version (equal to the parameter 'oldestVersionSupported').",
		"eks",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			clusters, err := d.EKSClusters.Get()
			if err != nil {
				return nil, err
			}
			oldestSupported := strings.TrimSpace(os.Getenv("BPTOOLS_EKS_OLDEST_SUPPORTED_VERSION"))
			if oldestSupported == "" {
				oldestSupported = strings.TrimSpace(os.Getenv("BPTOOLS_EKS_MIN_SUPPORTED_VERSION"))
			}
			var res []ConfigResource
			for name, c := range clusters {
				if c.Version == nil || *c.Version == "" {
					res = append(res, ConfigResource{ID: name, Passing: false, Detail: "Version missing"})
					continue
				}
				ok := true
				if oldestSupported != "" {
					ok = eksVersionAtLeast(*c.Version, oldestSupported)
				}
				res = append(res, ConfigResource{ID: name, Passing: ok, Detail: fmt.Sprintf("Version: %s, oldest-supported: %s", *c.Version, oldestSupported)})
			}
			return res, nil
		},
	))
}
