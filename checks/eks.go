package checks

import (
	"fmt"

	"bptools/awsdata"
	"bptools/checker"
)

func RegisterEKSChecks(d *awsdata.Data) {
	// eks-cluster-logging-enabled and eks-cluster-log-enabled
	checker.Register(LoggingCheck(
		"eks-cluster-logging-enabled",
		"This rule checks EKS cluster logging enabled.",
		"eks",
		d,
		func(d *awsdata.Data) ([]LoggingResource, error) {
			clusters, err := d.EKSClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []LoggingResource
			for name, c := range clusters {
				logging := false
				if c.Logging != nil {
					for _, l := range c.Logging.ClusterLogging {
						if l.Enabled != nil && *l.Enabled {
							logging = true
							break
						}
					}
				}
				res = append(res, LoggingResource{ID: name, Logging: logging})
			}
			return res, nil
		},
	))
	checker.Register(LoggingCheck(
		"eks-cluster-log-enabled",
		"This rule checks EKS cluster log enabled.",
		"eks",
		d,
		func(d *awsdata.Data) ([]LoggingResource, error) {
			clusters, err := d.EKSClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []LoggingResource
			for name, c := range clusters {
				logging := false
				if c.Logging != nil {
					for _, l := range c.Logging.ClusterLogging {
						if l.Enabled != nil && *l.Enabled {
							logging = true
							break
						}
					}
				}
				res = append(res, LoggingResource{ID: name, Logging: logging})
			}
			return res, nil
		},
	))

	// eks-endpoint-no-public-access
	checker.Register(ConfigCheck(
		"eks-endpoint-no-public-access",
		"This rule checks EKS endpoint no public access.",
		"eks",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			clusters, err := d.EKSClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for name, c := range clusters {
				public := c.ResourcesVpcConfig != nil && c.ResourcesVpcConfig.EndpointPublicAccess != nil && *c.ResourcesVpcConfig.EndpointPublicAccess
				res = append(res, ConfigResource{ID: name, Passing: !public, Detail: fmt.Sprintf("PublicAccess: %v", public)})
			}
			return res, nil
		},
	))

	// eks-secrets-encrypted + eks-cluster-secrets-encrypted
	checker.Register(EncryptionCheck(
		"eks-secrets-encrypted",
		"This rule checks EKS secrets encrypted.",
		"eks",
		d,
		func(d *awsdata.Data) ([]EncryptionResource, error) {
			clusters, err := d.EKSClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []EncryptionResource
			for name, c := range clusters {
				encrypted := c.EncryptionConfig != nil && len(c.EncryptionConfig) > 0
				res = append(res, EncryptionResource{ID: name, Encrypted: encrypted})
			}
			return res, nil
		},
	))
	checker.Register(EncryptionCheck(
		"eks-cluster-secrets-encrypted",
		"This rule checks EKS cluster secrets encrypted.",
		"eks",
		d,
		func(d *awsdata.Data) ([]EncryptionResource, error) {
			clusters, err := d.EKSClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []EncryptionResource
			for name, c := range clusters {
				encrypted := c.EncryptionConfig != nil && len(c.EncryptionConfig) > 0
				res = append(res, EncryptionResource{ID: name, Encrypted: encrypted})
			}
			return res, nil
		},
	))

	// eks-addon-tagged
	checker.Register(TaggedCheck(
		"eks-addon-tagged",
		"This rule checks EKS addon tagged.",
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
		"This rule checks EKS fargate profile tagged.",
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
		"This rule checks EKS cluster supported version.",
		"eks",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			clusters, err := d.EKSClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for name, c := range clusters {
				ok := c.Version != nil && *c.Version != ""
				res = append(res, ConfigResource{ID: name, Passing: ok, Detail: fmt.Sprintf("Version: %v", c.Version)})
			}
			return res, nil
		},
	))
	checker.Register(ConfigCheck(
		"eks-cluster-oldest-supported-version",
		"This rule checks EKS cluster oldest supported version.",
		"eks",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			clusters, err := d.EKSClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for name, c := range clusters {
				ok := c.Version != nil && *c.Version != ""
				res = append(res, ConfigResource{ID: name, Passing: ok, Detail: fmt.Sprintf("Version: %v", c.Version)})
			}
			return res, nil
		},
	))
}
