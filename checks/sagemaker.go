package checks

import (
	"fmt"
	"os"
	"strings"

	"bptools/awsdata"
	"bptools/checker"

	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	sagemakertypes "github.com/aws/aws-sdk-go-v2/service/sagemaker/types"
)

// RegisterSageMakerChecks registers SageMaker-related checks.
func RegisterSageMakerChecks(d *awsdata.Data) {
	checker.Register(TaggedCheck(
		"sagemaker-app-image-config-tagged",
		"Checks if Amazon SageMaker app image configs have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"sagemaker",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			apps, err := d.SageMakerAppImageConfigs.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.SageMakerAppImageConfigTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, app := range apps {
				id := "unknown"
				if app.AppImageConfigArn != nil {
					id = *app.AppImageConfigArn
				}
				res = append(res, TaggedResource{ID: id, Tags: tags[id]})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"sagemaker-domain-in-vpc",
		"Checks if an Amazon SageMaker domain uses a customer owned Amazon Virtual Private Cloud (VPC) for non-EFS traffic. The rule is NON_COMPLIANT if configuration.AppNetworkAccessType is not set to VpcOnly.",
		"sagemaker",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			domains, err := d.SageMakerDomains.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, dom := range domains {
				id := "unknown"
				if dom.DomainArn != nil {
					id = *dom.DomainArn
				}
				if dom.DomainId == nil {
					res = append(res, ConfigResource{ID: id, Passing: false, Detail: "Missing DomainId"})
					continue
				}
				out, err := d.Clients.SageMaker.DescribeDomain(d.Ctx, &sagemaker.DescribeDomainInput{DomainId: dom.DomainId})
				if err != nil {
					res = append(res, ConfigResource{ID: id, Passing: false, Detail: fmt.Sprintf("DescribeDomain failed: %v", err)})
					continue
				}
				ok := out.VpcId != nil && *out.VpcId != ""
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("VpcId configured: %v", ok)})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"sagemaker-domain-tagged",
		"Checks if Amazon SageMaker domains have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"sagemaker",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			domains, err := d.SageMakerDomains.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.SageMakerDomainTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, dom := range domains {
				id := "unknown"
				if dom.DomainArn != nil {
					id = *dom.DomainArn
				}
				res = append(res, TaggedResource{ID: id, Tags: tags[id]})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"sagemaker-endpoint-configuration-kms-key-configured",
		"Checks if AWS Key Management Service (AWS KMS) key is configured for an Amazon SageMaker endpoint configuration. The rule is NON_COMPLIANT if 'KmsKeyId' is not specified for the Amazon SageMaker endpoint configuration.",
		"sagemaker",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			configs, err := d.SageMakerEndpointConfigDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, cfg := range configs {
				id := sagemakerEndpointConfigID(cfg)
				key := ""
				if cfg.KmsKeyId != nil {
					key = *cfg.KmsKeyId
				}
				ok := key != ""
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "KMS key configured"})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"sagemaker-endpoint-config-prod-instance-count",
		"Checks if Amazon SageMaker endpoint configurations have production variants `InitialInstanceCount` set to a value greater than 1. The rule is NON_COMPLIANT if production variants `InitialInstanceCount` is equal to 1.",
		"sagemaker",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			configs, err := d.SageMakerEndpointConfigDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, cfg := range configs {
				id := sagemakerEndpointConfigID(cfg)
				ok := len(cfg.ProductionVariants) > 0
				oneCountVariants := 0
				for _, pv := range cfg.ProductionVariants {
					if pv.InitialInstanceCount != nil && *pv.InitialInstanceCount == 1 {
						ok = false
						oneCountVariants++
					}
				}
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("Production variants with count==1: %d", oneCountVariants)})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"sagemaker-feature-group-tagged",
		"Checks if Amazon SageMaker feature groups have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"sagemaker",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			groups, err := d.SageMakerFeatureGroups.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.SageMakerFeatureGroupTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, g := range groups {
				id := "unknown"
				if g.FeatureGroupArn != nil {
					id = *g.FeatureGroupArn
				}
				res = append(res, TaggedResource{ID: id, Tags: tags[id]})
			}
			return res, nil
		},
	))

	checker.Register(DescriptionCheck(
		"sagemaker-image-description",
		"Checks if Amazon SageMaker images have a description. The rule is NON_COMPLIANT if configuration.ImageDescription does not exist.",
		"sagemaker",
		d,
		func(d *awsdata.Data) ([]DescriptionResource, error) {
			images, err := d.SageMakerImages.Get()
			if err != nil {
				return nil, err
			}
			details, err := d.SageMakerImageDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []DescriptionResource
			for _, img := range images {
				id := "unknown"
				if img.ImageArn != nil {
					id = *img.ImageArn
				}
				detail, ok := details[imageKey(img)]
				hasDesc := ok && detail.Description != nil && *detail.Description != ""
				res = append(res, DescriptionResource{ID: id, HasDescription: hasDesc})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"sagemaker-image-tagged",
		"Checks if Amazon SageMaker images have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"sagemaker",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			images, err := d.SageMakerImages.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.SageMakerImageTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, img := range images {
				id := "unknown"
				if img.ImageArn != nil {
					id = *img.ImageArn
				}
				res = append(res, TaggedResource{ID: id, Tags: tags[id]})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"sagemaker-model-in-vpc",
		"Checks if an Amazon SageMaker model uses an Amazon Virtual Private Cloud (Amazon VPC) for container traffic. The rule is NON_COMPLIANT if configuration.VpcConfig does not exist.",
		"sagemaker",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			models, err := d.SageMakerModelDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, m := range models {
				id := sagemakerModelID(m)
				ok := m.VpcConfig != nil && len(m.VpcConfig.Subnets) > 0
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "VpcConfig present"})
			}
			return res, nil
		},
	))

	checker.Register(EnabledCheck(
		"sagemaker-model-isolation-enabled",
		"Checks if an Amazon SageMaker model has network isolation enabled. The rule is NON_COMPLIANT if configuration.EnableNetworkIsolation is false.",
		"sagemaker",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			models, err := d.SageMakerModelDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, m := range models {
				id := sagemakerModelID(m)
				enabled := m.EnableNetworkIsolation != nil && *m.EnableNetworkIsolation
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"sagemaker-notebook-instance-inside-vpc",
		"Checks if an Amazon SageMaker notebook instance is launched within a VPC or within a list of approved subnets. The rule is NON_COMPLIANT if a notebook instance is not launched within a VPC or if its subnet ID is not included in the parameter list.",
		"sagemaker",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			nbs, err := d.SageMakerNotebookDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, nb := range nbs {
				id := sagemakerNotebookID(nb)
				subnet := ""
				if nb.SubnetId != nil {
					subnet = *nb.SubnetId
				}
				ok := subnet != ""
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("Subnet: %s", subnet)})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"sagemaker-notebook-instance-kms-key-configured",
		"Checks if an AWS Key Management Service (AWS KMS) key is configured for an Amazon SageMaker notebook instance. The rule is NON_COMPLIANT if 'KmsKeyId' is not specified for the SageMaker notebook instance.",
		"sagemaker",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			nbs, err := d.SageMakerNotebookDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, nb := range nbs {
				id := sagemakerNotebookID(nb)
				key := ""
				if nb.KmsKeyId != nil {
					key = *nb.KmsKeyId
				}
				ok := key != ""
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "KMS key configured"})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"sagemaker-notebook-instance-platform-version",
		"Checks if a Sagemaker Notebook Instance is configured to use a supported platform identifier version. The rule is NON_COMPLIANT if a Notebook Instance is not using the specified supported platform identifier version as specified in the parameter.",
		"sagemaker",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			nbs, err := d.SageMakerNotebookDetails.Get()
			if err != nil {
				return nil, err
			}
			supportedPlatforms := sagemakerParseCSV(strings.TrimSpace(os.Getenv("BPTOOLS_SAGEMAKER_NOTEBOOK_SUPPORTED_PLATFORM_VERSIONS")))
			supportedSet := make(map[string]bool, len(supportedPlatforms))
			for _, platform := range supportedPlatforms {
				supportedSet[strings.ToLower(strings.TrimSpace(platform))] = true
			}
			var res []ConfigResource
			for _, nb := range nbs {
				id := sagemakerNotebookID(nb)
				platform := ""
				if nb.PlatformIdentifier != nil {
					platform = *nb.PlatformIdentifier
				}
				ok := true
				if len(supportedSet) > 0 {
					ok = supportedSet[strings.ToLower(strings.TrimSpace(platform))]
				}
				detail := fmt.Sprintf("Platform: %s, supported: %v", platform, ok)
				if len(supportedSet) == 0 {
					detail = fmt.Sprintf("Platform: %s, no supported list configured (default allow-all)", platform)
				}
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: detail})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"sagemaker-notebook-instance-root-access-check",
		"Checks if the Amazon SageMaker RootAccess setting is enabled for Amazon SageMaker notebook instances. The rule is NON_COMPLIANT if the RootAccess setting is set to ‘Enabled’ for an Amazon SageMaker notebook instance.",
		"sagemaker",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			nbs, err := d.SageMakerNotebookDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, nb := range nbs {
				id := sagemakerNotebookID(nb)
				ok := nb.RootAccess == sagemakertypes.RootAccessDisabled
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("RootAccess: %s", nb.RootAccess)})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"sagemaker-notebook-no-direct-internet-access",
		"Checks if direct internet access is disabled for an Amazon SageMaker notebook instance. The rule is NON_COMPLIANT if a SageMaker notebook instance is internet-enabled.",
		"sagemaker",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			nbs, err := d.SageMakerNotebookDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, nb := range nbs {
				id := sagemakerNotebookID(nb)
				ok := nb.DirectInternetAccess == sagemakertypes.DirectInternetAccessDisabled
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("DirectInternetAccess: %s", nb.DirectInternetAccess)})
			}
			return res, nil
		},
	))
}

func imageKey(img sagemakertypes.Image) string {
	if img.ImageName != nil {
		return *img.ImageName
	}
	return ""
}

func sagemakerEndpointConfigID(cfg sagemaker.DescribeEndpointConfigOutput) string {
	if cfg.EndpointConfigArn != nil {
		return *cfg.EndpointConfigArn
	}
	if cfg.EndpointConfigName != nil {
		return *cfg.EndpointConfigName
	}
	return "unknown"
}

func sagemakerModelID(m sagemaker.DescribeModelOutput) string {
	if m.ModelArn != nil {
		return *m.ModelArn
	}
	if m.ModelName != nil {
		return *m.ModelName
	}
	return "unknown"
}

func sagemakerNotebookID(nb sagemaker.DescribeNotebookInstanceOutput) string {
	if nb.NotebookInstanceArn != nil {
		return *nb.NotebookInstanceArn
	}
	if nb.NotebookInstanceName != nil {
		return *nb.NotebookInstanceName
	}
	return "unknown"
}

func sagemakerParseCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}
