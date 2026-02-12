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
		"This rule checks tagging for SageMaker app image config exist.",
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
		"This rule checks VPC placement for SageMaker domain.",
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
		"This rule checks tagging for SageMaker domain exist.",
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
		"This rule checks SageMaker endpoint configuration KMS key configured.",
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
		"This rule checks SageMaker endpoint config prod instance count.",
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
		"This rule checks tagging for SageMaker feature group exist.",
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
		"This rule checks descriptions for SageMaker image exist.",
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
		"This rule checks tagging for SageMaker image exist.",
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
		"This rule checks VPC placement for SageMaker model.",
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
		"This rule checks enabled state for SageMaker model isolation.",
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
		"This rule checks SageMaker notebook instance inside VPC.",
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
		"This rule checks SageMaker notebook instance KMS key configured.",
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
		"This rule checks versions for SageMaker notebook instance platform.",
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
		"This rule checks configuration for SageMaker notebook instance root access.",
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
		"This rule checks SageMaker notebook no direct internet access.",
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
