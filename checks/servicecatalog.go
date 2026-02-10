package checks

import (
	"fmt"

	"bptools/awsdata"
	"bptools/checker"
)

// RegisterServiceCatalogChecks registers Service Catalog checks.
func RegisterServiceCatalogChecks(d *awsdata.Data) {
	checker.Register(TaggedCheck(
		"service-catalog-portfolio-tagged",
		"This rule checks service catalog portfolio tagged.",
		"servicecatalog",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			ports, err := d.ServiceCatalogPortfolios.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.ServiceCatalogPortfolioTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, p := range ports {
				id := "unknown"
				tagKey := ""
				if p.Id != nil {
					id = *p.Id
					tagKey = *p.Id
				} else if p.ARN != nil {
					id = *p.ARN
				}
				res = append(res, TaggedResource{ID: id, Tags: tags[tagKey]})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"service-catalog-shared-within-organization",
		"This rule checks service catalog shared within organization.",
		"servicecatalog",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			shares, err := d.ServiceCatalogPortfolioShares.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for id, accounts := range shares {
				ok := len(accounts) > 0
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("Shared accounts: %d", len(accounts))})
			}
			return res, nil
		},
	))
}
