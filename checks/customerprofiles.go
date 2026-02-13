package checks

import (
	"fmt"

	"bptools/awsdata"
	"bptools/checker"
)

// RegisterCustomerProfilesChecks registers Customer Profiles checks.
func RegisterCustomerProfilesChecks(d *awsdata.Data) {
	checker.Register(TaggedCheck(
		"customerprofiles-domain-tagged",
		"Checks if Amazon Connect Customer Profiles domains have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"customerprofiles",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			domains, err := d.CustomerProfilesDomains.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, dom := range domains {
				id := "unknown"
				if dom.DomainName != nil {
					id = *dom.DomainName
				}
				res = append(res, TaggedResource{ID: id, Tags: dom.Tags})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"customerprofiles-object-type-allow-profile-creation",
		"Checks if Amazon Connect Customer Profiles object types allow the creation of a new standard profile if one does not exist. The rule is NON_COMPLIANT if configuration.AllowProfileCreation is false.",
		"customerprofiles",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			details, err := d.CustomerProfilesObjectTypeDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for key, detail := range details {
				res = append(res, ConfigResource{
					ID:      key,
					Passing: detail.AllowProfileCreation,
					Detail:  fmt.Sprintf("AllowProfileCreation: %v", detail.AllowProfileCreation),
				})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"customerprofiles-object-type-tagged",
		"Checks if Amazon Connect Customer Profiles object types have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"customerprofiles",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			details, err := d.CustomerProfilesObjectTypeDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for key, detail := range details {
				res = append(res, TaggedResource{ID: key, Tags: detail.Tags})
			}
			return res, nil
		},
	))
}
