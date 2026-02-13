package checks

import (
	"bptools/awsdata"
	"bptools/checker"
)

// RegisterAppStreamChecks registers AppStream checks.
func RegisterAppStreamChecks(d *awsdata.Data) {
	checker.Register(ConfigCheck(
		"appstream-fleet-in-vpc",
		"Checks if Amazon AppStream 2.0 fleets use an Amazon Virtual Private Cloud (Amazon VPC). The rule is NON_COMPLIANT if configuration.VpcConfig does not exist. The rule does not check Elastic fleets.",
		"appstream",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			fleets, err := d.AppStreamFleets.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, f := range fleets {
				id := "unknown"
				if f.Arn != nil {
					id = *f.Arn
				} else if f.Name != nil {
					id = *f.Name
				}
				ok := f.VpcConfig != nil && len(f.VpcConfig.SubnetIds) > 0
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "Fleet has VPC subnets configured"})
			}
			return res, nil
		},
	))
}
