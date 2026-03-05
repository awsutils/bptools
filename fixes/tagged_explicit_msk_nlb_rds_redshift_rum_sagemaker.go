package fixes

import (
	"bptools/awsdata"
	"bptools/fix"
)

func registerMultiBatch14(d *awsdata.Data) {
	checkIDs := []string{
		"msk-cluster-tagged",
		"nlb-listener-tagged",
		"nlb-tagged",
		"rds-event-subscription-tagged",
		"rds-option-group-tagged",
		"redshift-cluster-parameter-group-tagged",
		"rum-app-monitor-tagged",
		"sagemaker-app-image-config-tagged",
		"sagemaker-domain-tagged",
		"sagemaker-feature-group-tagged",
	}

	for _, id := range checkIDs {
		if fix.Lookup(id) != nil {
			continue
		}
		fix.Register(&genericTaggedFix{checkID: id, clients: d.Clients})
	}
}
