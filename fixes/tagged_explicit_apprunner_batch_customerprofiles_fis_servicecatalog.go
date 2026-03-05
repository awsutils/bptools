package fixes

import (
	"bptools/awsdata"
	"bptools/fix"
)

func registerMultiBatch07(d *awsdata.Data) {
	register := func(id string) {
		if fix.Lookup(id) != nil {
			return
		}
		fix.Register(&genericTaggedFix{checkID: id, clients: d.Clients})
	}

	register("apprunner-service-tagged")
	register("apprunner-vpc-connector-tagged")
	register("batch-compute-environment-tagged")
	register("batch-job-queue-tagged")
	register("batch-managed-compute-env-compute-resources-tagged")
	register("batch-scheduling-policy-tagged")
	register("customerprofiles-domain-tagged")
	register("customerprofiles-object-type-tagged")
	register("fis-experiment-template-tagged")
	register("service-catalog-portfolio-tagged")
}
