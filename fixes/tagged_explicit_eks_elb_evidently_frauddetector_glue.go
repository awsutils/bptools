package fixes

import (
	"bptools/awsdata"
	"bptools/fix"
)

func registerMultiBatch13(d *awsdata.Data) {
	if fix.Lookup("eks-addon-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "eks-addon-tagged", clients: d.Clients})
	}
	if fix.Lookup("eks-fargate-profile-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "eks-fargate-profile-tagged", clients: d.Clients})
	}
	if fix.Lookup("elb-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "elb-tagged", clients: d.Clients})
	}
	if fix.Lookup("evidently-launch-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "evidently-launch-tagged", clients: d.Clients})
	}
	if fix.Lookup("evidently-project-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "evidently-project-tagged", clients: d.Clients})
	}
	if fix.Lookup("evidently-segment-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "evidently-segment-tagged", clients: d.Clients})
	}
	if fix.Lookup("frauddetector-entity-type-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "frauddetector-entity-type-tagged", clients: d.Clients})
	}
	if fix.Lookup("frauddetector-label-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "frauddetector-label-tagged", clients: d.Clients})
	}
	if fix.Lookup("frauddetector-outcome-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "frauddetector-outcome-tagged", clients: d.Clients})
	}
	if fix.Lookup("glue-ml-transform-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "glue-ml-transform-tagged", clients: d.Clients})
	}
}
