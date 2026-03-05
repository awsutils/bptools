package fixes

import (
	"bptools/awsdata"
	"bptools/fix"
)

func registerMultiBatch12(d *awsdata.Data) {
	if fix.Lookup("ec2-network-insights-access-scope-analysis-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "ec2-network-insights-access-scope-analysis-tagged", clients: d.Clients})
	}
	if fix.Lookup("ec2-network-insights-access-scope-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "ec2-network-insights-access-scope-tagged", clients: d.Clients})
	}
	if fix.Lookup("ec2-network-insights-analysis-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "ec2-network-insights-analysis-tagged", clients: d.Clients})
	}
	if fix.Lookup("ec2-network-insights-path-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "ec2-network-insights-path-tagged", clients: d.Clients})
	}
	if fix.Lookup("ec2-traffic-mirror-filter-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "ec2-traffic-mirror-filter-tagged", clients: d.Clients})
	}
	if fix.Lookup("ec2-traffic-mirror-session-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "ec2-traffic-mirror-session-tagged", clients: d.Clients})
	}
	if fix.Lookup("ec2-traffic-mirror-target-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "ec2-traffic-mirror-target-tagged", clients: d.Clients})
	}
	if fix.Lookup("ec2-transit-gateway-multicast-domain-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "ec2-transit-gateway-multicast-domain-tagged", clients: d.Clients})
	}
	if fix.Lookup("ecs-capacity-provider-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "ecs-capacity-provider-tagged", clients: d.Clients})
	}
	if fix.Lookup("efs-file-system-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "efs-file-system-tagged", clients: d.Clients})
	}
}
