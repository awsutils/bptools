package fixes

import (
	"bptools/awsdata"
	"bptools/fix"
)

func registerMultiBatch11(d *awsdata.Data) {
	if fix.Lookup("alb-listener-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "alb-listener-tagged", clients: d.Clients})
	}

	if fix.Lookup("alb-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "alb-tagged", clients: d.Clients})
	}

	if fix.Lookup("aps-rule-groups-namespace-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "aps-rule-groups-namespace-tagged", clients: d.Clients})
	}

	if fix.Lookup("auditmanager-assessment-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "auditmanager-assessment-tagged", clients: d.Clients})
	}

	if fix.Lookup("codebuild-report-group-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "codebuild-report-group-tagged", clients: d.Clients})
	}

	if fix.Lookup("cognito-user-pool-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "cognito-user-pool-tagged", clients: d.Clients})
	}

	if fix.Lookup("datasync-task-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "datasync-task-tagged", clients: d.Clients})
	}

	if fix.Lookup("dms-endpoint-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "dms-endpoint-tagged", clients: d.Clients})
	}

	if fix.Lookup("dms-replication-task-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "dms-replication-task-tagged", clients: d.Clients})
	}

	if fix.Lookup("ec2-carrier-gateway-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "ec2-carrier-gateway-tagged", clients: d.Clients})
	}
}
