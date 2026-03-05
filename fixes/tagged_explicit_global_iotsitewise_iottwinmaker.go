package fixes

import (
	"bptools/awsdata"
	"bptools/fix"
)

func registerMultiBatch08(d *awsdata.Data) {
	if fix.Lookup("glb-listener-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "glb-listener-tagged", clients: d.Clients})
	}

	if fix.Lookup("glb-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "glb-tagged", clients: d.Clients})
	}

	if fix.Lookup("iotsitewise-asset-model-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "iotsitewise-asset-model-tagged", clients: d.Clients})
	}

	if fix.Lookup("iotsitewise-dashboard-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "iotsitewise-dashboard-tagged", clients: d.Clients})
	}

	if fix.Lookup("iotsitewise-gateway-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "iotsitewise-gateway-tagged", clients: d.Clients})
	}

	if fix.Lookup("iotsitewise-portal-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "iotsitewise-portal-tagged", clients: d.Clients})
	}

	if fix.Lookup("iotsitewise-project-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "iotsitewise-project-tagged", clients: d.Clients})
	}

	if fix.Lookup("iottwinmaker-component-type-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "iottwinmaker-component-type-tagged", clients: d.Clients})
	}

	if fix.Lookup("iottwinmaker-entity-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "iottwinmaker-entity-tagged", clients: d.Clients})
	}

	if fix.Lookup("iottwinmaker-scene-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "iottwinmaker-scene-tagged", clients: d.Clients})
	}
}
