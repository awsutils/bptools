package fixes

import (
	"bptools/awsdata"
	"bptools/fix"
)

func registerMultiBatch06(d *awsdata.Data) {
	registerTagged := func(id string) {
		if fix.Lookup(id) != nil {
			return
		}
		fix.Register(&genericTaggedFix{checkID: id, clients: d.Clients})
	}

	registerTagged("acmpca-certificate-authority-tagged")
	registerTagged("appflow-flow-tagged")
	registerTagged("appintegrations-event-integration-tagged")
	registerTagged("appmesh-gateway-route-tagged")
	registerTagged("appmesh-mesh-tagged")
	registerTagged("appmesh-route-tagged")
	registerTagged("appmesh-virtual-gateway-tagged")
	registerTagged("appmesh-virtual-node-tagged")
	registerTagged("appmesh-virtual-router-tagged")
	registerTagged("appmesh-virtual-service-tagged")
}
