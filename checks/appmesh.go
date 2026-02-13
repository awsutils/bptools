package checks

import (
	"fmt"

	"bptools/awsdata"
	"bptools/checker"

	appmeshtypes "github.com/aws/aws-sdk-go-v2/service/appmesh/types"
)

func RegisterAppMeshChecks(d *awsdata.Data) {
	// appmesh-mesh-tagged
	checker.Register(TaggedCheck(
		"appmesh-mesh-tagged",
		"Checks if AWS App Mesh meshes have tags. Optionally, you can specify tag keys for the rule to check. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"appmesh",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			meshes, err := d.AppMeshMeshes.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.AppMeshTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, m := range meshes {
				if m.Arn == nil {
					continue
				}
				res = append(res, TaggedResource{ID: *m.Arn, Tags: tags[*m.Arn]})
			}
			return res, nil
		},
	))

	// appmesh-route-tagged
	checker.Register(TaggedCheck(
		"appmesh-route-tagged",
		"Checks if AWS App Mesh routes have tags. Optionally, you can specify tag keys for the rule to check. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"appmesh",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			routes, err := d.AppMeshRoutes.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.AppMeshTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, items := range routes {
				for _, r := range items {
					if r.Arn == nil {
						continue
					}
					res = append(res, TaggedResource{ID: *r.Arn, Tags: tags[*r.Arn]})
				}
			}
			return res, nil
		},
	))

	// appmesh-gateway-route-tagged
	checker.Register(TaggedCheck(
		"appmesh-gateway-route-tagged",
		"Checks if AWS App Mesh gateway routes have tags. Optionally, you can specify tag keys for the rule. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"appmesh",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			routes, err := d.AppMeshGatewayRoutes.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.AppMeshTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, items := range routes {
				for _, r := range items {
					if r.Arn == nil {
						continue
					}
					res = append(res, TaggedResource{ID: *r.Arn, Tags: tags[*r.Arn]})
				}
			}
			return res, nil
		},
	))

	// appmesh-virtual-node-tagged
	checker.Register(TaggedCheck(
		"appmesh-virtual-node-tagged",
		"Checks if AWS App Mesh virtual nodes have tags. Optionally, you can specify tag keys for the rule to check. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"appmesh",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			vns, err := d.AppMeshVirtualNodes.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.AppMeshTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, items := range vns {
				for _, vn := range items {
					if vn.Arn == nil {
						continue
					}
					res = append(res, TaggedResource{ID: *vn.Arn, Tags: tags[*vn.Arn]})
				}
			}
			return res, nil
		},
	))

	// appmesh-virtual-router-tagged
	checker.Register(TaggedCheck(
		"appmesh-virtual-router-tagged",
		"Checks if AWS App Mesh virtual routers have tags. Optionally, you can specify tag keys for the rule. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"appmesh",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			vrs, err := d.AppMeshVirtualRouters.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.AppMeshTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, items := range vrs {
				for _, vr := range items {
					if vr.Arn == nil {
						continue
					}
					res = append(res, TaggedResource{ID: *vr.Arn, Tags: tags[*vr.Arn]})
				}
			}
			return res, nil
		},
	))

	// appmesh-virtual-service-tagged
	checker.Register(TaggedCheck(
		"appmesh-virtual-service-tagged",
		"Checks if AWS App Mesh virtual services have tags. Optionally, you can specify tag keys for the rule. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"appmesh",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			vss, err := d.AppMeshVirtualServices.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.AppMeshTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, items := range vss {
				for _, vs := range items {
					if vs.Arn == nil {
						continue
					}
					res = append(res, TaggedResource{ID: *vs.Arn, Tags: tags[*vs.Arn]})
				}
			}
			return res, nil
		},
	))

	// appmesh-virtual-gateway-tagged
	checker.Register(TaggedCheck(
		"appmesh-virtual-gateway-tagged",
		"Checks if AWS App Mesh virtual gateways have tags. Optionally, you can specify tag keys for the rule. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"appmesh",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			vgs, err := d.AppMeshVirtualGateways.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.AppMeshTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, items := range vgs {
				for _, vg := range items {
					if vg.Arn == nil {
						continue
					}
					res = append(res, TaggedResource{ID: *vg.Arn, Tags: tags[*vg.Arn]})
				}
			}
			return res, nil
		},
	))

	// appmesh-mesh-deny-tcp-forwarding
	checker.Register(ConfigCheck(
		"appmesh-mesh-deny-tcp-forwarding",
		"Checks if proxies for AWS App Mesh service meshes do not forward TCP traffic directly to services that aren't deployed with a proxy that is defined in the mesh. The rule is NON_COMPLIANT if configuration.Spec.EgressFilter.Type is set to 'ALLOW_ALL'.",
		"appmesh",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			meshes, err := d.AppMeshMeshDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for name, m := range meshes {
				ok := m.Spec.EgressFilter != nil && m.Spec.EgressFilter.Type == appmeshtypes.EgressFilterTypeDropAll
				res = append(res, ConfigResource{ID: name, Passing: ok, Detail: fmt.Sprintf("EgressFilter: %v", m.Spec.EgressFilter)})
			}
			return res, nil
		},
	))

	// appmesh-virtual-gateway-backend-defaults-tls
	checker.Register(ConfigCheck(
		"appmesh-virtual-gateway-backend-defaults-tls",
		"Checks if backend defaults for AWS App Mesh virtual gateways require the virtual gateways to communicate with all ports using TLS. The rule is NON_COMPLIANT if configuration.Spec.BackendDefaults.ClientPolicy.Tls.Enforce is false.",
		"appmesh",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			vgs, err := d.AppMeshVirtualGatewayDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for key, vg := range vgs {
				enforced := false
				if vg.Spec.BackendDefaults != nil && vg.Spec.BackendDefaults.ClientPolicy != nil && vg.Spec.BackendDefaults.ClientPolicy.Tls != nil {
					enforced = vg.Spec.BackendDefaults.ClientPolicy.Tls.Enforce != nil && *vg.Spec.BackendDefaults.ClientPolicy.Tls.Enforce
				}
				res = append(res, ConfigResource{ID: key, Passing: enforced, Detail: fmt.Sprintf("BackendDefaults TLS enforce: %v", enforced)})
			}
			return res, nil
		},
	))

	// appmesh-virtual-gateway-logging-file-path-exists
	checker.Register(ConfigCheck(
		"appmesh-virtual-gateway-logging-file-path-exists",
		"Checks if AWS App Mesh virtual gateways have a file path to write access logs to. The rule is NON_COMPLIANT if configuration.Spec.Logging.AccessLog.File.Path does not exist.",
		"appmesh",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			vgs, err := d.AppMeshVirtualGatewayDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for key, vg := range vgs {
				path := ""
				if vg.Spec.Logging != nil && vg.Spec.Logging.AccessLog != nil {
					if fileLog, ok := vg.Spec.Logging.AccessLog.(*appmeshtypes.VirtualGatewayAccessLogMemberFile); ok && fileLog.Value.Path != nil {
						path = *fileLog.Value.Path
					}
				}
				ok := path != ""
				res = append(res, ConfigResource{ID: key, Passing: ok, Detail: fmt.Sprintf("Log path: %s", path)})
			}
			return res, nil
		},
	))

	// appmesh-virtual-node-backend-defaults-tls-on
	checker.Register(ConfigCheck(
		"appmesh-virtual-node-backend-defaults-tls-on",
		"Checks if backend defaults for AWS App Mesh virtual nodes require the virtual nodes to communicate with all ports using TLS. The rule is NON_COMPLIANT if configuration.Spec.BackendDefaults.ClientPolicy.Tls.Enforce is false.",
		"appmesh",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			vns, err := d.AppMeshVirtualNodeDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for key, vn := range vns {
				enforced := false
				if vn.Spec.BackendDefaults != nil && vn.Spec.BackendDefaults.ClientPolicy != nil && vn.Spec.BackendDefaults.ClientPolicy.Tls != nil {
					enforced = vn.Spec.BackendDefaults.ClientPolicy.Tls.Enforce != nil && *vn.Spec.BackendDefaults.ClientPolicy.Tls.Enforce
				}
				res = append(res, ConfigResource{ID: key, Passing: enforced, Detail: fmt.Sprintf("BackendDefaults TLS enforce: %v", enforced)})
			}
			return res, nil
		},
	))

	// appmesh-virtual-node-cloud-map-ip-pref-check
	checker.Register(ConfigCheck(
		"appmesh-virtual-node-cloud-map-ip-pref-check",
		"Checks if an AWS App Mesh virtual node is configured with the specified IP preference for AWS Cloud Map service discovery. The rule is NON_COMPLIANT if the virtual node is not configured with the IP preference specified in the required rule parameter.",
		"appmesh",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			vns, err := d.AppMeshVirtualNodeDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for key, vn := range vns {
				ok := true
				if vn.Spec.ServiceDiscovery != nil {
					if cloudMap, ok := vn.Spec.ServiceDiscovery.(*appmeshtypes.ServiceDiscoveryMemberAwsCloudMap); ok {
						ok = cloudMap.Value.IpPreference != ""
					}
				}
				res = append(res, ConfigResource{ID: key, Passing: ok, Detail: "Cloud Map IP preference set"})
			}
			return res, nil
		},
	))

	// appmesh-virtual-node-dns-ip-pref-check
	checker.Register(ConfigCheck(
		"appmesh-virtual-node-dns-ip-pref-check",
		"Checks if an AWS App Mesh virtual node is configured with the specified IP preference for DNS service discovery. The rule is NON_COMPLIANT if the virtual node is not configured with the IP preference specified in the required rule parameter.",
		"appmesh",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			vns, err := d.AppMeshVirtualNodeDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for key, vn := range vns {
				ok := true
				if vn.Spec.ServiceDiscovery != nil {
					if dns, ok := vn.Spec.ServiceDiscovery.(*appmeshtypes.ServiceDiscoveryMemberDns); ok {
						ok = dns.Value.IpPreference != ""
					}
				}
				res = append(res, ConfigResource{ID: key, Passing: ok, Detail: "DNS IP preference set"})
			}
			return res, nil
		},
	))

	// appmesh-virtual-node-logging-file-path-exists
	checker.Register(ConfigCheck(
		"appmesh-virtual-node-logging-file-path-exists",
		"Checks if AWS App Mesh virtual nodes have a file path to write access logs to. The rule is NON_COMPLIANT if configuration.Spec.Logging.AccessLog.File.Path does not exist.",
		"appmesh",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			vns, err := d.AppMeshVirtualNodeDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for key, vn := range vns {
				path := ""
				if vn.Spec.Logging != nil && vn.Spec.Logging.AccessLog != nil {
					if fileLog, ok := vn.Spec.Logging.AccessLog.(*appmeshtypes.AccessLogMemberFile); ok && fileLog.Value.Path != nil {
						path = *fileLog.Value.Path
					}
				}
				ok := path != ""
				res = append(res, ConfigResource{ID: key, Passing: ok, Detail: fmt.Sprintf("Log path: %s", path)})
			}
			return res, nil
		},
	))
}
