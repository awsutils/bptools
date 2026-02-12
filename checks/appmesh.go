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
		"This rule checks tagging for App Mesh mesh exist.",
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
		"This rule checks tagging for App Mesh route exist.",
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
		"This rule checks tagging for App Mesh gateway route exist.",
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
		"This rule checks tagging for App Mesh virtual node exist.",
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
		"This rule checks tagging for App Mesh virtual router exist.",
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
		"This rule checks tagging for App Mesh virtual service exist.",
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
		"This rule checks tagging for App Mesh virtual gateway exist.",
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
		"This rule checks App Mesh mesh deny tcp forwarding.",
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
		"This rule checks App Mesh virtual gateway backend defaults TLS.",
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
		"This rule checks logging file paths exist for App Mesh virtual gateway.",
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
		"This rule checks App Mesh virtual node backend defaults TLS on.",
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
		"This rule checks configuration for App Mesh virtual node cloud map IP pref.",
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
		"This rule checks configuration for App Mesh virtual node DNS IP pref.",
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
		"This rule checks logging file paths exist for App Mesh virtual node.",
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
