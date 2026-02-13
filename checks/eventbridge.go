package checks

import (
	"bptools/awsdata"
	"bptools/checker"

	eventbridgetypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
)

// RegisterEventBridgeChecks registers EventBridge checks.
func RegisterEventBridgeChecks(d *awsdata.Data) {
	checker.Register(ConfigCheck(
		"custom-eventbus-policy-attached",
		"Checks if Amazon EventBridge custom event buses have a resource-based policy attached. The rule is NON_COMPLIANT if a custom event bus policy does not have an attached resource-based policy.",
		"eventbridge",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			buses, err := d.EventBridgeBuses.Get()
			if err != nil {
				return nil, err
			}
			policies, err := d.EventBridgeBusPolicies.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, b := range buses {
				if b.Name == nil || *b.Name == "default" {
					continue
				}
				pol := policies[*b.Name]
				ok := pol != ""
				res = append(res, ConfigResource{ID: *b.Name, Passing: ok, Detail: "Event bus policy attached"})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"global-endpoint-event-replication-enabled",
		"Checks if event replication is enabled for Amazon EventBridge global endpoints. The rule is NON_COMPLIANT if event replication is not enabled.",
		"eventbridge",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			endpoints, err := d.EventBridgeEndpointDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for name, ep := range endpoints {
				ok := ep.ReplicationConfig != nil && ep.ReplicationConfig.State == eventbridgetypes.ReplicationStateEnabled
				res = append(res, ConfigResource{ID: name, Passing: ok, Detail: "Replication enabled"})
			}
			return res, nil
		},
	))
}
