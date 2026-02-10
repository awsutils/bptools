package checks

import (
	"bptools/awsdata"
	"bptools/checker"
)

// RegisterConnectChecks registers Amazon Connect checks.
func RegisterConnectChecks(d *awsdata.Data) {
	checker.Register(EnabledCheck(
		"connect-instance-logging-enabled",
		"This rule checks connect instance logging enabled.",
		"connect",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			instances, err := d.ConnectInstances.Get()
			if err != nil {
				return nil, err
			}
			logging, err := d.ConnectInstanceContactFlowLogs.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, inst := range instances {
				id := "unknown"
				key := ""
				if inst.Id != nil {
					id = *inst.Id
					key = *inst.Id
				} else if inst.Arn != nil {
					id = *inst.Arn
				}
				res = append(res, EnabledResource{ID: id, Enabled: logging[key]})
			}
			return res, nil
		},
	))
}
