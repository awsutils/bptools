package checks

import (
	"bptools/awsdata"
	"bptools/checker"
)

// RegisterRUMChecks registers RUM checks.
func RegisterRUMChecks(d *awsdata.Data) {
	checker.Register(ConfigCheck(
		"rum-app-monitor-cloudwatch-logs-enabled",
		"This rule checks rum app monitor cloudwatch logs enabled.",
		"rum",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			monitors, err := d.RUMAppMonitorDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for name, m := range monitors {
				enabled := false
				if m.AppMonitor != nil && m.AppMonitor.DataStorage != nil && m.AppMonitor.DataStorage.CwLog != nil {
					enabled = m.AppMonitor.DataStorage.CwLog.CwLogEnabled != nil && *m.AppMonitor.DataStorage.CwLog.CwLogEnabled
				}
				res = append(res, ConfigResource{ID: name, Passing: enabled, Detail: "CloudWatch Logs enabled"})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"rum-app-monitor-tagged",
		"This rule checks rum app monitor tagged.",
		"rum",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			monitors, err := d.RUMAppMonitors.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.RUMAppMonitorTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, m := range monitors {
				id := "unknown"
				tagKey := ""
				if m.Name != nil {
					id = *m.Name
					tagKey = *m.Name
				} else if m.Id != nil {
					id = *m.Id
				}
				res = append(res, TaggedResource{ID: id, Tags: tags[tagKey]})
			}
			return res, nil
		},
	))
}
