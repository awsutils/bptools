package fixes

import (
	"bptools/awsdata"
	"bptools/fix"
)

func registerMultiBatch10(d *awsdata.Data) {
	checkIDs := []string{
		"lightsail-disk-tagged",
		"iot-job-template-tagged",
		"iot-provisioning-template-tagged",
		"iot-scheduled-audit-tagged",
		"iotdevicedefender-custom-metric-tagged",
		"iotevents-input-tagged",
		"codeguruprofiler-profiling-group-tagged",
		"codegurureviewer-repository-association-tagged",
		"cassandra-keyspace-tagged",
		"frauddetector-variable-tagged",
	}

	for _, id := range checkIDs {
		if fix.Lookup(id) != nil {
			continue
		}
		fix.Register(&genericTaggedFix{checkID: id, clients: d.Clients})
	}
}
