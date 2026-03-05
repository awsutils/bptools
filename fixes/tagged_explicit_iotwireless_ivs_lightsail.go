package fixes

import (
	"bptools/awsdata"
	"bptools/fix"
)

func registerMultiBatch09(d *awsdata.Data) {
	if fix.Lookup("iottwinmaker-sync-job-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "iottwinmaker-sync-job-tagged", clients: d.Clients})
	}
	if fix.Lookup("iottwinmaker-workspace-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "iottwinmaker-workspace-tagged", clients: d.Clients})
	}
	if fix.Lookup("iotwireless-fuota-task-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "iotwireless-fuota-task-tagged", clients: d.Clients})
	}
	if fix.Lookup("iotwireless-multicast-group-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "iotwireless-multicast-group-tagged", clients: d.Clients})
	}
	if fix.Lookup("iotwireless-service-profile-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "iotwireless-service-profile-tagged", clients: d.Clients})
	}
	if fix.Lookup("ivs-channel-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "ivs-channel-tagged", clients: d.Clients})
	}
	if fix.Lookup("ivs-playback-key-pair-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "ivs-playback-key-pair-tagged", clients: d.Clients})
	}
	if fix.Lookup("ivs-recording-configuration-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "ivs-recording-configuration-tagged", clients: d.Clients})
	}
	if fix.Lookup("lightsail-bucket-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "lightsail-bucket-tagged", clients: d.Clients})
	}
	if fix.Lookup("lightsail-certificate-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "lightsail-certificate-tagged", clients: d.Clients})
	}
}
