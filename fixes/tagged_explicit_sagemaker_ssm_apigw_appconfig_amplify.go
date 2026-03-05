package fixes

import (
	"bptools/awsdata"
	"bptools/fix"
)

func registerMultiBatch15(d *awsdata.Data) {
	if fix.Lookup("sagemaker-image-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "sagemaker-image-tagged", clients: d.Clients})
	}
	if fix.Lookup("ssm-document-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "ssm-document-tagged", clients: d.Clients})
	}
	if fix.Lookup("api-gw-rest-api-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "api-gw-rest-api-tagged", clients: d.Clients})
	}
	if fix.Lookup("api-gw-stage-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "api-gw-stage-tagged", clients: d.Clients})
	}
	if fix.Lookup("appconfig-application-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "appconfig-application-tagged", clients: d.Clients})
	}
	if fix.Lookup("appconfig-environment-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "appconfig-environment-tagged", clients: d.Clients})
	}
	if fix.Lookup("appconfig-configuration-profile-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "appconfig-configuration-profile-tagged", clients: d.Clients})
	}
	if fix.Lookup("appconfig-deployment-strategy-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "appconfig-deployment-strategy-tagged", clients: d.Clients})
	}
	if fix.Lookup("appconfig-extension-association-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "appconfig-extension-association-tagged", clients: d.Clients})
	}
	if fix.Lookup("amplify-app-tagged") == nil {
		fix.Register(&genericTaggedFix{checkID: "amplify-app-tagged", clients: d.Clients})
	}
}
