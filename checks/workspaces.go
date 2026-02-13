package checks

import (
	"bptools/awsdata"
	"bptools/checker"
)

// RegisterWorkspacesChecks registers WorkSpaces checks.
func RegisterWorkspacesChecks(d *awsdata.Data) {
	checker.Register(TaggedCheck(
		"workspaces-connection-alias-tagged",
		"Checks if Amazon WorkSpaces connection aliases have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"workspaces",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			items, err := d.WorkspacesConnectionAlias.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.WorkspacesConnectionAliasTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, it := range items {
				id := "unknown"
				if it.AliasId != nil {
					id = *it.AliasId
				}
				res = append(res, TaggedResource{ID: id, Tags: tags[id]})
			}
			return res, nil
		},
	))

	checker.Register(EnabledCheck(
		"workspaces-root-volume-encryption-enabled",
		"Checks if an Amazon WorkSpace volume has the root volume encryption settings set to enabled. This rule is NON_COMPLIANT if the encryption setting is not enabled for the root volume.",
		"workspaces",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			items, err := d.Workspaces.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, it := range items {
				id := "unknown"
				if it.WorkspaceId != nil {
					id = *it.WorkspaceId
				}
				enabled := it.RootVolumeEncryptionEnabled != nil && *it.RootVolumeEncryptionEnabled
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	checker.Register(EnabledCheck(
		"workspaces-user-volume-encryption-enabled",
		"Checks if an Amazon WorkSpace volume has the user volume encryption settings set to enabled. This rule is NON_COMPLIANT if the encryption setting is not enabled for the user volume.",
		"workspaces",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			items, err := d.Workspaces.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, it := range items {
				id := "unknown"
				if it.WorkspaceId != nil {
					id = *it.WorkspaceId
				}
				enabled := it.UserVolumeEncryptionEnabled != nil && *it.UserVolumeEncryptionEnabled
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"workspaces-workspace-tagged",
		"Checks if Amazon WorkSpaces workspaces have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
		"workspaces",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			items, err := d.Workspaces.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.WorkspacesTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, it := range items {
				id := "unknown"
				if it.WorkspaceId != nil {
					id = *it.WorkspaceId
				}
				res = append(res, TaggedResource{ID: id, Tags: tags[id]})
			}
			return res, nil
		},
	))
}
