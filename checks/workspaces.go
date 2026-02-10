package checks

import (
	"bptools/awsdata"
	"bptools/checker"
)

// RegisterWorkspacesChecks registers WorkSpaces checks.
func RegisterWorkspacesChecks(d *awsdata.Data) {
	checker.Register(TaggedCheck(
		"workspaces-connection-alias-tagged",
		"This rule checks tagging for workspaces connection alias exist.",
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
		"This rule checks enabled state for workspaces root volume encryption.",
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
		"This rule checks enabled state for workspaces user volume encryption.",
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
		"This rule checks tagging for workspaces workspace exist.",
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
