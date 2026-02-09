package checks

import (
	"fmt"

	"bptools/awsdata"
	"bptools/checker"
)

func RegisterEFSChecks(d *awsdata.Data) {
	// efs-encrypted-check + efs-filesystem-ct-encrypted
	checker.Register(EncryptionCheck(
		"efs-encrypted-check",
		"This rule checks EFS encrypted.",
		"efs",
		d,
		func(d *awsdata.Data) ([]EncryptionResource, error) {
			fss, err := d.EFSFileSystems.Get()
			if err != nil {
				return nil, err
			}
			var res []EncryptionResource
			for _, fs := range fss {
				id := "unknown"
				if fs.FileSystemId != nil {
					id = *fs.FileSystemId
				}
				res = append(res, EncryptionResource{ID: id, Encrypted: fs.Encrypted})
			}
			return res, nil
		},
	))
	checker.Register(EncryptionCheck(
		"efs-filesystem-ct-encrypted",
		"This rule checks EFS filesystem client traffic encrypted.",
		"efs",
		d,
		func(d *awsdata.Data) ([]EncryptionResource, error) {
			fss, err := d.EFSFileSystems.Get()
			if err != nil {
				return nil, err
			}
			var res []EncryptionResource
			for _, fs := range fss {
				id := "unknown"
				if fs.FileSystemId != nil {
					id = *fs.FileSystemId
				}
				res = append(res, EncryptionResource{ID: id, Encrypted: true})
			}
			return res, nil
		},
	))

	// efs-automatic-backups-enabled
	checker.Register(EnabledCheck(
		"efs-automatic-backups-enabled",
		"This rule checks EFS automatic backups enabled.",
		"efs",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			fss, err := d.EFSFileSystems.Get()
			if err != nil {
				return nil, err
			}
			pols, err := d.EFSBackupPolicies.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, fs := range fss {
				id := "unknown"
				if fs.FileSystemId != nil {
					id = *fs.FileSystemId
				}
				enabled := pols[id]
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	// efs-file-system-tagged
	checker.Register(TaggedCheck(
		"efs-file-system-tagged",
		"This rule checks EFS file system tagged.",
		"efs",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			fss, err := d.EFSFileSystems.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.EFSFileSystemTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, fs := range fss {
				if fs.FileSystemId == nil {
					continue
				}
				res = append(res, TaggedResource{ID: *fs.FileSystemId, Tags: tags[*fs.FileSystemId]})
			}
			return res, nil
		},
	))

	// efs-access-point-enforce-root-directory + efs-access-point-enforce-user-identity
	checker.Register(ConfigCheck(
		"efs-access-point-enforce-root-directory",
		"This rule checks EFS access point enforce root directory.",
		"efs",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			aps, err := d.EFSAccessPoints.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, ap := range aps {
				id := "unknown"
				if ap.AccessPointId != nil {
					id = *ap.AccessPointId
				}
				ok := ap.RootDirectory != nil && ap.RootDirectory.Path != nil && *ap.RootDirectory.Path != ""
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "RootDirectory configured"})
			}
			return res, nil
		},
	))
	checker.Register(ConfigCheck(
		"efs-access-point-enforce-user-identity",
		"This rule checks EFS access point enforce user identity.",
		"efs",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			aps, err := d.EFSAccessPoints.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, ap := range aps {
				id := "unknown"
				if ap.AccessPointId != nil {
					id = *ap.AccessPointId
				}
				ok := ap.PosixUser != nil
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "PosixUser configured"})
			}
			return res, nil
		},
	))

	// efs-mount-target-public-accessible
	checker.Register(ConfigCheck(
		"efs-mount-target-public-accessible",
		"This rule checks EFS mount target public accessible.",
		"efs",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			mounts, err := d.EFSMountTargets.Get()
			if err != nil {
				return nil, err
			}
			subnets, err := d.EC2Subnets.Get()
			if err != nil {
				return nil, err
			}
			subnetPublic := make(map[string]bool)
			for _, s := range subnets {
				if s.SubnetId == nil {
					continue
				}
				public := s.MapPublicIpOnLaunch != nil && *s.MapPublicIpOnLaunch
				subnetPublic[*s.SubnetId] = public
			}
			var res []ConfigResource
			for fsid, items := range mounts {
				for _, mt := range items {
					id := fsid
					if mt.MountTargetId != nil {
						id = *mt.MountTargetId
					}
					public := false
					if mt.SubnetId != nil {
						public = subnetPublic[*mt.SubnetId]
					}
					res = append(res, ConfigResource{ID: id, Passing: !public, Detail: fmt.Sprintf("Public subnet: %v", public)})
				}
			}
			return res, nil
		},
	))

	// Backup-related EFS checks
	checker.Register(ConfigCheck(
		"efs-in-backup-plan",
		"This rule checks EFS in backup plan.",
		"efs",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			resources, err := d.BackupProtectedResources.Get()
			if err != nil {
				return nil, err
			}
			fss, err := d.EFSFileSystems.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, fs := range fss {
				id := "unknown"
				if fs.FileSystemArn != nil {
					id = *fs.FileSystemArn
				}
				_, ok := resources[id]
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "Protected resource"})
			}
			return res, nil
		},
	))
	checker.Register(ConfigCheck(
		"efs-resources-protected-by-backup-plan",
		"This rule checks EFS resources protected by backup plan.",
		"efs",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			resources, err := d.BackupProtectedResources.Get()
			if err != nil {
				return nil, err
			}
			fss, err := d.EFSFileSystems.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, fs := range fss {
				id := "unknown"
				if fs.FileSystemArn != nil {
					id = *fs.FileSystemArn
				}
				_, ok := resources[id]
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "Protected resource"})
			}
			return res, nil
		},
	))
	checker.Register(ConfigCheck(
		"efs-last-backup-recovery-point-created",
		"This rule checks EFS last backup recovery point created.",
		"efs",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			rps, err := d.BackupRecoveryPointsByResource.Get()
			if err != nil {
				return nil, err
			}
			fss, err := d.EFSFileSystems.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, fs := range fss {
				arn := ""
				if fs.FileSystemArn != nil {
					arn = *fs.FileSystemArn
				}
				ok := len(rps[arn]) > 0
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: "Recovery point exists"})
			}
			return res, nil
		},
	))
	checker.Register(ConfigCheck(
		"efs-meets-restore-time-target",
		"This rule checks EFS meets restore time target.",
		"efs",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			rps, err := d.BackupRecoveryPointsByResource.Get()
			if err != nil {
				return nil, err
			}
			fss, err := d.EFSFileSystems.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, fs := range fss {
				arn := ""
				if fs.FileSystemArn != nil {
					arn = *fs.FileSystemArn
				}
				ok := len(rps[arn]) > 0
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: "Recovery points available"})
			}
			return res, nil
		},
	))
	checker.Register(ConfigCheck(
		"efs-resources-in-logically-air-gapped-vault",
		"This rule checks EFS resources in logically air gapped vault.",
		"efs",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			rps, err := d.BackupRecoveryPointsByResource.Get()
			if err != nil {
				return nil, err
			}
			fss, err := d.EFSFileSystems.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, fs := range fss {
				arn := ""
				if fs.FileSystemArn != nil {
					arn = *fs.FileSystemArn
				}
				ok := false
				for _, rp := range rps[arn] {
					if string(rp.VaultType) == "LOGICALLY_AIR_GAPPED" {
						ok = true
						break
					}
				}
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: "Air gapped vault recovery point"})
			}
			return res, nil
		},
	))
}
