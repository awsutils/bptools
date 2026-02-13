package checks

import (
	"encoding/json"
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/checker"

	"github.com/aws/aws-sdk-go-v2/service/efs"
)

func RegisterEFSChecks(d *awsdata.Data) {
	// efs-encrypted-check + efs-filesystem-ct-encrypted
	checker.Register(EncryptionCheck(
		"efs-encrypted-check",
		"Checks if Amazon Elastic File System (Amazon EFS) is configured to encrypt the file data using AWS Key Management Service (AWS KMS). The rule is NON_COMPLIANT if the encrypted key is set to false on DescribeFileSystems or if the KmsKeyId key on DescribeFileSystems does not match the KmsKeyId parameter.",
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
				encrypted := fs.Encrypted != nil && *fs.Encrypted
				res = append(res, EncryptionResource{ID: id, Encrypted: encrypted})
			}
			return res, nil
		},
	))
	checker.Register(EncryptionCheck(
		"efs-filesystem-ct-encrypted",
		"Checks if Amazon Elastic File System (Amazon EFS) encrypts data with AWS Key Management Service (AWS KMS). The rule is NON_COMPLIANT if a file system is not encrypted. Optionally, you can check if a file system is not encrypted with specified KMS keys.",
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
				encrypted := false
				if fs.FileSystemId != nil {
					out, err := d.Clients.EFS.DescribeFileSystemPolicy(d.Ctx, &efs.DescribeFileSystemPolicyInput{FileSystemId: fs.FileSystemId})
					if err == nil && out.Policy != nil {
						encrypted = efsPolicyEnforcesTLS(*out.Policy)
					}
				}
				res = append(res, EncryptionResource{ID: id, Encrypted: encrypted})
			}
			return res, nil
		},
	))

	// efs-automatic-backups-enabled
	checker.Register(EnabledCheck(
		"efs-automatic-backups-enabled",
		"Checks if an Amazon Elastic File System (Amazon EFS) file system has automatic backups enabled. The rule is NON_COMPLIANT if `BackupPolicy.Status` is set to DISABLED.",
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
		"Checks if Amazon Elastic File System file systems have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
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
		"Checks if Amazon Elastic File System (Amazon EFS) access points are configured to enforce a root directory. The rule is NON_COMPLIANT if the value of 'Path' is set to '/' (default root directory of the file system).",
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
				ok := ap.RootDirectory != nil &&
					ap.RootDirectory.Path != nil &&
					*ap.RootDirectory.Path != "" &&
					*ap.RootDirectory.Path != "/"
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "RootDirectory configured"})
			}
			return res, nil
		},
	))
	checker.Register(ConfigCheck(
		"efs-access-point-enforce-user-identity",
		"Checks if Amazon Elastic File System (Amazon EFS) access points are configured to enforce a user identity. The rule is NON_COMPLIANT if 'PosixUser' is not defined or if parameters are provided and there is no match in the corresponding parameter.",
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
		"Checks if an Amazon Elastic File System (Amazon EFS) is associated with subnets that assign public IP addresses on launch. The rule is NON_COMPLIANT if the Amazon EFS mount target is associated with subnets that assign public IP addresses on launch.",
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
		"Checks if Amazon Elastic File System (Amazon EFS) file systems are added in the backup plans of AWS Backup. The rule is NON_COMPLIANT if EFS file systems are not included in the backup plans.",
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
		"Checks if Amazon Elastic File System (Amazon EFS) File Systems are protected by a backup plan. The rule is NON_COMPLIANT if the EFS File System is not covered by a backup plan.",
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
		"Checks if a recovery point was created for Amazon Elastic File System (Amazon EFS) File Systems. The rule is NON_COMPLIANT if the Amazon EFS File System does not have a corresponding Recovery Point created within the specified time period.",
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
				ok, detail := backupRecencyResult(rps[arn], backupRecoveryPointRecencyWindow)
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: detail})
			}
			return res, nil
		},
	))
	checker.Register(ConfigCheck(
		"efs-meets-restore-time-target",
		"Checks if the restore time of Amazon Elastic File System (Amazon EFS) File Systems meets the specified duration. The rule is NON_COMPLIANT if LatestRestoreExecutionTimeMinutes of an Amazon EFS File System is greater than maxRestoreTime minutes.",
		"efs",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
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
				ok, detail, err := restoreTimeTargetResult(d, arn, backupRestoreTimeTargetWindow)
				if err != nil {
					return nil, err
				}
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: detail})
			}
			return res, nil
		},
	))
	checker.Register(ConfigCheck(
		"efs-resources-in-logically-air-gapped-vault",
		"Checks if Amazon Elastic File System (Amazon EFS) File Systems are in a logically air-gapped vault. The rule is NON_COMPLIANT if an Amazon EFS File System is not in a logically air-gapped vault within the specified time period.",
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

func efsPolicyEnforcesTLS(policy string) bool {
	type statement struct {
		Effect    string         `json:"Effect"`
		Condition map[string]any `json:"Condition"`
	}
	type document struct {
		Statement []statement `json:"Statement"`
	}

	var doc document
	if err := json.Unmarshal([]byte(policy), &doc); err != nil {
		return false
	}
	for _, st := range doc.Statement {
		if !strings.EqualFold(st.Effect, "Deny") {
			continue
		}
		for op, conditionValues := range st.Condition {
			if !strings.EqualFold(op, "Bool") {
				continue
			}
			m, ok := conditionValues.(map[string]any)
			if !ok {
				continue
			}
			for key, value := range m {
				if strings.EqualFold(key, "aws:SecureTransport") {
					s := fmt.Sprint(value)
					if strings.EqualFold(s, "false") {
						return true
					}
				}
			}
		}
	}
	return false
}
