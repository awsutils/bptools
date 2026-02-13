package checks

import (
	"fmt"

	"bptools/awsdata"
	"bptools/checker"

	fsxtypes "github.com/aws/aws-sdk-go-v2/service/fsx/types"
)

// RegisterFSxChecks registers FSx checks.
func RegisterFSxChecks(d *awsdata.Data) {
	checker.Register(ConfigCheck(
		"fsx-last-backup-recovery-point-created",
		"Checks if a recovery point was created for Amazon FSx File Systems. The rule is NON_COMPLIANT if the Amazon FSx File System does not have a corresponding recovery point created within the specified time period.",
		"fsx",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			rps, err := d.BackupRecoveryPointsByResource.Get()
			if err != nil {
				return nil, err
			}
			fss, err := d.FSxFileSystems.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, fs := range fss {
				arn := ""
				if fs.ResourceARN != nil {
					arn = *fs.ResourceARN
				}
				ok := len(rps[arn]) > 0
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: "Recovery point exists"})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"fsx-lustre-copy-tags-to-backups",
		"Checks if the Amazon FSx for Lustre file systems are configured to copy tags to backups. The rule is NON_COMPLIANT if Lustre file systems are not configured to copy tags to backups.",
		"fsx",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			fss, err := d.FSxFileSystems.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, fs := range fss {
				if fs.FileSystemType != fsxtypes.FileSystemTypeLustre {
					continue
				}
				id := fsID(fs)
				ok := fs.LustreConfiguration != nil && fs.LustreConfiguration.CopyTagsToBackups != nil && *fs.LustreConfiguration.CopyTagsToBackups
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("CopyTagsToBackups: %v", ok)})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"fsx-meets-restore-time-target",
		"Checks if the restore time of Amazon FSx File Systems meets the specified duration. The rule is NON_COMPLIANT if LatestRestoreExecutionTimeMinutes of an Amazon FSx File System is greater than maxRestoreTime minutes.",
		"fsx",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			rps, err := d.BackupRecoveryPointsByResource.Get()
			if err != nil {
				return nil, err
			}
			fss, err := d.FSxFileSystems.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, fs := range fss {
				arn := ""
				if fs.ResourceARN != nil {
					arn = *fs.ResourceARN
				}
				ok := len(rps[arn]) > 0
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: "Recovery points available"})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"fsx-ontap-deployment-type-check",
		"Checks if Amazon FSx for NetApp ONTAP file systems are configured with certain deployment types. The rule is NON_COMPLIANT if the Amazon FSx for NetApp ONTAP file systems are not configured with the deployment types you specify.",
		"fsx",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			fss, err := d.FSxFileSystems.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, fs := range fss {
				if fs.FileSystemType != fsxtypes.FileSystemTypeOntap {
					continue
				}
				id := fsID(fs)
				deployment := ""
				if fs.OntapConfiguration != nil {
					deployment = string(fs.OntapConfiguration.DeploymentType)
				}
				ok := deployment == "MULTI_AZ_1"
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("DeploymentType: %s", deployment)})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"fsx-openzfs-copy-tags-enabled",
		"Checks if the Amazon FSx for OpenZFS file systems are configured to copy tags to backups and volumes. The rule is NON_COMPLIANT if FSx for OpenZFS file systems are not configured to copy tags to backups and volumes.",
		"fsx",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			fss, err := d.FSxFileSystems.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, fs := range fss {
				if fs.FileSystemType != fsxtypes.FileSystemTypeOpenzfs {
					continue
				}
				id := fsID(fs)
				ok := fs.OpenZFSConfiguration != nil && fs.OpenZFSConfiguration.CopyTagsToBackups != nil && *fs.OpenZFSConfiguration.CopyTagsToBackups
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("CopyTagsToBackups: %v", ok)})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"fsx-openzfs-deployment-type-check",
		"Checks if the Amazon FSx for OpenZFS file systems are configured with certain deployment types. The rule is NON_COMPLIANT if FSx for OpenZFS file systems are not configured with the deployment types you specify.",
		"fsx",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			fss, err := d.FSxFileSystems.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, fs := range fss {
				if fs.FileSystemType != fsxtypes.FileSystemTypeOpenzfs {
					continue
				}
				id := fsID(fs)
				deployment := ""
				if fs.OpenZFSConfiguration != nil {
					deployment = string(fs.OpenZFSConfiguration.DeploymentType)
				}
				ok := deployment == "MULTI_AZ_1"
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("DeploymentType: %s", deployment)})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"fsx-resources-protected-by-backup-plan",
		"Checks if Amazon FSx File Systems are protected by a backup plan. The rule is NON_COMPLIANT if the Amazon FSx File System is not covered by a backup plan.",
		"fsx",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			resources, err := d.BackupProtectedResources.Get()
			if err != nil {
				return nil, err
			}
			fss, err := d.FSxFileSystems.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, fs := range fss {
				arn := ""
				if fs.ResourceARN != nil {
					arn = *fs.ResourceARN
				}
				_, ok := resources[arn]
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: "Protected resource"})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"fsx-windows-audit-log-configured",
		"Checks if the Amazon FSx for Windows File Server file systems have file access auditing enabled. The rule is NON_COMPLIANT if the FSx for Windows File Server file systems do not have file access auditing enabled.",
		"fsx",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			fss, err := d.FSxFileSystems.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, fs := range fss {
				if fs.FileSystemType != fsxtypes.FileSystemTypeWindows {
					continue
				}
				id := fsID(fs)
				ok := fs.WindowsConfiguration != nil && fs.WindowsConfiguration.AuditLogConfiguration != nil && fs.WindowsConfiguration.AuditLogConfiguration.AuditLogDestination != nil && *fs.WindowsConfiguration.AuditLogConfiguration.AuditLogDestination != ""
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "Audit log configured"})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"fsx-windows-deployment-type-check",
		"Checks if the Amazon FSx for WINDOWS file systems are configured with certain deployment types. The rule is NON_COMPLIANT if FSx for WINDOWS file systems are not configured with the deployment types you specify.",
		"fsx",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			fss, err := d.FSxFileSystems.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, fs := range fss {
				if fs.FileSystemType != fsxtypes.FileSystemTypeWindows {
					continue
				}
				id := fsID(fs)
				deployment := ""
				if fs.WindowsConfiguration != nil {
					deployment = string(fs.WindowsConfiguration.DeploymentType)
				}
				ok := deployment == "MULTI_AZ_1"
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("DeploymentType: %s", deployment)})
			}
			return res, nil
		},
	))
}

func fsID(fs fsxtypes.FileSystem) string {
	if fs.ResourceARN != nil {
		return *fs.ResourceARN
	}
	if fs.FileSystemId != nil {
		return *fs.FileSystemId
	}
	return "unknown"
}
