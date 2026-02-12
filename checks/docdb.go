package checks

import (
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/checker"

	"github.com/aws/aws-sdk-go-v2/service/docdb"

	docdbtypes "github.com/aws/aws-sdk-go-v2/service/docdb/types"
)

// RegisterDocDBChecks registers DocumentDB checks.
func RegisterDocDBChecks(d *awsdata.Data) {
	checker.Register(LoggingCheck(
		"docdb-cluster-audit-logging-enabled",
		"This rule checks logging is enabled for docdb cluster audit.",
		"docdb",
		d,
		func(d *awsdata.Data) ([]LoggingResource, error) {
			clusters, err := d.DocDBClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []LoggingResource
			for _, c := range clusters {
				id := docdbID(c)
				logging := false
				for _, v := range c.EnabledCloudwatchLogsExports {
					if strings.EqualFold(v, "audit") {
						logging = true
						break
					}
				}
				res = append(res, LoggingResource{ID: id, Logging: logging})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"docdb-cluster-backup-retention-check",
		"This rule checks configuration for docdb cluster backup retention.",
		"docdb",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			clusters, err := d.DocDBClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, c := range clusters {
				id := docdbID(c)
				retention := int32(0)
				if c.BackupRetentionPeriod != nil {
					retention = *c.BackupRetentionPeriod
				}
				ok := retention >= 7
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("Retention days: %d", retention)})
			}
			return res, nil
		},
	))

	checker.Register(EnabledCheck(
		"docdb-cluster-deletion-protection-enabled",
		"This rule checks enabled state for docdb cluster deletion protection.",
		"docdb",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			clusters, err := d.DocDBClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, c := range clusters {
				id := docdbID(c)
				enabled := c.DeletionProtection != nil && *c.DeletionProtection
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	checker.Register(EncryptionCheck(
		"docdb-cluster-encrypted",
		"This rule checks docdb cluster encrypted.",
		"docdb",
		d,
		func(d *awsdata.Data) ([]EncryptionResource, error) {
			clusters, err := d.DocDBClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []EncryptionResource
			for _, c := range clusters {
				id := docdbID(c)
				encrypted := c.StorageEncrypted != nil && *c.StorageEncrypted
				res = append(res, EncryptionResource{ID: id, Encrypted: encrypted})
			}
			return res, nil
		},
	))

	checker.Register(EncryptionCheck(
		"docdb-cluster-encrypted-in-transit",
		"This rule checks docdb cluster encrypted in transit.",
		"docdb",
		d,
		func(d *awsdata.Data) ([]EncryptionResource, error) {
			clusters, err := d.DocDBClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []EncryptionResource
			for _, c := range clusters {
				id := docdbID(c)
				encrypted := false
				if c.DBClusterParameterGroup != nil && strings.TrimSpace(*c.DBClusterParameterGroup) != "" {
					required, _, err := docdbClusterTLSRequired(d, *c.DBClusterParameterGroup)
					if err == nil {
						encrypted = required
					}
				}
				res = append(res, EncryptionResource{ID: id, Encrypted: encrypted})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"docdb-cluster-snapshot-public-prohibited",
		"This rule checks docdb cluster snapshot public prohibited.",
		"docdb",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			snaps, err := d.DocDBSnapshots.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, s := range snaps {
				id := "unknown"
				if s.DBClusterSnapshotArn != nil {
					id = *s.DBClusterSnapshotArn
				}
				if s.DBClusterSnapshotIdentifier == nil {
					res = append(res, ConfigResource{ID: id, Passing: false, Detail: "Missing DBClusterSnapshotIdentifier"})
					continue
				}
				out, err := d.Clients.DocDB.DescribeDBClusterSnapshotAttributes(d.Ctx, &docdb.DescribeDBClusterSnapshotAttributesInput{DBClusterSnapshotIdentifier: s.DBClusterSnapshotIdentifier})
				if err != nil {
					res = append(res, ConfigResource{ID: id, Passing: false, Detail: fmt.Sprintf("DescribeDBClusterSnapshotAttributes failed: %v", err)})
					continue
				}
				public := docdbSnapshotAttributesIncludePublic(out.DBClusterSnapshotAttributesResult.DBClusterSnapshotAttributes)
				res = append(res, ConfigResource{ID: id, Passing: !public, Detail: fmt.Sprintf("Public restore access: %v", public)})
			}
			return res, nil
		},
	))
}

func docdbSnapshotAttributesIncludePublic(attrs []docdbtypes.DBClusterSnapshotAttribute) bool {
	for _, attr := range attrs {
		if attr.AttributeName == nil || !strings.EqualFold(*attr.AttributeName, "restore") {
			continue
		}
		for _, v := range attr.AttributeValues {
			if strings.EqualFold(v, "all") {
				return true
			}
		}
	}
	return false
}

func docdbClusterTLSRequired(d *awsdata.Data, parameterGroupName string) (bool, string, error) {
	marker := (*string)(nil)
	for {
		out, err := d.Clients.DocDB.DescribeDBClusterParameters(d.Ctx, &docdb.DescribeDBClusterParametersInput{
			DBClusterParameterGroupName: &parameterGroupName,
			Marker:                      marker,
			MaxRecords:                  int32Ptr(100),
		})
		if err != nil {
			return false, "", err
		}
		for _, p := range out.Parameters {
			if p.ParameterName == nil || !strings.EqualFold(strings.TrimSpace(*p.ParameterName), "tls") {
				continue
			}
			value := ""
			if p.ParameterValue != nil {
				value = strings.ToLower(strings.TrimSpace(*p.ParameterValue))
			}
			return value == "enabled" || value == "fips-140-3" || value == "tls1.2+" || value == "tls1.3+" || value == "true" || value == "1" || value == "on" || value == "required", value, nil
		}
		if out.Marker == nil || *out.Marker == "" {
			break
		}
		marker = out.Marker
	}
	return false, "", nil
}

func int32Ptr(v int32) *int32 { return &v }

func docdbID(c docdbtypes.DBCluster) string {
	if c.DBClusterArn != nil {
		return *c.DBClusterArn
	}
	if c.DBClusterIdentifier != nil {
		return *c.DBClusterIdentifier
	}
	return "unknown"
}
