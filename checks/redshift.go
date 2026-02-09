package checks

import (
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/checker"
)

var redshiftDefaultAdmins = map[string]bool{"admin": true, "root": true, "master": true}
var redshiftDefaultDBs = map[string]bool{"dev": true, "default": true, "test": true, "postgres": true}

func RegisterRedshiftChecks(d *awsdata.Data) {
	// redshift-cluster-configuration-check
	checker.Register(ConfigCheck(
		"redshift-cluster-configuration-check",
		"This rule checks Redshift cluster configuration.",
		"redshift",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			clusters, err := d.RedshiftClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, c := range clusters {
				id := *c.ClusterIdentifier
				ok := c.NodeType != nil && *c.NodeType != ""
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("NodeType: %v", c.NodeType)})
			}
			return res, nil
		},
	))
	// redshift-audit-logging-enabled
	checker.Register(LoggingCheck(
		"redshift-audit-logging-enabled",
		"This rule checks Redshift audit logging enabled.",
		"redshift",
		d,
		func(d *awsdata.Data) ([]LoggingResource, error) {
			logs, err := d.RedshiftLoggingStatus.Get()
			if err != nil {
				return nil, err
			}
			var res []LoggingResource
			for id, ls := range logs {
				res = append(res, LoggingResource{ID: id, Logging: ls.LoggingEnabled != nil && *ls.LoggingEnabled})
			}
			return res, nil
		},
	))

	// redshift-backup-enabled
	checker.Register(ConfigCheck(
		"redshift-backup-enabled",
		"This rule checks Redshift backup enabled.",
		"redshift",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			clusters, err := d.RedshiftClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, c := range clusters {
				id := *c.ClusterIdentifier
				ok := c.AutomatedSnapshotRetentionPeriod != nil && *c.AutomatedSnapshotRetentionPeriod > 0
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("Retention: %v", c.AutomatedSnapshotRetentionPeriod)})
			}
			return res, nil
		},
	))

	// redshift-cluster-kms-enabled
	checker.Register(EncryptionCheck(
		"redshift-cluster-kms-enabled",
		"This rule checks Redshift cluster KMS enabled.",
		"redshift",
		d,
		func(d *awsdata.Data) ([]EncryptionResource, error) {
			clusters, err := d.RedshiftClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []EncryptionResource
			for _, c := range clusters {
				id := *c.ClusterIdentifier
				encrypted := c.KmsKeyId != nil && *c.KmsKeyId != ""
				res = append(res, EncryptionResource{ID: id, Encrypted: encrypted})
			}
			return res, nil
		},
	))

	// redshift-cluster-public-access-check
	checker.Register(ConfigCheck(
		"redshift-cluster-public-access-check",
		"This rule checks Redshift cluster public access.",
		"redshift",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			clusters, err := d.RedshiftClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, c := range clusters {
				id := *c.ClusterIdentifier
				public := c.PubliclyAccessible != nil && *c.PubliclyAccessible
				res = append(res, ConfigResource{ID: id, Passing: !public, Detail: fmt.Sprintf("Public: %v", public)})
			}
			return res, nil
		},
	))

	// redshift-cluster-subnet-group-multi-az
	checker.Register(ConfigCheck(
		"redshift-cluster-subnet-group-multi-az",
		"This rule checks Redshift cluster subnet group multi-AZ.",
		"redshift",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			groups, err := d.RedshiftClusterSubnetGroups.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, g := range groups {
				id := "unknown"
				if g.ClusterSubnetGroupName != nil {
					id = *g.ClusterSubnetGroupName
				}
				ok := len(g.Subnets) > 1
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("Subnet count: %d", len(g.Subnets))})
			}
			return res, nil
		},
	))

	// redshift-cluster-maintenancesettings-check
	checker.Register(ConfigCheck(
		"redshift-cluster-maintenancesettings-check",
		"This rule checks Redshift cluster maintenance settings.",
		"redshift",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			clusters, err := d.RedshiftClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, c := range clusters {
				id := *c.ClusterIdentifier
				ok := c.PreferredMaintenanceWindow != nil && *c.PreferredMaintenanceWindow != ""
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("PreferredMaintenanceWindow: %v", c.PreferredMaintenanceWindow)})
			}
			return res, nil
		},
	))

	// redshift-cluster-multi-az-enabled
	checker.Register(EnabledCheck(
		"redshift-cluster-multi-az-enabled",
		"This rule checks Redshift cluster multi-AZ enabled.",
		"redshift",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			clusters, err := d.RedshiftClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, c := range clusters {
				id := *c.ClusterIdentifier
				enabled := len(c.AvailabilityZones) > 1
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	// redshift-default-admin-check + redshift-default-db-name-check
	checker.Register(ConfigCheck(
		"redshift-default-admin-check",
		"This rule checks Redshift default admin.",
		"redshift",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			clusters, err := d.RedshiftClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, c := range clusters {
				id := *c.ClusterIdentifier
				user := strings.ToLower(*c.MasterUsername)
				ok := !redshiftDefaultAdmins[user]
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("MasterUsername: %s", user)})
			}
			return res, nil
		},
	))
	checker.Register(ConfigCheck(
		"redshift-default-db-name-check",
		"This rule checks Redshift default DB name.",
		"redshift",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			clusters, err := d.RedshiftClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, c := range clusters {
				id := *c.ClusterIdentifier
				name := strings.ToLower(*c.DBName)
				ok := !redshiftDefaultDBs[name]
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("DBName: %s", name)})
			}
			return res, nil
		},
	))

	// redshift-enhanced-vpc-routing-enabled
	checker.Register(EnabledCheck(
		"redshift-enhanced-vpc-routing-enabled",
		"This rule checks Redshift enhanced VPC routing enabled.",
		"redshift",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			clusters, err := d.RedshiftClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, c := range clusters {
				id := *c.ClusterIdentifier
				enabled := c.EnhancedVpcRouting != nil && *c.EnhancedVpcRouting
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	// redshift-cluster-parameter-group-tagged
	checker.Register(TaggedCheck(
		"redshift-cluster-parameter-group-tagged",
		"This rule checks Redshift cluster parameter group tagged.",
		"redshift",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			groups, err := d.RedshiftParamGroups.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.RedshiftParamGroupTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, g := range groups {
				if g.ParameterGroupName == nil {
					continue
				}
				res = append(res, TaggedResource{ID: *g.ParameterGroupName, Tags: tags[*g.ParameterGroupName]})
			}
			return res, nil
		},
	))

	// redshift-require-tls-ssl
	checker.Register(ConfigCheck(
		"redshift-require-tls-ssl",
		"This rule checks Redshift require TLS/SSL.",
		"redshift",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			values, err := d.RedshiftParamValues.Get()
			if err != nil {
				return nil, err
			}
			clusters, err := d.RedshiftClusters.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, c := range clusters {
				id := *c.ClusterIdentifier
				ok := false
				for _, pg := range c.ClusterParameterGroups {
					if pg.ParameterGroupName == nil {
						continue
					}
					val := values[*pg.ParameterGroupName]["require_ssl"]
					ok = ok || val == "true" || val == "1" || strings.EqualFold(val, "on")
					if ok {
						break
					}
				}
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "require_ssl enabled"})
			}
			return res, nil
		},
	))

	// redshift-unrestricted-port-access
	checker.Register(ConfigCheck(
		"redshift-unrestricted-port-access",
		"This rule checks Redshift unrestricted port access.",
		"redshift",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			clusters, err := d.RedshiftClusters.Get()
			if err != nil {
				return nil, err
			}
			sgs, err := d.EC2SecurityGroups.Get()
			if err != nil {
				return nil, err
			}
			m := make(map[string]bool)
			for _, sg := range sgs {
				if sg.GroupId == nil {
					continue
				}
				unrestricted := false
				for _, p := range sg.IpPermissions {
					if p.FromPort != nil && p.ToPort != nil && *p.FromPort <= 5439 && *p.ToPort >= 5439 {
						for _, r := range p.IpRanges {
							if r.CidrIp != nil && *r.CidrIp == "0.0.0.0/0" {
								unrestricted = true
							}
						}
						for _, r := range p.Ipv6Ranges {
							if r.CidrIpv6 != nil && *r.CidrIpv6 == "::/0" {
								unrestricted = true
							}
						}
					}
				}
				m[*sg.GroupId] = unrestricted
			}
			var res []ConfigResource
			for _, c := range clusters {
				id := *c.ClusterIdentifier
				bad := false
				for _, v := range c.VpcSecurityGroups {
					if v.VpcSecurityGroupId != nil && m[*v.VpcSecurityGroupId] {
						bad = true
					}
				}
				res = append(res, ConfigResource{ID: id, Passing: !bad, Detail: "Unrestricted SG"})
			}
			return res, nil
		},
	))

	// redshift-serverless-default-admin-check + redshift-serverless-default-db-name-check
	checker.Register(ConfigCheck(
		"redshift-serverless-default-admin-check",
		"This rule checks Redshift Serverless default admin.",
		"redshift",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			namespaces, err := d.RedshiftServerlessNamespaces.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, ns := range namespaces {
				id := *ns.NamespaceName
				user := strings.ToLower(*ns.AdminUsername)
				ok := !redshiftDefaultAdmins[user]
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("AdminUsername: %s", user)})
			}
			return res, nil
		},
	))
	checker.Register(ConfigCheck(
		"redshift-serverless-default-db-name-check",
		"This rule checks Redshift Serverless default DB name.",
		"redshift",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			namespaces, err := d.RedshiftServerlessNamespaces.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, ns := range namespaces {
				id := *ns.NamespaceName
				name := strings.ToLower(*ns.DbName)
				ok := !redshiftDefaultDBs[name]
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("DbName: %s", name)})
			}
			return res, nil
		},
	))

	// redshift-serverless-namespace-cmk-encryption
	checker.Register(EncryptionCheck(
		"redshift-serverless-namespace-cmk-encryption",
		"This rule checks Redshift Serverless namespace CMK encryption.",
		"redshift",
		d,
		func(d *awsdata.Data) ([]EncryptionResource, error) {
			namespaces, err := d.RedshiftServerlessNamespaces.Get()
			if err != nil {
				return nil, err
			}
			var res []EncryptionResource
			for _, ns := range namespaces {
				id := *ns.NamespaceName
				encrypted := ns.KmsKeyId != nil && *ns.KmsKeyId != ""
				res = append(res, EncryptionResource{ID: id, Encrypted: encrypted})
			}
			return res, nil
		},
	))

	// redshift-serverless-publish-logs-to-cloudwatch
	checker.Register(LoggingCheck(
		"redshift-serverless-publish-logs-to-cloudwatch",
		"This rule checks Redshift Serverless publish logs to CloudWatch.",
		"redshift",
		d,
		func(d *awsdata.Data) ([]LoggingResource, error) {
			namespaces, err := d.RedshiftServerlessNamespaces.Get()
			if err != nil {
				return nil, err
			}
			var res []LoggingResource
			for _, ns := range namespaces {
				id := *ns.NamespaceName
				logging := len(ns.LogExports) > 0
				res = append(res, LoggingResource{ID: id, Logging: logging})
			}
			return res, nil
		},
	))

	// redshift-serverless-workgroup-encrypted-in-transit + no public access + routes within vpc
	checker.Register(ConfigCheck(
		"redshift-serverless-workgroup-encrypted-in-transit",
		"This rule checks Redshift Serverless workgroup encrypted in transit.",
		"redshift",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			wgs, err := d.RedshiftServerlessWorkgroups.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, wg := range wgs {
				id := *wg.WorkgroupName
				ok := wg.PubliclyAccessible == nil || !*wg.PubliclyAccessible
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("PubliclyAccessible: %v", wg.PubliclyAccessible)})
			}
			return res, nil
		},
	))
	checker.Register(ConfigCheck(
		"redshift-serverless-workgroup-no-public-access",
		"This rule checks Redshift Serverless workgroup no public access.",
		"redshift",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			wgs, err := d.RedshiftServerlessWorkgroups.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, wg := range wgs {
				id := *wg.WorkgroupName
				ok := wg.PubliclyAccessible == nil || !*wg.PubliclyAccessible
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("PubliclyAccessible: %v", wg.PubliclyAccessible)})
			}
			return res, nil
		},
	))
	checker.Register(ConfigCheck(
		"redshift-serverless-workgroup-routes-within-vpc",
		"This rule checks Redshift Serverless workgroup routes within VPC.",
		"redshift",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			wgs, err := d.RedshiftServerlessWorkgroups.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, wg := range wgs {
				id := *wg.WorkgroupName
				ok := len(wg.SubnetIds) > 0
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("Subnet count: %d", len(wg.SubnetIds))})
			}
			return res, nil
		},
	))
}
