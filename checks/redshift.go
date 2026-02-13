package checks

import (
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/checker"

	rsstypes "github.com/aws/aws-sdk-go-v2/service/redshiftserverless/types"
)

var redshiftDefaultAdmins = map[string]bool{"admin": true, "root": true, "master": true, "awsuser": true}
var redshiftDefaultDBs = map[string]bool{"dev": true, "default": true, "test": true, "postgres": true}

func RegisterRedshiftChecks(d *awsdata.Data) {
	// redshift-cluster-configuration-check
	checker.Register(ConfigCheck(
		"redshift-cluster-configuration-check",
		"Checks if Amazon Redshift clusters have the specified settings. The rule is NON_COMPLIANT if the Amazon Redshift cluster is not encrypted or encrypted with another key, or if a cluster does not have audit logging enabled.",
		"redshift",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			clusters, err := d.RedshiftClusters.Get()
			if err != nil {
				return nil, err
			}
			logging, err := d.RedshiftLoggingStatus.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, c := range clusters {
				id := *c.ClusterIdentifier
				encrypted := c.Encrypted != nil && *c.Encrypted
				logged := false
				if ls, ok := logging[id]; ok {
					logged = ls.LoggingEnabled != nil && *ls.LoggingEnabled
				}
				ok := encrypted && logged
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("Encrypted: %v, AuditLogging: %v", encrypted, logged)})
			}
			return res, nil
		},
	))
	// redshift-audit-logging-enabled
	checker.Register(LoggingCheck(
		"redshift-audit-logging-enabled",
		"Checks if Amazon Redshift clusters are logging audits to a specific bucket. The rule is NON_COMPLIANT if audit logging is not enabled for a Redshift cluster or if the 'bucketNames' parameter is provided but the audit logging destination does not match.",
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
		"Checks that Amazon Redshift automated snapshots are enabled for clusters. The rule is NON_COMPLIANT if the value for automatedSnapshotRetentionPeriod is greater than MaxRetentionPeriod or less than MinRetentionPeriod or the value is 0.",
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
		"Checks if Amazon Redshift clusters are using a specified AWS Key Management Service (AWS KMS) key for encryption. The rule is COMPLIANT if encryption is enabled and the cluster is encrypted with the key provided in the kmsKeyArn parameter. The rule is NON_COMPLIANT if the cluster is not encrypted or encrypted with another key.",
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
		"Checks whether Amazon Redshift clusters are not publicly accessible. The rule is NON_COMPLIANT if the publiclyAccessible field is true in the cluster configuration item.",
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
		"Checks If Amazon Redshift subnet groups contain subnets from more than one Availability Zone. The rule is NON_COMPLIANT if an Amazon Redshift subnet group does not contain subnets from at least two different Availability Zones.",
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
				azs := map[string]struct{}{}
				for _, subnet := range g.Subnets {
					if subnet.SubnetAvailabilityZone == nil || subnet.SubnetAvailabilityZone.Name == nil || *subnet.SubnetAvailabilityZone.Name == "" {
						continue
					}
					azs[*subnet.SubnetAvailabilityZone.Name] = struct{}{}
				}
				ok := len(azs) >= 2
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("Distinct subnet AZ count: %d", len(azs))})
			}
			return res, nil
		},
	))

	// redshift-cluster-maintenancesettings-check
	checker.Register(ConfigCheck(
		"redshift-cluster-maintenancesettings-check",
		"Checks if Amazon Redshift clusters have the specified maintenance settings. The rule is NON_COMPLIANT if the automatic upgrades to major version is disabled.",
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
				ok := c.AllowVersionUpgrade != nil && *c.AllowVersionUpgrade
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("AllowVersionUpgrade: %v", c.AllowVersionUpgrade)})
			}
			return res, nil
		},
	))

	// redshift-cluster-multi-az-enabled
	checker.Register(EnabledCheck(
		"redshift-cluster-multi-az-enabled",
		"Checks if an Amazon Redshift cluster has multiple Availability Zones deployments enabled. This rule is NON_COMPLIANT if Amazon Redshift cluster does not have multiple Availability Zones deployments enabled.",
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
				enabled := c.MultiAZ != nil && strings.EqualFold(*c.MultiAZ, "true")
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	// redshift-default-admin-check + redshift-default-db-name-check
	checker.Register(ConfigCheck(
		"redshift-default-admin-check",
		"Checks if an Amazon Redshift cluster has changed the admin username from its default value. The rule is NON_COMPLIANT if the admin username for a Redshift cluster is set to “awsuser” or if the username does not match what is listed in parameter.",
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
		"Checks if a Redshift cluster has changed its database name from the default value. The rule is NON_COMPLIANT if the database name for a Redshift cluster is set to “dev”, or if the optional parameter is provided and the database name does not match.",
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
		"Checks if Amazon Redshift cluster has 'enhancedVpcRouting' enabled. The rule is NON_COMPLIANT if 'enhancedVpcRouting' is not enabled or if the configuration.enhancedVpcRouting field is 'false'.",
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
		"Checks if Amazon Redshift cluster parameter groups have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
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
		"Checks if Amazon Redshift clusters require TLS/SSL encryption to connect to SQL clients. The rule is NON_COMPLIANT if any Amazon Redshift cluster has parameter require_SSL not set to true.",
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
		"Checks if security groups associated with an Amazon Redshift cluster have inbound rules that allow unrestricted incoming traffic. The rule is NON_COMPLIANT if there are inbound rules that allow unrestricted incoming traffic to the Redshift cluster port.",
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
			var res []ConfigResource
			for _, c := range clusters {
				id := *c.ClusterIdentifier
				port := int32(5439)
				if c.Endpoint != nil && c.Endpoint.Port != nil && *c.Endpoint.Port > 0 {
					port = *c.Endpoint.Port
				}
				bad := false
				for _, v := range c.VpcSecurityGroups {
					if v.VpcSecurityGroupId == nil {
						continue
					}
					for _, sg := range sgs {
						if sg.GroupId == nil || *sg.GroupId != *v.VpcSecurityGroupId {
							continue
						}
						for _, p := range sg.IpPermissions {
							if p.FromPort == nil || p.ToPort == nil || *p.FromPort > port || *p.ToPort < port {
								continue
							}
							for _, r := range p.IpRanges {
								if r.CidrIp != nil && *r.CidrIp == "0.0.0.0/0" {
									bad = true
									break
								}
							}
							for _, r := range p.Ipv6Ranges {
								if r.CidrIpv6 != nil && *r.CidrIpv6 == "::/0" {
									bad = true
									break
								}
							}
							if bad {
								break
							}
						}
						if bad {
							break
						}
					}
					if bad {
						break
					}
				}
				res = append(res, ConfigResource{ID: id, Passing: !bad, Detail: fmt.Sprintf("No unrestricted access on cluster port %d", port)})
			}
			return res, nil
		},
	))

	// redshift-serverless-default-admin-check + redshift-serverless-default-db-name-check
	checker.Register(ConfigCheck(
		"redshift-serverless-default-admin-check",
		"Checks if an Amazon Redshift Serverless Namespace has changed the admin username from its default value. The rule is NON_COMPLIANT if the admin username for a Redshift Serverless Namespace is set to “admin”.",
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
		"Checks if an Amazon Redshift Serverless namespace has changed its database name from the default value. The rule is NON_COMPLIANT if the database name for an Amazon Redshift Serverless namespace is set to `dev`.",
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
		"Checks if Amazon Redshift Serverless namespaces are encrypted by customer managed AWS KMS keys. The rule is NON_COMPLIANT if a namespace is not encrypted by a customer managed key. Optionally, you can specify a list of KMS keys for rule to check.",
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
		"Checks if Amazon Redshift Serverless Namespace is configured to publish the following logs to Amazon CloudWatch Logs. This rule is NON_COMPLIANT if the Namespace is not configured to publish the following logs to Amazon CloudWatch Logs.",
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
				logging := redshiftServerlessHasRequiredLogExports(ns.LogExports)
				res = append(res, LoggingResource{ID: id, Logging: logging})
			}
			return res, nil
		},
	))

	// redshift-serverless-workgroup-encrypted-in-transit + no public access + routes within vpc
	checker.Register(ConfigCheck(
		"redshift-serverless-workgroup-encrypted-in-transit",
		"Checks if AWS Redshift Serverless workgroups have the require_ssl config parameter set to true. The rule is NON_COMPLIANT if require_ssl is set to false.",
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
				requireSSL := false
				for _, cp := range wg.ConfigParameters {
					if cp.ParameterKey == nil || !strings.EqualFold(*cp.ParameterKey, "require_ssl") || cp.ParameterValue == nil {
						continue
					}
					val := strings.TrimSpace(strings.ToLower(*cp.ParameterValue))
					requireSSL = val == "true" || val == "1" || val == "on"
					break
				}
				res = append(res, ConfigResource{ID: id, Passing: requireSSL, Detail: fmt.Sprintf("require_ssl: %v", requireSSL)})
			}
			return res, nil
		},
	))
	checker.Register(ConfigCheck(
		"redshift-serverless-workgroup-no-public-access",
		"Checks if Amazon Redshift Serverless workgroups do not allow public access. The rule is NON_COMPLIANT if a workgroup has 'Turn on Public Accessible' enabled.",
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
		"Checks if Amazon Redshift Serverless workgroups route the network traffic through a VPC. The rule is NON_COMPLIANT if workgroups have 'Turn on Enhanced VPC routing' disabled.",
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
				ok := wg.EnhancedVpcRouting != nil && *wg.EnhancedVpcRouting
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("EnhancedVpcRouting: %v", wg.EnhancedVpcRouting)})
			}
			return res, nil
		},
	))
}

func redshiftServerlessHasRequiredLogExports(exports []rsstypes.LogExport) bool {
	required := map[string]bool{"connectionlog": false, "userlog": false}
	for _, exp := range exports {
		name := strings.ToLower(strings.TrimSpace(string(exp)))
		if _, ok := required[name]; ok {
			required[name] = true
		}
	}
	for _, ok := range required {
		if !ok {
			return false
		}
	}
	return true
}
