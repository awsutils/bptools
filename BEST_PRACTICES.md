access-keys-rotated
Checks if active IAM access keys are rotated (changed) within the number of days specified in maxAccessKeyAge. The rule is NON_COMPLIANT if access keys are not rotated within the specified time period. The default value is 90 days.

account-part-of-organizations
Checks if an AWS account is part of AWS Organizations. The rule is NON_COMPLIANT if an AWS account is not part of AWS Organizations or AWS Organizations master account ID does not match rule parameter MasterAccountId.

acmpca-certificate-authority-tagged
Checks if AWS Private CA certificate authorities have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

acm-certificate-expiration-check
Checks if AWS Certificate Manager Certificates in your account are marked for expiration within the specified number of days. Certificates provided by ACM are automatically renewed. ACM does not automatically renew certificates that you import. The rule is NON_COMPLIANT if your certificates are about to expire.

acm-certificate-rsa-check
Checks if RSA certificates managed by AWS Certificate Manager (ACM) have a key length of at least '2048' bits.The rule is NON_COMPLIANT if the minimum key length is less than 2048 bits.

acm-pca-root-ca-disabled
Checks if AWS Private Certificate Authority (AWS Private CA) has a root CA that is disabled. The rule is NON_COMPLIANT for root CAs with status that is not DISABLED.

active-mq-supported-version
Checks if an Amazon MQ ActiveMQ broker is running on a specified minimum supported engine version. The rule is NON_COMPLIANT if the ActiveMQ broker is not running on the minimum supported engine version that you specify.

alb-desync-mode-check
Checks if an Application Load Balancer (ALB) is configured with a user defined desync mitigation mode. The rule is NON_COMPLIANT if ALB desync mitigation mode does not match with the user defined desync mitigation mode.

alb-http-drop-invalid-header-enabled
Checks if rule evaluates AWS Application Load Balancers (ALB) to ensure they are configured to drop http headers. The rule is NON_COMPLIANT if the value of routing.http.drop_invalid_header_fields.enabled is set to false

alb-http-to-https-redirection-check
Checks if HTTP to HTTPS redirection is configured on all HTTP listeners of Application Load Balancers. The rule is NON_COMPLIANT if one or more HTTP listeners of Application Load Balancer do not have HTTP to HTTPS redirection configured. The rule is also NON_COMPLIANT if one of more HTTP listeners have forwarding to an HTTP listener instead of redirection.

alb-internal-scheme-check
Checks if an Application Load Balancer scheme is internal. The rule is NON_COMPLIANT if configuration.scheme is not set to internal.

alb-listener-tagged
Checks if Application Load Balancer listeners have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

alb-tagged
Checks if Application Load Balancers have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

alb-waf-enabled
Checks if Web Application Firewall (WAF) is enabled on Application Load Balancers (ALBs). This rule is NON_COMPLIANT if key: waf.enabled is set to false.

amplify-app-branch-auto-deletion-enabled
Checks if AWS Amplify apps automatically disconnect a branch in Amplify Hosting when you delete a branch from your Git repository. The rule is NON_COMPLIANT if configuration.EnableBranchAutoDeletion is false.

amplify-app-description
Checks if AWS Amplify apps have a description. The rule is NON_COMPLIANT if configuration.Description does not exist or is an empty string.

amplify-app-no-environment-variables
Checks that AWS Amplify apps do not contain environment variables. The rule is NON_COMPLIANT if configuration.EnvironmentVariables is not an empty list.

amplify-app-tagged
Checks if AWS Amplify apps have tags. Optionally, you can specify tag keys for the rule. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

amplify-branch-description
Checks if AWS Amplify branches have a description. The rule is NON_COMPLIANT if configuration.Description does not exist or is an empty string.

amplify-branch-performance-mode-enabled
Checks if AWS Amplify branches have performance mode enabled. The rule is NON_COMPLIANT if configuration.EnablePerformanceMode is false.

amplify-branch-tagged
Checks if AWS Amplify branches have tags. Optionally, you can specify tag keys for the rule. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

apigatewayv2-stage-description
Checks if Amazon API Gateway V2 stages have a description. The rule is NON_COMPLIANT if configuration.Description does not exist or is an empty string.

apigateway-stage-access-logs-enabled
Checks if Amazon API Gateway stages have access logging enabled. The rule is NON_COMPLIANT if 'accessLogSettings' is not present in Stage configuration.

apigateway-stage-description
Checks if Amazon API Gateway stages have a description. The rule is NON_COMPLIANT if configuration.Description does not exist or is an empty string.

api-gwv2-access-logs-enabled
Checks if Amazon API Gateway V2 stages have access logging enabled. The rule is NON_COMPLIANT if 'accessLogSettings' is not present in Stage configuration.

api-gwv2-authorization-type-configured
Checks if Amazon API Gatewayv2 API routes have an authorization type set. This rule is NON_COMPLIANT if the authorization type is NONE.

api-gwv2-stage-default-route-detailed-metrics-enabled
Checks if the default route settings for Amazon API Gateway V2 stages have detailed metrics enabled. The rule is NON_COMPLIANT if configuration.defaultRouteSettings.detailedMetricsEnabled is false.

api-gw-associated-with-waf
Checks if an Amazon API Gateway API stage is using an AWS WAF web access control list (web ACL). The rule is NON_COMPLIANT if an AWS WAF Web ACL is not used or if a used AWS Web ACL does not match what is listed in the rule parameter.

api-gw-cache-enabled-and-encrypted
Checks if all methods in Amazon API Gateway stages have cache enabled and cache encrypted. The rule is NON_COMPLIANT if any method in an Amazon API Gateway stage is not configured to cache or the cache is not encrypted.

api-gw-endpoint-type-check
Checks if Amazon API Gateway APIs are of the type specified in the rule parameter endpointConfigurationType. The rule returns NON_COMPLIANT if the REST API does not match the endpoint type configured in the rule parameter.

api-gw-execution-logging-enabled
Checks if all methods in Amazon API Gateway stages have logging enabled. The rule is NON_COMPLIANT if logging is not enabled, or if loggingLevel is neither ERROR nor INFO.

api-gw-rest-api-tagged
Checks if AWS ApiGateway REST API resources resources have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

api-gw-ssl-enabled
Checks if a REST API stage uses an SSL certificate. The rule is NON_COMPLIANT if the REST API stage does not have an associated SSL certificate.

api-gw-stage-tagged
Checks if AWS ApiGateway stage resources resources have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

api-gw-xray-enabled
Checks if AWS X-Ray tracing is enabled on Amazon API Gateway REST APIs. The rule is COMPLIANT if X-Ray tracing is enabled and NON_COMPLIANT otherwise.

appconfig-application-description
Checks if AWS AppConfig applications have a description. The rule is NON_COMPLIANT if configuration.Description does not exist or is an empty string.

appconfig-application-tagged
Checks if AWS AppConfig applications have tags. Optionally, you can specify tag keys for the rule to check. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

appconfig-configuration-profile-tagged
Checks if AWS AppConfig configuration profiles have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

appconfig-configuration-profile-validators-not-empty
Checks if an AWS AppConfig configuration profile includes at least one validator for syntactic or semantic check to ensure the configuration deploy functions as intended. The rule is NON_COMPLIANT if the Validators property is an empty array.

appconfig-deployment-strategy-description
Checks if AWS AppConfig deployment strategies have a description. The rule is NON_COMPLIANT if configuration.Description does not exist or is an empty string.

appconfig-deployment-strategy-minimum-final-bake-time
Checks if an AWS AppConfig deployment strategy requires the specified minimum bake time. The rule is NON_COMPLIANT if the deployment strategy has a final bake time less than value specified in the rule parameter. The default value is 30 minutes.

appconfig-deployment-strategy-replicate-to-ssm
Checks if AWS AppConfig deployment strategies save the deployment strategy to an AWS Systems Manager (SSM) document. The rule is NON_COMPLIANT if configuration.ReplicateTo is not 'SSM_DOCUMENT'.

appconfig-deployment-strategy-tagged
Checks if AWS AppConfig deployment strategies have tags. Optionally, you can specify tag keys for the rule. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

appconfig-environment-description
Checks if AWS AppConfig environments have a description. The rule is NON_COMPLIANT if configuration.Description does not exist or is an empty string.

appconfig-environment-tagged
Checks if AWS AppConfig environments have tags. Optionally, you can specify tag keys for the rule to check. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

appconfig-extension-association-tagged
Checks if AWS AppConfig extension associations have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

appconfig-freeform-profile-config-storage
Checks if freeform configuration profiles for AWS AppConfig store their configuration data in AWS Secrets Manager or AWS AppConfig hosted configuration store. The rule is NON_COMPLIANT if configuration.LocationUri is not secretsmanager or hosted.

appconfig-hosted-configuration-version-description
Checks if AWS AppConfig hosted configuration versions have a description. The rule is NON_COMPLIANT if configuration.Description does not exist or is an empty string.

appflow-flow-tagged
Checks if Amazon AppFlow flows have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

appflow-flow-trigger-type-check
Checks if an Amazon AppFlow flow runs using the specified trigger type. The rule is NON_COMPLAINT if the flow does not run using the flow type specified in the required rule parameter.

appintegrations-event-integration-description
Checks if Amazon AppIntegrations event integrations have a description. The rule is NON_COMPLIANT if configuration.Description does not exist.

appintegrations-event-integration-tagged
Checks if Amazon AppIntegrations event integrations have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

appmesh-gateway-route-tagged
Checks if AWS App Mesh gateway routes have tags. Optionally, you can specify tag keys for the rule. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

appmesh-mesh-deny-tcp-forwarding
Checks if proxies for AWS App Mesh service meshes do not forward TCP traffic directly to services that aren't deployed with a proxy that is defined in the mesh. The rule is NON_COMPLIANT if configuration.Spec.EgressFilter.Type is set to 'ALLOW_ALL'.

appmesh-mesh-tagged
Checks if AWS App Mesh meshes have tags. Optionally, you can specify tag keys for the rule to check. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

appmesh-route-tagged
Checks if AWS App Mesh routes have tags. Optionally, you can specify tag keys for the rule to check. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

appmesh-virtual-gateway-backend-defaults-tls
Checks if backend defaults for AWS App Mesh virtual gateways require the virtual gateways to communicate with all ports using TLS. The rule is NON_COMPLIANT if configuration.Spec.BackendDefaults.ClientPolicy.Tls.Enforce is false.

appmesh-virtual-gateway-logging-file-path-exists
Checks if AWS App Mesh virtual gateways have a file path to write access logs to. The rule is NON_COMPLIANT if configuration.Spec.Logging.AccessLog.File.Path does not exist.

appmesh-virtual-gateway-tagged
Checks if AWS App Mesh virtual gateways have tags. Optionally, you can specify tag keys for the rule. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

appmesh-virtual-node-backend-defaults-tls-on
Checks if backend defaults for AWS App Mesh virtual nodes require the virtual nodes to communicate with all ports using TLS. The rule is NON_COMPLIANT if configuration.Spec.BackendDefaults.ClientPolicy.Tls.Enforce is false.

appmesh-virtual-node-cloud-map-ip-pref-check
Checks if an AWS App Mesh virtual node is configured with the specified IP preference for AWS Cloud Map service discovery. The rule is NON_COMPLIANT if the virtual node is not configured with the IP preference specified in the required rule parameter.

appmesh-virtual-node-dns-ip-pref-check
Checks if an AWS App Mesh virtual node is configured with the specified IP preference for DNS service discovery. The rule is NON_COMPLIANT if the virtual node is not configured with the IP preference specified in the required rule parameter.

appmesh-virtual-node-logging-file-path-exists
Checks if AWS App Mesh virtual nodes have a file path to write access logs to. The rule is NON_COMPLIANT if configuration.Spec.Logging.AccessLog.File.Path does not exist.

appmesh-virtual-node-tagged
Checks if AWS App Mesh virtual nodes have tags. Optionally, you can specify tag keys for the rule to check. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

appmesh-virtual-router-tagged
Checks if AWS App Mesh virtual routers have tags. Optionally, you can specify tag keys for the rule. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

appmesh-virtual-service-tagged
Checks if AWS App Mesh virtual services have tags. Optionally, you can specify tag keys for the rule. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

approved-amis-by-id
Checks if EC2 instances are using specified Amazon Machine Images (AMIs). Specify a list of approved AMI IDs. Running instances with AMIs that are not on this list are NON_COMPLIANT.

approved-amis-by-tag
Checks if EC2 instances are using specified Amazon Machine Images (AMIs). Specify the tags that identify the AMIs. Running instances with AMIs that don't have at least one of the specified tags are NON_COMPLIANT.

apprunner-service-in-vpc
Checks if AWS App Runner services route egress traffic through custom VPC. The rule is NON_COMPLIANT if configuration.NetworkConfiguration.EgressConfiguration.EgressType is equal to DEFAULT.

apprunner-service-ip-address-type-check
Checks if an AWS App Runner service is configured with the specified IP address type for incoming public network configuration. The rule is NON_COMPLIANT if the service is not configured with the IP address type specified in the required rule parameter.

apprunner-service-max-unhealthy-threshold
Checks if an AWS App Runner service is configured to have an unhealthy threshold less than or equal to the specified value. The rule is NON_COMPLIANT if the unhealthy threshold is greater than the value specified in the required rule parameter.

apprunner-service-no-public-access
Checks if AWS AppRunner Services are not publicly accessible. The rule is NON_COMPLIANT if service.configuration.NetworkConfiguration.IngressConfiguration.IsPubliclyAccessible is False.

apprunner-service-observability-enabled
Checks if AWS App Runner services have observability enabled. The rule is NON_COMPLIANT if configuration.ObservabilityConfiguration.ObservabilityEnabled is false'.

apprunner-service-tagged
Checks if AWS App Runner services have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

apprunner-vpc-connector-tagged
Checks if AWS App Runner VPC connectors have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

appstream-fleet-in-vpc
Checks if Amazon AppStream 2.0 fleets use an Amazon Virtual Private Cloud (Amazon VPC). The rule is NON_COMPLIANT if configuration.VpcConfig does not exist. The rule does not check Elastic fleets.

appsync-associated-with-waf
Checks if AWS AppSync APIs are associated with AWS WAFv2 web access control lists (ACLs). The rule is NON_COMPLIANT for an AWS AppSync API if it is not associated with a web ACL.

appsync-authorization-check
Checks if an AWS AppSync API is using allowed authorization mechanisms. The rule is NON_COMPLIANT if an unapproved authorization mechanism is being used.

appsync-cache-ct-encryption-at-rest
Checks if an AWS AppSync API cache has encryption at rest enabled. This rule is NON_COMPLIANT if 'AtRestEncryptionEnabled' is false.

appsync-cache-ct-encryption-in-transit
Checks if an AWS AppSync API cache has encryption in transit enabled. The rule is NON_COMPLIANT if 'TransitEncryptionEnabled' is false.

appsync-cache-encryption-at-rest
Checks if an AWS AppSync API cache has encryption at rest enabled. This rule is NON_COMPLIANT if 'AtRestEncryptionEnabled' is false.

appsync-graphql-api-xray-enabled
Checks if AWS AppSync GraphQL APIs have AWS X-Ray tracing enabled. The rule is NON_COMPLIANT if configuration.XrayEnabled is false.

appsync-logging-enabled
Checks if an AWS AppSync API has field level logging enabled. The rule is NON_COMPLIANT if field level logging is not enabled, or if the field logging levels for the AppSync API do not match the values specified in the 'fieldLoggingLevel' parameter.

aps-rule-groups-namespace-tagged
Checks if Amazon Managed Service for Prometheus rule groups namepaces have tags. You can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

athena-data-catalog-description
Checks if Amazon Athena data catalogs have a description. The rule is NON_COMPLIANT if configuration.Description does not exist.

athena-prepared-statement-description
Checks if Amazon Athena prepared statements have a description. The rule is NON_COMPLIANT if configuration.Description does not exist.

athena-workgroup-description
Checks if Amazon Athena workgroups have a description. The rule is NON_COMPLIANT if configuration.Description does not exist or is an empty string.

athena-workgroup-encrypted-at-rest
Checks if an Amazon Athena workgroup is encrypted at rest. The rule is NON_COMPLIANT if encryption of data at rest is not enabled for an Athena workgroup.

athena-workgroup-enforce-workgroup-configuration
Checks if Amazon Athena workgroups using Athena engine enforce workgroup configuration to override client-side settings. The rule is NON_COMPLIANT if configuration.WorkGroupConfiguration.EnforceWorkGroupConfiguration is false.

athena-workgroup-engine-version-auto-upgrade
Checks if Amazon Athena workgroups using Athena engine are configured to auto upgrade. The rule is NON_COMPLIANT if configuration.WorkGroupConfiguration.EngineVersion.SelectedEngineVersion is not 'AUTO'.

athena-workgroup-logging-enabled
Checks if Amazon Athena WorkGroup publishes usage metrics to Amazon CloudWatch. The rule is NON_COMPLIANT if an Amazon Athena WorkGroup 'PublishCloudWatchMetricsEnabled' is set to false.

auditmanager-assessment-tagged
Checks if AWS Audit Manager assessments have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

aurora-global-database-encryption-at-rest
Checks if Amazon Aurora Global Databases have storage encryption enabled. This rule is NON_COMPLIANT if an Amazon Aurora Global Database does not have storage encryption enabled.

aurora-last-backup-recovery-point-created
Checks if a recovery point was created for Amazon Aurora DB clusters. The rule is NON_COMPLIANT if the Amazon Relational Database Service (Amazon RDS) DB Cluster does not have a corresponding recovery point created within the specified time period.

aurora-meets-restore-time-target
Checks if the restore time of Amazon Aurora DB clusters meets the specified duration. The rule is NON_COMPLIANT if LatestRestoreExecutionTimeMinutes of an Aurora DB Cluster is greater than maxRestoreTime minutes.

aurora-mysql-backtracking-enabled
Checks if an Amazon Aurora MySQL cluster has backtracking enabled. The rule is NON_COMPLIANT if the Aurora cluster uses MySQL and it does not have backtracking enabled.

aurora-mysql-cluster-audit-logging
Checks if Amazon Aurora MySQL DB clusters have audit logging enabled. The rule is NON_COMPLIANT if a DB cluster does not have audit logging enabled.

aurora-resources-in-logically-air-gapped-vault
Checks if Amazon Aurora DB clusters are in a logically air-gapped vault. The rule is NON_COMPLIANT if an Amazon Aurora DB cluster is not in a logically air-gapped vault within the specified time period.

aurora-resources-protected-by-backup-plan
Checks if Amazon Aurora DB clusters are protected by a backup plan. The rule is NON_COMPLIANT if the Amazon Relational Database Service (Amazon RDS) Database Cluster is not protected by a backup plan.

autoscaling-capacity-rebalancing
Checks if Capacity Rebalancing is enabled for Amazon EC2 Auto Scaling groups that use multiple instance types. The rule is NON_COMPLIANT if capacity Rebalancing is not enabled.

autoscaling-group-elb-healthcheck-required
Checks if your Amazon EC2 Auto Scaling groups that are associated with an Elastic Load Balancer use Elastic Load Balancing health checks. The rule is NON_COMPLIANT if the Amazon EC2 Auto Scaling groups are not using Elastic Load Balancing health checks.

autoscaling-launchconfig-requires-imdsv2
Checks whether only IMDSv2 is enabled. This rule is NON_COMPLIANT if the Metadata version is not included in the launch configuration or if both Metadata V1 and V2 are enabled.

autoscaling-launch-config-hop-limit
Checks the number of network hops that the metadata token can travel. This rule is NON_COMPLIANT if the Metadata response hop limit is greater than 1.

autoscaling-launch-config-public-ip-disabled
Checks if Amazon EC2 Auto Scaling groups have public IP addresses enabled through Launch Configurations. The rule is NON_COMPLIANT if the Launch Configuration for an Amazon EC2 Auto Scaling group has AssociatePublicIpAddress set to 'true'.

autoscaling-launch-template
Checks if an Amazon Elastic Compute Cloud (EC2) Auto Scaling group is created from an EC2 launch template. The rule is NON_COMPLIANT if the scaling group is not created from an EC2 launch template.

autoscaling-multiple-az
Checks if the Auto Scaling group spans multiple Availability Zones. The rule is NON_COMPLIANT if the Auto Scaling group does not span multiple Availability Zones.

autoscaling-multiple-instance-types
Checks if an Amazon EC2 Auto Scaling group uses multiple instance types. The rule is NON_COMPLIANT if the Amazon EC2 Auto Scaling group has only one instance type defined. This rule does not evaluate attribute-based instance types.

backup-plan-min-frequency-and-min-retention-check
Checks if a backup plan has a backup rule that satisfies the required frequency and retention period. The rule is NON_COMPLIANT if recovery points are not created at least as often as the specified frequency or expire before the specified period.

backup-recovery-point-encrypted
Checks if a recovery point is encrypted. The rule is NON_COMPLIANT if the recovery point is not encrypted.

backup-recovery-point-manual-deletion-disabled
Checks if a backup vault has an attached resource-based policy which prevents deletion of recovery points. The rule is NON_COMPLIANT if the Backup Vault does not have resource-based policies or has policies without a suitable 'Deny' statement (statement with backup:DeleteRecoveryPoint, backup:UpdateRecoveryPointLifecycle, and backup:PutBackupVaultAccessPolicy permissions).

backup-recovery-point-minimum-retention-check
Checks if a recovery point expires no earlier than after the specified period. The rule is NON_COMPLIANT if the recovery point has a retention point that is less than the required retention period.

batch-compute-environment-enabled
Checks if AWS Batch compute environments are enabled. The rule is NON_COMPLIANT if configuration.State is 'DISABLED'.

batch-compute-environment-managed
Checks if AWS Batch compute environments are managed. The rule is NON_COMPLIANT if configuration.Type is 'UNMANAGED'.

batch-compute-environment-tagged
Checks if AWS Batch compute environments have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

batch-job-queue-enabled
Checks if AWS Batch job queues are enabled. The rule is NON_COMPLIANT if configuration.State is 'DISABLED'.

batch-job-queue-tagged
Checks if AWS Batch job queues have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

batch-managed-compute-environment-using-launch-template
Checks if AWS Batch managed compute environments are configured using a launch template. The rule is NON_COMPLIANT if configuration.ComputeResources.LaunchTemplate does not exist.

batch-managed-compute-env-allocation-strategy-check
Checks if an AWS Batch managed compute environment is configured with a specified allocation strategy. The rule is NON_COMPLIANT if the compute environment is not configured with an allocation strategy specified in the required rule parameter.

batch-managed-compute-env-compute-resources-tagged
Checks if AWS Batch managed compute environments compute resources have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. Tags starting with 'aws:' are not checked.

batch-managed-spot-compute-environment-max-bid
Checks if an AWS Batch managed Spot compute environment is configured to have a bid percentage less than or equal to the specified value. The rule is NON_COMPLIANT if the bid percentage is greater than the value specified in the required rule parameter.

batch-scheduling-policy-tagged
Checks if AWS Batch scheduling policies have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

beanstalk-enhanced-health-reporting-enabled
Checks if an AWS Elastic Beanstalk environment is configured for enhanced health reporting. The rule is COMPLIANT if the environment is configured for enhanced health reporting. The rule is NON_COMPLIANT if the environment is configured for basic health reporting.

cassandra-keyspace-tagged
Checks if Amazon Keyspaces (for Apache Cassandra) keyspaces have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

clb-desync-mode-check
Checks if Classic Load Balancers (CLB) are configured with a user defined Desync mitigation mode. The rule is NON_COMPLIANT if CLB Desync mitigation mode does not match with user defined Desync mitigation mode.

clb-multiple-az
Checks if a Classic Load Balancer spans multiple Availability Zones (AZs). The rule is NON_COMPLIANT if a Classic Load Balancer spans less than 2 AZs or does not span number of AZs mentioned in the minAvailabilityZones parameter (if provided).

cloudformation-stack-drift-detection-check
Checks if the actual configuration of a AWS CloudFormation (CloudFormation) stack differs, or has drifted, from the expected configuration. A stack is considered to have drifted if one or more of its resources differ from their expected configuration. The rule and the stack are COMPLIANT when the stack drift status is IN_SYNC. The rule is NON_COMPLIANT if the stack drift status is DRIFTED.

cloudformation-stack-notification-check
Checks if your CloudFormation stacks send event notifications to an Amazon SNS topic. Optionally checks if specified Amazon SNS topics are used. The rule is NON_COMPLIANT if CloudFormation stacks do not send notifications.

cloudformation-stack-service-role-check
Checks if AWS CloudFormation stacks are using service roles. The rule is NON_COMPLIANT if a CloudFormation stack does not have service role associated with it.

cloudformation-termination-protection-check
Checks if an AWS CloudFormation stack has termination protection enabled. This rule is NON_COMPLIANT if termination protection is not enabled on a CloudFormation stack.

cloudfront-accesslogs-enabled
Checks if Amazon CloudFront distributions are configured to deliver access logs to an Amazon S3 bucket using standard logging (legacy). The rule is NON_COMPLIANT if a CloudFront distribution does not have legacy logging configured.

cloudfront-associated-with-waf
Checks if Amazon CloudFront distributions are associated with either web application firewall (WAF) or WAFv2 web access control lists (ACLs). The rule is NON_COMPLIANT if a CloudFront distribution is not associated with a WAF web ACL.

cloudfront-custom-ssl-certificate
Checks if the certificate associated with an Amazon CloudFront distribution is the default SSL certificate. The rule is NON_COMPLIANT if a CloudFront distribution uses the default SSL certificate.

cloudfront-default-root-object-configured
Checks if an Amazon CloudFront distribution is configured to return a specific object that is the default root object. The rule is NON_COMPLIANT if Amazon CloudFront distribution does not have a default root object configured.

cloudfront-distribution-key-group-enabled
Checks if Amazon CloudFront distributions are configured to use only trusted key groups for signed URL or signed cookie authentication for all cache behaviors. The rule is NON_COMPLIANT if any cache behavior in the distribution is using trusted signers.

cloudfront-no-deprecated-ssl-protocols
Checks if CloudFront distributions are using deprecated SSL protocols for HTTPS communication between CloudFront edge locations and custom origins. This rule is NON_COMPLIANT for a CloudFront distribution if any ‘OriginSslProtocols’ includes ‘SSLv3’.

cloudfront-origin-access-identity-enabled
Checks if CloudFront distribution with Amazon S3 Origin type has origin access identity configured. The rule is NON_COMPLIANT if the CloudFront distribution is backed by S3 and any origin type is not OAI configured, or the origin is not an S3 bucket.

cloudfront-origin-failover-enabled
Checks if an origin group is configured for the distribution of at least two origins in the origin group for Amazon CloudFront. The rule is NON_COMPLIANT if there are no origin groups for the distribution.

cloudfront-origin-lambda-url-oac-enabled
Checks if Amazon CloudFront distributions with Amazon Lambda Function URL origins have origin access control (OAC) enabled. The rule is NON_COMPLIANT if any Lambda Function URL origin in a CloudFront distribution does not have OAC enabled.

cloudfront-s3-origin-access-control-enabled
Checks if an Amazon CloudFront distribution with an Amazon Simple Storage Service (Amazon S3) Origin type has origin access control (OAC) enabled. The rule is NON_COMPLIANT for CloudFront distributions with Amazon S3 origins that don't have OAC enabled.

cloudfront-s3-origin-non-existent-bucket
Checks if Amazon CloudFront distributions point to a non-existent S3 bucket. The rule is NON_COMPLIANT if `S3OriginConfig` for a CloudFront distribution points to a non-existent S3 bucket. The rule does not evaluate S3 buckets with static website hosting.

cloudfront-security-policy-check
Checks if Amazon CloudFront distributions are using a minimum security policy and cipher suite of TLSv1.2 or greater for viewer connections. This rule is NON_COMPLIANT for a CloudFront distribution if the minimumProtocolVersion is below TLSv1.2_2018.

cloudfront-sni-enabled
Checks if Amazon CloudFront distributions are using a custom SSL certificate and are configured to use SNI to serve HTTPS requests. The rule is NON_COMPLIANT if a custom SSL certificate is associated but the SSL support method is a dedicated IP address.

cloudfront-ssl-policy-check
Checks if Amazon CloudFront distributions are configured with the specified security policies.The rule is NON_COMPLIANT if a CloudFront Distribution is not configured with security policies that you specify.

cloudfront-traffic-to-origin-encrypted
Checks if Amazon CloudFront distributions are encrypting traffic to custom origins. The rule is NON_COMPLIANT if ‘OriginProtocolPolicy’ is ‘http-only’ or if ‘OriginProtocolPolicy’ is ‘match-viewer’ and ‘ViewerProtocolPolicy’ is ‘allow-all’.

cloudfront-viewer-policy-https
Checks whether your Amazon CloudFront distributions use HTTPS (directly or via a redirection). The rule is NON_COMPLIANT if the value of ViewerProtocolPolicy is set to 'allow-all' for the defaultCacheBehavior or for the CacheBehaviors.

cloudtrail-all-read-s3-data-event-check
Checks if an AWS CloudTrail multi-Region trail is enabled and logs all read S3 data events for your buckets. The rule is NON_COMPLIANT if no multi-Region trail logs all read S3 data event types for all current and future S3 buckets.

cloudtrail-all-write-s3-data-event-check
Checks if an AWS CloudTrail multi-Region trail is enabled and logs all write S3 data events for your buckets. The rule is NON_COMPLIANT if no multi-Region trail logs all write S3 data event types for all current and future S3 buckets.

cloudtrail-s3-bucket-access-logging
Checks if the S3 bucket configurations for your AWS CloudTrail logs have Amazon S3 server access logging enabled. The rule is NON_COMPLIANT if at least one S3 bucket for a CloudTrail trail does not have S3 server access logging enabled.

cloudtrail-s3-bucket-public-access-prohibited
Checks if the S3 bucket configurations for your AWS CloudTrail logs block public access. The rule is NON_COMPLIANT if at least one S3 bucket for a CloudTrail trail is publicly accessible.

cloudtrail-s3-dataevents-enabled
Checks if at least one AWS CloudTrail trail is logging Amazon Simple Storage Service (Amazon S3) data events for all S3 buckets. The rule is NON_COMPLIANT if there are trails or if no trails record S3 data events.

cloudtrail-security-trail-enabled
Checks that there is at least one AWS CloudTrail trail defined with security best practices. This rule is COMPLIANT if there is at least one trail that meets all of the following:

cloudwatch-alarm-action-check
Checks if CloudWatch alarms have an action configured for the ALARM, INSUFFICIENT_DATA, or OK state. Optionally checks if any actions match a named ARN. The rule is NON_COMPLIANT if there is no action specified for the alarm or optional parameter.

cloudwatch-alarm-action-enabled-check
Checks if Amazon CloudWatch alarms actions are in enabled state. The rule is NON_COMPLIANT if the CloudWatch alarms actions are not in enabled state.

cloudwatch-alarm-resource-check
Checks if a resource type has a CloudWatch alarm for the named metric. For resource type, you can specify EBS volumes, EC2 instances, Amazon RDS clusters, or S3 buckets. The rule is COMPLIANT if the named metric has a resource ID and CloudWatch alarm.

cloudwatch-alarm-settings-check
Checks whether CloudWatch alarms with the given metric name have the specified settings.

cloudwatch-log-group-encrypted
Checks if Amazon CloudWatch Log Groups are encrypted with any AWS KMS key or a specified AWS KMS key Id. The rule is NON_COMPLIANT if a CloudWatch Log Group is not encrypted with a KMS key or is encrypted with a KMS key not supplied in the rule parameter.

cloudwatch-metric-stream-tagged
Checks if Amazon CloudWatch metric streams have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

cloud-trail-cloud-watch-logs-enabled
Checks if AWS CloudTrail trails are configured to send logs to CloudWatch logs. The trail is NON_COMPLIANT if the CloudWatchLogsLogGroupArn property of the trail is empty.

cloudtrail-enabled
Checks if an AWS CloudTrail trail is enabled in your AWS account. The rule is NON_COMPLIANT if a trail is not enabled. Optionally, the rule checks a specific S3 bucket, Amazon Simple Notification Service (Amazon SNS) topic, and CloudWatch log group.

cloud-trail-encryption-enabled
Checks if AWS CloudTrail is configured to use the server side encryption (SSE) AWS Key Management Service (AWS KMS) encryption. The rule is COMPLIANT if the KmsKeyId is defined.

cloud-trail-log-file-validation-enabled
Checks if AWS CloudTrail creates a signed digest file with logs. AWS recommends that the file validation must be enabled on all trails. The rule is NON_COMPLIANT if the validation is not enabled.

cmk-backing-key-rotation-enabled
Checks if automatic key rotation is enabled for each key and matches to the key ID of the customer created AWS KMS key. The rule is NON_COMPLIANT if the AWS Config recorder role for a resource does not have the kms:DescribeKey permission.

codebuild-project-artifact-encryption
Checks if an AWS CodeBuild project has encryption enabled for all of its artifacts. The rule is NON_COMPLIANT if 'encryptionDisabled' is set to 'true' for any primary or secondary (if present) artifact configurations.

codebuild-project-environment-privileged-check
Checks if an AWS CodeBuild project environment has privileged mode enabled. The rule is NON_COMPLIANT for a CodeBuild project if ‘privilegedMode’ is set to ‘true’.

codebuild-project-envvar-awscred-check
Checks if the project contains environment variables AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY. The rule is NON_COMPLIANT when the project environment variables contains plaintext credentials.

codebuild-project-logging-enabled
Checks if an AWS CodeBuild project environment has at least one log option enabled. The rule is NON_COMPLIANT if the status of all present log configurations is set to 'DISABLED'.

codebuild-project-s3-logs-encrypted
Checks if a AWS CodeBuild project configured with Amazon S3 Logs has encryption enabled for its logs. The rule is NON_COMPLIANT if ‘encryptionDisabled’ is set to ‘true’ in a S3LogsConfig of a CodeBuild project.

codebuild-project-source-repo-url-check
Checks if the Bitbucket source repository URL contains sign-in credentials or not. The rule is NON_COMPLIANT if the URL contains any sign-in information and COMPLIANT if it doesn't.

codebuild-report-group-encrypted-at-rest
Checks if an AWS CodeBuild report group has encryption at rest setting enabled. The rule is NON_COMPLIANT if 'EncryptionDisabled' is 'true'.

codebuild-report-group-tagged
Checks if AWS CodeBuild report groups have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

codedeploy-auto-rollback-monitor-enabled
Checks if the deployment group is configured with automatic deployment rollback and deployment monitoring with alarms attached. The rule is NON_COMPLIANT if AutoRollbackConfiguration or AlarmConfiguration has not been configured or is not enabled.

codedeploy-deployment-group-auto-rollback-enabled
Checks if AWS CodeDeploy deployment groups have auto rollback configuration enabled. The rule is NON_COMPLIANT if configuration.autoRollbackConfiguration.enabled is false or does not exist.

codedeploy-deployment-group-outdated-instances-update
Checks if AWS CodeDeploy deployment groups automatically update outdated instances. The rule is NON_COMPLIANT if configuration.outdatedInstancesStrategy is 'IGNORE'.

codedeploy-ec2-minimum-healthy-hosts-configured
Checks if the deployment group for EC2/On-Premises Compute Platform is configured with a minimum healthy hosts fleet percentage or host count greater than or equal to the input threshold. The rule is NON_COMPLIANT if either is below the threshold.

codedeploy-lambda-allatonce-traffic-shift-disabled
Checks if the deployment group for Lambda Compute Platform is not using the default deployment configuration. The rule is NON_COMPLIANT if the deployment group is using the deployment configuration 'CodeDeployDefault.LambdaAllAtOnce'.

codeguruprofiler-profiling-group-tagged
Checks if Amazon CodeGuru Profiler profiling groups have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

codegurureviewer-repository-association-tagged
Checks if Amazon CodeGuru Reviewer repository associations have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

codepipeline-deployment-count-check
Checks if the first deployment stage of AWS CodePipeline performs more than one deployment. Optionally checks if each of the subsequent remaining stages deploy to more than the specified number of deployments (deploymentLimit).

codepipeline-region-fanout-check
Checks if each stage in the AWS CodePipeline deploys to more than N times the number of the regions the AWS CodePipeline has deployed in all the previous combined stages, where N is the region fanout number. The first deployment stage can deploy to a maximum of one region and the second deployment stage can deploy to a maximum number specified in the regionFanoutFactor. If you do not provide a regionFanoutFactor, by default the value is three. For example: If 1st deployment stage deploys to one region and 2nd deployment stage deploys to three regions, 3rd deployment stage can deploy to 12 regions, that is, sum of previous stages multiplied by the region fanout (three) number. The rule is NON_COMPLIANT if the deployment is in more than one region in 1st stage or three regions in 2nd stage or 12 regions in 3rd stage.

cognito-identity-pool-unauthenticated-logins
Checks if Amazon Cognito identity pools disallow unauthenticated logins. The rule is NON_COMPLIANT if configuration.AllowUnauthenticatedIdentities is true.

cognito-identity-pool-unauth-access-check
Checks if Amazon Cognito Identity Pool allows unauthenticated identities. The rule is NON_COMPLIANT if the Identity Pool is configured to allow unauthenticated identities.

cognito-userpool-cust-auth-threat-full-check
Checks if Amazon Cognito user pools have threat protection enabled with full-function enforcement mode for custom authentication. This rule is NON_COMPLIANT if threat protection for custom authentication is not set to full-function enforcement mode.

cognito-user-pool-advanced-security-enabled
Checks if an Amazon Cognito user pool has advanced security enabled for standard authentication. The rule is NON_COMPLIANT if advanced security is not enabled. Optionally, you can specify an advanced security mode for the rule to check.

cognito-user-pool-deletion-protection-enabled
Checks whether Amazon Cognito user pools has deletion protection enabled. This rule is NON_COMPLIANT if a user pool has deletion protection disabled.

cognito-user-pool-mfa-enabled
Checks if Amazon Cognito user pools configured with a PASSWORD-only sign-in policy have Multi-Factor Authentication (MFA) enabled. This rule is NON_COMPLIANT if the Cognito user pool configured with PASSWORD only sign in policy does not have MFA enabled.

cognito-user-pool-password-policy-check
Checks if the password policy for Amazon cognito user pool meets the specified requirements indicated in the parameters. The rule is NON_COMPLIANT if the user pool password policy does not meet the specified requirements.

cognito-user-pool-tagged
Checks if Amazon Cognito user pools have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

connect-instance-logging-enabled
Checks if Amazon Connect instances have flow logs enabled in an Amazon CloudWatch log group. The rule is NON_COMPLIANT if an Amazon Connect instance does not have flow logs enabled.

customerprofiles-domain-tagged
Checks if Amazon Connect Customer Profiles domains have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

customerprofiles-object-type-allow-profile-creation
Checks if Amazon Connect Customer Profiles object types allow the creation of a new standard profile if one does not exist. The rule is NON_COMPLIANT if configuration.AllowProfileCreation is false.

customerprofiles-object-type-tagged
Checks if Amazon Connect Customer Profiles object types have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

custom-eventbus-policy-attached
Checks if Amazon EventBridge custom event buses have a resource-based policy attached. The rule is NON_COMPLIANT if a custom event bus policy does not have an attached resource-based policy.

custom-schema-registry-policy-attached
Checks if custom Amazon EventBridge schema registries have a resource policy attached. The rule is NON_COMPLIANT for custom schema registries without a resource policy attached.

cw-loggroup-retention-period-check
Checks if an Amazon CloudWatch LogGroup retention period is set to greater than 365 days or else a specified retention period. The rule is NON_COMPLIANT if the retention period is less than MinRetentionTime, if specified, or else 365 days.

datasync-location-object-storage-using-https
Checks if AWS DataSync location object storage servers use the HTTPS protocol to communicate. The rule is NON_COMPLIANT if configuration.ServerProtocol is not 'HTTPS'.

datasync-task-data-verification-enabled
Checks if AWS DataSync tasks have data verification enabled to perform additional verification at the end of your transfer. The rule is NON_COMPLIANT if configuration.Options.VerifyMode is 'NONE'.

datasync-task-logging-enabled
Checks if an AWS DataSync task has Amazon CloudWatch logging enabled. The rule is NON_COMPLIANT if an AWS DataSync task does not have Amazon CloudWatch logging enabled or if the logging level is not equivalent to the logging level that you specify.

datasync-task-tagged
Checks if AWS DataSync tasks have tags. Optionally, you can specify tag keys for the rule. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

dax-encryption-enabled
Checks if Amazon DynamoDB Accelerator (DAX) clusters are encrypted. The rule is NON_COMPLIANT if a DAX cluster is not encrypted.

dax-tls-endpoint-encryption
Checks if your Amazon DynamoDB Accelerator (DAX) cluster has ClusterEndpointEncryptionType set to TLS. The rule is NON_COMPLIANT if a DAX cluster is not encrypted by transport layer security (TLS).

db-instance-backup-enabled
Checks if RDS DB instances have backups enabled. Optionally, the rule checks the backup retention period and the backup window.

desired-instance-tenancy
Checks EC2 instances for a 'tenancy' value. Also checks if AMI IDs are specified to be launched from those AMIs or if Host IDs are launched on those Dedicated Hosts. The rule is COMPLIANT if the instance matches a host and an AMI, if specified, in a list.

desired-instance-type
Checks if your EC2 instances are of a specific instance type. The rule is NON_COMPLIANT if an EC2 instance is not specified in the parameter list. For a list of supported EC2 instance types, see Instance types in the EC2 User Guide for Linux Instances.

dms-auto-minor-version-upgrade-check
Checks if an AWS Database Migration Service (AWS DMS) replication instance has automatic minor version upgrades enabled. The rule is NON_COMPLIANT if an AWS DMS replication instance is not configured with automatic minor version upgrades.

dms-endpoint-ssl-configured
Checks if AWS Database Migration Service (AWS DMS) endpoints are configured with an SSL connection. The rule is NON_COMPLIANT if AWS DMS does not have an SSL connection configured.

dms-endpoint-tagged
Checks if AWS DMS endpoints have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

dms-mongo-db-authentication-enabled
Checks if AWS Database Migration Service (AWS DMS) endpoints for MongoDb data stores are enabled for password-based authentication and access control. The rule is NON_COMPLIANT if password-based authentication and access control is not enabled.

dms-neptune-iam-authorization-enabled
Checks if an AWS Database Migration Service (AWS DMS) endpoint for Amazon Neptune databases is configured with IAM authorization. The rule is NON_COMPLIANT if an AWS DMS endpoint where Neptune is the target has IamAuthEnabled set to false.

dms-redis-tls-enabled
Checks if AWS Database Migration Service (AWS DMS) endpoints for Redis data stores are enabled for TLS/SSL encryption of data communicated with other endpoints. The rule is NON_COMPLIANT if TLS/SSL encryption is not enabled.

dms-replication-instance-multi-az-enabled
Checks if AWS Database Migration Service (DMS) replication instances are configured with multiple Availability Zones. The rule is NON_COMPLIANT if a DMS replication instance is not configured to use multiple Availability Zones.

dms-replication-not-public
Checks if AWS Database Migration Service (AWS DMS) replication instances are public. The rule is NON_COMPLIANT if PubliclyAccessible field is set to true.

dms-replication-task-sourcedb-logging
Checks if logging is enabled with a valid severity level for AWS DMS replication tasks of a source database. The rule is NON_COMPLIANT if logging is not enabled or logs for DMS replication tasks of a source database have a severity level that is not valid.

dms-replication-task-tagged
Checks if AWS DMS replication tasks have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

dms-replication-task-targetdb-logging
Checks if logging is enabled with a valid severity level for AWS DMS replication task events of a target database. The rule is NON_COMPLIANT if logging is not enabled or replication task logging of a target database has a severity level that is not valid.

docdb-cluster-audit-logging-enabled
Checks if an Amazon DocumentDB (with MongoDB compatibility) instance cluster has CloudWatch log export enabled for audit logs. The rule is NON_COMPLIANT if an Amazon DocumentDB instance cluster does not have CloudWatch log export enabled for audit logs.

docdb-cluster-backup-retention-check
Checks if an Amazon Document DB cluster retention period is set to specific number of days. The rule is NON_COMPLIANT if the retention period is less than the value specified by the parameter.

docdb-cluster-deletion-protection-enabled
Checks if an Amazon DocumentDB (with MongoDB compatibility) cluster has deletion protection enabled. The rule is NON_COMPLIANT if an Amazon DocumentDB cluster has the deletionProtection field set to false.

docdb-cluster-encrypted
Checks if storage encryption is enabled for your Amazon DocumentDB (with MongoDB compatibility) clusters. The rule is NON_COMPLIANT if storage encryption is not enabled.

docdb-cluster-encrypted-in-transit
Checks if connections to Amazon DocumentDB clusters are configured to use encryption in transit. The rule is NON_COMPLIANT if the parameter group is not "in-sync", or the TLS parameter is set to either "disabled" or a value in excludeTlsParameters.

docdb-cluster-snapshot-public-prohibited
Checks if Amazon DocumentDB manual cluster snapshots are public. The rule is NON_COMPLIANT if any Amazon DocumentDB manual cluster snapshots are public.

dynamodb-autoscaling-enabled
Checks if Amazon DynamoDB tables or global secondary indexes can process read/write capacity using on-demand mode or provisioned mode with auto scaling enabled. The rule is NON_COMPLIANT if either mode is used without auto scaling enabled

dynamodb-in-backup-plan
Checks whether Amazon DynamoDB table is present in AWS Backup Plans. The rule is NON_COMPLIANT if Amazon DynamoDB tables are not present in any AWS Backup plan.

dynamodb-last-backup-recovery-point-created
Checks if a recovery point was created for Amazon DynamoDB Tables within the specified period. The rule is NON_COMPLIANT if the DynamoDB Table does not have a corresponding recovery point created within the specified time period.

dynamodb-meets-restore-time-target
Checks if the restore time of Amazon DynamoDB Tables meets the specified duration. The rule is NON_COMPLIANT if LatestRestoreExecutionTimeMinutes of a DynamoDB Table is greater than maxRestoreTime minutes.

dynamodb-pitr-enabled
Checks if point-in-time recovery (PITR) is enabled for Amazon DynamoDB tables. The rule is NON_COMPLIANT if PITR is not enabled for DynamoDB tables.

dynamodb-resources-protected-by-backup-plan
Checks if Amazon DynamoDB tables are protected by a backup plan. The rule is NON_COMPLIANT if the DynamoDB Table is not covered by a backup plan.

dynamodb-table-deletion-protection-enabled
Checks if an Amazon DynamoDB table have deletion protection set to enabled. The rule is NON_COMPLIANT if the table have deletion protection set to disabled.

dynamodb-table-encrypted-kms
Checks if Amazon DynamoDB table is encrypted with AWS Key Management Service (KMS). The rule is NON_COMPLIANT if Amazon DynamoDB table is not encrypted with AWS KMS. The rule is also NON_COMPLIANT if the encrypted AWS KMS key is not present in kmsKeyArns input parameter.

dynamodb-table-encryption-enabled
Checks if the Amazon DynamoDB tables are encrypted and checks their status. The rule is COMPLIANT if the status is enabled or enabling.

dynamodb-throughput-limit-check
Checks if provisioned DynamoDB throughput is approaching the maximum limit for your account. By default, the rule checks if provisioned throughput exceeds a threshold of 80 percent of your account limits.

ebs-in-backup-plan
Check if Amazon Elastic Block Store (Amazon EBS) volumes are added in backup plans of AWS Backup. The rule is NON_COMPLIANT if Amazon EBS volumes are not included in backup plans.

ebs-last-backup-recovery-point-created
Checks if a recovery point was created for Amazon Elastic Block Store (Amazon EBS). The rule is NON_COMPLIANT if the Amazon EBS volume does not have a corresponding recovery point created within the specified time period.

ebs-meets-restore-time-target
Checks if the restore time of Amazon Elastic Block Store (Amazon EBS) volumes meets the specified duration. The rule is NON_COMPLIANT if LatestRestoreExecutionTimeMinutes of an Amazon EBS volume is greater than maxRestoreTime minutes.

ebs-optimized-instance
Checks if Amazon EBS optimization is enabled for your Amazon Elastic Compute Cloud (Amazon EC2) instances that can be Amazon EBS-optimized. The rule is NON_COMPLIANT if EBS optimization is not enabled for an Amazon EC2 instance that can be EBS-optimized.

ebs-resources-in-logically-air-gapped-vault
Checks if Amazon Elastic Block Store (Amazon EBS) volumes are in a logically air-gapped vault. The rule is NON_COMPLIANT if an Amazon EBS volume is not in a logically air-gapped vault within the specified time period.

ebs-resources-protected-by-backup-plan
Checks if Amazon Elastic Block Store (Amazon EBS) volumes are protected by a backup plan. The rule is NON_COMPLIANT if the Amazon EBS volume is not covered by a backup plan.

ebs-snapshot-block-public-access
Checks if block public access is enabled for Amazon EBS snapshots in an AWS Region. The rule is NON_COMPLIANT if block public access is not enabled for all public sharing of EBS snapshots in an AWS Region.

ebs-snapshot-public-restorable-check
Checks if Amazon Elastic Block Store (Amazon EBS) snapshots are not publicly restorable. The rule is NON_COMPLIANT if one or more snapshots with RestorableByUserIds field are set to all, that is, Amazon EBS snapshots are public.

ec2-capacity-reservation-tagged
Checks if Amazon EC2 capacity reservations have tags. Optionally, you can specify tag keys for the rule. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

ec2-carrier-gateway-tagged
Checks if Amazon EC2 carrier gateways have tags. Optionally, you can specify tag keys for the rule. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

ec2-client-vpn-connection-log-enabled
Checks if AWS Client VPN endpoint has client connection logging enabled. The rule is NON_COMPLIANT if 'Configuration.ConnectionLogOptions.Enabled' is set to false.

ec2-client-vpn-endpoint-tagged
Checks if Amazon EC2 client VPN endpoints have tags. Optionally, you can specify tag keys for the rule. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

ec2-client-vpn-not-authorize-all
Checks if the AWS Client VPN authorization rules authorizes connection access for all clients. The rule is NON_COMPLIANT if 'AccessAll' is present and set to true.

ec2-dhcp-options-tagged
Checks if Amazon EC2 DHCP options have tags. Optionally, you can specify tag keys for the rule. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

ec2-ebs-encryption-by-default
Checks if Amazon Elastic Block Store (EBS) encryption is enabled by default. The rule is NON_COMPLIANT if the encryption is not enabled.

ec2-enis-source-destination-check-enabled
Checks if EC2 ENIs managed by users have source/destination check enabled. The rule is NON_COMPLIANT if source/destination check is disabled on these ENIs for 'lambda', 'aws_codestar_connections_managed', 'branch', 'efa', 'interface', and 'quicksight'.

ec2-fleet-tagged
Checks if Amazon EC2 fleets have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

ec2-imdsv2-check
Checks whether your Amazon Elastic Compute Cloud (Amazon EC2) instance metadata version is configured with Instance Metadata Service Version 2 (IMDSv2). The rule is NON_COMPLIANT if the HttpTokens is set to optional.

ec2-instance-detailed-monitoring-enabled
Checks if detailed monitoring is enabled for EC2 instances. The rule is NON_COMPLIANT if detailed monitoring is not enabled.

ec2-instance-launched-with-allowed-ami
Checks if running or stopped EC2 instances were launched with Amazon Machine Images (AMIs) that meet your Allowed AMIs criteria. The rule is NON_COMPLIANT if an AMI doesn't meet the Allowed AMIs criteria and the Allowed AMIs settings isn't disabled.

ec2-instance-managed-by-systems-manager
Checks if your Amazon EC2 instances are managed by AWS Systems Manager Agent (SSM Agent). The rule is NON_COMPLIANT if an EC2 instance is running and the SSM Agent is stopped, or if an EC2 instance is running and the SSM Agent is terminated.

ec2-instance-multiple-eni-check
Checks if Amazon Elastic Compute Cloud (Amazon EC2) uses multiple Elastic Network Interfaces (ENIs) or Elastic Fabric Adapters (EFAs). The rule is NON_COMPLIANT an Amazon EC2 instance use multiple network interfaces.

ec2-instance-no-public-ip
Checks whether Amazon Elastic Compute Cloud (Amazon EC2) instances have a public IP association. The rule is NON_COMPLIANT if the publicIp field is present in the Amazon EC2 instance configuration item. This rule applies only to IPv4.

ec2-instance-profile-attached
Checks if an EC2 instance has an AWS Identity and Access Management (IAM) profile attached to it. The rule is NON_COMPLIANT if no IAM profile is attached to the EC2 instance.

ec2-last-backup-recovery-point-created
Checks if a recovery point was created for Amazon Elastic Compute Cloud (Amazon EC2) instances. The rule is NON_COMPLIANT if the Amazon EC2 instance does not have a corresponding recovery point created within the specified time period.

ec2-launch-templates-ebs-volume-encrypted
Checks whether Amazon EC2 launch templates have encryption enabled for all attached EBS volumes.The rule is NON_COMPLIANT if encryption is set to False for any EBS volume configured in the launch template.

ec2-launch-template-imdsv2-check
Checks if the currently set default version of an Amazon EC2 Launch Template requires new launched instances to use V2 of the Amazon EC2 Instance Metadata Service (IMDSv2). The rule is NON_COMPLIANT if 'Metadata version' is not specified as V2 (IMDSv2).

ec2-launch-template-public-ip-disabled
Checks if Amazon EC2 Launch Templates are set to assign public IP addresses to Network Interfaces. The rule is NON_COMPLIANT if the default version of an EC2 Launch Template has at least 1 Network Interface with 'AssociatePublicIpAddress' set to 'true'.

ec2-launch-template-tagged
Checks if Amazon EC2 launch templates have tags. Optionally, you can specify tag keys for the rule. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

ec2-managedinstance-applications-blacklisted
Checks if none of the specified applications are installed on the instance. Optionally, specify the version. Newer versions will not be denylisted. Optionally, specify the platform to apply the rule only to instances running that platform.

ec2-managedinstance-applications-required
Checks if all of the specified applications are installed on the instance. Optionally, specify the minimum acceptable version. You can also specify the platform to apply the rule only to instances running that platform.

ec2-managedinstance-association-compliance-status-check
Checks if the status of the AWS Systems Manager association compliance is COMPLIANT or NON_COMPLIANT after the association execution on the instance. The rule is compliant if the field status is COMPLIANT. For more information about associations, see What is an association?.

ec2-managedinstance-inventory-blacklisted
Checks whether instances managed by Amazon EC2 Systems Manager are configured to collect blacklisted inventory types.

ec2-managedinstance-patch-compliance-status-check
Checks if the compliance status of the AWS Systems Manager patch compliance is COMPLIANT or NON_COMPLIANT after the patch installation on the instance. The rule is compliant if the field status is COMPLIANT.

ec2-managedinstance-platform-check
Checks whether EC2 managed instances have the desired configurations.

ec2-meets-restore-time-target
Checks if the restore time of Amazon Elastic Compute Cloud (Amazon EC2) instances meets the specified duration. The rule is NON_COMPLIANT if LatestRestoreExecutionTimeMinutes of an Amazon EC2 instance is greater than maxRestoreTime minutes.

ec2-network-insights-access-scope-analysis-tagged
Checks if Amazon EC2 network insights access scope analyses have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

ec2-network-insights-access-scope-tagged
Checks if Amazon EC2 network insights access scopes have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

ec2-network-insights-analysis-tagged
Checks if Amazon EC2 network insights analyses have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

ec2-network-insights-path-tagged
Checks if Amazon EC2 network insights paths have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

ec2-no-amazon-key-pair
Checks if running Amazon Elastic Compute Cloud (EC2) instances are launched using amazon key pairs. The rule is NON_COMPLIANT if a running EC2 instance is launched with a key pair.

ec2-paravirtual-instance-check
Checks if the virtualization type of an EC2 instance is paravirtual. This rule is NON_COMPLIANT for an EC2 instance if 'virtualizationType' is set to 'paravirtual'.

ec2-prefix-list-tagged
Checks if Amazon EC2 managed prefix lists have tags. Optionally, you can specify tag keys for the rule. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

ec2-resources-in-logically-air-gapped-vault
Checks if Amazon Elastic Compute Cloud (Amazon EC2) instances are in a logically air-gapped vault. The rule is NON_COMPLIANT if an Amazon EC2 instance is not in a logically air-gapped vault within the specified time period.

ec2-resources-protected-by-backup-plan
Checks if Amazon Elastic Compute Cloud (Amazon EC2) instances are protected by a backup plan. The rule is NON_COMPLIANT if the Amazon EC2 instance is not covered by a backup plan.

ec2-security-group-attached-to-eni
Checks that non-default security groups are attached to Amazon Elastic Compute Cloud (EC2) instances or an elastic network interfaces (ENIs). The rule returns NON_COMPLIANT if the security group is not associated with an EC2 instance or an ENI.

ec2-security-group-attached-to-eni-periodic
Checks if non-default security groups are attached to Elastic network interfaces (ENIs). The rule is NON_COMPLIANT if the security group is not associated with an ENI. Security groups not owned by the calling account evaluate as NOT_APPLICABLE.

ec2-spot-fleet-request-ct-encryption-at-rest
Checks if Amazon EC2 Spot Fleet request launch parameters set encrypted to True for attached EBS volumes. The rule is NON_COMPLIANT if any EBS volumes has encrypted set to False. The rule does not evaluate spot fleet requests using launch templates.

ec2-stopped-instance
Checks if there are Amazon Elastic Compute Cloud (Amazon EC2) instances stopped for more than the allowed number of days. The rule is NON_COMPLIANT if the state of an Amazon EC2 instance has been stopped for longer than the allowed number of days, or if the amount of time cannot be determined.

ec2-token-hop-limit-check
Checks if an Amazon Elastic Compute Cloud (EC2) instance metadata has a specified token hop limit that is below the desired limit. The rule is NON_COMPLIANT for an instance if it has a hop limit value above the intended limit.

ec2-traffic-mirror-filter-description
Checks if Amazon EC2 traffic mirror filters have a description. The rule is NON_COMPLIANT if configuration.Description does not exist.

ec2-traffic-mirror-filter-tagged
Checks if Amazon EC2 traffic mirror filters have tags. Optionally, you can specify tag keys for the rule. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

ec2-traffic-mirror-session-description
Checks if Amazon EC2 traffic mirror sessions have a description. The rule is NON_COMPLIANT if configuration.Description does not exist.

ec2-traffic-mirror-session-tagged
Checks if Amazon EC2 traffic mirror sessions have tags. Optionally, you can specify tag keys for the rule. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

ec2-traffic-mirror-target-description
Checks if Amazon EC2 traffic mirror targets have a description. The rule is NON_COMPLIANT if configuration.Description does not exist.

ec2-traffic-mirror-target-tagged
Checks if Amazon EC2 traffic mirror targets have tags. Optionally, you can specify tag keys for the rule. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

ec2-transit-gateway-auto-vpc-attach-disabled
Checks if Amazon Elastic Compute Cloud (Amazon EC2) Transit Gateways have 'AutoAcceptSharedAttachments' enabled. The rule is NON_COMPLIANT for a Transit Gateway if 'AutoAcceptSharedAttachments' is set to 'enable'.

ec2-transit-gateway-multicast-domain-tagged
Checks if Amazon EC2 transit gateway multicast domains have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

ec2-volume-inuse-check
Checks if EBS volumes are attached to EC2 instances. Optionally checks if EBS volumes are marked for deletion when an instance is terminated.

ec2-vpn-connection-logging-enabled
Checks if AWS Site-to-Site VPN connections have Amazon CloudWatch logging enabled for both tunnels. The rule is NON_COMPLIANT if a Site-to-Site VPN connection does not have CloudWatch logging enabled for either or both tunnels.

ec2-vpn-connection-tagged
Checks if Amazon EC2 VPN connections have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

ecr-private-image-scanning-enabled
Checks if a private Amazon Elastic Container Registry (Amazon ECR) repository has image scanning enabled. The rule is NON_COMPLIANT if the private Amazon ECR repository's scan frequency is not on scan on push or continuous scan. For more information on enabling image scanning, see Image scanning in the Amazon ECR User Guide.

ecr-private-lifecycle-policy-configured
Checks if a private Amazon Elastic Container Registry (ECR) repository has at least one lifecycle policy configured. The rule is NON_COMPLIANT if no lifecycle policy is configured for the ECR private repository.

ecr-private-tag-immutability-enabled
Checks if a private Amazon Elastic Container Registry (ECR) repository has tag immutability enabled. This rule is NON_COMPLIANT if tag immutability is not enabled for the private ECR repository.

ecr-repository-cmk-encryption-enabled
Checks if ECR repository is encrypted at rest using customer-managed KMS key. This rule is NON_COMPLIANT if the repository is encrypted using AES256 or the default KMS key ('aws/ecr').

ecr-repository-tagged
Checks if Amazon ECR repositories have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

ecs-awsvpc-networking-enabled
Checks if the networking mode for active ECSTaskDefinitions is set to ‘awsvpc’. This rule is NON_COMPLIANT if active ECSTaskDefinitions is not set to ‘awsvpc’.

ecs-capacity-provider-tagged
Checks if Amazon ECS capacity providers have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

ecs-capacity-provider-termination-check
Checks if an Amazon ECS Capacity provider containing Auto Scaling groups has managed termination protection enabled. This rule is NON_COMPLIANT if managed termination protection is disabled on the ECS Capacity Provider.

ecs-containers-nonprivileged
Checks if the privileged parameter in the container definition of ECSTaskDefinitions is set to ‘true’. The rule is NON_COMPLIANT if the privileged parameter is ‘true’.

ecs-containers-readonly-access
Checks if Amazon Elastic Container Service (Amazon ECS) Containers only have read-only access to its root filesystems. The rule is NON_COMPLIANT if the readonlyRootFilesystem parameter in the container definition of ECSTaskDefinitions is set to ‘false’.

ecs-container-insights-enabled
Checks if Amazon Elastic Container Service clusters have container insights enabled. The rule is NON_COMPLIANT if container insights are not enabled.

ecs-fargate-latest-platform-version
Checks if ECS Fargate services is set to the latest platform version. The rule is NON_COMPLIANT if PlatformVersion for the Fargate launch type is not set to LATEST, or if neither latestLinuxVersion nor latestWindowsVersion are provided as parameters.

ecs-no-environment-secrets
Checks if secrets are passed as container environment variables. The rule is NON_COMPLIANT if 1 or more environment variable key matches a key listed in the 'secretKeys' parameter (excluding environmental variables from other locations such as Amazon S3).

ecs-task-definition-efs-encryption-enabled
Checks if Amazon ECS Task Definitions with EFS volumes have in-transit encryption enabled. The rule is NON_COMPLIANT if an ECS Task Definition contains an EFS volume without transit encryption enabled.

ecs-task-definition-linux-user-non-root
Checks if the latest active revision of an Amazon ECS task definition configures Linux containers to run as non-root users.The rule is NON_COMPLIANT if root user is specified or user configuration is absent for any container.

ecs-task-definition-log-configuration
Checks if logConfiguration is set on active ECS Task Definitions. This rule is NON_COMPLIANT if an active ECSTaskDefinition does not have the logConfiguration resource defined or the value for logConfiguration is null in at least one container definition.

ecs-task-definition-memory-hard-limit
Checks if Amazon Elastic Container Service (ECS) task definitions have a set memory limit for its container definitions. The rule is NON_COMPLIANT for a task definition if the ‘memory’ parameter is absent for one container definition.

ecs-task-definition-network-mode-not-host
Checks if the latest active revision of Amazon ECS task definitions use host network mode. The rule is NON_COMPLIANT if the latest active revision of the ECS task definition uses host network mode.

ecs-task-definition-nonroot-user
Checks if ECSTaskDefinitions specify a user for Amazon Elastic Container Service (Amazon ECS) EC2 launch type containers to run on. The rule is NON_COMPLIANT if the ‘user’ parameter is not present or set to ‘root’.

ecs-task-definition-pid-mode-check
Checks if ECSTaskDefinitions are configured to share a host’s process namespace with its Amazon Elastic Container Service (Amazon ECS) containers. The rule is NON_COMPLIANT if the pidMode parameter is set to ‘host’.

ecs-task-definition-user-for-host-mode-check
Checks if Amazon ECS task definitions with host network mode have privileged OR nonroot in the container definition. The rule is NON_COMPLIANT if the latest active revision of a task definition has privileged=false (or is null) AND user=root (or is null).

ecs-task-definition-windows-user-non-admin
Checks if the latest active revision of an Amazon ECS task definition configures Windows containers to run as non-administrator users. The rule is NON_COMPLIANT if default administrator user is specified or user configuration is absent for any container.

efs-access-point-enforce-root-directory
Checks if Amazon Elastic File System (Amazon EFS) access points are configured to enforce a root directory. The rule is NON_COMPLIANT if the value of 'Path' is set to '/' (default root directory of the file system).

efs-access-point-enforce-user-identity
Checks if Amazon Elastic File System (Amazon EFS) access points are configured to enforce a user identity. The rule is NON_COMPLIANT if 'PosixUser' is not defined or if parameters are provided and there is no match in the corresponding parameter.

efs-automatic-backups-enabled
Checks if an Amazon Elastic File System (Amazon EFS) file system has automatic backups enabled. The rule is NON_COMPLIANT if `BackupPolicy.Status` is set to DISABLED.

efs-encrypted-check
Checks if Amazon Elastic File System (Amazon EFS) is configured to encrypt the file data using AWS Key Management Service (AWS KMS). The rule is NON_COMPLIANT if the encrypted key is set to false on DescribeFileSystems or if the KmsKeyId key on DescribeFileSystems does not match the KmsKeyId parameter.

efs-filesystem-ct-encrypted
Checks if Amazon Elastic File System (Amazon EFS) encrypts data with AWS Key Management Service (AWS KMS). The rule is NON_COMPLIANT if a file system is not encrypted. Optionally, you can check if a file system is not encrypted with specified KMS keys.

efs-file-system-tagged
Checks if Amazon Elastic File System file systems have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

efs-in-backup-plan
Checks if Amazon Elastic File System (Amazon EFS) file systems are added in the backup plans of AWS Backup. The rule is NON_COMPLIANT if EFS file systems are not included in the backup plans.

efs-last-backup-recovery-point-created
Checks if a recovery point was created for Amazon Elastic File System (Amazon EFS) File Systems. The rule is NON_COMPLIANT if the Amazon EFS File System does not have a corresponding Recovery Point created within the specified time period.

efs-meets-restore-time-target
Checks if the restore time of Amazon Elastic File System (Amazon EFS) File Systems meets the specified duration. The rule is NON_COMPLIANT if LatestRestoreExecutionTimeMinutes of an Amazon EFS File System is greater than maxRestoreTime minutes.

efs-mount-target-public-accessible
Checks if an Amazon Elastic File System (Amazon EFS) is associated with subnets that assign public IP addresses on launch. The rule is NON_COMPLIANT if the Amazon EFS mount target is associated with subnets that assign public IP addresses on launch.

efs-resources-in-logically-air-gapped-vault
Checks if Amazon Elastic File System (Amazon EFS) File Systems are in a logically air-gapped vault. The rule is NON_COMPLIANT if an Amazon EFS File System is not in a logically air-gapped vault within the specified time period.

efs-resources-protected-by-backup-plan
Checks if Amazon Elastic File System (Amazon EFS) File Systems are protected by a backup plan. The rule is NON_COMPLIANT if the EFS File System is not covered by a backup plan.

eip-attached
Checks if all Elastic IP addresses that are allocated to an AWS account are attached to EC2 instances or in-use elastic network interfaces. The rule is NON_COMPLIANT if the 'AssociationId' is null for the Elastic IP address.

eks-addon-tagged
Checks if Amazon EKS add-ons have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

eks-cluster-logging-enabled
Checks if an Amazon Elastic Kubernetes Service (Amazon EKS) cluster is configured with logging enabled. The rule is NON_COMPLIANT if logging for Amazon EKS clusters is not enabled for all log types.

eks-cluster-log-enabled
Checks if an Amazon Elastic Kubernetes Service (Amazon EKS) cluster is configured with logging enabled. The rule is NON_COMPLIANT if logging for Amazon EKS clusters is not enabled or if logging is not enabled with the log type mentioned.

eks-cluster-oldest-supported-version
Checks if an Amazon Elastic Kubernetes Service (EKS) cluster is running the oldest supported version. The rule is NON_COMPLIANT if an EKS cluster is running oldest supported version (equal to the parameter 'oldestVersionSupported').

eks-cluster-secrets-encrypted
Checks if Amazon EKS clusters are configured to have Kubernetes secrets encrypted using AWS KMS. The rule is NON_COMPLIANT if an EKS cluster does not have an encryptionConfig resource or if encryptionConfig does not name secrets as a resource.

eks-cluster-supported-version
Checks if an Amazon Elastic Kubernetes Service (EKS) cluster is running a supported Kubernetes version. This rule is NON_COMPLIANT if an EKS cluster is running an unsupported version (less than the parameter 'oldestVersionSupported').

eks-endpoint-no-public-access
Checks if the Amazon Elastic Kubernetes Service (Amazon EKS) endpoint is not publicly accessible. The rule is NON_COMPLIANT if the endpoint is publicly accessible.

eks-fargate-profile-tagged
Checks if Amazon EKS fargate profiles have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

eks-secrets-encrypted
Checks if Amazon Elastic Kubernetes Service clusters are configured to have Kubernetes secrets encrypted using AWS Key Management Service (KMS) keys.

elasticache-automatic-backup-check-enabled
Checks if Amazon ElastiCache clusters (Valkey or Redis OSS) have automatic backup turned on. The rule is NON_COMPLIANT if automated backup is not enabled or the SnapshotRetentionLimit for a cluster is less than the specified snapshotRetentionPeriod.

elasticache-auto-minor-version-upgrade-check
Checks if Amazon ElastiCache clusters have auto minor version upgrades enabled. The rule is NON_COMPLIANT for an ElastiCache cluster if it is using the Redis or Valkey engine and 'AutoMinorVersionUpgrade' is not set to 'true'.

elasticache-rbac-auth-enabled
Checks if Amazon ElastiCache replication groups have RBAC authentication enabled. The rule is NON_COMPLIANT if the Redis version is 6 or above and ‘UserGroupIds’ is missing, empty, or does not match an entry provided by the 'allowedUserGroupIDs' parameter.

elasticache-redis-cluster-automatic-backup-check
Check if the Amazon ElastiCache Redis clusters have automatic backup turned on. The rule is NON_COMPLIANT if the SnapshotRetentionLimit for Redis cluster is less than the SnapshotRetentionPeriod parameter. For example: If the parameter is 15 then the rule is non-compliant if the snapshotRetentionPeriod is between 0-15.

elasticache-repl-grp-auto-failover-enabled
Checks if Amazon ElastiCache Redis replication groups have automatic failover enabled. The rule is NON_COMPLIANT for an ElastiCache replication group if ‘AutomaticFailover’ is not set to ‘enabled’.

elasticache-repl-grp-encrypted-at-rest
Checks if Amazon ElastiCache replication groups have encryption-at-rest enabled. The rule is NON_COMPLIANT for an ElastiCache replication group if 'AtRestEncryptionEnabled' is disabled or if the KMS key ARN does not match the approvedKMSKeyArns parameter.

elasticache-repl-grp-encrypted-in-transit
Checks if Amazon ElastiCache replication groups have encryption-in-transit enabled. The rule is NON_COMPLIANT for an ElastiCache replication group if ‘TransitEncryptionEnabled’ is set to ‘false’.

elasticache-repl-grp-redis-auth-enabled
Checks if Amazon ElastiCache replication groups have Redis AUTH enabled. The rule is NON_COMPLIANT for an ElastiCache replication group if the Redis version of its nodes is below 6 (Version 6+ use Redis ACLs) and ‘AuthToken’ is missing or is empty/null.

elasticache-subnet-group-check
Checks if Amazon ElastiCache clusters are configured with a custom subnet group. The rule is NON_COMPLIANT for an ElastiCache cluster if it is using a default subnet group.

elasticache-supported-engine-version
Checks if ElastiCache clusters are running a version greater or equal to the recommended engine version. The rule is NON_COMPLIANT if the 'EngineVersion' for an ElastiCache cluster is less than the specified recommended version for its given engine.

elasticbeanstalk-application-description
Checks if AWS Elastic Beanstalk applications have a description. The rule is NON_COMPLIANT if configuration.description does not exist or is an empty string.

elasticbeanstalk-application-version-description
Checks if AWS Elastic Beanstalk application versions have a description. The rule is NON_COMPLIANT if configuration.description does not exist or is an empty string.

elasticbeanstalk-environment-description
Checks if AWS Elastic Beanstalk environments have a description. The rule is NON_COMPLIANT if configuration.description does not exist or is an empty string.

elasticsearch-encrypted-at-rest
Checks if Amazon OpenSearch Service (previously called Elasticsearch) domains have encryption at rest configuration enabled. The rule is NON_COMPLIANT if the EncryptionAtRestOptions field is not enabled.

elasticsearch-in-vpc-only
Checks if Amazon OpenSearch Service (previously called Elasticsearch) domains are in Amazon Virtual Private Cloud (Amazon VPC). The rule is NON_COMPLIANT if an OpenSearch Service domain endpoint is public.

elasticsearch-logs-to-cloudwatch
Checks if OpenSearch Service (previously called Elasticsearch) domains are configured to send logs to CloudWatch Logs. The rule is COMPLIANT if a log is enabled for an OpenSearch Service domain. The rule is NON_COMPLIANT if logging is not configured.

elasticsearch-node-to-node-encryption-check
Check that Amazon OpenSearch Service nodes are encrypted end to end. The rule is NON_COMPLIANT if the node-to-node encryption is disabled on the domain.

elastic-beanstalk-logs-to-cloudwatch
Checks if AWS Elastic Beanstalk environments are configured to send logs to Amazon CloudWatch Logs. The rule is NON_COMPLIANT if the value of `StreamLogs` is false.

elastic-beanstalk-managed-updates-enabled
Checks if managed platform updates in an AWS Elastic Beanstalk environment is enabled. The rule is COMPLIANT if the value for ManagedActionsEnabled is set to true. The rule is NON_COMPLIANT if the value for ManagedActionsEnabled is set to false, or if a parameter is provided and its value does not match the existing configurations.

elbv2-acm-certificate-required
Checks if Application Load Balancers and Network Load Balancers have listeners that are configured to use certificates from AWS Certificate Manager (ACM). This rule is NON_COMPLIANT if at least 1 load balancer has at least 1 listener that is configured without a certificate from ACM or is configured with a certificate different from an ACM certificate.

elbv2-listener-encryption-in-transit
Checks if listeners for the load balancers are configured with HTTPS or TLS termination. The rule is NON_COMPLIANT if listeners are not configured with HTTPS or TLS termination.

elbv2-multiple-az
Checks if an Elastic Load Balancer V2 (Application, Network, or Gateway Load Balancer) is mapped to multiple Availability Zones (AZs). The rule is NON_COMPLIANT if an Elastic Load Balancer V2 is mapped to less than 2 AZs. For more information, see Availability Zones for your Application Load Balancer.

elbv2-predefined-security-policy-ssl-check
Checks if listeners for Application Load Balancers (ALBs) or Network Load Balancers (NLBs) use certain security policies. The rule is NON_COMPLIANT if an HTTPS listener for an ALB or a TLS listener for a NLB does not use the security policies you specify.

elb-acm-certificate-required
Checks if the Classic Load Balancers use SSL certificates provided by AWS Certificate Manager. To use this rule, use an SSL or HTTPS listener with your Classic Load Balancer. This rule is only applicable to Classic Load Balancers. This rule does not check Application Load Balancers and Network Load Balancers.

elb-cross-zone-load-balancing-enabled
Checks if cross-zone load balancing is enabled for Classic Load Balancers. The rule is NON_COMPLIANT if cross-zone load balancing is not enabled for Classic Load Balancers.

elb-custom-security-policy-ssl-check
Checks whether your Classic Load Balancer SSL listeners are using a custom policy. The rule is only applicable if there are SSL listeners for the Classic Load Balancer.

elb-deletion-protection-enabled
Checks whether an Elastic Load Balancer has deletion protection enabled. The rule is NON_COMPLIANT if deletion_protection.enabled is false.

elb-internal-scheme-check
Checks if a Classic Load Balancer scheme is internal. The rule is NON_COMPLIANT if configuration.scheme is not set to internal.

elb-logging-enabled
Checks if the Application Load Balancer and the Classic Load Balancer have logging enabled. The rule is NON_COMPLIANT if the access_logs.s3.enabled is false or access_logs.S3.bucket is not equal to the s3BucketName that you provided.

elb-predefined-security-policy-ssl-check
Checks if your Classic Load Balancer SSL listeners use a predefined policy. The rule is NON_COMPLIANT if the Classic Load Balancer HTTPS/SSL listener's policy does not equal the value of the parameter 'predefinedPolicyName'.

elb-tagged
Checks if Classic Load Balancers have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

elb-tls-https-listeners-only
Checks if your Classic Load Balancer is configured with SSL or HTTPS listeners. The rule is NON_COMPLIANT if a listener is not configured with SSL or HTTPS.

emr-block-public-access
Checks if an account with Amazon EMR has block public access settings enabled. The rule is NON_COMPLIANT if BlockPublicSecurityGroupRules is false, or if true, ports other than Port 22 are listed in PermittedPublicSecurityGroupRuleRanges.

emr-kerberos-enabled
Checks if Amazon EMR clusters have Kerberos enabled. The rule is NON_COMPLIANT if a security configuration is not attached to the cluster or the security configuration does not satisfy the specified rule parameters.

emr-master-no-public-ip
Checks if Amazon EMR clusters' master nodes have public IPs. The rule is NON_COMPLIANT if the master node has a public IP.

emr-security-configuration-encryption-rest
Checks if an Amazon EMR security configuration has encryption at rest enabled. The rule is NON_COMPLIANT if configuration.SecurityConfiguration.EncryptionConfiguration.EnableAtRestEncryption is false.

emr-security-configuration-encryption-transit
Checks if an Amazon EMR security configuration has encryption in transit enabled. The rule is NON_COMPLIANT if configuration.SecurityConfiguration.EncryptionConfiguration.EnableInTransitEncryption is false.

encrypted-volumes
Checks if attached Amazon EBS volumes are encrypted and optionally are encrypted with a specified KMS key. The rule is NON_COMPLIANT if attached EBS volumes are unencrypted or are encrypted with a KMS key not in the supplied parameters.

event-data-store-cmk-encryption-enabled
Checks if AWS Cloud Trail event data stores have customer managed AWS KMS keys enabled. The rule is NON_COMPLIANT if an event data store has disabled customer managed KMS keys. Optionally, you can specify a list of KMS keys for the rule to check.

evidently-launch-description
Checks if Amazon CloudWatch Evidently launches have a description. The rule is NON_COMPLIANT if configuration.Description does not exist or is an empty string.

evidently-launch-tagged
Checks if Amazon CloudWatch Evidently launches have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

evidently-project-description
Checks if Amazon CloudWatch Evidently projects have a description. The rule is NON_COMPLIANT if configuration.Description does not exist or is an empty string.

evidently-project-tagged
Checks if Amazon CloudWatch Evidently projects have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

evidently-segment-description
Checks if Amazon CloudWatch Evidently segments have a description. The rule is NON_COMPLIANT if configuration.Description does not exist or is an empty string.

evidently-segment-tagged
Checks if Amazon CloudWatch Evidently segments have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

fis-experiment-template-log-configuration-exists
Checks if AWS FIS experiment templates have experiment logging configured. The rule is NON_COMPLIANT if configuration.LogConfiguration does not exist.

fis-experiment-template-tagged
Checks if AWS FIS experiment templates have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

fms-shield-resource-policy-check
Checks if resources that AWS Shield Advanced can protect are protected by Shield Advanced. The rule is NON_COMPLIANT if a specified resource is not protected.

fms-webacl-resource-policy-check
Checks if the web ACL is associated with an Application Load Balancer, API Gateway stage, or Amazon CloudFront distributions. When AWS Firewall Manager creates this rule, the FMS policy owner specifies the WebACLId in the FMS policy and can optionally enable remediation.

fms-webacl-rulegroup-association-check
Checks if the rule groups associate with the web ACL at the correct priority. The correct priority is decided by the rank of the rule groups in the ruleGroups parameter. When AWS Firewall Manager creates this rule, it assigns the highest priority 0 followed by 1, 2, and so on. The FMS policy owner specifies the ruleGroups rank in the FMS policy and can optionally enable remediation.

frauddetector-entity-type-tagged
Checks if Amazon Fraud Detector entity types have tags. Optionally, you can specify tag keys for the rule. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

frauddetector-label-tagged
Checks if Amazon Fraud Detector labels have tags. Optionally, you can specify tag keys for the rule. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

frauddetector-outcome-tagged
Checks if Amazon Fraud Detector outcomes have tags. Optionally, you can specify tag keys for the rule. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

frauddetector-variable-tagged
Checks if Amazon Fraud Detector variables have tags. Optionally, you can specify tag keys for the rule. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

fsx-last-backup-recovery-point-created
Checks if a recovery point was created for Amazon FSx File Systems. The rule is NON_COMPLIANT if the Amazon FSx File System does not have a corresponding recovery point created within the specified time period.

fsx-lustre-copy-tags-to-backups
Checks if the Amazon FSx for Lustre file systems are configured to copy tags to backups. The rule is NON_COMPLIANT if Lustre file systems are not configured to copy tags to backups.

fsx-meets-restore-time-target
Checks if the restore time of Amazon FSx File Systems meets the specified duration. The rule is NON_COMPLIANT if LatestRestoreExecutionTimeMinutes of an Amazon FSx File System is greater than maxRestoreTime minutes.

fsx-ontap-deployment-type-check
Checks if Amazon FSx for NetApp ONTAP file systems are configured with certain deployment types. The rule is NON_COMPLIANT if the Amazon FSx for NetApp ONTAP file systems are not configured with the deployment types you specify.

fsx-openzfs-copy-tags-enabled
Checks if the Amazon FSx for OpenZFS file systems are configured to copy tags to backups and volumes. The rule is NON_COMPLIANT if FSx for OpenZFS file systems are not configured to copy tags to backups and volumes.

fsx-openzfs-deployment-type-check
Checks if the Amazon FSx for OpenZFS file systems are configured with certain deployment types. The rule is NON_COMPLIANT if FSx for OpenZFS file systems are not configured with the deployment types you specify.

fsx-resources-protected-by-backup-plan
Checks if Amazon FSx File Systems are protected by a backup plan. The rule is NON_COMPLIANT if the Amazon FSx File System is not covered by a backup plan.

fsx-windows-audit-log-configured
Checks if the Amazon FSx for Windows File Server file systems have file access auditing enabled. The rule is NON_COMPLIANT if the FSx for Windows File Server file systems do not have file access auditing enabled.

fsx-windows-deployment-type-check
Checks if the Amazon FSx for WINDOWS file systems are configured with certain deployment types. The rule is NON_COMPLIANT if FSx for WINDOWS file systems are not configured with the deployment types you specify.

glb-listener-tagged
Checks if Gateway Load Balancer listeners have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

glb-tagged
Checks if Gateway Load Balancers have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

global-endpoint-event-replication-enabled
Checks if event replication is enabled for Amazon EventBridge global endpoints. The rule is NON_COMPLIANT if event replication is not enabled.

glue-job-logging-enabled
Checks if an AWS Glue job has logging enabled. The rule is NON_COMPLIANT if an AWS Glue job does not have Amazon CloudWatch logs enabled.

glue-ml-transform-encrypted-at-rest
Checks if an AWS Glue ML Transform has encryption at rest enabled. The rule is NON_COMPLIANT if `MLUserDataEncryptionMode` is set to `DISABLED`.

glue-ml-transform-tagged
Checks if AWS Glue machine learning transforms have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

glue-spark-job-supported-version
Checks if an AWS Glue Spark job is running on the specified minimum supported AWS Glue version. The rule is NON_COMPLIANT if the AWS Glue Spark job is not running on the minimum supported AWS Glue version that you specify.

guardduty-ec2-protection-runtime-enabled
Checks if ECS Runtime Monitoring with automated agent management is enabled for Amazon GuardDuty detector. The rule is NON_COMPLIANT if the feature is not enabled for your account or at least one member account in your organization.

guardduty-ecs-protection-runtime-enabled
Checks if ECS Runtime Monitoring with automated agent management is enabled for Amazon GuardDuty detector. The rule is NON_COMPLIANT if the feature is not enabled for your account or at least one member account in your organization.

guardduty-eks-protection-audit-enabled
Checks if Audit Log Monitoring for Amazon Elastic Kubernetes Service (Amazon EKS) is enabled for an Amazon GuardDuty detector in your account. The rule is NON_COMPLIANT if the EKS Audit Log Monitoring feature is not enabled for your account.

guardduty-eks-protection-runtime-enabled
Checks if Amazon EKS Runtime Monitoring with automated agent management is enabled for GuardDuty detector in your account. The rule is NON_COMPLIANT if EKS Runtime Monitoring with automated agent management in GuardDuty is not enabled for your account.

guardduty-enabled-centralized
Checks if Amazon GuardDuty is enabled in your AWS account and AWS Region. If you provide an AWS account for centralization, the rule evaluates the GuardDuty results in the centralized account. The rule is COMPLIANT when GuardDuty is enabled.

guardduty-lambda-protection-enabled
Checks if Lambda Protection is enabled for an Amazon GuardDuty detector in your account. The rule is NON_COMPLIANT if the Lambda Protection feature in Amazon GuardDuty is not enabled for your account.

guardduty-malware-protection-enabled
Checks if Malware Protection is enabled for an Amazon GuardDuty detector in your account. The rule is NON_COMPLIANT if the Malware Protection feature in Amazon GuardDuty is not enabled for your account.

guardduty-non-archived-findings
Checks if Amazon GuardDuty has findings that are non-archived. The rule is NON_COMPLIANT if GuardDuty has non-archived low/medium/high severity findings older than the specified number in the daysLowSev/daysMediumSev/daysHighSev parameter.

guardduty-rds-protection-enabled
Checks if Amazon Relational Database Service (Amazon RDS) protection is enabled for an Amazon GuardDuty detector in your account. The rule is NON_COMPLIANT if the Amazon RDS protection feature in Amazon GuardDuty is not enabled for you account.

guardduty-runtime-monitoring-enabled
Checks if Runtime Monitoring is enabled for Amazon GuardDuty detector in your account or organization. The rule is NON_COMPLIANT if Runtime Monitoring in GuardDuty is not enabled for your account or at least one member account in your organization.

guardduty-s3-protection-enabled
Checks if S3 Protection is enabled for an Amazon GuardDuty Detector in your account. The rule is NON_COMPLIANT if the S3 Protection feature in Amazon GuardDuty is not enabled for your account.

iam-customer-policy-blocked-kms-actions
Checks if the managed AWS Identity and Access Management (IAM) policies that you create do not allow blocked KMS actions on all AWS KMS key resources. The rule is NON_COMPLIANT if any blocked action is allowed on all AWS KMS keys by the managed IAM policy.

iam-external-access-analyzer-enabled
Checks if an IAM Access Analyzer for external access is activated in your account per region. The rule is NON_COMPLIANT if there are no analyzers for external access in the region or if the 'status' attribute is not set to 'ACTIVE'.

iam-group-has-users-check
Checks whether IAM groups have at least one IAM user.

iam-inline-policy-blocked-kms-actions
Checks if the inline policies attached to your IAM users, roles, and groups do not allow blocked actions on all AWS KMS keys. The rule is NON_COMPLIANT if any blocked action is allowed on all AWS KMS keys in an inline policy.

iam-no-inline-policy-check
Checks if the inline policy feature is not in use. The rule is NON_COMPLIANT if an AWS Identity and Access Management (IAM) user, IAM role or IAM group has any inline policy.

iam-oidc-provider-tagged
Checks if AWS IAM OIDC providers have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

iam-password-policy
Checks if the account password policy for AWS Identity and Access Management (IAM) users meets the specified requirements indicated in the parameters. The rule is NON_COMPLIANT if the account password policy does not meet the specified requirements.

iam-policy-blacklisted-check
Checks in each AWS Identity and Access Management (IAM) resource, if a policy Amazon Resource Name (ARN) in the input parameter is attached to the IAM resource. The rule is NON_COMPLIANT if the policy ARN is attached to the IAM resource.

iam-policy-in-use
Checks whether the IAM policy ARN is attached to an IAM user, or a group with one or more IAM users, or an IAM role with one or more trusted entity.

iam-policy-no-statements-with-admin-access
Checks if AWS Identity and Access Management (IAM) policies that you create have Allow statements that grant permissions to all actions on all resources. The rule is NON_COMPLIANT if any customer managed IAM policy statement includes "Effect": "Allow" with "Action": "*" over "Resource": "*".

iam-policy-no-statements-with-full-access
Checks if AWS Identity and Access Management (IAM) policies that you create grant permissions to all actions on individual AWS resources. The rule is NON_COMPLIANT if any customer managed IAM policy allows full access to at least 1 AWS service.

iam-role-managed-policy-check
Checks if all managed policies specified in the list of managed policies are attached to the AWS Identity and Access Management (IAM) role. The rule is NON_COMPLIANT if a managed policy is not attached to the IAM role.

iam-root-access-key-check
Checks if the root user access key is available. The rule is COMPLIANT if the user access key does not exist. Otherwise, NON_COMPLIANT.

iam-saml-provider-tagged
Checks if AWS IAM SAML providers have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

iam-server-certificate-expiration-check
Checks if AWS IAM SSL/TLS server certificates stored in IAM are expired. The rule is NON_COMPLIANT if an IAM server certificate is expired.

iam-server-certificate-tagged
Checks if AWS IAM server certificates have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

iam-user-group-membership-check
Checks whether IAM users are members of at least one IAM group.

iam-user-mfa-enabled
Checks if the AWS Identity and Access Management (IAM) users have multi-factor authentication (MFA) enabled. The rule is NON_COMPLIANT if MFA is not enabled for at least one IAM user.

iam-user-no-policies-check
Checks if none of your AWS Identity and Access Management (IAM) users have policies attached. IAM users must inherit permissions from IAM groups or roles. The rule is NON_COMPLIANT if there is at least one policy that is attached to the IAM user.

iam-user-unused-credentials-check
Checks if your AWS Identity and Access Management (IAM) users have passwords or active access keys that have not been used within the specified number of days you provided. The rule is NON_COMPLIANT if there are inactive accounts not recently used.

restricted-ssh
Checks if the incoming SSH traffic for the security groups is accessible. The rule is COMPLIANT if the IP addresses of the incoming SSH traffic in the security groups are restricted (CIDR other than 0.0.0.0/0 or ::/0). Otherwise, NON_COMPLIANT.

inspector-ec2-scan-enabled
Checks if Amazon Inspector V2 EC2 scanning is activated for your single or multi-account environment to detect potential vulnerabilities and network reachability issues on your EC2 instances. The rule is NON_COMPLIANT if EC2 scanning is not activated.

inspector-ecr-scan-enabled
Checks if Amazon Inspector V2 ECR scanning is activated for your single or multi-account environment to detect potential software vulnerabilities in your container images. The rule is NON_COMPLIANT if ECR scanning is not activated.

inspector-lambda-code-scan-enabled
Checks if Amazon Inspector V2 Lambda code scanning is activated for your single or multi-account environment to detect potential code vulnerabilities. The rule is NON_COMPLIANT if Lambda code scanning is not activated.

inspector-lambda-standard-scan-enabled
Checks if Amazon Inspector V2 Lambda standard scanning is activated for your single or multi-account environment to detect potential software vulnerabilities. The rule is NON_COMPLIANT if Lambda standard scanning is not activated.

ec2-instances-in-vpc
Checks if your EC2 instances belong to a virtual private cloud (VPC). Optionally, you can specify the VPC ID to associate with your instances.

internet-gateway-authorized-vpc-only
Checks if internet gateways are attached to an authorized virtual private cloud (Amazon VPC). The rule is NON_COMPLIANT if internet gateways are attached to an unauthorized VPC.

iotdevicedefender-custom-metric-tagged
AWS IoT Device Defender custom metrics have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

iotevents-alarm-model-tagged
Checks if AWS IoT Events alarm models have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

iotevents-detector-model-tagged
Checks if AWS IoT Events detector models have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

iotevents-input-tagged
Checks if AWS IoT Events inputs have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

iotsitewise-asset-model-tagged
Checks if AWS IoT SiteWise asset models have tags. Optionally, you can specify tag keys for the rule. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

iotsitewise-dashboard-tagged
Checks if AWS IoT SiteWise dashboards have tags. Optionally, you can specify tag keys for the rule. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

iotsitewise-gateway-tagged
Checks if AWS IoT SiteWise gateways have tags. Optionally, you can specify tag keys for the rule. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

iotsitewise-portal-tagged
Checks if AWS IoT SiteWise portals have tags. Optionally, you can specify tag keys for the rule. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

iotsitewise-project-tagged
Checks if AWS IoT SiteWise projects have tags. Optionally, you can specify tag keys for the rule. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

iottwinmaker-component-type-tagged
Checks if AWS IoT TwinMaker component types have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

iottwinmaker-entity-tagged
Checks if AWS IoT TwinMaker entities have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

iottwinmaker-scene-tagged
Checks if AWS IoT TwinMaker scenes have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

iottwinmaker-sync-job-tagged
Checks if AWS IoT TwinMaker sync jobs have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

iottwinmaker-workspace-tagged
Checks if AWS IoT TwinMaker workspaces have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

iotwireless-fuota-task-tagged
Checks if AWS IoT Wireless FUOTA tasks have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

iotwireless-multicast-group-tagged
Checks if AWS IoT Wireless multicast groups have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

iotwireless-service-profile-tagged
Checks if AWS IoT Wireless service profiles have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

iot-authorizer-token-signing-enabled
Checks if an AWS IoT Core authorizer has not disabled the signing requirements for validating the token signature in an authorization request. The rule is NON_COMPLIANT if the authorizer has configuration.SigningDisabled set to True.

iot-job-template-tagged
Checks if AWS IoT job template resources resources have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

iot-provisioning-template-description
Checks if AWS IoT provisioning templates have a description. The rule is NON_COMPLIANT if configuration.Description does not exist or is an empty string.

iot-provisioning-template-jitp
Checks if AWS IoT provisioning templates are using just-in-time provisioning (JITP). The rule is NON_COMPLIANT if configuration.TemplateType is not 'JITP'.

iot-provisioning-template-tagged
Checks if AWS IoT provisioning templates have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

iot-scheduled-audit-tagged
Checks if AWS IoT scheduled audits have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

ivs-channel-playback-authorization-enabled
Checks if Amazon IVS channels have playback authorization enabled. The rule is NON_COMPLIANT if configuration.Authorized is false.

ivs-channel-tagged
Checks if Amazon IVS channels have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

ivs-playback-key-pair-tagged
Checks if Amazon IVS playback key pairs have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

ivs-recording-configuration-tagged
Checks if Amazon IVS recording configurations have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

kinesis-firehose-delivery-stream-encrypted
Checks if Amazon Kinesis Data Firehose delivery streams are encrypted at rest with server-side encryption. The rule is NON_COMPLIANT if a Kinesis Data Firehose delivery stream is not encrypted at rest with server-side encryption.

kinesis-stream-backup-retention-check
Checks if an Amazon Kinesis Data Stream has its data record retention period set to a specific number of hours. The rule is NON_COMPLIANT if the property `RetentionPeriodHours` is set to a value less than the value specified by the parameter.

kinesis-stream-encrypted
Checks if Amazon Kinesis streams are encrypted at rest with server-side encryption. The rule is NON_COMPLIANT for a Kinesis stream if 'StreamEncryption' is not present.

kinesis-video-stream-minimum-data-retention
Checks if an Amazon Kinesis Video stream is configured with a value greater than or equal to the specified minimum data retention. The rule is NON_COMPLIANT if DataRetentionInHours is less than the value specified in the required rule parameter.

kms-cmk-not-scheduled-for-deletion
Checks if AWS Key Management Service (AWS KMS) keys are not scheduled for deletion in AWS KMS. The rule is NON_COMPLIANT if KMS keys are scheduled for deletion.

kms-key-policy-no-public-access
Checks if the AWS KMS key policy allows public access. The rule is NON_COMPLIANT if the KMS key policy allows public access to the KMS key.

kms-key-tagged
Checks if AWS Key Management Service (KMS) keys have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

lambda-concurrency-check
Checks if the Lambda function is configured with a function-level concurrent execution limit. The rule is NON_COMPLIANT if the Lambda function is not configured with a function-level concurrent execution limit.

lambda-dlq-check
Checks whether an AWS Lambda function is configured with a dead-letter queue. The rule is NON_COMPLIANT if the Lambda function is not configured with a dead-letter queue.

lambda-function-description
Checks if AWS Lambda functions have a description. The rule is NON_COMPLIANT if configuration.description does not exist or is an empty string.

lambda-function-public-access-prohibited
Checks if the AWS Lambda function policy attached to the Lambda resource prohibits public access. If the Lambda function policy allows public access it is NON_COMPLIANT.

lambda-function-settings-check
Checks if the AWS Lambda function settings for runtime, role, timeout, and memory size match the expected values. The rule ignores functions with the 'Image' package type and functions with runtime set to 'OS-only Runtime'. The rule is NON_COMPLIANT if the Lambda function settings do not match the expected values.

lambda-function-xray-enabled
Checks if AWS X-Ray is enabled on AWS Lambda functions.The rule is NON_COMPLIANT if X-Ray tracing is disabled for a Lambda function.

lambda-inside-vpc
Checks if a Lambda function is allowed access to a virtual private cloud (VPC). The rule is NON_COMPLIANT if the Lambda function is not VPC enabled.

lambda-vpc-multi-az-check
Checks if Lambda has more than 1 availability zone associated. The rule is NON_COMPLIANT if only 1 availability zone is associated with the Lambda or the number of availability zones associated is less than number specified in the optional parameter.

lightsail-bucket-allow-public-overrides-disabled
Checks if Amazon Lightsail buckets have allow public overrides disabled. The rule is NON_COMPLIANT if AllowPublicOverrides is true. Note: AllowPublicOverrides has no effect if GetObject is public, see lightsail-bucket-get-object-private.

lightsail-bucket-tagged
Checks if Amazon Lightsail buckets have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

lightsail-certificate-tagged
Checks if Amazon Lightsail certificates have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

lightsail-disk-tagged
Checks if Amazon Lightsail disks have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

macie-auto-sensitive-data-discovery-check
Checks if automated sensitive data discovery is enabled for Amazon Macie. The rule is NON_COMPLIANT if automated sensitive data discovery is disabled. The rule is APPLICABLE for administrator accounts and NOT_APPLICABLE for member accounts.

macie-status-check
Checks if Amazon Macie is enabled in your account per region. The rule is NON_COMPLIANT if the 'status' attribute is not set to 'ENABLED'.

mariadb-publish-logs-to-cloudwatch-logs
Checks if Amazon MariaDB database instances are configured to publish logs to Amazon CloudWatch Logs. The rule is NON_COMPLIANT if a database instance is not configured to publish logs to CloudWatch Logs.

mfa-enabled-for-iam-console-access
Checks if AWS multi-factor authentication (MFA) is enabled for all AWS Identity and Access Management (IAM) users that use a console password. The rule is COMPLIANT if MFA is enabled.

mq-active-broker-ldap-authentication
Checks if Amazon MQ ActiveMQ brokers use the LDAP authentication strategy to secure the broker. The rule is NON_COMPLIANT if configuration.AuthenticationStrategy is not 'ldap'.

mq-active-deployment-mode
Checks the deployment mode configured for Amazon MQ ActiveMQ broker engine. The rule is NON_COMPLIANT if the default single-instance broker mode is being used.

mq-active-single-instance-broker-storage-type-efs
Checks if an Amazon MQ for ActiveMQ single-instance broker using the mq.m5 instance type family is configured with Amazon Elastic File System (EFS) for broker storage. The rule is NON_COMPLIANT if configuration.StorageType is not 'efs'.

mq-automatic-minor-version-upgrade-enabled
Checks if automatic minor version upgrades are enabled for Amazon MQ brokers. The rule is NON_COMPLIANT if the 'AutoMinorVersionUpgrade' field is not enabled for an Amazon MQ broker.

mq-auto-minor-version-upgrade-enabled
Checks if automatic minor version upgrades are enabled for Amazon MQ brokers. The rule is NON_COMPLIANT if the 'AutoMinorVersionUpgrade' field is not enabled for an Amazon MQ broker.

mq-broker-general-logging-enabled
Checks if Amazon MQ brokers have general logging enabled. The rule is NON_COMPLIANT if configuration.Logs.General is false.

mq-cloudwatch-audit-logging-enabled
Checks if Amazon MQ brokers have Amazon CloudWatch audit logging enabled. The rule is NON_COMPLIANT if a broker does not have audit logging enabled.

mq-cloudwatch-audit-log-enabled
Checks if an Amazon MQ broker has CloudWatch audit logging enabled. The rule is NON_COMPLIANT if the broker does not have audit logging enabled.

mq-no-public-access
Checks if Amazon MQ brokers are not publicly accessible. The rule is NON_COMPLIANT if the 'PubliclyAccessible' field is set to true for an Amazon MQ broker.

mq-rabbit-deployment-mode
Checks the deployment mode configured for the Amazon MQ RabbitMQ broker engine. The rule is NON_COMPLIANT if the default single-instance broker mode is being used.

msk-cluster-public-access-disabled
Checks if public access is disabled on Amazon MSK clusters. The rule is NON_COMPLIANT if public access on an Amazon MSK cluster is not disabled.

msk-cluster-tagged
Checks if Amazon MSK clusters have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

msk-connect-connector-logging-enabled
Checks if Amazon MSK Connector has logging enabled to any one of the log destinations. The rule is NON_COMPLIANT if Amazon MSK Connector does not have logging enabled.

msk-enhanced-monitoring-enabled
Checks if enhanced monitoring is enabled for an Amazon MSK cluster set to PER_TOPIC_PER_BROKER or PER_TOPIC_PER_PARTITION. The rule is NON_COMPLIANT if enhanced monitoring is enabled and set to DEFAULT or PER_BROKER.

msk-in-cluster-node-require-tls
Checks if an Amazon MSK cluster enforces encryption in transit using HTTPS (TLS) with the broker nodes of the cluster. The rule is NON_COMPLIANT if plain text communication is enabled for in-cluster broker node connections.

msk-unrestricted-access-check
Checks if an Amazon MSK Cluster has unauthenticated access disabled. The rule is NON_COMPLIANT if Amazon MSK Cluster has unauthenticated access enabled.

multi-region-cloudtrail-enabled
Checks if there is at least one multi-region AWS CloudTrail. The rule is NON_COMPLIANT if the trails do not match input parameters. The rule is NON_COMPLIANT if the ExcludeManagementEventSources field is not empty or if AWS CloudTrail is configured to exclude management events such as AWS KMS events or Amazon RDS Data API events.

nacl-no-unrestricted-ssh-rdp
Checks if default ports for SSH/RDP ingress traffic for network access control lists (NACLs) is unrestricted. The rule is NON_COMPLIANT if a NACL inbound entry allows a source TCP or UDP CIDR block for ports 22 or 3389.

neptune-cluster-backup-retention-check
Checks if an Amazon Neptune DB cluster retention period is set to specific number of days. The rule is NON_COMPLIANT if the retention period is less than the value specified by the parameter.

neptune-cluster-cloudwatch-log-export-enabled
Checks if an Amazon Neptune cluster has CloudWatch log export enabled for audit logs. The rule is NON_COMPLIANT if a Neptune cluster does not have CloudWatch log export enabled for audit logs.

neptune-cluster-copy-tags-to-snapshot-enabled
Checks if an Amazon Neptune cluster is configured to copy all tags to snapshots when the snapshots are created. The rule is NON_COMPLIANT if 'copyTagsToSnapshot' is set to false.

neptune-cluster-deletion-protection-enabled
Checks if an Amazon Neptune DB cluster has deletion protection enabled. The rule is NON_COMPLIANT if an Amazon Neptune cluster has the deletionProtection field set to false.

neptune-cluster-encrypted
Checks if storage encryption is enabled for your Amazon Neptune DB clusters. The rule is NON_COMPLIANT if storage encryption is not enabled.

neptune-cluster-iam-database-authentication
Checks if an Amazon Neptune cluster has AWS Identity and Access Management (IAM) database authentication enabled. The rule is NON_COMPLIANT if an Amazon Neptune cluster does not have IAM database authentication enabled.

neptune-cluster-multi-az-enabled
Checks if an Amazon Neptune cluster is configured with Amazon RDS Multi-AZ replication. The rule is NON_COMPLIANT if Multi-AZ replication is not enabled.

neptune-cluster-snapshot-encrypted
Checks if an Amazon Neptune DB cluster has snapshots encrypted. The rule is NON_COMPLIANT if a Neptune cluster does not have snapshots encrypted.

neptune-cluster-snapshot-public-prohibited
Checks if an Amazon Neptune manual DB cluster snapshot is public. The rule is NON_COMPLIANT if any existing and new Neptune cluster snapshot is public.

netfw-deletion-protection-enabled
Checks if AWS Network Firewall has deletion protection enabled. The rule is NON_COMPLIANT if Network Firewall does not have deletion protection enabled.

netfw-logging-enabled
Checks if AWS Network Firewall firewalls have logging enabled. The rule is NON_COMPLIANT if a logging type is not configured. You can specify which logging type you want the rule to check.

netfw-multi-az-enabled
Checks if AWS Network Firewall firewalls are deployed across multiple Availability Zones. The rule is NON_COMPLIANT if firewalls are deployed in only one Availability Zone or in fewer zones than the number listed in the optional parameter.

netfw-policy-default-action-fragment-packets
Checks if an AWS Network Firewall policy is configured with a user defined stateless default action for fragmented packets. The rule is NON_COMPLIANT if stateless default action for fragmented packets does not match with user defined default action.

netfw-policy-default-action-full-packets
Checks if an AWS Network Firewall policy is configured with a user defined default stateless action for full packets. This rule is NON_COMPLIANT if default stateless action for full packets does not match with user defined default stateless action.

netfw-policy-rule-group-associated
Check AWS Network Firewall policy is associated with stateful OR stateless rule groups. This rule is NON_COMPLIANT if no stateful or stateless rule groups are associated with the Network Firewall policy else COMPLIANT if any one of the rule group exists.

netfw-stateless-rule-group-not-empty
Checks if a Stateless Network Firewall Rule Group contains rules. The rule is NON_COMPLIANT if there are no rules in a Stateless Network Firewall Rule Group.

netfw-subnet-change-protection-enabled
Checks if AWS Network Firewall has subnet change protection enabled. The rule is NON_COMPLIANT if subnet change protection is not enabled.

nlb-cross-zone-load-balancing-enabled
Checks if cross-zone load balancing is enabled on Network Load Balancers (NLBs). The rule is NON_COMPLIANT if cross-zone load balancing is not enabled for an NLB.

nlb-internal-scheme-check
Checks if a Network Load Balancer scheme is internal. The rule is NON_COMPLIANT if configuration.scheme is not set to internal.

nlb-listener-tagged
Checks if Network Load Balancer listeners have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

nlb-logging-enabled
Checks if access logging is enabled for Network Load Balancers. The rule is NON_COMPLIANT if access logging is not enabled for a Network Load balancer.

nlb-tagged
Checks if Network Load Balancers have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

no-unrestricted-route-to-igw
Checks if there are public routes in the route table to an Internet gateway (IGW). The rule is NON_COMPLIANT if a route to an IGW has a destination CIDR block of '0.0.0.0/0' or '::/0' or if a destination CIDR block does not match the rule parameter.

opensearch-access-control-enabled
Checks if Amazon OpenSearch Service domains have fine-grained access control enabled. The rule is NON_COMPLIANT if AdvancedSecurityOptions is not enabled for the OpenSearch Service domain.

opensearch-audit-logging-enabled
Checks if Amazon OpenSearch Service domains have audit logging enabled. The rule is NON_COMPLIANT if an OpenSearch Service domain does not have audit logging enabled.

opensearch-data-node-fault-tolerance
Checks if Amazon OpenSearch Service domains are configured with at least three data nodes and zoneAwarenessEnabled is true. The rule is NON_COMPLIANT for an OpenSearch domain if 'instanceCount' is less than 3 or 'zoneAwarenessEnabled' is set to 'false'.

opensearch-encrypted-at-rest
Checks if Amazon OpenSearch Service domains have encryption at rest configuration enabled. The rule is NON_COMPLIANT if the EncryptionAtRestOptions field is not enabled.

opensearch-https-required
Checks whether connections to OpenSearch domains are using HTTPS. The rule is NON_COMPLIANT if the Amazon OpenSearch domain 'EnforceHTTPS' is not 'true' or is 'true' and 'TLSSecurityPolicy' is not in 'tlsPolicies'.

opensearch-in-vpc-only
Checks if Amazon OpenSearch Service domains are in an Amazon Virtual Private Cloud (VPC). The rule is NON_COMPLIANT if an OpenSearch Service domain endpoint is public.

opensearch-logs-to-cloudwatch
Checks if Amazon OpenSearch Service domains are configured to send logs to Amazon CloudWatch Logs. The rule is NON_COMPLIANT if logging is not configured.

opensearch-node-to-node-encryption-check
Check if Amazon OpenSearch Service nodes are encrypted end to end. The rule is NON_COMPLIANT if the node-to-node encryption is not enabled on the domain

opensearch-primary-node-fault-tolerance
Checks if Amazon OpenSearch Service domains are configured with at least three dedicated primary nodes. The rule is NON_COMPLIANT for an OpenSearch Service domain if 'DedicatedMasterEnabled' is set to 'false', or 'DedicatedMasterCount' is less than 3.

opensearch-update-check
Checks if Amazon OpenSearch Service version updates are available but not installed. The rule is NON_COMPLIANT for an OpenSearch domain if the latest software updates are not installed.

rabbit-mq-supported-version
Checks if an Amazon MQ RabbitMQ broker is running on a specified minimum supported engine version. The rule is NON_COMPLIANT if the RabbitMQ broker is not running on the minimum supported engine version that you specify.

rds-aurora-mysql-audit-logging-enabled
Checks if Amazon Aurora MySQL-Compatible Edition clusters are configured to publish audit logs to Amazon CloudWatch Logs. The rule is NON_COMPLIANT if Aurora MySQL-Compatible Edition clusters do not have audit log publishing configured.

rds-aurora-postgresql-logs-to-cloudwatch
Checks if an Amazon Aurora PostgreSQL DB cluster is configured to publish PostgreSQL logs to Amazon CloudWatch Logs. This rule is NON_COMPLIANT if the DB cluster is not configured to publish PostgreSQL logs to Amazon CloudWatch Logs.

rds-automatic-minor-version-upgrade-enabled
Checks if Amazon Relational Database Service (RDS) database instances are configured for automatic minor version upgrades. The rule is NON_COMPLIANT if the value of 'autoMinorVersionUpgrade' is false.

rds-cluster-auto-minor-version-upgrade-enable
Checks if automatic minor version upgrades are enabled for Amazon RDS Multi-AZ cluster deployments. The rule is NON_COMPLIANT if autoMinorVersionUpgrade is set to false.

rds-cluster-default-admin-check
Checks if an Amazon Relational Database Service (Amazon RDS) database cluster has changed the admin username from its default value. The rule is NON_COMPLIANT if the admin username is set to the default value.

rds-cluster-deletion-protection-enabled
Checks if an Amazon Relational Database Service (Amazon RDS) cluster has deletion protection enabled. This rule is NON_COMPLIANT if an RDS cluster does not have deletion protection enabled.

rds-cluster-encrypted-at-rest
Checks if an Amazon Relational Database Service (Amazon RDS) cluster is encrypted at rest. The rule is NON_COMPLIANT if an Amazon RDS cluster is not encrypted at rest.

rds-cluster-iam-authentication-enabled
Checks if an Amazon Relational Database Service (Amazon RDS) cluster has AWS Identity and Access Management (IAM) authentication enabled. The rule is NON_COMPLIANT if an Amazon RDS Cluster does not have IAM authentication enabled.

rds-cluster-multi-az-enabled
Checks if Multi-Availability Zone (Multi-AZ) replication is enabled on Amazon Aurora and Multi-AZ DB clusters managed by Amazon Relational Database Service (Amazon RDS). The rule is NON_COMPLIANT if an Amazon RDS instance is not configured with Multi-AZ.

rds-db-security-group-not-allowed
Checks if there are any Amazon Relational Database Service (Amazon RDS) DB security groups that are not the default DB security group. The rule is NON_COMPLIANT if there are any DB security groups that are not the default DB security group.

rds-enhanced-monitoring-enabled
Checks if enhanced monitoring is enabled for Amazon RDS instances. This rule is NON_COMPLIANT if 'monitoringInterval' is '0' in the configuration item of the RDS instance, or if 'monitoringInterval' does not match the rule parameter value.

rds-event-subscription-tagged
Checks if Amazon RDS event subscriptions have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

rds-instance-default-admin-check
Checks if an Amazon Relational Database Service (Amazon RDS) database has changed the admin username from its default value. This rule will only run on RDS database instances. The rule is NON_COMPLIANT if the admin username is set to the default value.

rds-instance-deletion-protection-enabled
Checks if an Amazon Relational Database Service (Amazon RDS) instance has deletion protection enabled. The rule is NON_COMPLIANT if an Amazon RDS instance does not have deletion protection enabled; for example, deletionProtection is set to false.

rds-instance-iam-authentication-enabled
Checks if an Amazon Relational Database Service (Amazon RDS) instance has AWS Identity and Access Management (IAM) authentication enabled. The rule is NON_COMPLIANT if an Amazon RDS instance does not have IAM authentication enabled.

rds-instance-public-access-check
Checks if the Amazon Relational Database Service (Amazon RDS) instances are not publicly accessible. The rule is NON_COMPLIANT if the publiclyAccessible field is true in the instance configuration item.

rds-instance-subnet-igw-check
Checks if RDS DB instances are deployed in a public subnet with a route to the internet gateway. The rule is NON_COMPLIANT if RDS DB instances is deployed in a public subnet

rds-in-backup-plan
Checks if Amazon Relational Database Service (Amazon RDS) databases are present in AWS Backup plans. The rule is NON_COMPLIANT if Amazon RDS databases are not included in any AWS Backup plan.

rds-last-backup-recovery-point-created
Checks if a recovery point was created for Amazon Relational Database Service (Amazon RDS). The rule is NON_COMPLIANT if the Amazon RDS instance does not have a corresponding recovery point created within the specified time period.

rds-logging-enabled
Checks if respective logs of Amazon Relational Database Service (Amazon RDS) are enabled. The rule is NON_COMPLIANT if any log types are not enabled.

rds-mariadb-instance-encrypted-in-transit
Checks if connections to Amazon RDS for MariaDB DB instances with engine version greater than or equal to 10.5 use encryption in transit. The rule is NON_COMPLIANT if the DB parameter group is not in-sync or if require_secure_transport is not set to ON.

rds-meets-restore-time-target
Checks if the restore time of Amazon Relational Database Service (Amazon RDS) instances meets specified duration. The rule is NON_COMPLIANT if LatestRestoreExecutionTimeMinutes of an Amazon RDS instance is greater than maxRestoreTime minutes.

rds-multi-az-support
Checks whether high availability is enabled for your RDS DB instances.

rds-mysql-cluster-copy-tags-to-snapshot-check
Checks if Amazon Relational Database Service (Amazon RDS) MySQL DB clusters are configured to copy tags to snapshots. The rule is NON_COMPLIANT if an Amazon RDS MySQL DB cluster is not configured to copy tags to snapshots.

rds-mysql-instance-encrypted-in-transit
Checks if connections to Amazon RDS for MySQL database instances are configured to use encryption in transit. The rule is NON_COMPLIANT if the associated database parameter group is not in-sync or if the require_secure_transport parameter is not set to 1.

rds-option-group-tagged
Checks if Amazon RDS option group resources have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

rds-pgsql-cluster-copy-tags-to-snapshot-check
Checks if Amazon Relational Database Service (Amazon RDS) PostgreSQL DB clusters are configured to copy tags to snapshots. The rule is NON_COMPLIANT if an RDS PostgreSQL DB cluster's CopyTagsToSnapshot property is set to false.

rds-postgresql-logs-to-cloudwatch
Checks if an Amazon PostgreSQL DB instance is configured to publish logs to Amazon CloudWatch Logs. The rule is NON_COMPLIANT if the DB instance is not configured to publish logs to Amazon CloudWatch Logs.

rds-postgres-instance-encrypted-in-transit
Checks if connections to Amazon RDS PostgreSQL database instances are configured to use encryption in transit. The rule is NON_COMPLIANT if the associated database parameter group is not in-sync or if the rds.force_ssl parameter is not set to 1.

rds-proxy-tls-encryption
Checks if Amazon RDS proxies enforce TLS for all connections. The rule is NON_COMPLIANT if an Amazon RDS proxy does not have TLS enforced for all connections.

rds-resources-protected-by-backup-plan
Checks if Amazon Relational Database Service (Amazon RDS) instances are protected by a backup plan. The rule is NON_COMPLIANT if the Amazon RDS Database instance is not covered by a backup plan.

rds-snapshots-public-prohibited
Checks if Amazon Relational Database Service (Amazon RDS) snapshots are public. The rule is NON_COMPLIANT if any existing and new Amazon RDS snapshots are public.

rds-snapshot-encrypted
Checks if Amazon Relational Database Service (Amazon RDS) DB snapshots are encrypted. The rule is NON_COMPLIANT if the Amazon RDS DB snapshots are not encrypted.

rds-sqlserver-encrypted-in-transit
Checks if connections to Amazon RDS SQL server database instances are configured to use encryption in transit. The rule is NON_COMPLIANT if the DB parameter force_ssl for the parameter group is not set to 1 or the ApplyStatus parameter is not 'in-sync'.

rds-sql-server-logs-to-cloudwatch
Checks if an Amazon SQL Server DB instance is configured to publish logs to Amazon CloudWatch Logs. This rule is NON_COMPLIANT if the DB instance is not configured to publish logs to Amazon CloudWatch Logs.

rds-storage-encrypted
Checks if storage encryption is enabled for your Amazon Relational Database Service (Amazon RDS) DB instances. The rule is NON_COMPLIANT if storage encryption is not enabled.

redshift-audit-logging-enabled
Checks if Amazon Redshift clusters are logging audits to a specific bucket. The rule is NON_COMPLIANT if audit logging is not enabled for a Redshift cluster or if the 'bucketNames' parameter is provided but the audit logging destination does not match.

redshift-backup-enabled
Checks that Amazon Redshift automated snapshots are enabled for clusters. The rule is NON_COMPLIANT if the value for automatedSnapshotRetentionPeriod is greater than MaxRetentionPeriod or less than MinRetentionPeriod or the value is 0.

redshift-cluster-configuration-check
Checks if Amazon Redshift clusters have the specified settings. The rule is NON_COMPLIANT if the Amazon Redshift cluster is not encrypted or encrypted with another key, or if a cluster does not have audit logging enabled.

redshift-cluster-kms-enabled
Checks if Amazon Redshift clusters are using a specified AWS Key Management Service (AWS KMS) key for encryption. The rule is COMPLIANT if encryption is enabled and the cluster is encrypted with the key provided in the kmsKeyArn parameter. The rule is NON_COMPLIANT if the cluster is not encrypted or encrypted with another key.

redshift-cluster-maintenancesettings-check
Checks if Amazon Redshift clusters have the specified maintenance settings. The rule is NON_COMPLIANT if the automatic upgrades to major version is disabled.

redshift-cluster-multi-az-enabled
Checks if an Amazon Redshift cluster has multiple Availability Zones deployments enabled. This rule is NON_COMPLIANT if Amazon Redshift cluster does not have multiple Availability Zones deployments enabled.

redshift-cluster-parameter-group-tagged
Checks if Amazon Redshift cluster parameter groups have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

redshift-cluster-public-access-check
Checks whether Amazon Redshift clusters are not publicly accessible. The rule is NON_COMPLIANT if the publiclyAccessible field is true in the cluster configuration item.

redshift-cluster-subnet-group-multi-az
Checks If Amazon Redshift subnet groups contain subnets from more than one Availability Zone. The rule is NON_COMPLIANT if an Amazon Redshift subnet group does not contain subnets from at least two different Availability Zones.

redshift-default-admin-check
Checks if an Amazon Redshift cluster has changed the admin username from its default value. The rule is NON_COMPLIANT if the admin username for a Redshift cluster is set to “awsuser” or if the username does not match what is listed in parameter.

redshift-default-db-name-check
Checks if a Redshift cluster has changed its database name from the default value. The rule is NON_COMPLIANT if the database name for a Redshift cluster is set to “dev”, or if the optional parameter is provided and the database name does not match.

redshift-enhanced-vpc-routing-enabled
Checks if Amazon Redshift cluster has 'enhancedVpcRouting' enabled. The rule is NON_COMPLIANT if 'enhancedVpcRouting' is not enabled or if the configuration.enhancedVpcRouting field is 'false'.

redshift-require-tls-ssl
Checks if Amazon Redshift clusters require TLS/SSL encryption to connect to SQL clients. The rule is NON_COMPLIANT if any Amazon Redshift cluster has parameter require_SSL not set to true.

redshift-serverless-default-admin-check
Checks if an Amazon Redshift Serverless Namespace has changed the admin username from its default value. The rule is NON_COMPLIANT if the admin username for a Redshift Serverless Namespace is set to “admin”.

redshift-serverless-default-db-name-check
Checks if an Amazon Redshift Serverless namespace has changed its database name from the default value. The rule is NON_COMPLIANT if the database name for an Amazon Redshift Serverless namespace is set to `dev`.

redshift-serverless-namespace-cmk-encryption
Checks if Amazon Redshift Serverless namespaces are encrypted by customer managed AWS KMS keys. The rule is NON_COMPLIANT if a namespace is not encrypted by a customer managed key. Optionally, you can specify a list of KMS keys for rule to check.

redshift-serverless-publish-logs-to-cloudwatch
Checks if Amazon Redshift Serverless Namespace is configured to publish the following logs to Amazon CloudWatch Logs. This rule is NON_COMPLIANT if the Namespace is not configured to publish the following logs to Amazon CloudWatch Logs.

redshift-serverless-workgroup-encrypted-in-transit
Checks if AWS Redshift Serverless workgroups have the require_ssl config parameter set to true. The rule is NON_COMPLIANT if require_ssl is set to false.

redshift-serverless-workgroup-no-public-access
Checks if Amazon Redshift Serverless workgroups do not allow public access. The rule is NON_COMPLIANT if a workgroup has 'Turn on Public Accessible' enabled.

redshift-serverless-workgroup-routes-within-vpc
Checks if Amazon Redshift Serverless workgroups route the network traffic through a VPC. The rule is NON_COMPLIANT if workgroups have 'Turn on Enhanced VPC routing' disabled.

redshift-unrestricted-port-access
Checks if security groups associated with an Amazon Redshift cluster have inbound rules that allow unrestricted incoming traffic. The rule is NON_COMPLIANT if there are inbound rules that allow unrestricted incoming traffic to the Redshift cluster port.

required-tags
Checks if your resources have the tags that you specify. For example, you can check whether your Amazon EC2 instances have the CostCenter tag, while also checking if all your RDS instance have one set of Keys tag. Separate multiple values with commas. You can check up to 6 tags at a time.

restricted-common-ports
Checks if the security groups in use do not allow unrestricted incoming Transmission Control Protocol (TCP) traffic to specified ports. The rule is COMPLIANT if:

root-account-hardware-mfa-enabled
Checks if your AWS account is enabled to use multi-factor authentication (MFA) hardware device to sign in with root credentials. The rule is NON_COMPLIANT if any virtual MFA devices are permitted for signing in with root credentials.

root-account-mfa-enabled
Checks if the root user of your AWS account requires multi-factor authentication for console sign-in. The rule is NON_COMPLIANT if the AWS Identity and Access Management (IAM) root account user does not have multi-factor authentication (MFA) enabled.

route53-health-check-tagged
Checks if Amazon Route 53 health checks have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

route53-hosted-zone-tagged
Checks if Amazon Route 53 hosted zones have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

route53-query-logging-enabled
Checks if DNS query logging is enabled for your Amazon Route 53 public hosted zones. The rule is NON_COMPLIANT if DNS query logging is not enabled for your Amazon Route 53 public hosted zones.

route53-resolver-firewall-domain-list-tagged
Checks if Amazon Route 53 Resolver firewall domain lists have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

route53-resolver-firewall-rule-group-association-tagged
Checks if Amazon Route 53 Resolver firewall rule group associations have tags. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

route53-resolver-firewall-rule-group-tagged
Checks if Amazon Route 53 Resolver firewall rule groups have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

route53-resolver-resolver-rule-tagged
Checks if Amazon Route 53 Resolver resolver rules have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

rum-app-monitor-cloudwatch-logs-enabled
Checks if Amazon CloudWatch RUM app monitors have CloudWatch logs enabled. The rule is NON_COMPLIANT if configuration.CwLogEnabled is false.

rum-app-monitor-tagged
Checks if Amazon CloudWatch RUM app monitors have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

s3express-dir-bucket-lifecycle-rules-check
Checks if lifecycle rules are configured for an Amazon S3 Express directory bucket. The rule is NON_COMPLIANT if there is no active lifecycle configuration rules or the configuration does not match with the parameter values.

s3-access-point-in-vpc-only
Checks if an Amazon S3 access point does not allow access from the internet (NetworkOrigin is VPC). The rule is NON_COMPLIANT if NetworkOrigin is Internet.

s3-access-point-public-access-blocks
Checks if Amazon S3 access points have block public access settings enabled. The rule is NON_COMPLIANT if block public access settings are not enabled for S3 access points.

s3-account-level-public-access-blocks
Checks if the required public access block settings are configured from account level. The rule is only NON_COMPLIANT when the fields set below do not match the corresponding fields in the configuration item.

s3-account-level-public-access-blocks-periodic
Checks if the required public access block settings are configured at the account level. The rule is NON_COMPLIANT if the configuration item does not match one or more settings from parameters (or default).

s3-bucket-acl-prohibited
Checks if Amazon Simple Storage Service (Amazon S3) Buckets allow user permissions through access control lists (ACLs). The rule is NON_COMPLIANT if ACLs are configured for user access in Amazon S3 Buckets.

s3-bucket-blacklisted-actions-prohibited
Checks if an Amazon Simple Storage Service (Amazon S3) bucket policy does not allow blocklisted bucket-level and object-level actions on resources in the bucket for principals from other AWS accounts. For example, the rule checks that the Amazon S3 bucket policy does not allow another AWS account to perform any s3:GetBucket* actions and s3:DeleteObject on any object in the bucket. The rule is NON_COMPLIANT if any blocklisted actions are allowed by the Amazon S3 bucket policy.

s3-bucket-cross-region-replication-enabled
Checks if you have enabled S3 Cross-Region Replication for your Amazon S3 buckets. The rule is NON_COMPLIANT if there are no replication rules enabled for Cross-Region Replication.

s3-bucket-default-lock-enabled
Checks if the S3 bucket has lock enabled, by default. The rule is NON_COMPLIANT if the lock is not enabled.

s3-bucket-level-public-access-prohibited
Checks if S3 buckets are publicly accessible. The rule is NON_COMPLIANT if an S3 bucket is not listed in the excludedPublicBuckets parameter and bucket level settings are public.

s3-bucket-logging-enabled
Checks if logging is enabled for your S3 buckets. The rule is NON_COMPLIANT if logging is not enabled.

s3-bucket-mfa-delete-enabled
Checks if MFA Delete is enabled in the Amazon Simple Storage Service (Amazon S3) bucket versioning configuration. The rule is NON_COMPLIANT if MFA Delete is not enabled.

s3-bucket-policy-grantee-check
Checks that the access granted by the Amazon S3 bucket is restricted by any of the AWS principals, federated users, service principals, IP addresses, or VPCs that you provide. The rule is COMPLIANT if a bucket policy is not present.

s3-bucket-policy-not-more-permissive
Checks if your Amazon Simple Storage Service bucket policies do not allow other inter-account permissions than the control Amazon S3 bucket policy that you provide.

s3-bucket-public-read-prohibited
Checks if your Amazon S3 buckets do not allow public read access. The rule checks the Block Public Access settings, the bucket policy, and the bucket access control list (ACL).

s3-bucket-public-write-prohibited
Checks if your Amazon S3 buckets do not allow public write access. The rule checks the Block Public Access settings, the bucket policy, and the bucket access control list (ACL).

s3-bucket-replication-enabled
Checks if S3 buckets have replication rules enabled. The rule is NON_COMPLIANT if an S3 bucket does not have a replication rule or has a replication rule that is not enabled.

s3-bucket-server-side-encryption-enabled
Checks if your Amazon S3 bucket either has the Amazon S3 default encryption enabled or that the Amazon S3 bucket policy explicitly denies put-object requests without server side encryption that uses AES-256 or AWS Key Management Service. The rule is NON_COMPLIANT if your Amazon S3 bucket is not encrypted by default.

s3-bucket-ssl-requests-only
Checks if S3 buckets have policies that require requests to use SSL/TLS. The rule is NON_COMPLIANT if any S3 bucket has policies allowing HTTP requests.

s3-bucket-tagged
Checks if Amazon S3 buckets have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

s3-bucket-versioning-enabled
Checks if versioning is enabled for your S3 buckets. Optionally, the rule checks if MFA delete is enabled for your S3 buckets.

s3-default-encryption-kms
Checks if the S3 buckets are encrypted with AWS Key Management Service (AWS KMS). The rule is NON_COMPLIANT if the S3 bucket is not encrypted with an AWS KMS key.

s3-event-notifications-enabled
Checks if Amazon S3 Events Notifications are enabled on an S3 bucket. The rule is NON_COMPLIANT if S3 Events Notifications are not set on a bucket, or if the event type or destination do not match the eventTypes and destinationArn parameters.

s3-last-backup-recovery-point-created
Checks if a recovery point was created for Amazon Simple Storage Service (Amazon S3). The rule is NON_COMPLIANT if the Amazon S3 bucket does not have a corresponding recovery point created within the specified time period.

s3-lifecycle-policy-check
Checks if a lifecycle rule is configured for an Amazon Simple Storage Service (Amazon S3) bucket. The rule is NON_COMPLIANT if there is no active lifecycle configuration rules or the configuration does not match with the parameter values.

s3-meets-restore-time-target
Checks if the restore time of Amazon Simple Storage Service (Amazon S3) buckets meets the specified duration. The rule is NON_COMPLIANT if LatestRestoreExecutionTimeMinutes of an Amazon S3 bucket is greater than maxRestoreTime minutes.

s3-resources-in-logically-air-gapped-vault
Checks if Amazon Simple Storage Service (Amazon S3) buckets are in a logically air-gapped vault. The rule is NON_COMPLIANT if an Amazon S3 bucket is not in a logically air-gapped vault within the specified time period.

s3-resources-protected-by-backup-plan
Checks if Amazon Simple Storage Service (Amazon S3) buckets are protected by a backup plan. The rule is NON_COMPLIANT if the Amazon S3 bucket is not covered by a backup plan.

s3-version-lifecycle-policy-check
Checks if Amazon Simple Storage Service (Amazon S3) version enabled buckets have lifecycle policy configured. The rule is NON_COMPLIANT if Amazon S3 lifecycle policy is not enabled.

sagemaker-app-image-config-tagged
Checks if Amazon SageMaker app image configs have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

sagemaker-domain-in-vpc
Checks if an Amazon SageMaker domain uses a customer owned Amazon Virtual Private Cloud (VPC) for non-EFS traffic. The rule is NON_COMPLIANT if configuration.AppNetworkAccessType is not set to VpcOnly.

sagemaker-domain-tagged
Checks if Amazon SageMaker domains have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

sagemaker-endpoint-configuration-kms-key-configured
Checks if AWS Key Management Service (AWS KMS) key is configured for an Amazon SageMaker endpoint configuration. The rule is NON_COMPLIANT if 'KmsKeyId' is not specified for the Amazon SageMaker endpoint configuration.

sagemaker-endpoint-config-prod-instance-count
Checks if Amazon SageMaker endpoint configurations have production variants `InitialInstanceCount` set to a value greater than 1. The rule is NON_COMPLIANT if production variants `InitialInstanceCount` is equal to 1.

sagemaker-feature-group-tagged
Checks if Amazon SageMaker feature groups have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

sagemaker-image-description
Checks if Amazon SageMaker images have a description. The rule is NON_COMPLIANT if configuration.ImageDescription does not exist.

sagemaker-image-tagged
Checks if Amazon SageMaker images have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

sagemaker-model-in-vpc
Checks if an Amazon SageMaker model uses an Amazon Virtual Private Cloud (Amazon VPC) for container traffic. The rule is NON_COMPLIANT if configuration.VpcConfig does not exist.

sagemaker-model-isolation-enabled
Checks if an Amazon SageMaker model has network isolation enabled. The rule is NON_COMPLIANT if configuration.EnableNetworkIsolation is false.

sagemaker-notebook-instance-inside-vpc
Checks if an Amazon SageMaker notebook instance is launched within a VPC or within a list of approved subnets. The rule is NON_COMPLIANT if a notebook instance is not launched within a VPC or if its subnet ID is not included in the parameter list.

sagemaker-notebook-instance-kms-key-configured
Checks if an AWS Key Management Service (AWS KMS) key is configured for an Amazon SageMaker notebook instance. The rule is NON_COMPLIANT if 'KmsKeyId' is not specified for the SageMaker notebook instance.

sagemaker-notebook-instance-platform-version
Checks if a Sagemaker Notebook Instance is configured to use a supported platform identifier version. The rule is NON_COMPLIANT if a Notebook Instance is not using the specified supported platform identifier version as specified in the parameter.

sagemaker-notebook-instance-root-access-check
Checks if the Amazon SageMaker RootAccess setting is enabled for Amazon SageMaker notebook instances. The rule is NON_COMPLIANT if the RootAccess setting is set to ‘Enabled’ for an Amazon SageMaker notebook instance.

sagemaker-notebook-no-direct-internet-access
Checks if direct internet access is disabled for an Amazon SageMaker notebook instance. The rule is NON_COMPLIANT if a SageMaker notebook instance is internet-enabled.

secretsmanager-rotation-enabled-check
Checks if AWS Secrets Manager secret has rotation enabled. The rule also checks an optional maximumAllowedRotationFrequency parameter. If the parameter is specified, the rotation frequency of the secret is compared with the maximum allowed frequency. The rule is NON_COMPLIANT if the secret is not scheduled for rotation. The rule is also NON_COMPLIANT if the rotation frequency is higher than the number specified in the maximumAllowedRotationFrequency parameter.

secretsmanager-scheduled-rotation-success-check
Checks if AWS Secrets Manager secrets rotated successfully according to the rotation schedule. Secrets Manager calculates the date the rotation should happen. The rule is NON_COMPLIANT if the date passes and the secret isn't rotated.

secretsmanager-secret-periodic-rotation
Checks if AWS Secrets Manager secrets have been rotated in the past specified number of days. The rule is NON_COMPLIANT if a secret has not been rotated for more than maxDaysSinceRotation number of days. The default value is 90 days.

secretsmanager-secret-unused
Checks if AWS Secrets Manager secrets have been accessed within a specified number of days. The rule is NON_COMPLIANT if a secret has not been accessed in 'unusedForDays' number of days. The default value is 90 days.

secretsmanager-using-cmk
Checks if all secrets in AWS Secrets Manager are encrypted using the AWS managed key (aws/secretsmanager) or a customer managed key that was created in AWS Key Management Service (AWS KMS). The rule is COMPLIANT if a secret is encrypted using a customer managed key. This rule is NON_COMPLIANT if a secret is encrypted using aws/secretsmanager.

securityhub-enabled
Checks if AWS Security Hub is enabled for an AWS Account. The rule is NON_COMPLIANT if AWS Security Hub is not enabled.

security-account-information-provided
Checks if you have provided security contact information for your AWS account contacts. The rule is NON_COMPLIANT if security contact information within the account is not provided.

service-catalog-portfolio-tagged
Checks if AWS Service Catalog portfolio resources have tags. Optionally, required tag keys can be specified. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

service-catalog-shared-within-organization
Checks if AWS Service Catalog shares portfolios to an organization (a collection of AWS accounts treated as a single unit) when integration is enabled with AWS Organizations. The rule is NON_COMPLIANT if the `Type` value of a share is `ACCOUNT`.

service-vpc-endpoint-enabled
Checks if Service Endpoint for the service provided in rule parameter is created for each Amazon Virtual Private Cloud (Amazon VPC). The rule is NON_COMPLIANT if an Amazon VPC doesn't have an Amazon VPC endpoint created for the service.

ses-malware-scanning-enabled
Checks if malware and spam scanning on receiving messages is enabled for Amazon Simple Email Service (Amazon SES). The rule is NON_COMPLIANT if malware and spam scanning is not enabled.

ses-sending-tls-required
Checks if Amazon Simple Email Service (SES) Configuration Set has TLS encryption enforced for email delivery. The rule is NON_COMPLIANT if the TLS Policy is not set to 'REQUIRE' in the Configuration Set.

shield-advanced-enabled-autorenew
Checks if AWS Shield Advanced is enabled in your AWS account and this subscription is set to automatically renew. The rule is COMPLIANT if Shield Advanced is enabled and auto renew is enabled.

shield-drt-access
Checks if the Shield Response Team (SRT) can access your AWS account. The rule is NON_COMPLIANT if AWS Shield Advanced is enabled but the role for SRT access is not configured.

sns-encrypted-kms
Checks if SNS topics are encrypted with AWS Key Management Service (AWS KMS). The rule is NON_COMPLIANT if an SNS topic is not encrypted with AWS KMS. Optionally, specify the key ARNs, the alias ARNs, the alias name, or the key IDs for the rule to check.

sns-topic-message-delivery-notification-enabled
Checks if Amazon Simple Notification Service (SNS) logging is enabled for the delivery status of notification messages sent to a topic for the endpoints. The rule is NON_COMPLIANT if the delivery status notification for messages is not enabled.

sns-topic-no-public-access
Checks if the SNS topic access policy allows public access. The rule is NON_COMPLIANT if the SNS topic access policy allows public access.

sqs-queue-dlq-check
Checks if Amazon Simple Queue Service (Amazon SQS) queues have configuration to use dead-letter queue (DLQ). The rule is NON_COMPLIANT if an Amazon SQS queue does not have any configuration to use DLQ.

sqs-queue-no-public-access
Checks if the SQS queue access policy allows public access. The rule is NON_COMPLIANT if the SQS queue access policy allows public access.

sqs-queue-policy-full-access-check
Checks if the SQS queue access policy allows full access. The rule is NON_COMPLIANT if the SQS policy contains `SQS:*` within `Action` and `Effect` is `Allow`.

ssm-automation-block-public-sharing
Checks if AWS Systems Manager Documents has block public sharing enabled. The rule is NON_COMPLIANT if Systems Manager Documents has block public sharing disabled.

ssm-automation-logging-enabled
Checks if AWS Systems Manager Automation has Amazon CloudWatch logging enabled. The rule returns NON_COMPLIANT if Systems Manager Automation doesn't have CloudWatch logging enabled.

ssm-document-not-public
Checks if AWS Systems Manager documents owned by the account are public. The rule is NON_COMPLIANT if Systems Manager documents with the owner 'Self' are public.

ssm-document-tagged
Checks if AWS Systems Manager documents have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

stepfunctions-state-machine-tagged
Checks if AWS Step Functions state machines have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

step-functions-state-machine-logging-enabled
Checks if AWS Step Functions machine has logging enabled. The rule is NON_COMPLIANT if a state machine does not have logging enabled or the logging configuration is not at the minimum level provided.

storagegateway-last-backup-recovery-point-created
Checks if a recovery point was created for AWS Storage Gateway volumes. The rule is NON_COMPLIANT if the Storage Gateway volume does not have a corresponding recovery point created within the specified time period.

storagegateway-resources-in-logically-air-gapped-vault
Checks if AWS Storage Gateway volumes are in a logically air-gapped vault. The rule is NON_COMPLIANT if an AWS Storage Gateway volume is not in a logically air-gapped vault within the specified time period.

storagegateway-resources-protected-by-backup-plan
Checks if AWS Storage Gateway volumes are protected by a backup plan. The rule is NON_COMPLIANT if the Storage Gateway volume is not covered by a backup plan.

subnet-auto-assign-public-ip-disabled
Checks if Amazon Virtual Private Cloud (Amazon VPC) subnets are configured to automatically assign public IP addresses to instances launched within them. This rule is COMPLIANT if subnets do not auto-assign public IPv4 or IPv6 addresses. This rule is NON_COMPLIANT if subnets auto-assign public IPv4 or IPv6 addresses.

transfer-agreement-description
Checks if AWS Transfer Family agreements have a description. The rule is NON_COMPLIANT if configuration.Description does not exist.

transfer-agreement-tagged
Checks if AWS Transfer Family agreements have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

transfer-certificate-description
Checks if AWS Transfer Family certificates have a description. The rule is NON_COMPLIANT if configuration.Description does not exist.

transfer-certificate-tagged
Checks if AWS Transfer Family certificates have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

transfer-connector-logging-enabled
Checks if AWS Transfer Family Connector publishes logs to Amazon CloudWatch. The rule is NON_COMPLIANT if a Connector does not have a LoggingRole assigned.

transfer-connector-tagged
Checks if AWS Transfer Family connectors have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

transfer-family-server-no-ftp
Checks if a server created with AWS Transfer Family uses FTP for endpoint connection. The rule is NON_COMPLIANT if the server protocol for endpoint connection is FTP-enabled.

transfer-profile-tagged
Checks if AWS Transfer Family profiles have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

transfer-workflow-description
Checks if AWS Transfer Family workflows have a description. The rule is NON_COMPLIANT if configuration.Description does not exist or is an empty string.

transfer-workflow-tagged
Checks if AWS Transfer Family workflows have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

virtualmachine-last-backup-recovery-point-created
Checks if a recovery point was created for AWS Backup-Gateway VirtualMachines. The rule is NON_COMPLIANT if an AWS Backup-Gateway VirtualMachines does not have a corresponding recovery point created within the specified time period.

virtualmachine-resources-in-logically-air-gapped-vault
Checks if AWS Backup-Gateway VirtualMachines are in a logically air-gapped vault. The rule is NON_COMPLIANT if an AWS Backup-Gateway VirtualMachines is not in a logically air-gapped vault within the specified time period.

virtualmachine-resources-protected-by-backup-plan
Checks if AWS Backup-Gateway VirtualMachines are protected by a backup plan. The rule is NON_COMPLIANT if the Backup-Gateway VirtualMachine is not covered by a backup plan.

vpc-default-security-group-closed
Checks if the default security group of any Amazon Virtual Private Cloud (Amazon VPC) does not allow inbound or outbound traffic. The rule is NON_COMPLIANT if the default security group has one or more inbound or outbound traffic rules.

vpc-endpoint-enabled
Checks if each service specified in the parameter has an Amazon VPC endpoint. The rule is NON_COMPLIANT if Amazon VPC does not have a VPC endpoint created for each specified service. Optionally, you can specify certain VPCs for the rule to check.

vpc-flow-logs-enabled
Checks if Amazon Virtual Private Cloud (Amazon VPC) flow logs are found and enabled for all Amazon VPCs. The rule is NON_COMPLIANT if flow logs are not enabled for at least one Amazon VPC.

vpc-network-acl-unused-check
Checks if there are unused network access control lists (network ACLs). The rule is COMPLIANT if each network ACL is associated with a subnet. The rule is NON_COMPLIANT if a network ACL is not associated with a subnet.

vpc-peering-dns-resolution-check
Checks if DNS resolution from accepter/requester VPC to private IP is enabled. The rule is NON_COMPLIANT if DNS resolution from accepter/requester VPC to private IP is not enabled.

vpc-sg-open-only-to-authorized-ports
Checks if security groups allowing unrestricted incoming traffic ('0.0.0.0/0' or '::/0') only allow inbound TCP or UDP connections on authorized ports. The rule is NON_COMPLIANT if such security groups do not have ports specified in the rule parameters.

vpc-sg-port-restriction-check
Checks if security groups restrict incoming traffic to restricted ports explicitly from 0.0.0.0/0 or ::/0. The rule is NON_COMPLIANT if security groups allow incoming traffic from 0.0.0.0/0 or ::/0 over TCP/UDP ports 22/3389 or as specified in parameters.

vpc-vpn-2-tunnels-up
Checks if both virtual private network (VPN) tunnels provided by AWS Site-to-Site VPN are in UP status. The rule is NON_COMPLIANT if one or both tunnels are in DOWN status.

wafv2-logging-enabled
Checks if logging is enabled on AWS WAFv2 regional and global web access control lists (web ACLs). The rule is NON_COMPLIANT if the logging is enabled but the logging destination does not match the value of the parameter.

wafv2-rulegroup-logging-enabled
Checks if Amazon CloudWatch security metrics collection on AWS WAFv2 rule groups is enabled. The rule is NON_COMPLIANT if the 'VisibilityConfig.CloudWatchMetricsEnabled' field is set to false.

wafv2-rulegroup-not-empty
Checks if WAFv2 Rule Groups contain rules. The rule is NON_COMPLIANT if there are no rules in a WAFv2 Rule Group.

wafv2-webacl-not-empty
Checks if a WAFv2 Web ACL contains any WAF rules or WAF rule groups. This rule is NON_COMPLIANT if a Web ACL does not contain any WAF rules or WAF rule groups.

waf-classic-logging-enabled
Checks if logging is enabled on AWS WAF classic global web access control lists (web ACLs). The rule is NON_COMPLIANT for a global web ACL, if it does not have logging enabled.

waf-global-rulegroup-not-empty
Checks if an AWS WAF Classic rule group contains any rules. The rule is NON_COMPLIANT if there are no rules present within a rule group.

waf-global-rule-not-empty
Checks if an AWS WAF global rule contains any conditions. The rule is NON_COMPLIANT if no conditions are present within the WAF global rule.

waf-global-webacl-not-empty
Checks whether a WAF Global Web ACL contains any WAF rules or rule groups. This rule is NON_COMPLIANT if a Web ACL does not contain any WAF rule or rule group.

waf-regional-rulegroup-not-empty
Checks if WAF Regional rule groups contain any rules. The rule is NON_COMPLIANT if there are no rules present within a WAF Regional rule group.

waf-regional-rule-not-empty
Checks whether WAF regional rule contains conditions. This rule is COMPLIANT if the regional rule contains at least one condition and NON_COMPLIANT otherwise.

waf-regional-webacl-not-empty
Checks if a WAF regional Web ACL contains any WAF rules or rule groups. The rule is NON_COMPLIANT if there are no WAF rules or rule groups present within a Web ACL.

workspaces-connection-alias-tagged
Checks if Amazon WorkSpaces connection aliases have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.

workspaces-root-volume-encryption-enabled
Checks if an Amazon WorkSpace volume has the root volume encryption settings set to enabled. This rule is NON_COMPLIANT if the encryption setting is not enabled for the root volume.

workspaces-user-volume-encryption-enabled
Checks if an Amazon WorkSpace volume has the user volume encryption settings set to enabled. This rule is NON_COMPLIANT if the encryption setting is not enabled for the user volume.

workspaces-workspace-tagged
Checks if Amazon WorkSpaces workspaces have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.
