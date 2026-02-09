package awsdata

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"bptools/cache"

	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	acmpcatypes "github.com/aws/aws-sdk-go-v2/service/acmpca/types"
	"github.com/aws/aws-sdk-go-v2/service/amplify"
	amplifytypes "github.com/aws/aws-sdk-go-v2/service/amplify/types"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	apigwtypes "github.com/aws/aws-sdk-go-v2/service/apigateway/types"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	apigwv2types "github.com/aws/aws-sdk-go-v2/service/apigatewayv2/types"
	"github.com/aws/aws-sdk-go-v2/service/appconfig"
	appconfigtypes "github.com/aws/aws-sdk-go-v2/service/appconfig/types"
	"github.com/aws/aws-sdk-go-v2/service/appflow"
	appflowtypes "github.com/aws/aws-sdk-go-v2/service/appflow/types"
	"github.com/aws/aws-sdk-go-v2/service/appintegrations"
	appintegrationstypes "github.com/aws/aws-sdk-go-v2/service/appintegrations/types"
	"github.com/aws/aws-sdk-go-v2/service/applicationautoscaling"
	applicationautoscalingtypes "github.com/aws/aws-sdk-go-v2/service/applicationautoscaling/types"
	"github.com/aws/aws-sdk-go-v2/service/appmesh"
	appmeshtypes "github.com/aws/aws-sdk-go-v2/service/appmesh/types"
	"github.com/aws/aws-sdk-go-v2/service/apprunner"
	apprunnertypes "github.com/aws/aws-sdk-go-v2/service/apprunner/types"
	"github.com/aws/aws-sdk-go-v2/service/appsync"
	appsynctypes "github.com/aws/aws-sdk-go-v2/service/appsync/types"
	"github.com/aws/aws-sdk-go-v2/service/athena"
	athenatypes "github.com/aws/aws-sdk-go-v2/service/athena/types"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	autoscalingtypes "github.com/aws/aws-sdk-go-v2/service/autoscaling/types"
	"github.com/aws/aws-sdk-go-v2/service/backup"
	backuptypes "github.com/aws/aws-sdk-go-v2/service/backup/types"
	"github.com/aws/aws-sdk-go-v2/service/batch"
	batchtypes "github.com/aws/aws-sdk-go-v2/service/batch/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cftypescf "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cloudtrailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cloudwatchtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	logstypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	codebuildtypes "github.com/aws/aws-sdk-go-v2/service/codebuild/types"
	"github.com/aws/aws-sdk-go-v2/service/codedeploy"
	codedeploytypes "github.com/aws/aws-sdk-go-v2/service/codedeploy/types"
	"github.com/aws/aws-sdk-go-v2/service/codepipeline"
	codepipelinetypes "github.com/aws/aws-sdk-go-v2/service/codepipeline/types"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentity"
	cognitoidtypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentity/types"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	cognitoidptypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/aws/aws-sdk-go-v2/service/databasemigrationservice"
	dmstypes "github.com/aws/aws-sdk-go-v2/service/databasemigrationservice/types"
	"github.com/aws/aws-sdk-go-v2/service/dax"
	daxtypes "github.com/aws/aws-sdk-go-v2/service/dax/types"
	"github.com/aws/aws-sdk-go-v2/service/docdb"
	docdbtypes "github.com/aws/aws-sdk-go-v2/service/docdb/types"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamodbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	efstypes "github.com/aws/aws-sdk-go-v2/service/efs/types"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	elasticachetypes "github.com/aws/aws-sdk-go-v2/service/elasticache/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk"
	ebtypes "github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticsearchservice"
	estypes "github.com/aws/aws-sdk-go-v2/service/elasticsearchservice/types"
	"github.com/aws/aws-sdk-go-v2/service/emr"
	"github.com/aws/aws-sdk-go-v2/service/fsx"
	fsxtypes "github.com/aws/aws-sdk-go-v2/service/fsx/types"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	gluetypes "github.com/aws/aws-sdk-go-v2/service/glue/types"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	guarddutytypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/mq"
	mqtypes "github.com/aws/aws-sdk-go-v2/service/mq/types"
	"github.com/aws/aws-sdk-go-v2/service/neptune"
	neptunetypes "github.com/aws/aws-sdk-go-v2/service/neptune/types"
	"github.com/aws/aws-sdk-go-v2/service/networkfirewall"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	opentypes "github.com/aws/aws-sdk-go-v2/service/opensearch/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
	redshifttypes "github.com/aws/aws-sdk-go-v2/service/redshift/types"
	"github.com/aws/aws-sdk-go-v2/service/redshiftserverless"
	rsstypes "github.com/aws/aws-sdk-go-v2/service/redshiftserverless/types"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	route53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	sagemakertypes "github.com/aws/aws-sdk-go-v2/service/sagemaker/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	sfntypes "github.com/aws/aws-sdk-go-v2/service/sfn/types"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	snstypes "github.com/aws/aws-sdk-go-v2/service/sns/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/transfer"
	transfertypes "github.com/aws/aws-sdk-go-v2/service/transfer/types"
	"github.com/aws/aws-sdk-go-v2/service/waf"
	waftypes "github.com/aws/aws-sdk-go-v2/service/waf/types"
	"github.com/aws/aws-sdk-go-v2/service/wafregional"
	wafregionaltypes "github.com/aws/aws-sdk-go-v2/service/wafregional/types"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	wafv2types "github.com/aws/aws-sdk-go-v2/service/wafv2/types"
	"github.com/aws/aws-sdk-go-v2/service/workspaces"
	workspacestypes "github.com/aws/aws-sdk-go-v2/service/workspaces/types"
)

// Data holds all memoized AWS API call results.
type Data struct {
	Ctx     context.Context
	Clients *Clients

	// STS
	AccountID *cache.Memo[string]

	// IAM
	IAMUsers                 *cache.Memo[[]iamtypes.User]
	IAMRoles                 *cache.Memo[[]iamtypes.Role]
	IAMGroups                *cache.Memo[[]iamtypes.Group]
	IAMPolicies              *cache.Memo[[]iamtypes.Policy]
	IAMServerCertificates    *cache.Memo[[]iamtypes.ServerCertificateMetadata]
	IAMCredentialReport      *cache.Memo[[]byte]
	IAMAccountPasswordPolicy *cache.Memo[*iamtypes.PasswordPolicy]
	IAMAccountSummary        *cache.Memo[map[string]int32]
	IAMSAMLProviders         *cache.Memo[[]iamtypes.SAMLProviderListEntry]
	IAMOIDCProviders         *cache.Memo[[]string]
	IAMVirtualMFADevices     *cache.Memo[[]iamtypes.VirtualMFADevice]

	// Organizations
	OrgAccount *cache.Memo[*organizations.DescribeOrganizationOutput]

	// EC2
	EC2Instances                    *cache.Memo[[]ec2types.Reservation]
	EC2SecurityGroups               *cache.Memo[[]ec2types.SecurityGroup]
	EC2Volumes                      *cache.Memo[[]ec2types.Volume]
	EC2VPCs                         *cache.Memo[[]ec2types.Vpc]
	EC2Subnets                      *cache.Memo[[]ec2types.Subnet]
	EC2RouteTables                  *cache.Memo[[]ec2types.RouteTable]
	EC2NetworkACLs                  *cache.Memo[[]ec2types.NetworkAcl]
	EC2InternetGateways             *cache.Memo[[]ec2types.InternetGateway]
	EC2NATGateways                  *cache.Memo[[]ec2types.NatGateway]
	EC2NetworkInterfaces            *cache.Memo[[]ec2types.NetworkInterface]
	EC2Addresses                    *cache.Memo[[]ec2types.Address]
	EC2Snapshots                    *cache.Memo[[]ec2types.Snapshot]
	EC2LaunchTemplates              *cache.Memo[[]ec2types.LaunchTemplate]
	EC2LaunchTemplateVersions       *cache.Memo[map[string]ec2types.LaunchTemplateVersion]
	EC2TransitGateways              *cache.Memo[[]ec2types.TransitGateway]
	EC2VPNConnections               *cache.Memo[[]ec2types.VpnConnection]
	EC2FlowLogs                     *cache.Memo[[]ec2types.FlowLog]
	EC2VPCEndpoints                 *cache.Memo[[]ec2types.VpcEndpoint]
	EC2VPCPeeringConnections        *cache.Memo[[]ec2types.VpcPeeringConnection]
	EC2PrefixLists                  *cache.Memo[[]ec2types.ManagedPrefixList]
	EC2Fleets                       *cache.Memo[[]ec2types.FleetData]
	EC2CapacityReservations         *cache.Memo[[]ec2types.CapacityReservation]
	EC2DHCPOptions                  *cache.Memo[[]ec2types.DhcpOptions]
	EC2ClientVPNEndpoints           *cache.Memo[[]ec2types.ClientVpnEndpoint]
	EC2EBSEncryptionByDefault       *cache.Memo[bool]
	EC2EBSSnapshotBlockPublicAccess *cache.Memo[string]

	// S3
	S3Buckets *cache.Memo[[]s3types.Bucket]

	// RDS
	RDSDBInstances     *cache.Memo[[]rdstypes.DBInstance]
	RDSDBClusters      *cache.Memo[[]rdstypes.DBCluster]
	RDSSnapshots       *cache.Memo[[]rdstypes.DBSnapshot]
	RDSOptionGroups    *cache.Memo[[]rdstypes.OptionGroup]
	RDSEventSubs       *cache.Memo[[]rdstypes.EventSubscription]
	RDSProxies         *cache.Memo[[]rdstypes.DBProxy]
	RDSDBSubnetGroups  *cache.Memo[[]rdstypes.DBSubnetGroup]
	RDSEventSubTags    *cache.Memo[map[string]map[string]string]
	RDSOptionGroupTags *cache.Memo[map[string]map[string]string]
	RDSDBParamValues   *cache.Memo[map[string]map[string]string]

	// Lambda
	LambdaFunctions *cache.Memo[[]lambdatypes.FunctionConfiguration]

	// DynamoDB
	DynamoDBTableNames  *cache.Memo[[]string]
	DynamoDBTables      *cache.Memo[map[string]dynamodbtypes.TableDescription]
	DynamoDBPITR        *cache.Memo[map[string]bool]
	DynamoDBAutoScaling *cache.Memo[map[string]bool]

	// ECS
	ECSClusters             *cache.Memo[[]string]
	ECSTaskDefinitions      *cache.Memo[[]string]
	ECSClusterDetails       *cache.Memo[map[string]ecstypes.Cluster]
	ECSTaskDefDetails       *cache.Memo[map[string]ecstypes.TaskDefinition]
	ECSCapacityProviders    *cache.Memo[[]ecstypes.CapacityProvider]
	ECSCapacityProviderTags *cache.Memo[map[string]map[string]string]
	ECSServicesByCluster    *cache.Memo[map[string][]ecstypes.Service]

	// EKS
	EKSClusterNames    *cache.Memo[[]string]
	EKSClusters        *cache.Memo[map[string]ekstypes.Cluster]
	EKSAddons          *cache.Memo[map[string][]ekstypes.Addon]
	EKSFargateProfiles *cache.Memo[map[string][]ekstypes.FargateProfile]

	// ElastiCache
	ElastiCacheClusters     *cache.Memo[[]elasticachetypes.CacheCluster]
	ElastiCacheReplGroups   *cache.Memo[[]elasticachetypes.ReplicationGroup]
	ElastiCacheSubnetGroups *cache.Memo[[]elasticachetypes.CacheSubnetGroup]

	// CloudTrail
	CloudTrailTrails *cache.Memo[[]cloudtrailtypes.TrailInfo]

	// CloudWatch
	CloudWatchAlarms        *cache.Memo[[]cloudwatchtypes.MetricAlarm]
	CloudWatchLogGroups     *cache.Memo[[]logstypes.LogGroup]
	CloudWatchMetricStreams *cache.Memo[[]cloudwatchtypes.MetricStreamEntry]

	// CloudFront
	CloudFrontDistributions        *cache.Memo[[]cftypescf.DistributionSummary]
	CloudFrontDistributionConfigs  *cache.Memo[map[string]cftypescf.DistributionConfig]
	CloudFrontDistributionTags     *cache.Memo[map[string]map[string]string]
	CloudFrontDistributionARNs     *cache.Memo[map[string]string]
	CloudFrontDistributionWAF      *cache.Memo[map[string]bool]
	CloudFrontS3OriginBucketExists *cache.Memo[map[string]bool]

	// CloudFormation
	CloudFormationStacks *cache.Memo[[]cftypes.StackSummary]

	// ACM
	ACMCertificates       *cache.Memo[[]acmtypes.CertificateSummary]
	ACMCertificateDetails *cache.Memo[map[string]acmtypes.CertificateDetail]

	// ACM PCA
	ACMPCACertificateAuthorities   *cache.Memo[[]acmpcatypes.CertificateAuthority]
	ACMPCACertificateAuthorityTags *cache.Memo[map[string]map[string]string]

	// KMS
	KMSKeys *cache.Memo[[]kmstypes.KeyListEntry]

	// SNS
	SNSTopics *cache.Memo[[]snstypes.Topic]

	// SQS
	SQSQueues *cache.Memo[[]string]

	// Secrets Manager
	SecretsManagerSecrets *cache.Memo[[]smtypes.SecretListEntry]

	// SSM
	SSMDocuments *cache.Memo[[]ssmtypes.DocumentIdentifier]

	// Step Functions
	SFNStateMachines *cache.Memo[[]sfntypes.StateMachineListItem]

	// Redshift
	RedshiftClusters            *cache.Memo[[]redshifttypes.Cluster]
	RedshiftParamGroups         *cache.Memo[[]redshifttypes.ClusterParameterGroup]
	RedshiftClusterSubnetGroups *cache.Memo[[]redshifttypes.ClusterSubnetGroup]
	RedshiftLoggingStatus       *cache.Memo[map[string]redshift.DescribeLoggingStatusOutput]
	RedshiftParamGroupTags      *cache.Memo[map[string]map[string]string]
	RedshiftParamValues         *cache.Memo[map[string]map[string]string]

	// Redshift Serverless
	RedshiftServerlessWorkgroups *cache.Memo[[]rsstypes.Workgroup]
	RedshiftServerlessNamespaces *cache.Memo[[]rsstypes.Namespace]

	// EFS
	EFSFileSystems    *cache.Memo[[]efstypes.FileSystemDescription]
	EFSAccessPoints   *cache.Memo[[]efstypes.AccessPointDescription]
	EFSFileSystemTags *cache.Memo[map[string]map[string]string]
	EFSMountTargets   *cache.Memo[map[string][]efstypes.MountTargetDescription]
	EFSBackupPolicies *cache.Memo[map[string]bool]

	// ELB
	ELBClassicLBs        *cache.Memo[[]elbtypes.LoadBalancerDescription]
	ELBClassicTags       *cache.Memo[map[string]map[string]string]
	ELBClassicAttributes *cache.Memo[map[string]elbtypes.LoadBalancerAttributes]
	ELBClassicPolicies   *cache.Memo[map[string][]elbtypes.PolicyDescription]

	// ELBv2
	ELBv2LoadBalancers *cache.Memo[[]elbv2types.LoadBalancer]
	ELBv2Listeners     *cache.Memo[[]elbv2types.Listener]
	ELBv2TargetGroups  *cache.Memo[[]elbv2types.TargetGroup]
	ELBv2Tags          *cache.Memo[map[string]map[string]string]
	ELBv2LBAttributes  *cache.Memo[map[string]map[string]string]

	// ECR
	ECRRepositories *cache.Memo[[]ecrtypes.Repository]

	// Neptune
	NeptuneClusters  *cache.Memo[[]neptunetypes.DBCluster]
	NeptuneSnapshots *cache.Memo[[]neptunetypes.DBClusterSnapshot]

	// OpenSearch
	OpenSearchDomains *cache.Memo[[]opentypes.DomainStatus]

	// Elasticsearch
	ElasticsearchDomains *cache.Memo[[]estypes.ElasticsearchDomainStatus]

	// Glue
	GlueJobs *cache.Memo[[]gluetypes.Job]

	// GuardDuty
	GuardDutyDetectorIDs         *cache.Memo[[]string]
	GuardDutyDetectors           *cache.Memo[map[string]guardduty.GetDetectorOutput]
	GuardDutyNonArchivedFindings *cache.Memo[map[string]int]

	// Backup
	BackupPlans                    *cache.Memo[[]backuptypes.BackupPlansListMember]
	BackupVaults                   *cache.Memo[[]backuptypes.BackupVaultListMember]
	BackupPlanDetails              *cache.Memo[map[string]backuptypes.BackupPlan]
	BackupRecoveryPoints           *cache.Memo[map[string][]backuptypes.RecoveryPointByBackupVault]
	BackupVaultLockConfigs         *cache.Memo[map[string]backuptypes.BackupVaultLockConfiguration]
	BackupProtectedResources       *cache.Memo[map[string]backuptypes.ProtectedResource]
	BackupRecoveryPointsByResource *cache.Memo[map[string][]backuptypes.RecoveryPointByResource]

	// DocDB
	DocDBClusters *cache.Memo[[]docdbtypes.DBCluster]

	// DAX
	DAXClusters *cache.Memo[[]daxtypes.Cluster]

	// DMS
	DMSReplicationInstances *cache.Memo[[]dmstypes.ReplicationInstance]
	DMSEndpoints            *cache.Memo[[]dmstypes.Endpoint]
	DMSReplicationTasks     *cache.Memo[[]dmstypes.ReplicationTask]
	DMSEndpointTags         *cache.Memo[map[string]map[string]string]
	DMSReplicationTaskTags  *cache.Memo[map[string]map[string]string]

	// Batch
	BatchComputeEnvs          *cache.Memo[[]batchtypes.ComputeEnvironmentDetail]
	BatchJobQueues            *cache.Memo[[]batchtypes.JobQueueDetail]
	BatchSchedulingPolicies   *cache.Memo[[]batchtypes.SchedulingPolicyListingDetail]
	BatchComputeEnvTags       *cache.Memo[map[string]map[string]string]
	BatchJobQueueTags         *cache.Memo[map[string]map[string]string]
	BatchSchedulingPolicyTags *cache.Memo[map[string]map[string]string]

	// CodeBuild
	CodeBuildProjects     *cache.Memo[[]codebuildtypes.Project]
	CodeBuildReportGroups *cache.Memo[[]string]

	// CodeDeploy
	CodeDeployApps *cache.Memo[[]string]

	// CodePipeline
	CodePipelines *cache.Memo[[]codepipelinetypes.PipelineSummary]

	// Cognito
	CognitoUserPools     *cache.Memo[[]cognitoidptypes.UserPoolDescriptionType]
	CognitoIdentityPools *cache.Memo[[]cognitoidtypes.IdentityPoolShortDescription]

	// FSx
	FSxFileSystems    *cache.Memo[[]fsxtypes.FileSystem]
	FSxFileSystemTags *cache.Memo[map[string]map[string]string]

	// EMR
	EMRClusters *cache.Memo[[]string]

	// Athena
	AthenaWorkgroups         *cache.Memo[[]athenatypes.WorkgroupSummary]
	AthenaWorkgroupDetails   *cache.Memo[map[string]athenatypes.WorkGroup]
	AthenaDataCatalogs       *cache.Memo[[]athenatypes.DataCatalog]
	AthenaPreparedStatements *cache.Memo[[]athenatypes.PreparedStatementSummary]

	// AppSync
	AppSyncAPIs                   *cache.Memo[[]appsynctypes.GraphqlApi]
	AppSyncTags                   *cache.Memo[map[string]map[string]string]
	AppSyncWAFv2WebACLForResource *cache.Memo[map[string]bool]

	// API Gateway
	APIGatewayRestAPIs    *cache.Memo[[]apigwtypes.RestApi]
	APIGatewayStages      *cache.Memo[map[string][]apigwtypes.Stage]
	APIGatewayTags        *cache.Memo[map[string]map[string]string]
	APIGatewayStageTags   *cache.Memo[map[string]map[string]string]
	APIGatewayDomainNames *cache.Memo[[]apigwtypes.DomainName]
	APIGatewayStageWAF    *cache.Memo[map[string]bool]

	// API Gateway V2
	APIGatewayV2APIs   *cache.Memo[[]apigwv2types.Api]
	APIGatewayV2Stages *cache.Memo[map[string][]apigwv2types.Stage]
	APIGatewayV2Routes *cache.Memo[map[string][]apigwv2types.Route]
	APIGatewayV2Tags   *cache.Memo[map[string]map[string]string]

	// Amplify
	AmplifyApps       *cache.Memo[[]amplifytypes.App]
	AmplifyBranches   *cache.Memo[map[string][]amplifytypes.Branch]
	AmplifyAppTags    *cache.Memo[map[string]map[string]string]
	AmplifyBranchTags *cache.Memo[map[string]map[string]string]

	// AppConfig
	AppConfigApplications          *cache.Memo[[]appconfigtypes.Application]
	AppConfigEnvironments          *cache.Memo[map[string][]appconfigtypes.Environment]
	AppConfigProfiles              *cache.Memo[map[string][]appconfigtypes.ConfigurationProfileSummary]
	AppConfigDeploymentStrategies  *cache.Memo[[]appconfigtypes.DeploymentStrategy]
	AppConfigExtensionAssociations *cache.Memo[[]appconfigtypes.ExtensionAssociationSummary]
	AppConfigHostedConfigVersions  *cache.Memo[map[string][]appconfigtypes.HostedConfigurationVersionSummary]

	// AppFlow
	AppFlowFlows       *cache.Memo[[]appflowtypes.FlowDefinition]
	AppFlowFlowDetails *cache.Memo[map[string]appflow.DescribeFlowOutput]
	AppFlowTags        *cache.Memo[map[string]map[string]string]

	// AppRunner
	AppRunnerServices         *cache.Memo[[]apprunnertypes.ServiceSummary]
	AppRunnerVPCConnectors    *cache.Memo[[]apprunnertypes.VpcConnector]
	AppRunnerServiceDetails   *cache.Memo[map[string]apprunnertypes.Service]
	AppRunnerServiceTags      *cache.Memo[map[string]map[string]string]
	AppRunnerVPCConnectorTags *cache.Memo[map[string]map[string]string]

	// AppIntegrations
	AppIntegrationsEventIntegrations *cache.Memo[[]appintegrationstypes.EventIntegration]
	AppIntegrationsTags              *cache.Memo[map[string]map[string]string]

	// AppMesh
	AppMeshMeshes                *cache.Memo[[]appmeshtypes.MeshRef]
	AppMeshMeshDetails           *cache.Memo[map[string]appmeshtypes.MeshData]
	AppMeshVirtualNodes          *cache.Memo[map[string][]appmeshtypes.VirtualNodeRef]
	AppMeshVirtualNodeDetails    *cache.Memo[map[string]appmeshtypes.VirtualNodeData]
	AppMeshVirtualRouters        *cache.Memo[map[string][]appmeshtypes.VirtualRouterRef]
	AppMeshVirtualServices       *cache.Memo[map[string][]appmeshtypes.VirtualServiceRef]
	AppMeshVirtualGateways       *cache.Memo[map[string][]appmeshtypes.VirtualGatewayRef]
	AppMeshVirtualGatewayDetails *cache.Memo[map[string]appmeshtypes.VirtualGatewayData]
	AppMeshRoutes                *cache.Memo[map[string][]appmeshtypes.RouteRef]
	AppMeshGatewayRoutes         *cache.Memo[map[string][]appmeshtypes.GatewayRouteRef]
	AppMeshTags                  *cache.Memo[map[string]map[string]string]

	// AutoScaling
	AutoScalingGroups        *cache.Memo[[]autoscalingtypes.AutoScalingGroup]
	AutoScalingLaunchConfigs *cache.Memo[[]autoscalingtypes.LaunchConfiguration]

	// Kinesis
	KinesisStreams *cache.Memo[[]string]

	// Route53
	Route53HostedZones  *cache.Memo[[]route53types.HostedZone]
	Route53HealthChecks *cache.Memo[[]route53types.HealthCheck]

	// SageMaker
	SageMakerNotebooks             *cache.Memo[[]sagemakertypes.NotebookInstanceSummary]
	SageMakerEndpointConfigs       *cache.Memo[[]sagemakertypes.EndpointConfigSummary]
	SageMakerDomains               *cache.Memo[[]sagemakertypes.DomainDetails]
	SageMakerModels                *cache.Memo[[]sagemakertypes.ModelSummary]
	SageMakerNotebookDetails       *cache.Memo[map[string]sagemakertypes.NotebookInstance]
	SageMakerEndpointConfigDetails *cache.Memo[map[string]sagemakertypes.EndpointConfig]
	SageMakerDomainTags            *cache.Memo[map[string]map[string]string]
	SageMakerModelDetails          *cache.Memo[map[string]sagemakertypes.Model]
	SageMakerFeatureGroups         *cache.Memo[[]sagemakertypes.FeatureGroupSummary]
	SageMakerFeatureGroupTags      *cache.Memo[map[string]map[string]string]
	SageMakerImages                *cache.Memo[[]sagemakertypes.ImageSummary]
	SageMakerImageDetails          *cache.Memo[map[string]sagemaker.DescribeImageOutput]
	SageMakerImageTags             *cache.Memo[map[string]map[string]string]
	SageMakerAppImageConfigs       *cache.Memo[[]sagemakertypes.AppImageConfigSummary]
	SageMakerAppImageConfigTags    *cache.Memo[map[string]map[string]string]

	// Transfer
	TransferServers            *cache.Memo[[]transfertypes.ListedServer]
	TransferServerDetails      *cache.Memo[map[string]transfertypes.DescribedServer]
	TransferAgreements         *cache.Memo[[]transfertypes.ListedAgreement]
	TransferAgreementDetails   *cache.Memo[map[string]transfertypes.DescribedAgreement]
	TransferCertificates       *cache.Memo[[]transfertypes.ListedCertificate]
	TransferCertificateDetails *cache.Memo[map[string]transfertypes.DescribedCertificate]
	TransferConnectors         *cache.Memo[[]transfertypes.ListedConnector]
	TransferConnectorDetails   *cache.Memo[map[string]transfertypes.DescribedConnector]
	TransferProfiles           *cache.Memo[[]transfertypes.ListedProfile]
	TransferProfileDetails     *cache.Memo[map[string]transfertypes.DescribedProfile]
	TransferWorkflows          *cache.Memo[[]transfertypes.ListedWorkflow]
	TransferWorkflowDetails    *cache.Memo[map[string]transfertypes.DescribedWorkflow]
	TransferTags               *cache.Memo[map[string]map[string]string]

	// MQ
	MQBrokers       *cache.Memo[[]mqtypes.BrokerSummary]
	MQBrokerDetails *cache.Memo[map[string]mq.DescribeBrokerOutput]

	// Network Firewall
	NetworkFirewalls *cache.Memo[[]networkfirewall.ListFirewallsOutput]

	// WAF
	WAFWebACLs    *cache.Memo[[]waftypes.WebACLSummary]
	WAFRules      *cache.Memo[[]waftypes.RuleSummary]
	WAFRuleGroups *cache.Memo[[]waftypes.RuleGroupSummary]

	// WAF Regional
	WAFRegionalWebACLs    *cache.Memo[[]wafregionaltypes.WebACLSummary]
	WAFRegionalRules      *cache.Memo[[]wafregionaltypes.RuleSummary]
	WAFRegionalRuleGroups *cache.Memo[[]wafregionaltypes.RuleGroupSummary]

	// WAFv2
	WAFv2WebACLs           *cache.Memo[[]wafv2types.WebACLSummary]
	WAFv2RuleGroups        *cache.Memo[[]wafv2types.RuleGroupSummary]
	WAFv2WebACLForResource *cache.Memo[map[string]bool]

	// Workspaces
	Workspaces *cache.Memo[[]workspacestypes.Workspace]

	// ElasticBeanstalk
	ElasticBeanstalkApps        *cache.Memo[[]ebtypes.ApplicationDescription]
	ElasticBeanstalkEnvs        *cache.Memo[[]ebtypes.EnvironmentDescription]
	ElasticBeanstalkAppVersions *cache.Memo[[]ebtypes.ApplicationVersionDescription]
}

// New creates a Data struct with all memoized API calls wired up.
func New(ctx context.Context, clients *Clients) *Data {
	d := &Data{Ctx: ctx, Clients: clients}
	d.init()
	return d
}

func (d *Data) init() {
	ctx := d.Ctx
	c := d.Clients

	// STS
	d.AccountID = cache.New(func() (string, error) {
		out, err := c.STS.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
		if err != nil {
			return "", err
		}
		return *out.Account, nil
	})

	// Organizations
	d.OrgAccount = cache.New(func() (*organizations.DescribeOrganizationOutput, error) {
		return c.Organizations.DescribeOrganization(ctx, &organizations.DescribeOrganizationInput{})
	})

	// IAM
	d.IAMUsers = cache.New(func() ([]iamtypes.User, error) {
		out, err := c.IAM.ListUsers(ctx, &iam.ListUsersInput{})
		if err != nil {
			return nil, err
		}
		return out.Users, nil
	})
	d.IAMRoles = cache.New(func() ([]iamtypes.Role, error) {
		out, err := c.IAM.ListRoles(ctx, &iam.ListRolesInput{})
		if err != nil {
			return nil, err
		}
		return out.Roles, nil
	})
	d.IAMGroups = cache.New(func() ([]iamtypes.Group, error) {
		out, err := c.IAM.ListGroups(ctx, &iam.ListGroupsInput{})
		if err != nil {
			return nil, err
		}
		return out.Groups, nil
	})
	d.IAMPolicies = cache.New(func() ([]iamtypes.Policy, error) {
		out, err := c.IAM.ListPolicies(ctx, &iam.ListPoliciesInput{Scope: iamtypes.PolicyScopeTypeLocal})
		if err != nil {
			return nil, err
		}
		return out.Policies, nil
	})
	d.IAMServerCertificates = cache.New(func() ([]iamtypes.ServerCertificateMetadata, error) {
		out, err := c.IAM.ListServerCertificates(ctx, &iam.ListServerCertificatesInput{})
		if err != nil {
			return nil, err
		}
		return out.ServerCertificateMetadataList, nil
	})
	d.IAMCredentialReport = cache.New(func() ([]byte, error) {
		_, _ = c.IAM.GenerateCredentialReport(ctx, &iam.GenerateCredentialReportInput{})
		out, err := c.IAM.GetCredentialReport(ctx, &iam.GetCredentialReportInput{})
		if err != nil {
			return nil, err
		}
		return out.Content, nil
	})
	d.IAMAccountPasswordPolicy = cache.New(func() (*iamtypes.PasswordPolicy, error) {
		out, err := c.IAM.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{})
		if err != nil {
			return nil, err
		}
		return out.PasswordPolicy, nil
	})
	d.IAMAccountSummary = cache.New(func() (map[string]int32, error) {
		out, err := c.IAM.GetAccountAuthorizationDetails(ctx, &iam.GetAccountAuthorizationDetailsInput{})
		if err != nil {
			// fallback
			sum, err2 := c.IAM.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
			if err2 != nil {
				return nil, err
			}
			return sum.SummaryMap, nil
		}
		_ = out
		sum, err := c.IAM.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
		if err != nil {
			return nil, err
		}
		return sum.SummaryMap, nil
	})
	d.IAMSAMLProviders = cache.New(func() ([]iamtypes.SAMLProviderListEntry, error) {
		out, err := c.IAM.ListSAMLProviders(ctx, &iam.ListSAMLProvidersInput{})
		if err != nil {
			return nil, err
		}
		return out.SAMLProviderList, nil
	})
	d.IAMOIDCProviders = cache.New(func() ([]string, error) {
		out, err := c.IAM.ListOpenIDConnectProviders(ctx, &iam.ListOpenIDConnectProvidersInput{})
		if err != nil {
			return nil, err
		}
		var arns []string
		for _, p := range out.OpenIDConnectProviderList {
			if p.Arn != nil {
				arns = append(arns, *p.Arn)
			}
		}
		return arns, nil
	})
	d.IAMVirtualMFADevices = cache.New(func() ([]iamtypes.VirtualMFADevice, error) {
		out, err := c.IAM.ListVirtualMFADevices(ctx, &iam.ListVirtualMFADevicesInput{})
		if err != nil {
			return nil, err
		}
		return out.VirtualMFADevices, nil
	})

	// EC2
	d.EC2Instances = cache.New(func() ([]ec2types.Reservation, error) {
		out, err := c.EC2.DescribeInstances(ctx, &ec2.DescribeInstancesInput{})
		if err != nil {
			return nil, err
		}
		return out.Reservations, nil
	})
	d.EC2SecurityGroups = cache.New(func() ([]ec2types.SecurityGroup, error) {
		out, err := c.EC2.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
		if err != nil {
			return nil, err
		}
		return out.SecurityGroups, nil
	})
	d.EC2Volumes = cache.New(func() ([]ec2types.Volume, error) {
		out, err := c.EC2.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{})
		if err != nil {
			return nil, err
		}
		return out.Volumes, nil
	})
	d.EC2VPCs = cache.New(func() ([]ec2types.Vpc, error) {
		out, err := c.EC2.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{})
		if err != nil {
			return nil, err
		}
		return out.Vpcs, nil
	})
	d.EC2Subnets = cache.New(func() ([]ec2types.Subnet, error) {
		out, err := c.EC2.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{})
		if err != nil {
			return nil, err
		}
		return out.Subnets, nil
	})
	d.EC2RouteTables = cache.New(func() ([]ec2types.RouteTable, error) {
		out, err := c.EC2.DescribeRouteTables(ctx, &ec2.DescribeRouteTablesInput{})
		if err != nil {
			return nil, err
		}
		return out.RouteTables, nil
	})
	d.EC2NetworkACLs = cache.New(func() ([]ec2types.NetworkAcl, error) {
		out, err := c.EC2.DescribeNetworkAcls(ctx, &ec2.DescribeNetworkAclsInput{})
		if err != nil {
			return nil, err
		}
		return out.NetworkAcls, nil
	})
	d.EC2InternetGateways = cache.New(func() ([]ec2types.InternetGateway, error) {
		out, err := c.EC2.DescribeInternetGateways(ctx, &ec2.DescribeInternetGatewaysInput{})
		if err != nil {
			return nil, err
		}
		return out.InternetGateways, nil
	})
	d.EC2NATGateways = cache.New(func() ([]ec2types.NatGateway, error) {
		out, err := c.EC2.DescribeNatGateways(ctx, &ec2.DescribeNatGatewaysInput{})
		if err != nil {
			return nil, err
		}
		return out.NatGateways, nil
	})
	d.EC2NetworkInterfaces = cache.New(func() ([]ec2types.NetworkInterface, error) {
		out, err := c.EC2.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{})
		if err != nil {
			return nil, err
		}
		return out.NetworkInterfaces, nil
	})
	d.EC2Addresses = cache.New(func() ([]ec2types.Address, error) {
		out, err := c.EC2.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{})
		if err != nil {
			return nil, err
		}
		return out.Addresses, nil
	})
	d.EC2Snapshots = cache.New(func() ([]ec2types.Snapshot, error) {
		out, err := c.EC2.DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{OwnerIds: []string{"self"}})
		if err != nil {
			return nil, err
		}
		return out.Snapshots, nil
	})
	d.EC2LaunchTemplates = cache.New(func() ([]ec2types.LaunchTemplate, error) {
		out, err := c.EC2.DescribeLaunchTemplates(ctx, &ec2.DescribeLaunchTemplatesInput{})
		if err != nil {
			return nil, err
		}
		return out.LaunchTemplates, nil
	})
	d.EC2LaunchTemplateVersions = cache.New(func() (map[string]ec2types.LaunchTemplateVersion, error) {
		lts, err := d.EC2LaunchTemplates.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]ec2types.LaunchTemplateVersion)
		for _, lt := range lts {
			if lt.LaunchTemplateId == nil || lt.DefaultVersionNumber == nil {
				continue
			}
			ver := fmt.Sprintf("%d", *lt.DefaultVersionNumber)
			vers, err := c.EC2.DescribeLaunchTemplateVersions(ctx, &ec2.DescribeLaunchTemplateVersionsInput{LaunchTemplateId: lt.LaunchTemplateId, Versions: []string{ver}})
			if err != nil || len(vers.LaunchTemplateVersions) == 0 {
				continue
			}
			out[*lt.LaunchTemplateId] = vers.LaunchTemplateVersions[0]
		}
		return out, nil
	})
	d.EC2TransitGateways = cache.New(func() ([]ec2types.TransitGateway, error) {
		out, err := c.EC2.DescribeTransitGateways(ctx, &ec2.DescribeTransitGatewaysInput{})
		if err != nil {
			return nil, err
		}
		return out.TransitGateways, nil
	})
	d.EC2VPNConnections = cache.New(func() ([]ec2types.VpnConnection, error) {
		out, err := c.EC2.DescribeVpnConnections(ctx, &ec2.DescribeVpnConnectionsInput{})
		if err != nil {
			return nil, err
		}
		return out.VpnConnections, nil
	})
	d.EC2FlowLogs = cache.New(func() ([]ec2types.FlowLog, error) {
		out, err := c.EC2.DescribeFlowLogs(ctx, &ec2.DescribeFlowLogsInput{})
		if err != nil {
			return nil, err
		}
		return out.FlowLogs, nil
	})
	d.EC2VPCEndpoints = cache.New(func() ([]ec2types.VpcEndpoint, error) {
		out, err := c.EC2.DescribeVpcEndpoints(ctx, &ec2.DescribeVpcEndpointsInput{})
		if err != nil {
			return nil, err
		}
		return out.VpcEndpoints, nil
	})
	d.EC2VPCPeeringConnections = cache.New(func() ([]ec2types.VpcPeeringConnection, error) {
		out, err := c.EC2.DescribeVpcPeeringConnections(ctx, &ec2.DescribeVpcPeeringConnectionsInput{})
		if err != nil {
			return nil, err
		}
		return out.VpcPeeringConnections, nil
	})
	d.EC2PrefixLists = cache.New(func() ([]ec2types.ManagedPrefixList, error) {
		out, err := c.EC2.DescribeManagedPrefixLists(ctx, &ec2.DescribeManagedPrefixListsInput{})
		if err != nil {
			return nil, err
		}
		return out.PrefixLists, nil
	})
	d.EC2Fleets = cache.New(func() ([]ec2types.FleetData, error) {
		out, err := c.EC2.DescribeFleets(ctx, &ec2.DescribeFleetsInput{})
		if err != nil {
			return nil, err
		}
		return out.Fleets, nil
	})
	d.EC2CapacityReservations = cache.New(func() ([]ec2types.CapacityReservation, error) {
		out, err := c.EC2.DescribeCapacityReservations(ctx, &ec2.DescribeCapacityReservationsInput{})
		if err != nil {
			return nil, err
		}
		return out.CapacityReservations, nil
	})
	d.EC2DHCPOptions = cache.New(func() ([]ec2types.DhcpOptions, error) {
		out, err := c.EC2.DescribeDhcpOptions(ctx, &ec2.DescribeDhcpOptionsInput{})
		if err != nil {
			return nil, err
		}
		return out.DhcpOptions, nil
	})
	d.EC2ClientVPNEndpoints = cache.New(func() ([]ec2types.ClientVpnEndpoint, error) {
		out, err := c.EC2.DescribeClientVpnEndpoints(ctx, &ec2.DescribeClientVpnEndpointsInput{})
		if err != nil {
			return nil, err
		}
		return out.ClientVpnEndpoints, nil
	})
	d.EC2EBSEncryptionByDefault = cache.New(func() (bool, error) {
		out, err := c.EC2.GetEbsEncryptionByDefault(ctx, &ec2.GetEbsEncryptionByDefaultInput{})
		if err != nil {
			return false, err
		}
		if out.EbsEncryptionByDefault != nil {
			return *out.EbsEncryptionByDefault, nil
		}
		return false, nil
	})
	d.EC2EBSSnapshotBlockPublicAccess = cache.New(func() (string, error) {
		out, err := c.EC2.GetSnapshotBlockPublicAccessState(ctx, &ec2.GetSnapshotBlockPublicAccessStateInput{})
		if err != nil {
			return "", err
		}
		return string(out.State), nil
	})

	// S3
	d.S3Buckets = cache.New(func() ([]s3types.Bucket, error) {
		out, err := c.S3.ListBuckets(ctx, &s3.ListBucketsInput{})
		if err != nil {
			return nil, err
		}
		return out.Buckets, nil
	})

	// RDS
	d.RDSDBInstances = cache.New(func() ([]rdstypes.DBInstance, error) {
		out, err := c.RDS.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{})
		if err != nil {
			return nil, err
		}
		return out.DBInstances, nil
	})
	d.RDSDBClusters = cache.New(func() ([]rdstypes.DBCluster, error) {
		out, err := c.RDS.DescribeDBClusters(ctx, &rds.DescribeDBClustersInput{})
		if err != nil {
			return nil, err
		}
		return out.DBClusters, nil
	})
	d.RDSSnapshots = cache.New(func() ([]rdstypes.DBSnapshot, error) {
		out, err := c.RDS.DescribeDBSnapshots(ctx, &rds.DescribeDBSnapshotsInput{})
		if err != nil {
			return nil, err
		}
		return out.DBSnapshots, nil
	})
	d.RDSOptionGroups = cache.New(func() ([]rdstypes.OptionGroup, error) {
		out, err := c.RDS.DescribeOptionGroups(ctx, &rds.DescribeOptionGroupsInput{})
		if err != nil {
			return nil, err
		}
		return out.OptionGroupsList, nil
	})
	d.RDSEventSubs = cache.New(func() ([]rdstypes.EventSubscription, error) {
		out, err := c.RDS.DescribeEventSubscriptions(ctx, &rds.DescribeEventSubscriptionsInput{})
		if err != nil {
			return nil, err
		}
		return out.EventSubscriptionsList, nil
	})
	d.RDSProxies = cache.New(func() ([]rdstypes.DBProxy, error) {
		out, err := c.RDS.DescribeDBProxies(ctx, &rds.DescribeDBProxiesInput{})
		if err != nil {
			return nil, err
		}
		return out.DBProxies, nil
	})
	d.RDSDBSubnetGroups = cache.New(func() ([]rdstypes.DBSubnetGroup, error) {
		out, err := c.RDS.DescribeDBSubnetGroups(ctx, &rds.DescribeDBSubnetGroupsInput{})
		if err != nil {
			return nil, err
		}
		return out.DBSubnetGroups, nil
	})
	d.RDSEventSubTags = cache.New(func() (map[string]map[string]string, error) {
		subs, err := d.RDSEventSubs.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, s := range subs {
			if s.EventSubscriptionArn == nil {
				continue
			}
			tags, err := c.RDS.ListTagsForResource(ctx, &rds.ListTagsForResourceInput{ResourceName: s.EventSubscriptionArn})
			if err != nil {
				continue
			}
			m := make(map[string]string)
			for _, t := range tags.TagList {
				if t.Key != nil && t.Value != nil {
					m[*t.Key] = *t.Value
				}
			}
			out[*s.EventSubscriptionArn] = m
		}
		return out, nil
	})
	d.RDSOptionGroupTags = cache.New(func() (map[string]map[string]string, error) {
		ogs, err := d.RDSOptionGroups.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, og := range ogs {
			if og.OptionGroupArn == nil {
				continue
			}
			tags, err := c.RDS.ListTagsForResource(ctx, &rds.ListTagsForResourceInput{ResourceName: og.OptionGroupArn})
			if err != nil {
				continue
			}
			m := make(map[string]string)
			for _, t := range tags.TagList {
				if t.Key != nil && t.Value != nil {
					m[*t.Key] = *t.Value
				}
			}
			out[*og.OptionGroupArn] = m
		}
		return out, nil
	})
	d.RDSDBParamValues = cache.New(func() (map[string]map[string]string, error) {
		instances, err := d.RDSDBInstances.Get()
		if err != nil {
			return nil, err
		}
		groupNames := make(map[string]bool)
		for _, inst := range instances {
			for _, pg := range inst.DBParameterGroups {
				if pg.DBParameterGroupName != nil {
					groupNames[*pg.DBParameterGroupName] = true
				}
			}
		}
		out := make(map[string]map[string]string)
		for name := range groupNames {
			values := make(map[string]string)
			var marker *string
			for {
				resp, err := c.RDS.DescribeDBParameters(ctx, &rds.DescribeDBParametersInput{
					DBParameterGroupName: &name,
					Marker:               marker,
				})
				if err != nil {
					break
				}
				for _, p := range resp.Parameters {
					if p.ParameterName != nil && p.ParameterValue != nil {
						values[*p.ParameterName] = *p.ParameterValue
					}
				}
				if resp.Marker == nil || *resp.Marker == "" {
					break
				}
				marker = resp.Marker
			}
			out[name] = values
		}
		return out, nil
	})

	// Lambda
	d.LambdaFunctions = cache.New(func() ([]lambdatypes.FunctionConfiguration, error) {
		out, err := c.Lambda.ListFunctions(ctx, &lambda.ListFunctionsInput{})
		if err != nil {
			return nil, err
		}
		return out.Functions, nil
	})

	// DynamoDB
	d.DynamoDBTableNames = cache.New(func() ([]string, error) {
		out, err := c.DynamoDB.ListTables(ctx, &dynamodb.ListTablesInput{})
		if err != nil {
			return nil, err
		}
		return out.TableNames, nil
	})
	d.DynamoDBTables = cache.New(func() (map[string]dynamodbtypes.TableDescription, error) {
		names, err := d.DynamoDBTableNames.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]dynamodbtypes.TableDescription)
		for _, name := range names {
			desc, err := c.DynamoDB.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: &name})
			if err != nil || desc.Table == nil {
				continue
			}
			out[name] = *desc.Table
		}
		return out, nil
	})
	d.DynamoDBPITR = cache.New(func() (map[string]bool, error) {
		names, err := d.DynamoDBTableNames.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]bool)
		for _, name := range names {
			desc, err := c.DynamoDB.DescribeContinuousBackups(ctx, &dynamodb.DescribeContinuousBackupsInput{TableName: &name})
			if err != nil || desc.ContinuousBackupsDescription == nil || desc.ContinuousBackupsDescription.PointInTimeRecoveryDescription == nil {
				out[name] = false
				continue
			}
			out[name] = desc.ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus == dynamodbtypes.PointInTimeRecoveryStatusEnabled
		}
		return out, nil
	})
	d.DynamoDBAutoScaling = cache.New(func() (map[string]bool, error) {
		names, err := d.DynamoDBTableNames.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]bool)
		for _, name := range names {
			resourceID := "table/" + name
			resp, err := c.ApplicationAutoScaling.DescribeScalableTargets(ctx, &applicationautoscaling.DescribeScalableTargetsInput{
				ServiceNamespace: applicationautoscalingtypes.ServiceNamespaceDynamodb,
				ResourceIds:      []string{resourceID},
			})
			if err != nil {
				out[name] = false
				continue
			}
			out[name] = len(resp.ScalableTargets) > 0
		}
		return out, nil
	})

	// ECS
	d.ECSClusters = cache.New(func() ([]string, error) {
		out, err := c.ECS.ListClusters(ctx, &ecs.ListClustersInput{})
		if err != nil {
			return nil, err
		}
		return out.ClusterArns, nil
	})
	d.ECSTaskDefinitions = cache.New(func() ([]string, error) {
		out, err := c.ECS.ListTaskDefinitions(ctx, &ecs.ListTaskDefinitionsInput{})
		if err != nil {
			return nil, err
		}
		return out.TaskDefinitionArns, nil
	})
	d.ECSClusterDetails = cache.New(func() (map[string]ecstypes.Cluster, error) {
		arns, err := d.ECSClusters.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]ecstypes.Cluster)
		if len(arns) == 0 {
			return out, nil
		}
		desc, err := c.ECS.DescribeClusters(ctx, &ecs.DescribeClustersInput{Clusters: arns})
		if err != nil {
			return nil, err
		}
		for _, cl := range desc.Clusters {
			if cl.ClusterArn != nil {
				out[*cl.ClusterArn] = cl
			}
		}
		return out, nil
	})
	d.ECSTaskDefDetails = cache.New(func() (map[string]ecstypes.TaskDefinition, error) {
		arns, err := d.ECSTaskDefinitions.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]ecstypes.TaskDefinition)
		for _, arn := range arns {
			td, err := c.ECS.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{TaskDefinition: &arn})
			if err != nil || td.TaskDefinition == nil {
				continue
			}
			out[arn] = *td.TaskDefinition
		}
		return out, nil
	})
	d.ECSCapacityProviders = cache.New(func() ([]ecstypes.CapacityProvider, error) {
		out, err := c.ECS.DescribeCapacityProviders(ctx, &ecs.DescribeCapacityProvidersInput{})
		if err != nil {
			return nil, err
		}
		return out.CapacityProviders, nil
	})
	d.ECSCapacityProviderTags = cache.New(func() (map[string]map[string]string, error) {
		cps, err := d.ECSCapacityProviders.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, cp := range cps {
			if cp.CapacityProviderArn == nil {
				continue
			}
			tags, err := c.ECS.ListTagsForResource(ctx, &ecs.ListTagsForResourceInput{ResourceArn: cp.CapacityProviderArn})
			if err != nil {
				continue
			}
			m := make(map[string]string)
			for _, t := range tags.Tags {
				if t.Key != nil && t.Value != nil {
					m[*t.Key] = *t.Value
				}
			}
			out[*cp.CapacityProviderArn] = m
		}
		return out, nil
	})
	d.ECSServicesByCluster = cache.New(func() (map[string][]ecstypes.Service, error) {
		arns, err := d.ECSClusters.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string][]ecstypes.Service)
		for _, cl := range arns {
			svcList, err := c.ECS.ListServices(ctx, &ecs.ListServicesInput{Cluster: &cl})
			if err != nil {
				continue
			}
			if len(svcList.ServiceArns) == 0 {
				continue
			}
			desc, err := c.ECS.DescribeServices(ctx, &ecs.DescribeServicesInput{Cluster: &cl, Services: svcList.ServiceArns})
			if err != nil {
				continue
			}
			out[cl] = desc.Services
		}
		return out, nil
	})

	// EKS
	d.EKSClusterNames = cache.New(func() ([]string, error) {
		out, err := c.EKS.ListClusters(ctx, &eks.ListClustersInput{})
		if err != nil {
			return nil, err
		}
		return out.Clusters, nil
	})
	d.EKSClusters = cache.New(func() (map[string]ekstypes.Cluster, error) {
		names, err := d.EKSClusterNames.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]ekstypes.Cluster)
		for _, name := range names {
			desc, err := c.EKS.DescribeCluster(ctx, &eks.DescribeClusterInput{Name: &name})
			if err != nil || desc.Cluster == nil {
				continue
			}
			out[name] = *desc.Cluster
		}
		return out, nil
	})
	d.EKSAddons = cache.New(func() (map[string][]ekstypes.Addon, error) {
		names, err := d.EKSClusterNames.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string][]ekstypes.Addon)
		for _, name := range names {
			addons, err := c.EKS.ListAddons(ctx, &eks.ListAddonsInput{ClusterName: &name})
			if err != nil {
				continue
			}
			for _, a := range addons.Addons {
				desc, err := c.EKS.DescribeAddon(ctx, &eks.DescribeAddonInput{ClusterName: &name, AddonName: &a})
				if err != nil || desc.Addon == nil {
					continue
				}
				out[name] = append(out[name], *desc.Addon)
			}
		}
		return out, nil
	})
	d.EKSFargateProfiles = cache.New(func() (map[string][]ekstypes.FargateProfile, error) {
		names, err := d.EKSClusterNames.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string][]ekstypes.FargateProfile)
		for _, name := range names {
			fps, err := c.EKS.ListFargateProfiles(ctx, &eks.ListFargateProfilesInput{ClusterName: &name})
			if err != nil {
				continue
			}
			for _, fp := range fps.FargateProfileNames {
				desc, err := c.EKS.DescribeFargateProfile(ctx, &eks.DescribeFargateProfileInput{ClusterName: &name, FargateProfileName: &fp})
				if err != nil || desc.FargateProfile == nil {
					continue
				}
				out[name] = append(out[name], *desc.FargateProfile)
			}
		}
		return out, nil
	})

	// ElastiCache
	d.ElastiCacheClusters = cache.New(func() ([]elasticachetypes.CacheCluster, error) {
		out, err := c.ElastiCache.DescribeCacheClusters(ctx, &elasticache.DescribeCacheClustersInput{})
		if err != nil {
			return nil, err
		}
		return out.CacheClusters, nil
	})
	d.ElastiCacheReplGroups = cache.New(func() ([]elasticachetypes.ReplicationGroup, error) {
		out, err := c.ElastiCache.DescribeReplicationGroups(ctx, &elasticache.DescribeReplicationGroupsInput{})
		if err != nil {
			return nil, err
		}
		return out.ReplicationGroups, nil
	})
	d.ElastiCacheSubnetGroups = cache.New(func() ([]elasticachetypes.CacheSubnetGroup, error) {
		out, err := c.ElastiCache.DescribeCacheSubnetGroups(ctx, &elasticache.DescribeCacheSubnetGroupsInput{})
		if err != nil {
			return nil, err
		}
		return out.CacheSubnetGroups, nil
	})

	// CloudTrail
	d.CloudTrailTrails = cache.New(func() ([]cloudtrailtypes.TrailInfo, error) {
		out, err := c.CloudTrail.ListTrails(ctx, &cloudtrail.ListTrailsInput{})
		if err != nil {
			return nil, err
		}
		return out.Trails, nil
	})

	// CloudWatch
	d.CloudWatchAlarms = cache.New(func() ([]cloudwatchtypes.MetricAlarm, error) {
		out, err := c.CloudWatch.DescribeAlarms(ctx, &cloudwatch.DescribeAlarmsInput{})
		if err != nil {
			return nil, err
		}
		return out.MetricAlarms, nil
	})
	d.CloudWatchLogGroups = cache.New(func() ([]logstypes.LogGroup, error) {
		out, err := c.CloudWatchLogs.DescribeLogGroups(ctx, &cloudwatchlogs.DescribeLogGroupsInput{})
		if err != nil {
			return nil, err
		}
		return out.LogGroups, nil
	})
	d.CloudWatchMetricStreams = cache.New(func() ([]cloudwatchtypes.MetricStreamEntry, error) {
		out, err := c.CloudWatch.ListMetricStreams(ctx, &cloudwatch.ListMetricStreamsInput{})
		if err != nil {
			return nil, err
		}
		return out.Entries, nil
	})

	// CloudFront
	d.CloudFrontDistributions = cache.New(func() ([]cftypescf.DistributionSummary, error) {
		out, err := c.CloudFront.ListDistributions(ctx, &cloudfront.ListDistributionsInput{})
		if err != nil {
			return nil, err
		}
		if out.DistributionList == nil {
			return nil, nil
		}
		return out.DistributionList.Items, nil
	})
	d.CloudFrontDistributionConfigs = cache.New(func() (map[string]cftypescf.DistributionConfig, error) {
		dists, err := d.CloudFrontDistributions.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]cftypescf.DistributionConfig)
		for _, dist := range dists {
			if dist.Id == nil {
				continue
			}
			desc, err := c.CloudFront.GetDistribution(ctx, &cloudfront.GetDistributionInput{Id: dist.Id})
			if err != nil || desc.Distribution == nil || desc.Distribution.DistributionConfig == nil {
				continue
			}
			out[*dist.Id] = *desc.Distribution.DistributionConfig
		}
		return out, nil
	})
	d.CloudFrontDistributionARNs = cache.New(func() (map[string]string, error) {
		dists, err := d.CloudFrontDistributions.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]string)
		for _, dist := range dists {
			if dist.Id == nil {
				continue
			}
			desc, err := c.CloudFront.GetDistribution(ctx, &cloudfront.GetDistributionInput{Id: dist.Id})
			if err != nil || desc.Distribution == nil || desc.Distribution.ARN == nil {
				continue
			}
			out[*dist.Id] = *desc.Distribution.ARN
		}
		return out, nil
	})
	d.CloudFrontDistributionTags = cache.New(func() (map[string]map[string]string, error) {
		arns, err := d.CloudFrontDistributionARNs.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for id, arn := range arns {
			tags, err := c.CloudFront.ListTagsForResource(ctx, &cloudfront.ListTagsForResourceInput{Resource: &arn})
			if err != nil || tags.Tags == nil {
				continue
			}
			m := make(map[string]string)
			for _, t := range tags.Tags.Items {
				if t.Key != nil && t.Value != nil {
					m[*t.Key] = *t.Value
				}
			}
			out[id] = m
		}
		return out, nil
	})
	d.CloudFrontDistributionWAF = cache.New(func() (map[string]bool, error) {
		arns, err := d.CloudFrontDistributionARNs.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]bool)
		for id, arn := range arns {
			_, err := c.WAFv2.GetWebACLForResource(ctx, &wafv2.GetWebACLForResourceInput{ResourceArn: &arn})
			if err != nil {
				var nf *wafv2types.WAFNonexistentItemException
				if errors.As(err, &nf) {
					out[id] = false
					continue
				}
				return nil, err
			}
			out[id] = true
		}
		return out, nil
	})
	d.CloudFrontS3OriginBucketExists = cache.New(func() (map[string]bool, error) {
		configs, err := d.CloudFrontDistributionConfigs.Get()
		if err != nil {
			return nil, err
		}
		seen := make(map[string]bool)
		for _, cfg := range configs {
			for _, o := range cfg.Origins.Items {
				if o.DomainName == nil {
					continue
				}
				dn := *o.DomainName
				if !strings.Contains(dn, ".s3.") && !strings.HasSuffix(dn, ".s3.amazonaws.com") {
					continue
				}
				bucket := dn
				if idx := strings.Index(dn, ".s3"); idx > 0 {
					bucket = dn[:idx]
				}
				if bucket != "" {
					seen[bucket] = false
				}
			}
		}
		out := make(map[string]bool)
		for b := range seen {
			_, err := c.S3.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: &b})
			out[b] = err == nil
		}
		return out, nil
	})

	// CloudFormation
	d.CloudFormationStacks = cache.New(func() ([]cftypes.StackSummary, error) {
		out, err := c.CloudFormation.ListStacks(ctx, &cloudformation.ListStacksInput{})
		if err != nil {
			return nil, err
		}
		return out.StackSummaries, nil
	})

	// ACM
	d.ACMCertificates = cache.New(func() ([]acmtypes.CertificateSummary, error) {
		out, err := c.ACM.ListCertificates(ctx, &acm.ListCertificatesInput{})
		if err != nil {
			return nil, err
		}
		return out.CertificateSummaryList, nil
	})
	d.ACMCertificateDetails = cache.New(func() (map[string]acmtypes.CertificateDetail, error) {
		certs, err := d.ACMCertificates.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]acmtypes.CertificateDetail)
		for _, cs := range certs {
			if cs.CertificateArn == nil {
				continue
			}
			desc, err := c.ACM.DescribeCertificate(ctx, &acm.DescribeCertificateInput{CertificateArn: cs.CertificateArn})
			if err != nil || desc.Certificate == nil {
				continue
			}
			out[*cs.CertificateArn] = *desc.Certificate
		}
		return out, nil
	})

	// ACM PCA
	d.ACMPCACertificateAuthorities = cache.New(func() ([]acmpcatypes.CertificateAuthority, error) {
		out, err := c.ACMPCA.ListCertificateAuthorities(ctx, &acmpca.ListCertificateAuthoritiesInput{})
		if err != nil {
			return nil, err
		}
		return out.CertificateAuthorities, nil
	})
	d.ACMPCACertificateAuthorityTags = cache.New(func() (map[string]map[string]string, error) {
		cas, err := d.ACMPCACertificateAuthorities.Get()
		if err != nil {
			return nil, err
		}
		tags := make(map[string]map[string]string)
		for _, ca := range cas {
			if ca.Arn == nil {
				continue
			}
			out, err := c.ACMPCA.ListTags(ctx, &acmpca.ListTagsInput{CertificateAuthorityArn: ca.Arn})
			if err != nil {
				continue
			}
			m := make(map[string]string)
			for _, t := range out.Tags {
				if t.Key != nil && t.Value != nil {
					m[*t.Key] = *t.Value
				}
			}
			tags[*ca.Arn] = m
		}
		return tags, nil
	})

	// KMS
	d.KMSKeys = cache.New(func() ([]kmstypes.KeyListEntry, error) {
		out, err := c.KMS.ListKeys(ctx, &kms.ListKeysInput{})
		if err != nil {
			return nil, err
		}
		return out.Keys, nil
	})

	// SNS
	d.SNSTopics = cache.New(func() ([]snstypes.Topic, error) {
		out, err := c.SNS.ListTopics(ctx, &sns.ListTopicsInput{})
		if err != nil {
			return nil, err
		}
		return out.Topics, nil
	})

	// SQS
	d.SQSQueues = cache.New(func() ([]string, error) {
		out, err := c.SQS.ListQueues(ctx, &sqs.ListQueuesInput{})
		if err != nil {
			return nil, err
		}
		return out.QueueUrls, nil
	})

	// Secrets Manager
	d.SecretsManagerSecrets = cache.New(func() ([]smtypes.SecretListEntry, error) {
		out, err := c.SecretsManager.ListSecrets(ctx, &secretsmanager.ListSecretsInput{})
		if err != nil {
			return nil, err
		}
		return out.SecretList, nil
	})

	// SSM
	d.SSMDocuments = cache.New(func() ([]ssmtypes.DocumentIdentifier, error) {
		out, err := c.SSM.ListDocuments(ctx, &ssm.ListDocumentsInput{})
		if err != nil {
			return nil, err
		}
		return out.DocumentIdentifiers, nil
	})

	// Step Functions
	d.SFNStateMachines = cache.New(func() ([]sfntypes.StateMachineListItem, error) {
		out, err := c.SFN.ListStateMachines(ctx, &sfn.ListStateMachinesInput{})
		if err != nil {
			return nil, err
		}
		return out.StateMachines, nil
	})

	// Redshift
	d.RedshiftClusters = cache.New(func() ([]redshifttypes.Cluster, error) {
		out, err := c.Redshift.DescribeClusters(ctx, &redshift.DescribeClustersInput{})
		if err != nil {
			return nil, err
		}
		return out.Clusters, nil
	})
	d.RedshiftParamGroups = cache.New(func() ([]redshifttypes.ClusterParameterGroup, error) {
		out, err := c.Redshift.DescribeClusterParameterGroups(ctx, &redshift.DescribeClusterParameterGroupsInput{})
		if err != nil {
			return nil, err
		}
		return out.ParameterGroups, nil
	})
	d.RedshiftClusterSubnetGroups = cache.New(func() ([]redshifttypes.ClusterSubnetGroup, error) {
		out, err := c.Redshift.DescribeClusterSubnetGroups(ctx, &redshift.DescribeClusterSubnetGroupsInput{})
		if err != nil {
			return nil, err
		}
		return out.ClusterSubnetGroups, nil
	})
	d.RedshiftLoggingStatus = cache.New(func() (map[string]redshift.DescribeLoggingStatusOutput, error) {
		clusters, err := d.RedshiftClusters.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]redshift.DescribeLoggingStatusOutput)
		for _, c := range clusters {
			if c.ClusterIdentifier == nil {
				continue
			}
			ls, err := c.Redshift.DescribeLoggingStatus(ctx, &redshift.DescribeLoggingStatusInput{ClusterIdentifier: c.ClusterIdentifier})
			if err != nil {
				continue
			}
			out[*c.ClusterIdentifier] = *ls
		}
		return out, nil
	})
	d.RedshiftParamGroupTags = cache.New(func() (map[string]map[string]string, error) {
		groups, err := d.RedshiftParamGroups.Get()
		if err != nil {
			return nil, err
		}
		acct, err := d.AccountID.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, g := range groups {
			if g.ParameterGroupName == nil {
				continue
			}
			arn := fmt.Sprintf("arn:aws:redshift:%s:%s:parametergroup:%s", c.Redshift.Options().Region, acct, *g.ParameterGroupName)
			tags, err := c.Redshift.DescribeTags(ctx, &redshift.DescribeTagsInput{ResourceName: &arn})
			if err != nil {
				continue
			}
			m := make(map[string]string)
			for _, t := range tags.TaggedResources {
				if t.Tag != nil && t.Tag.Key != nil && t.Tag.Value != nil {
					m[*t.Tag.Key] = *t.Tag.Value
				}
			}
			out[*g.ParameterGroupName] = m
		}
		return out, nil
	})
	d.RedshiftParamValues = cache.New(func() (map[string]map[string]string, error) {
		groups, err := d.RedshiftParamGroups.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, g := range groups {
			if g.ParameterGroupName == nil {
				continue
			}
			values := make(map[string]string)
			var marker *string
			for {
				resp, err := c.Redshift.DescribeClusterParameters(ctx, &redshift.DescribeClusterParametersInput{
					ParameterGroupName: g.ParameterGroupName,
					Marker:             marker,
				})
				if err != nil {
					break
				}
				for _, p := range resp.Parameters {
					if p.ParameterName != nil && p.ParameterValue != nil {
						values[*p.ParameterName] = *p.ParameterValue
					}
				}
				if resp.Marker == nil || *resp.Marker == "" {
					break
				}
				marker = resp.Marker
			}
			out[*g.ParameterGroupName] = values
		}
		return out, nil
	})

	// Redshift Serverless
	d.RedshiftServerlessWorkgroups = cache.New(func() ([]rsstypes.Workgroup, error) {
		out, err := c.RedshiftServerless.ListWorkgroups(ctx, &redshiftserverless.ListWorkgroupsInput{})
		if err != nil {
			return nil, err
		}
		return out.Workgroups, nil
	})
	d.RedshiftServerlessNamespaces = cache.New(func() ([]rsstypes.Namespace, error) {
		out, err := c.RedshiftServerless.ListNamespaces(ctx, &redshiftserverless.ListNamespacesInput{})
		if err != nil {
			return nil, err
		}
		return out.Namespaces, nil
	})

	// EFS
	d.EFSFileSystems = cache.New(func() ([]efstypes.FileSystemDescription, error) {
		out, err := c.EFS.DescribeFileSystems(ctx, &efs.DescribeFileSystemsInput{})
		if err != nil {
			return nil, err
		}
		return out.FileSystems, nil
	})
	d.EFSAccessPoints = cache.New(func() ([]efstypes.AccessPointDescription, error) {
		out, err := c.EFS.DescribeAccessPoints(ctx, &efs.DescribeAccessPointsInput{})
		if err != nil {
			return nil, err
		}
		return out.AccessPoints, nil
	})
	d.EFSMountTargets = cache.New(func() (map[string][]efstypes.MountTargetDescription, error) {
		fss, err := d.EFSFileSystems.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string][]efstypes.MountTargetDescription)
		for _, fs := range fss {
			if fs.FileSystemId == nil {
				continue
			}
			mt, err := c.EFS.DescribeMountTargets(ctx, &efs.DescribeMountTargetsInput{FileSystemId: fs.FileSystemId})
			if err != nil {
				continue
			}
			out[*fs.FileSystemId] = mt.MountTargets
		}
		return out, nil
	})
	d.EFSBackupPolicies = cache.New(func() (map[string]bool, error) {
		fss, err := d.EFSFileSystems.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]bool)
		for _, fs := range fss {
			if fs.FileSystemId == nil {
				continue
			}
			pol, err := c.EFS.DescribeBackupPolicy(ctx, &efs.DescribeBackupPolicyInput{FileSystemId: fs.FileSystemId})
			if err != nil || pol.BackupPolicy == nil {
				out[*fs.FileSystemId] = false
				continue
			}
			out[*fs.FileSystemId] = pol.BackupPolicy.Status == efstypes.StatusEnabled
		}
		return out, nil
	})
	d.EFSFileSystemTags = cache.New(func() (map[string]map[string]string, error) {
		fss, err := d.EFSFileSystems.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, fs := range fss {
			if fs.FileSystemId == nil {
				continue
			}
			tags, err := c.EFS.ListTagsForResource(ctx, &efs.ListTagsForResourceInput{ResourceId: fs.FileSystemId})
			if err != nil {
				continue
			}
			m := make(map[string]string)
			for _, t := range tags.Tags {
				if t.Key != nil && t.Value != nil {
					m[*t.Key] = *t.Value
				}
			}
			out[*fs.FileSystemId] = m
		}
		return out, nil
	})

	// ELB
	d.ELBClassicLBs = cache.New(func() ([]elbtypes.LoadBalancerDescription, error) {
		out, err := c.ELB.DescribeLoadBalancers(ctx, &elasticloadbalancing.DescribeLoadBalancersInput{})
		if err != nil {
			return nil, err
		}
		return out.LoadBalancerDescriptions, nil
	})
	d.ELBClassicTags = cache.New(func() (map[string]map[string]string, error) {
		lbs, err := d.ELBClassicLBs.Get()
		if err != nil {
			return nil, err
		}
		var names []string
		for _, lb := range lbs {
			if lb.LoadBalancerName != nil {
				names = append(names, *lb.LoadBalancerName)
			}
		}
		out := make(map[string]map[string]string)
		const batchSize = 20
		for i := 0; i < len(names); i += batchSize {
			end := i + batchSize
			if end > len(names) {
				end = len(names)
			}
			resp, err := c.ELB.DescribeTags(ctx, &elasticloadbalancing.DescribeTagsInput{LoadBalancerNames: names[i:end]})
			if err != nil {
				continue
			}
			for _, td := range resp.TagDescriptions {
				if td.LoadBalancerName == nil {
					continue
				}
				m := make(map[string]string)
				for _, t := range td.Tags {
					if t.Key != nil && t.Value != nil {
						m[*t.Key] = *t.Value
					}
				}
				out[*td.LoadBalancerName] = m
			}
		}
		return out, nil
	})
	d.ELBClassicAttributes = cache.New(func() (map[string]elbtypes.LoadBalancerAttributes, error) {
		lbs, err := d.ELBClassicLBs.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]elbtypes.LoadBalancerAttributes)
		for _, lb := range lbs {
			if lb.LoadBalancerName == nil {
				continue
			}
			attr, err := c.ELB.DescribeLoadBalancerAttributes(ctx, &elasticloadbalancing.DescribeLoadBalancerAttributesInput{LoadBalancerName: lb.LoadBalancerName})
			if err != nil || attr.LoadBalancerAttributes == nil {
				continue
			}
			out[*lb.LoadBalancerName] = *attr.LoadBalancerAttributes
		}
		return out, nil
	})
	d.ELBClassicPolicies = cache.New(func() (map[string][]elbtypes.PolicyDescription, error) {
		lbs, err := d.ELBClassicLBs.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string][]elbtypes.PolicyDescription)
		for _, lb := range lbs {
			if lb.LoadBalancerName == nil {
				continue
			}
			resp, err := c.ELB.DescribeLoadBalancerPolicies(ctx, &elasticloadbalancing.DescribeLoadBalancerPoliciesInput{LoadBalancerName: lb.LoadBalancerName})
			if err != nil {
				continue
			}
			out[*lb.LoadBalancerName] = resp.PolicyDescriptions
		}
		return out, nil
	})

	// ELBv2
	d.ELBv2LoadBalancers = cache.New(func() ([]elbv2types.LoadBalancer, error) {
		out, err := c.ELBv2.DescribeLoadBalancers(ctx, &elasticloadbalancingv2.DescribeLoadBalancersInput{})
		if err != nil {
			return nil, err
		}
		return out.LoadBalancers, nil
	})
	d.ELBv2Listeners = cache.New(func() ([]elbv2types.Listener, error) {
		lbs, err := d.ELBv2LoadBalancers.Get()
		if err != nil {
			return nil, err
		}
		var all []elbv2types.Listener
		for _, lb := range lbs {
			out, err := c.ELBv2.DescribeListeners(ctx, &elasticloadbalancingv2.DescribeListenersInput{LoadBalancerArn: lb.LoadBalancerArn})
			if err != nil {
				continue
			}
			all = append(all, out.Listeners...)
		}
		return all, nil
	})
	d.ELBv2TargetGroups = cache.New(func() ([]elbv2types.TargetGroup, error) {
		out, err := c.ELBv2.DescribeTargetGroups(ctx, &elasticloadbalancingv2.DescribeTargetGroupsInput{})
		if err != nil {
			return nil, err
		}
		return out.TargetGroups, nil
	})
	d.ELBv2Tags = cache.New(func() (map[string]map[string]string, error) {
		lbs, err := d.ELBv2LoadBalancers.Get()
		if err != nil {
			return nil, err
		}
		listeners, err := d.ELBv2Listeners.Get()
		if err != nil {
			return nil, err
		}
		var arns []string
		for _, lb := range lbs {
			if lb.LoadBalancerArn != nil {
				arns = append(arns, *lb.LoadBalancerArn)
			}
		}
		for _, l := range listeners {
			if l.ListenerArn != nil {
				arns = append(arns, *l.ListenerArn)
			}
		}
		tags := make(map[string]map[string]string)
		const batch = 20
		for i := 0; i < len(arns); i += batch {
			end := i + batch
			if end > len(arns) {
				end = len(arns)
			}
			out, err := c.ELBv2.DescribeTags(ctx, &elasticloadbalancingv2.DescribeTagsInput{ResourceArns: arns[i:end]})
			if err != nil {
				continue
			}
			for _, td := range out.TagDescriptions {
				if td.ResourceArn == nil {
					continue
				}
				m := make(map[string]string)
				for _, t := range td.Tags {
					if t.Key != nil && t.Value != nil {
						m[*t.Key] = *t.Value
					}
				}
				tags[*td.ResourceArn] = m
			}
		}
		return tags, nil
	})
	d.ELBv2LBAttributes = cache.New(func() (map[string]map[string]string, error) {
		lbs, err := d.ELBv2LoadBalancers.Get()
		if err != nil {
			return nil, err
		}
		attrs := make(map[string]map[string]string)
		for _, lb := range lbs {
			if lb.LoadBalancerArn == nil {
				continue
			}
			out, err := c.ELBv2.DescribeLoadBalancerAttributes(ctx, &elasticloadbalancingv2.DescribeLoadBalancerAttributesInput{LoadBalancerArn: lb.LoadBalancerArn})
			if err != nil {
				continue
			}
			m := make(map[string]string)
			for _, a := range out.Attributes {
				if a.Key != nil && a.Value != nil {
					m[*a.Key] = *a.Value
				}
			}
			attrs[*lb.LoadBalancerArn] = m
		}
		return attrs, nil
	})

	// ECR
	d.ECRRepositories = cache.New(func() ([]ecrtypes.Repository, error) {
		out, err := c.ECR.DescribeRepositories(ctx, &ecr.DescribeRepositoriesInput{})
		if err != nil {
			return nil, err
		}
		return out.Repositories, nil
	})

	// Neptune
	d.NeptuneClusters = cache.New(func() ([]neptunetypes.DBCluster, error) {
		out, err := c.Neptune.DescribeDBClusters(ctx, &neptune.DescribeDBClustersInput{})
		if err != nil {
			return nil, err
		}
		return out.DBClusters, nil
	})
	d.NeptuneSnapshots = cache.New(func() ([]neptunetypes.DBClusterSnapshot, error) {
		out, err := c.Neptune.DescribeDBClusterSnapshots(ctx, &neptune.DescribeDBClusterSnapshotsInput{})
		if err != nil {
			return nil, err
		}
		return out.DBClusterSnapshots, nil
	})

	// OpenSearch
	d.OpenSearchDomains = cache.New(func() ([]opentypes.DomainStatus, error) {
		list, err := c.OpenSearch.ListDomainNames(ctx, &opensearch.ListDomainNamesInput{})
		if err != nil {
			return nil, err
		}
		if len(list.DomainNames) == 0 {
			return nil, nil
		}
		var names []string
		for _, d := range list.DomainNames {
			if d.DomainName != nil {
				names = append(names, *d.DomainName)
			}
		}
		out, err := c.OpenSearch.DescribeDomains(ctx, &opensearch.DescribeDomainsInput{DomainNames: names})
		if err != nil {
			return nil, err
		}
		return out.DomainStatusList, nil
	})

	// Elasticsearch
	d.ElasticsearchDomains = cache.New(func() ([]estypes.ElasticsearchDomainStatus, error) {
		list, err := c.Elasticsearch.ListDomainNames(ctx, &elasticsearchservice.ListDomainNamesInput{})
		if err != nil {
			return nil, err
		}
		if len(list.DomainNames) == 0 {
			return nil, nil
		}
		var names []string
		for _, dn := range list.DomainNames {
			if dn.DomainName != nil {
				names = append(names, *dn.DomainName)
			}
		}
		out, err := c.Elasticsearch.DescribeElasticsearchDomains(ctx, &elasticsearchservice.DescribeElasticsearchDomainsInput{DomainNames: names})
		if err != nil {
			return nil, err
		}
		return out.DomainStatusList, nil
	})

	// Glue
	d.GlueJobs = cache.New(func() ([]gluetypes.Job, error) {
		out, err := c.Glue.GetJobs(ctx, &glue.GetJobsInput{})
		if err != nil {
			return nil, err
		}
		return out.Jobs, nil
	})

	// GuardDuty
	d.GuardDutyDetectorIDs = cache.New(func() ([]string, error) {
		out, err := c.GuardDuty.ListDetectors(ctx, &guardduty.ListDetectorsInput{})
		if err != nil {
			return nil, err
		}
		return out.DetectorIds, nil
	})
	d.GuardDutyDetectors = cache.New(func() (map[string]guardduty.GetDetectorOutput, error) {
		ids, err := d.GuardDutyDetectorIDs.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]guardduty.GetDetectorOutput)
		for _, id := range ids {
			desc, err := c.GuardDuty.GetDetector(ctx, &guardduty.GetDetectorInput{DetectorId: &id})
			if err != nil {
				continue
			}
			out[id] = *desc
		}
		return out, nil
	})
	d.GuardDutyNonArchivedFindings = cache.New(func() (map[string]int, error) {
		ids, err := d.GuardDutyDetectorIDs.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]int)
		for _, id := range ids {
			criteria := guarddutytypes.FindingCriteria{
				Criterion: map[string]guarddutytypes.Condition{
					"service.archived": {Eq: []string{"false"}},
				},
			}
			resp, err := c.GuardDuty.ListFindings(ctx, &guardduty.ListFindingsInput{DetectorId: &id, FindingCriteria: &criteria})
			if err != nil {
				continue
			}
			out[id] = len(resp.FindingIds)
		}
		return out, nil
	})

	// Backup
	d.BackupPlans = cache.New(func() ([]backuptypes.BackupPlansListMember, error) {
		out, err := c.Backup.ListBackupPlans(ctx, &backup.ListBackupPlansInput{})
		if err != nil {
			return nil, err
		}
		return out.BackupPlansList, nil
	})
	d.BackupVaults = cache.New(func() ([]backuptypes.BackupVaultListMember, error) {
		out, err := c.Backup.ListBackupVaults(ctx, &backup.ListBackupVaultsInput{})
		if err != nil {
			return nil, err
		}
		return out.BackupVaultList, nil
	})
	d.BackupPlanDetails = cache.New(func() (map[string]backuptypes.BackupPlan, error) {
		plans, err := d.BackupPlans.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]backuptypes.BackupPlan)
		for _, p := range plans {
			if p.BackupPlanId == nil {
				continue
			}
			detail, err := c.Backup.GetBackupPlan(ctx, &backup.GetBackupPlanInput{BackupPlanId: p.BackupPlanId})
			if err != nil || detail.BackupPlan == nil {
				continue
			}
			out[*p.BackupPlanId] = *detail.BackupPlan
		}
		return out, nil
	})
	d.BackupRecoveryPoints = cache.New(func() (map[string][]backuptypes.RecoveryPointByBackupVault, error) {
		vaults, err := d.BackupVaults.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string][]backuptypes.RecoveryPointByBackupVault)
		for _, v := range vaults {
			if v.BackupVaultName == nil {
				continue
			}
			list, err := c.Backup.ListRecoveryPointsByBackupVault(ctx, &backup.ListRecoveryPointsByBackupVaultInput{BackupVaultName: v.BackupVaultName})
			if err != nil {
				continue
			}
			out[*v.BackupVaultName] = list.RecoveryPoints
		}
		return out, nil
	})
	d.BackupVaultLockConfigs = cache.New(func() (map[string]backuptypes.BackupVaultLockConfiguration, error) {
		vaults, err := d.BackupVaults.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]backuptypes.BackupVaultLockConfiguration)
		for _, v := range vaults {
			if v.BackupVaultName == nil {
				continue
			}
			lock, err := c.Backup.GetBackupVaultLockConfiguration(ctx, &backup.GetBackupVaultLockConfigurationInput{BackupVaultName: v.BackupVaultName})
			if err != nil || lock.BackupVaultLockConfiguration == nil {
				continue
			}
			out[*v.BackupVaultName] = *lock.BackupVaultLockConfiguration
		}
		return out, nil
	})
	d.BackupProtectedResources = cache.New(func() (map[string]backuptypes.ProtectedResource, error) {
		out := make(map[string]backuptypes.ProtectedResource)
		list, err := c.Backup.ListProtectedResources(ctx, &backup.ListProtectedResourcesInput{})
		if err != nil {
			return nil, err
		}
		for _, r := range list.Results {
			if r.ResourceArn == nil {
				continue
			}
			out[*r.ResourceArn] = r
		}
		return out, nil
	})
	d.BackupRecoveryPointsByResource = cache.New(func() (map[string][]backuptypes.RecoveryPointByResource, error) {
		resources, err := d.BackupProtectedResources.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string][]backuptypes.RecoveryPointByResource)
		for arn := range resources {
			list, err := c.Backup.ListRecoveryPointsByResource(ctx, &backup.ListRecoveryPointsByResourceInput{ResourceArn: &arn})
			if err != nil {
				continue
			}
			out[arn] = list.RecoveryPoints
		}
		return out, nil
	})

	// DocDB
	d.DocDBClusters = cache.New(func() ([]docdbtypes.DBCluster, error) {
		out, err := c.DocDB.DescribeDBClusters(ctx, &docdb.DescribeDBClustersInput{})
		if err != nil {
			return nil, err
		}
		return out.DBClusters, nil
	})

	// DAX
	d.DAXClusters = cache.New(func() ([]daxtypes.Cluster, error) {
		out, err := c.DAX.DescribeClusters(ctx, &dax.DescribeClustersInput{})
		if err != nil {
			return nil, err
		}
		return out.Clusters, nil
	})

	// DMS
	d.DMSReplicationInstances = cache.New(func() ([]dmstypes.ReplicationInstance, error) {
		out, err := c.DMS.DescribeReplicationInstances(ctx, &databasemigrationservice.DescribeReplicationInstancesInput{})
		if err != nil {
			return nil, err
		}
		return out.ReplicationInstances, nil
	})
	d.DMSEndpoints = cache.New(func() ([]dmstypes.Endpoint, error) {
		out, err := c.DMS.DescribeEndpoints(ctx, &databasemigrationservice.DescribeEndpointsInput{})
		if err != nil {
			return nil, err
		}
		return out.Endpoints, nil
	})
	d.DMSReplicationTasks = cache.New(func() ([]dmstypes.ReplicationTask, error) {
		out, err := c.DMS.DescribeReplicationTasks(ctx, &databasemigrationservice.DescribeReplicationTasksInput{})
		if err != nil {
			return nil, err
		}
		return out.ReplicationTasks, nil
	})
	d.DMSEndpointTags = cache.New(func() (map[string]map[string]string, error) {
		eps, err := d.DMSEndpoints.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, e := range eps {
			if e.EndpointArn == nil {
				continue
			}
			tags, err := c.DMS.ListTagsForResource(ctx, &databasemigrationservice.ListTagsForResourceInput{ResourceArn: e.EndpointArn})
			if err != nil {
				continue
			}
			m := make(map[string]string)
			for _, t := range tags.TagList {
				if t.Key != nil && t.Value != nil {
					m[*t.Key] = *t.Value
				}
			}
			out[*e.EndpointArn] = m
		}
		return out, nil
	})
	d.DMSReplicationTaskTags = cache.New(func() (map[string]map[string]string, error) {
		tasks, err := d.DMSReplicationTasks.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, t := range tasks {
			if t.ReplicationTaskArn == nil {
				continue
			}
			tags, err := c.DMS.ListTagsForResource(ctx, &databasemigrationservice.ListTagsForResourceInput{ResourceArn: t.ReplicationTaskArn})
			if err != nil {
				continue
			}
			m := make(map[string]string)
			for _, tag := range tags.TagList {
				if tag.Key != nil && tag.Value != nil {
					m[*tag.Key] = *tag.Value
				}
			}
			out[*t.ReplicationTaskArn] = m
		}
		return out, nil
	})

	// Batch
	d.BatchComputeEnvs = cache.New(func() ([]batchtypes.ComputeEnvironmentDetail, error) {
		out, err := c.Batch.DescribeComputeEnvironments(ctx, &batch.DescribeComputeEnvironmentsInput{})
		if err != nil {
			return nil, err
		}
		return out.ComputeEnvironments, nil
	})
	d.BatchJobQueues = cache.New(func() ([]batchtypes.JobQueueDetail, error) {
		out, err := c.Batch.DescribeJobQueues(ctx, &batch.DescribeJobQueuesInput{})
		if err != nil {
			return nil, err
		}
		return out.JobQueues, nil
	})
	d.BatchSchedulingPolicies = cache.New(func() ([]batchtypes.SchedulingPolicyListingDetail, error) {
		out, err := c.Batch.ListSchedulingPolicies(ctx, &batch.ListSchedulingPoliciesInput{})
		if err != nil {
			return nil, err
		}
		return out.SchedulingPolicies, nil
	})
	d.BatchComputeEnvTags = cache.New(func() (map[string]map[string]string, error) {
		envs, err := d.BatchComputeEnvs.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, e := range envs {
			if e.ComputeEnvironmentArn == nil {
				continue
			}
			tags, err := c.Batch.ListTagsForResource(ctx, &batch.ListTagsForResourceInput{ResourceArn: e.ComputeEnvironmentArn})
			if err != nil {
				continue
			}
			out[*e.ComputeEnvironmentArn] = tags.Tags
		}
		return out, nil
	})
	d.BatchJobQueueTags = cache.New(func() (map[string]map[string]string, error) {
		qs, err := d.BatchJobQueues.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, q := range qs {
			if q.JobQueueArn == nil {
				continue
			}
			tags, err := c.Batch.ListTagsForResource(ctx, &batch.ListTagsForResourceInput{ResourceArn: q.JobQueueArn})
			if err != nil {
				continue
			}
			out[*q.JobQueueArn] = tags.Tags
		}
		return out, nil
	})
	d.BatchSchedulingPolicyTags = cache.New(func() (map[string]map[string]string, error) {
		pols, err := d.BatchSchedulingPolicies.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, p := range pols {
			if p.Arn == nil {
				continue
			}
			tags, err := c.Batch.ListTagsForResource(ctx, &batch.ListTagsForResourceInput{ResourceArn: p.Arn})
			if err != nil {
				continue
			}
			out[*p.Arn] = tags.Tags
		}
		return out, nil
	})

	// CodeBuild
	d.CodeBuildProjects = cache.New(func() ([]codebuildtypes.Project, error) {
		list, err := c.CodeBuild.ListProjects(ctx, &codebuild.ListProjectsInput{})
		if err != nil {
			return nil, err
		}
		if len(list.Projects) == 0 {
			return nil, nil
		}
		out, err := c.CodeBuild.BatchGetProjects(ctx, &codebuild.BatchGetProjectsInput{Names: list.Projects})
		if err != nil {
			return nil, err
		}
		return out.Projects, nil
	})
	d.CodeBuildReportGroups = cache.New(func() ([]string, error) {
		out, err := c.CodeBuild.ListReportGroups(ctx, &codebuild.ListReportGroupsInput{})
		if err != nil {
			return nil, err
		}
		return out.ReportGroups, nil
	})

	// CodeDeploy
	d.CodeDeployApps = cache.New(func() ([]string, error) {
		out, err := c.CodeDeploy.ListApplications(ctx, &codedeploy.ListApplicationsInput{})
		if err != nil {
			return nil, err
		}
		return out.Applications, nil
	})

	// CodePipeline
	d.CodePipelines = cache.New(func() ([]codepipelinetypes.PipelineSummary, error) {
		out, err := c.CodePipeline.ListPipelines(ctx, &codepipeline.ListPipelinesInput{})
		if err != nil {
			return nil, err
		}
		return out.Pipelines, nil
	})

	// Cognito
	d.CognitoUserPools = cache.New(func() ([]cognitoidptypes.UserPoolDescriptionType, error) {
		out, err := c.CognitoIDP.ListUserPools(ctx, &cognitoidentityprovider.ListUserPoolsInput{MaxResults: 60})
		if err != nil {
			return nil, err
		}
		return out.UserPools, nil
	})
	d.CognitoIdentityPools = cache.New(func() ([]cognitoidtypes.IdentityPoolShortDescription, error) {
		out, err := c.CognitoIdentity.ListIdentityPools(ctx, &cognitoidentity.ListIdentityPoolsInput{MaxResults: 60})
		if err != nil {
			return nil, err
		}
		return out.IdentityPools, nil
	})

	// FSx
	d.FSxFileSystems = cache.New(func() ([]fsxtypes.FileSystem, error) {
		out, err := c.FSx.DescribeFileSystems(ctx, &fsx.DescribeFileSystemsInput{})
		if err != nil {
			return nil, err
		}
		return out.FileSystems, nil
	})
	d.FSxFileSystemTags = cache.New(func() (map[string]map[string]string, error) {
		fss, err := d.FSxFileSystems.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, fs := range fss {
			if fs.ResourceARN == nil {
				continue
			}
			resp, err := c.FSx.ListTagsForResource(ctx, &fsx.ListTagsForResourceInput{ResourceARN: fs.ResourceARN})
			if err != nil {
				continue
			}
			m := make(map[string]string)
			for _, t := range resp.Tags {
				if t.Key != nil && t.Value != nil {
					m[*t.Key] = *t.Value
				}
			}
			out[*fs.ResourceARN] = m
		}
		return out, nil
	})

	// EMR
	d.EMRClusters = cache.New(func() ([]string, error) {
		out, err := c.EMR.ListClusters(ctx, &emr.ListClustersInput{})
		if err != nil {
			return nil, err
		}
		var ids []string
		for _, cs := range out.Clusters {
			if cs.Id != nil {
				ids = append(ids, *cs.Id)
			}
		}
		return ids, nil
	})

	// Athena
	d.AthenaWorkgroups = cache.New(func() ([]athenatypes.WorkgroupSummary, error) {
		out, err := c.Athena.ListWorkGroups(ctx, &athena.ListWorkGroupsInput{})
		if err != nil {
			return nil, err
		}
		return out.WorkGroups, nil
	})
	d.AthenaWorkgroupDetails = cache.New(func() (map[string]athenatypes.WorkGroup, error) {
		summaries, err := d.AthenaWorkgroups.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]athenatypes.WorkGroup)
		for _, wg := range summaries {
			if wg.Name == nil {
				continue
			}
			desc, err := c.Athena.GetWorkGroup(ctx, &athena.GetWorkGroupInput{WorkGroup: wg.Name})
			if err != nil || desc.WorkGroup == nil {
				continue
			}
			out[*wg.Name] = *desc.WorkGroup
		}
		return out, nil
	})
	d.AthenaDataCatalogs = cache.New(func() ([]athenatypes.DataCatalog, error) {
		out, err := c.Athena.ListDataCatalogs(ctx, &athena.ListDataCatalogsInput{})
		if err != nil {
			return nil, err
		}
		var all []athenatypes.DataCatalog
		for _, name := range out.DataCatalogsSummary {
			if name.CatalogName == nil {
				continue
			}
			desc, err := c.Athena.GetDataCatalog(ctx, &athena.GetDataCatalogInput{Name: name.CatalogName})
			if err != nil || desc.DataCatalog == nil {
				continue
			}
			all = append(all, *desc.DataCatalog)
		}
		return all, nil
	})
	d.AthenaPreparedStatements = cache.New(func() ([]athenatypes.PreparedStatementSummary, error) {
		workgroups, err := d.AthenaWorkgroups.Get()
		if err != nil {
			return nil, err
		}
		var all []athenatypes.PreparedStatementSummary
		for _, wg := range workgroups {
			if wg.Name == nil {
				continue
			}
			out, err := c.Athena.ListPreparedStatements(ctx, &athena.ListPreparedStatementsInput{WorkGroup: wg.Name})
			if err != nil {
				continue
			}
			all = append(all, out.PreparedStatements...)
		}
		return all, nil
	})

	// AppSync
	d.AppSyncAPIs = cache.New(func() ([]appsynctypes.GraphqlApi, error) {
		out, err := c.AppSync.ListGraphqlApis(ctx, &appsync.ListGraphqlApisInput{})
		if err != nil {
			return nil, err
		}
		return out.GraphqlApis, nil
	})
	d.AppSyncTags = cache.New(func() (map[string]map[string]string, error) {
		apis, err := d.AppSyncAPIs.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, api := range apis {
			if api.Arn == nil {
				continue
			}
			tags, err := c.AppSync.ListTagsForResource(ctx, &appsync.ListTagsForResourceInput{ResourceArn: api.Arn})
			if err != nil {
				continue
			}
			out[*api.Arn] = tags.Tags
		}
		return out, nil
	})
	d.AppSyncWAFv2WebACLForResource = cache.New(func() (map[string]bool, error) {
		apis, err := d.AppSyncAPIs.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]bool)
		for _, api := range apis {
			if api.Arn == nil {
				continue
			}
			_, err := c.WAFv2.GetWebACLForResource(ctx, &wafv2.GetWebACLForResourceInput{ResourceArn: api.Arn})
			if err != nil {
				var nf *wafv2types.WAFNonexistentItemException
				if errors.As(err, &nf) {
					out[*api.Arn] = false
					continue
				}
				return nil, err
			}
			out[*api.Arn] = true
		}
		return out, nil
	})

	// API Gateway
	d.APIGatewayRestAPIs = cache.New(func() ([]apigwtypes.RestApi, error) {
		out, err := c.APIGateway.GetRestApis(ctx, &apigateway.GetRestApisInput{})
		if err != nil {
			return nil, err
		}
		return out.Items, nil
	})
	d.APIGatewayStages = cache.New(func() (map[string][]apigwtypes.Stage, error) {
		apis, err := d.APIGatewayRestAPIs.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string][]apigwtypes.Stage)
		for _, api := range apis {
			if api.Id == nil {
				continue
			}
			stages, err := c.APIGateway.GetStages(ctx, &apigateway.GetStagesInput{RestApiId: api.Id})
			if err != nil {
				continue
			}
			out[*api.Id] = stages.Item
		}
		return out, nil
	})
	d.APIGatewayTags = cache.New(func() (map[string]map[string]string, error) {
		apis, err := d.APIGatewayRestAPIs.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, api := range apis {
			if api.Id == nil {
				continue
			}
			arn := fmt.Sprintf("arn:aws:apigateway:%s::/restapis/%s", c.APIGateway.Options().Region, *api.Id)
			tags, err := c.APIGateway.GetTags(ctx, &apigateway.GetTagsInput{ResourceArn: &arn})
			if err != nil {
				continue
			}
			out[*api.Id] = tags.Tags
		}
		return out, nil
	})
	d.APIGatewayStageTags = cache.New(func() (map[string]map[string]string, error) {
		stageTags := make(map[string]map[string]string)
		apis, err := d.APIGatewayRestAPIs.Get()
		if err != nil {
			return nil, err
		}
		stages, err := d.APIGatewayStages.Get()
		if err != nil {
			return nil, err
		}
		for _, api := range apis {
			if api.Id == nil {
				continue
			}
			for _, st := range stages[*api.Id] {
				if st.StageName == nil {
					continue
				}
				arn := fmt.Sprintf("arn:aws:apigateway:%s::/restapis/%s/stages/%s", c.APIGateway.Options().Region, *api.Id, *st.StageName)
				tags, err := c.APIGateway.GetTags(ctx, &apigateway.GetTagsInput{ResourceArn: &arn})
				if err != nil {
					continue
				}
				stageTags[arn] = tags.Tags
			}
		}
		return stageTags, nil
	})
	d.APIGatewayDomainNames = cache.New(func() ([]apigwtypes.DomainName, error) {
		out, err := c.APIGateway.GetDomainNames(ctx, &apigateway.GetDomainNamesInput{})
		if err != nil {
			return nil, err
		}
		return out.Items, nil
	})
	d.APIGatewayStageWAF = cache.New(func() (map[string]bool, error) {
		apis, err := d.APIGatewayRestAPIs.Get()
		if err != nil {
			return nil, err
		}
		stages, err := d.APIGatewayStages.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]bool)
		for _, api := range apis {
			if api.Id == nil {
				continue
			}
			for _, st := range stages[*api.Id] {
				if st.StageName == nil {
					continue
				}
				arn := fmt.Sprintf("arn:aws:apigateway:%s::/restapis/%s/stages/%s", c.APIGateway.Options().Region, *api.Id, *st.StageName)
				_, err := c.WAFv2.GetWebACLForResource(ctx, &wafv2.GetWebACLForResourceInput{ResourceArn: &arn})
				if err != nil {
					var nf *wafv2types.WAFNonexistentItemException
					if errors.As(err, &nf) {
						out[arn] = false
						continue
					}
					return nil, err
				}
				out[arn] = true
			}
		}
		return out, nil
	})

	// API Gateway V2
	d.APIGatewayV2APIs = cache.New(func() ([]apigwv2types.Api, error) {
		out, err := c.APIGatewayV2.GetApis(ctx, &apigatewayv2.GetApisInput{})
		if err != nil {
			return nil, err
		}
		return out.Items, nil
	})
	d.APIGatewayV2Stages = cache.New(func() (map[string][]apigwv2types.Stage, error) {
		apis, err := d.APIGatewayV2APIs.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string][]apigwv2types.Stage)
		for _, api := range apis {
			if api.ApiId == nil {
				continue
			}
			st, err := c.APIGatewayV2.GetStages(ctx, &apigatewayv2.GetStagesInput{ApiId: api.ApiId})
			if err != nil {
				continue
			}
			out[*api.ApiId] = st.Items
		}
		return out, nil
	})
	d.APIGatewayV2Routes = cache.New(func() (map[string][]apigwv2types.Route, error) {
		apis, err := d.APIGatewayV2APIs.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string][]apigwv2types.Route)
		for _, api := range apis {
			if api.ApiId == nil {
				continue
			}
			routes, err := c.APIGatewayV2.GetRoutes(ctx, &apigatewayv2.GetRoutesInput{ApiId: api.ApiId})
			if err != nil {
				continue
			}
			out[*api.ApiId] = routes.Items
		}
		return out, nil
	})
	d.APIGatewayV2Tags = cache.New(func() (map[string]map[string]string, error) {
		apis, err := d.APIGatewayV2APIs.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, api := range apis {
			if api.ApiId == nil {
				continue
			}
			arn := fmt.Sprintf("arn:aws:apigateway:%s::/apis/%s", c.APIGatewayV2.Options().Region, *api.ApiId)
			tags, err := c.APIGatewayV2.GetTags(ctx, &apigatewayv2.GetTagsInput{ResourceArn: &arn})
			if err != nil {
				continue
			}
			out[*api.ApiId] = tags.Tags
		}
		return out, nil
	})

	// Amplify
	d.AmplifyApps = cache.New(func() ([]amplifytypes.App, error) {
		out, err := c.Amplify.ListApps(ctx, &amplify.ListAppsInput{})
		if err != nil {
			return nil, err
		}
		return out.Apps, nil
	})
	d.AmplifyBranches = cache.New(func() (map[string][]amplifytypes.Branch, error) {
		apps, err := d.AmplifyApps.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string][]amplifytypes.Branch)
		for _, app := range apps {
			if app.AppId == nil {
				continue
			}
			branches, err := c.Amplify.ListBranches(ctx, &amplify.ListBranchesInput{AppId: app.AppId})
			if err != nil {
				continue
			}
			out[*app.AppId] = branches.Branches
		}
		return out, nil
	})
	d.AmplifyAppTags = cache.New(func() (map[string]map[string]string, error) {
		apps, err := d.AmplifyApps.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, app := range apps {
			if app.AppArn == nil {
				continue
			}
			tags, err := c.Amplify.ListTagsForResource(ctx, &amplify.ListTagsForResourceInput{ResourceArn: app.AppArn})
			if err != nil {
				continue
			}
			out[*app.AppArn] = tags.Tags
		}
		return out, nil
	})
	d.AmplifyBranchTags = cache.New(func() (map[string]map[string]string, error) {
		branchesByApp, err := d.AmplifyBranches.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, branches := range branchesByApp {
			for _, b := range branches {
				if b.BranchArn == nil {
					continue
				}
				tags, err := c.Amplify.ListTagsForResource(ctx, &amplify.ListTagsForResourceInput{ResourceArn: b.BranchArn})
				if err != nil {
					continue
				}
				out[*b.BranchArn] = tags.Tags
			}
		}
		return out, nil
	})

	// AppConfig
	d.AppConfigApplications = cache.New(func() ([]appconfigtypes.Application, error) {
		out, err := c.AppConfig.ListApplications(ctx, &appconfig.ListApplicationsInput{})
		if err != nil {
			return nil, err
		}
		return out.Items, nil
	})
	d.AppConfigEnvironments = cache.New(func() (map[string][]appconfigtypes.Environment, error) {
		apps, err := d.AppConfigApplications.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string][]appconfigtypes.Environment)
		for _, app := range apps {
			if app.Id == nil {
				continue
			}
			envs, err := c.AppConfig.ListEnvironments(ctx, &appconfig.ListEnvironmentsInput{ApplicationId: app.Id})
			if err != nil {
				continue
			}
			out[*app.Id] = envs.Items
		}
		return out, nil
	})
	d.AppConfigProfiles = cache.New(func() (map[string][]appconfigtypes.ConfigurationProfileSummary, error) {
		apps, err := d.AppConfigApplications.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string][]appconfigtypes.ConfigurationProfileSummary)
		for _, app := range apps {
			if app.Id == nil {
				continue
			}
			profiles, err := c.AppConfig.ListConfigurationProfiles(ctx, &appconfig.ListConfigurationProfilesInput{ApplicationId: app.Id})
			if err != nil {
				continue
			}
			out[*app.Id] = profiles.Items
		}
		return out, nil
	})
	d.AppConfigDeploymentStrategies = cache.New(func() ([]appconfigtypes.DeploymentStrategy, error) {
		out, err := c.AppConfig.ListDeploymentStrategies(ctx, &appconfig.ListDeploymentStrategiesInput{})
		if err != nil {
			return nil, err
		}
		return out.Items, nil
	})
	d.AppConfigExtensionAssociations = cache.New(func() ([]appconfigtypes.ExtensionAssociationSummary, error) {
		apps, err := d.AppConfigApplications.Get()
		if err != nil {
			return nil, err
		}
		envsByApp, err := d.AppConfigEnvironments.Get()
		if err != nil {
			return nil, err
		}
		var all []appconfigtypes.ExtensionAssociationSummary
		for _, app := range apps {
			if app.Id == nil {
				continue
			}
			resID := fmt.Sprintf("application/%s", *app.Id)
			out, err := c.AppConfig.ListExtensionAssociations(ctx, &appconfig.ListExtensionAssociationsInput{ResourceIdentifier: &resID})
			if err == nil {
				all = append(all, out.Items...)
			}
			for _, env := range envsByApp[*app.Id] {
				if env.Id == nil {
					continue
				}
				envID := fmt.Sprintf("application/%s/environment/%s", *app.Id, *env.Id)
				out, err := c.AppConfig.ListExtensionAssociations(ctx, &appconfig.ListExtensionAssociationsInput{ResourceIdentifier: &envID})
				if err != nil {
					continue
				}
				all = append(all, out.Items...)
			}
		}
		return all, nil
	})

	d.AppConfigHostedConfigVersions = cache.New(func() (map[string][]appconfigtypes.HostedConfigurationVersionSummary, error) {
		apps, err := d.AppConfigApplications.Get()
		if err != nil {
			return nil, err
		}
		profiles, err := d.AppConfigProfiles.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string][]appconfigtypes.HostedConfigurationVersionSummary)
		for _, app := range apps {
			if app.Id == nil {
				continue
			}
			for _, prof := range profiles[*app.Id] {
				if prof.Id == nil {
					continue
				}
				list, err := c.AppConfig.ListHostedConfigurationVersions(ctx, &appconfig.ListHostedConfigurationVersionsInput{ApplicationId: app.Id, ConfigurationProfileId: prof.Id})
				if err != nil {
					continue
				}
				key := *app.Id + "/" + *prof.Id
				out[key] = list.Items
			}
		}
		return out, nil
	})

	// AppFlow
	d.AppFlowFlows = cache.New(func() ([]appflowtypes.FlowDefinition, error) {
		out, err := c.AppFlow.ListFlows(ctx, &appflow.ListFlowsInput{})
		if err != nil {
			return nil, err
		}
		return out.Flows, nil
	})
	d.AppFlowFlowDetails = cache.New(func() (map[string]appflow.DescribeFlowOutput, error) {
		flows, err := d.AppFlowFlows.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]appflow.DescribeFlowOutput)
		for _, f := range flows {
			if f.FlowName == nil {
				continue
			}
			desc, err := c.AppFlow.DescribeFlow(ctx, &appflow.DescribeFlowInput{FlowName: f.FlowName})
			if err != nil {
				continue
			}
			out[*f.FlowName] = *desc
		}
		return out, nil
	})
	d.AppFlowTags = cache.New(func() (map[string]map[string]string, error) {
		flows, err := d.AppFlowFlows.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, f := range flows {
			if f.FlowArn == nil {
				continue
			}
			tags, err := c.AppFlow.ListTagsForResource(ctx, &appflow.ListTagsForResourceInput{ResourceArn: f.FlowArn})
			if err != nil {
				continue
			}
			out[*f.FlowArn] = tags.Tags
		}
		return out, nil
	})

	// AppRunner
	d.AppRunnerServices = cache.New(func() ([]apprunnertypes.ServiceSummary, error) {
		out, err := c.AppRunner.ListServices(ctx, &apprunner.ListServicesInput{})
		if err != nil {
			return nil, err
		}
		return out.ServiceSummaryList, nil
	})
	d.AppRunnerVPCConnectors = cache.New(func() ([]apprunnertypes.VpcConnector, error) {
		out, err := c.AppRunner.ListVpcConnectors(ctx, &apprunner.ListVpcConnectorsInput{})
		if err != nil {
			return nil, err
		}
		return out.VpcConnectors, nil
	})
	d.AppRunnerServiceDetails = cache.New(func() (map[string]apprunnertypes.Service, error) {
		services, err := d.AppRunnerServices.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]apprunnertypes.Service)
		for _, svc := range services {
			if svc.ServiceArn == nil {
				continue
			}
			desc, err := c.AppRunner.DescribeService(ctx, &apprunner.DescribeServiceInput{ServiceArn: svc.ServiceArn})
			if err != nil || desc.Service == nil {
				continue
			}
			out[*svc.ServiceArn] = *desc.Service
		}
		return out, nil
	})
	d.AppRunnerServiceTags = cache.New(func() (map[string]map[string]string, error) {
		services, err := d.AppRunnerServices.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, svc := range services {
			if svc.ServiceArn == nil {
				continue
			}
			tags, err := c.AppRunner.ListTagsForResource(ctx, &apprunner.ListTagsForResourceInput{ResourceArn: svc.ServiceArn})
			if err != nil {
				continue
			}
			out[*svc.ServiceArn] = tags.Tags
		}
		return out, nil
	})
	d.AppRunnerVPCConnectorTags = cache.New(func() (map[string]map[string]string, error) {
		vpcs, err := d.AppRunnerVPCConnectors.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, vc := range vpcs {
			if vc.VpcConnectorArn == nil {
				continue
			}
			tags, err := c.AppRunner.ListTagsForResource(ctx, &apprunner.ListTagsForResourceInput{ResourceArn: vc.VpcConnectorArn})
			if err != nil {
				continue
			}
			out[*vc.VpcConnectorArn] = tags.Tags
		}
		return out, nil
	})

	// AppIntegrations
	d.AppIntegrationsEventIntegrations = cache.New(func() ([]appintegrationstypes.EventIntegration, error) {
		out, err := c.AppIntegrations.ListEventIntegrations(ctx, &appintegrations.ListEventIntegrationsInput{})
		if err != nil {
			return nil, err
		}
		return out.EventIntegrations, nil
	})
	d.AppIntegrationsTags = cache.New(func() (map[string]map[string]string, error) {
		evs, err := d.AppIntegrationsEventIntegrations.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, e := range evs {
			if e.EventIntegrationArn == nil {
				continue
			}
			tags, err := c.AppIntegrations.ListTagsForResource(ctx, &appintegrations.ListTagsForResourceInput{ResourceArn: e.EventIntegrationArn})
			if err != nil {
				continue
			}
			out[*e.EventIntegrationArn] = tags.Tags
		}
		return out, nil
	})

	// AppMesh
	d.AppMeshMeshes = cache.New(func() ([]appmeshtypes.MeshRef, error) {
		out, err := c.AppMesh.ListMeshes(ctx, &appmesh.ListMeshesInput{})
		if err != nil {
			return nil, err
		}
		return out.Meshes, nil
	})
	d.AppMeshMeshDetails = cache.New(func() (map[string]appmeshtypes.MeshData, error) {
		meshes, err := d.AppMeshMeshes.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]appmeshtypes.MeshData)
		for _, m := range meshes {
			if m.MeshName == nil {
				continue
			}
			desc, err := c.AppMesh.DescribeMesh(ctx, &appmesh.DescribeMeshInput{MeshName: m.MeshName})
			if err != nil || desc.Mesh == nil {
				continue
			}
			out[*m.MeshName] = *desc.Mesh
		}
		return out, nil
	})
	d.AppMeshVirtualNodes = cache.New(func() (map[string][]appmeshtypes.VirtualNodeRef, error) {
		meshes, err := d.AppMeshMeshes.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string][]appmeshtypes.VirtualNodeRef)
		for _, m := range meshes {
			if m.MeshName == nil {
				continue
			}
			list, err := c.AppMesh.ListVirtualNodes(ctx, &appmesh.ListVirtualNodesInput{MeshName: m.MeshName})
			if err != nil {
				continue
			}
			out[*m.MeshName] = list.VirtualNodes
		}
		return out, nil
	})
	d.AppMeshVirtualNodeDetails = cache.New(func() (map[string]appmeshtypes.VirtualNodeData, error) {
		vnsByMesh, err := d.AppMeshVirtualNodes.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]appmeshtypes.VirtualNodeData)
		for mesh, vns := range vnsByMesh {
			for _, vn := range vns {
				if vn.VirtualNodeName == nil {
					continue
				}
				desc, err := c.AppMesh.DescribeVirtualNode(ctx, &appmesh.DescribeVirtualNodeInput{MeshName: &mesh, VirtualNodeName: vn.VirtualNodeName})
				if err != nil || desc.VirtualNode == nil {
					continue
				}
				out[mesh+":"+*vn.VirtualNodeName] = *desc.VirtualNode
			}
		}
		return out, nil
	})
	d.AppMeshVirtualRouters = cache.New(func() (map[string][]appmeshtypes.VirtualRouterRef, error) {
		meshes, err := d.AppMeshMeshes.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string][]appmeshtypes.VirtualRouterRef)
		for _, m := range meshes {
			if m.MeshName == nil {
				continue
			}
			list, err := c.AppMesh.ListVirtualRouters(ctx, &appmesh.ListVirtualRoutersInput{MeshName: m.MeshName})
			if err != nil {
				continue
			}
			out[*m.MeshName] = list.VirtualRouters
		}
		return out, nil
	})
	d.AppMeshVirtualServices = cache.New(func() (map[string][]appmeshtypes.VirtualServiceRef, error) {
		meshes, err := d.AppMeshMeshes.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string][]appmeshtypes.VirtualServiceRef)
		for _, m := range meshes {
			if m.MeshName == nil {
				continue
			}
			list, err := c.AppMesh.ListVirtualServices(ctx, &appmesh.ListVirtualServicesInput{MeshName: m.MeshName})
			if err != nil {
				continue
			}
			out[*m.MeshName] = list.VirtualServices
		}
		return out, nil
	})
	d.AppMeshVirtualGateways = cache.New(func() (map[string][]appmeshtypes.VirtualGatewayRef, error) {
		meshes, err := d.AppMeshMeshes.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string][]appmeshtypes.VirtualGatewayRef)
		for _, m := range meshes {
			if m.MeshName == nil {
				continue
			}
			list, err := c.AppMesh.ListVirtualGateways(ctx, &appmesh.ListVirtualGatewaysInput{MeshName: m.MeshName})
			if err != nil {
				continue
			}
			out[*m.MeshName] = list.VirtualGateways
		}
		return out, nil
	})
	d.AppMeshVirtualGatewayDetails = cache.New(func() (map[string]appmeshtypes.VirtualGatewayData, error) {
		vgsByMesh, err := d.AppMeshVirtualGateways.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]appmeshtypes.VirtualGatewayData)
		for mesh, vgs := range vgsByMesh {
			for _, vg := range vgs {
				if vg.VirtualGatewayName == nil {
					continue
				}
				desc, err := c.AppMesh.DescribeVirtualGateway(ctx, &appmesh.DescribeVirtualGatewayInput{MeshName: &mesh, VirtualGatewayName: vg.VirtualGatewayName})
				if err != nil || desc.VirtualGateway == nil {
					continue
				}
				out[mesh+":"+*vg.VirtualGatewayName] = *desc.VirtualGateway
			}
		}
		return out, nil
	})
	d.AppMeshRoutes = cache.New(func() (map[string][]appmeshtypes.RouteRef, error) {
		meshes, err := d.AppMeshMeshes.Get()
		if err != nil {
			return nil, err
		}
		routers, err := d.AppMeshVirtualRouters.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string][]appmeshtypes.RouteRef)
		for _, m := range meshes {
			if m.MeshName == nil {
				continue
			}
			for _, vr := range routers[*m.MeshName] {
				if vr.VirtualRouterName == nil {
					continue
				}
				list, err := c.AppMesh.ListRoutes(ctx, &appmesh.ListRoutesInput{MeshName: m.MeshName, VirtualRouterName: vr.VirtualRouterName})
				if err != nil {
					continue
				}
				out[*m.MeshName+":"+*vr.VirtualRouterName] = list.Routes
			}
		}
		return out, nil
	})
	d.AppMeshGatewayRoutes = cache.New(func() (map[string][]appmeshtypes.GatewayRouteRef, error) {
		meshes, err := d.AppMeshMeshes.Get()
		if err != nil {
			return nil, err
		}
		gws, err := d.AppMeshVirtualGateways.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string][]appmeshtypes.GatewayRouteRef)
		for _, m := range meshes {
			if m.MeshName == nil {
				continue
			}
			for _, vg := range gws[*m.MeshName] {
				if vg.VirtualGatewayName == nil {
					continue
				}
				list, err := c.AppMesh.ListGatewayRoutes(ctx, &appmesh.ListGatewayRoutesInput{MeshName: m.MeshName, VirtualGatewayName: vg.VirtualGatewayName})
				if err != nil {
					continue
				}
				out[*m.MeshName+":"+*vg.VirtualGatewayName] = list.GatewayRoutes
			}
		}
		return out, nil
	})
	d.AppMeshTags = cache.New(func() (map[string]map[string]string, error) {
		meshes, err := d.AppMeshMeshes.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, m := range meshes {
			if m.Arn == nil {
				continue
			}
			tags, err := c.AppMesh.ListTagsForResource(ctx, &appmesh.ListTagsForResourceInput{ResourceArn: m.Arn})
			if err != nil {
				continue
			}
			out[*m.Arn] = tags.Tags
		}
		vns, _ := d.AppMeshVirtualNodes.Get()
		for mesh, items := range vns {
			for _, vn := range items {
				if vn.Arn == nil {
					continue
				}
				tags, err := c.AppMesh.ListTagsForResource(ctx, &appmesh.ListTagsForResourceInput{ResourceArn: vn.Arn})
				if err != nil {
					continue
				}
				out[*vn.Arn] = tags.Tags
			}
		}
		vrs, _ := d.AppMeshVirtualRouters.Get()
		for _, items := range vrs {
			for _, vr := range items {
				if vr.Arn == nil {
					continue
				}
				tags, err := c.AppMesh.ListTagsForResource(ctx, &appmesh.ListTagsForResourceInput{ResourceArn: vr.Arn})
				if err != nil {
					continue
				}
				out[*vr.Arn] = tags.Tags
			}
		}
		vss, _ := d.AppMeshVirtualServices.Get()
		for _, items := range vss {
			for _, vs := range items {
				if vs.Arn == nil {
					continue
				}
				tags, err := c.AppMesh.ListTagsForResource(ctx, &appmesh.ListTagsForResourceInput{ResourceArn: vs.Arn})
				if err != nil {
					continue
				}
				out[*vs.Arn] = tags.Tags
			}
		}
		vgs, _ := d.AppMeshVirtualGateways.Get()
		for _, items := range vgs {
			for _, vg := range items {
				if vg.Arn == nil {
					continue
				}
				tags, err := c.AppMesh.ListTagsForResource(ctx, &appmesh.ListTagsForResourceInput{ResourceArn: vg.Arn})
				if err != nil {
					continue
				}
				out[*vg.Arn] = tags.Tags
			}
		}
		routes, _ := d.AppMeshRoutes.Get()
		for _, items := range routes {
			for _, r := range items {
				if r.Arn == nil {
					continue
				}
				tags, err := c.AppMesh.ListTagsForResource(ctx, &appmesh.ListTagsForResourceInput{ResourceArn: r.Arn})
				if err != nil {
					continue
				}
				out[*r.Arn] = tags.Tags
			}
		}
		gwRoutes, _ := d.AppMeshGatewayRoutes.Get()
		for _, items := range gwRoutes {
			for _, r := range items {
				if r.Arn == nil {
					continue
				}
				tags, err := c.AppMesh.ListTagsForResource(ctx, &appmesh.ListTagsForResourceInput{ResourceArn: r.Arn})
				if err != nil {
					continue
				}
				out[*r.Arn] = tags.Tags
			}
		}
		return out, nil
	})

	// AutoScaling
	d.AutoScalingGroups = cache.New(func() ([]autoscalingtypes.AutoScalingGroup, error) {
		out, err := c.AutoScaling.DescribeAutoScalingGroups(ctx, &autoscaling.DescribeAutoScalingGroupsInput{})
		if err != nil {
			return nil, err
		}
		return out.AutoScalingGroups, nil
	})
	d.AutoScalingLaunchConfigs = cache.New(func() ([]autoscalingtypes.LaunchConfiguration, error) {
		out, err := c.AutoScaling.DescribeLaunchConfigurations(ctx, &autoscaling.DescribeLaunchConfigurationsInput{})
		if err != nil {
			return nil, err
		}
		return out.LaunchConfigurations, nil
	})

	// Kinesis
	d.KinesisStreams = cache.New(func() ([]string, error) {
		out, err := c.Kinesis.ListStreams(ctx, &kinesis.ListStreamsInput{})
		if err != nil {
			return nil, err
		}
		return out.StreamNames, nil
	})

	// Route53
	d.Route53HostedZones = cache.New(func() ([]route53types.HostedZone, error) {
		out, err := c.Route53.ListHostedZones(ctx, &route53.ListHostedZonesInput{})
		if err != nil {
			return nil, err
		}
		return out.HostedZones, nil
	})
	d.Route53HealthChecks = cache.New(func() ([]route53types.HealthCheck, error) {
		out, err := c.Route53.ListHealthChecks(ctx, &route53.ListHealthChecksInput{})
		if err != nil {
			return nil, err
		}
		return out.HealthChecks, nil
	})

	// SageMaker
	d.SageMakerNotebooks = cache.New(func() ([]sagemakertypes.NotebookInstanceSummary, error) {
		out, err := c.SageMaker.ListNotebookInstances(ctx, &sagemaker.ListNotebookInstancesInput{})
		if err != nil {
			return nil, err
		}
		return out.NotebookInstances, nil
	})
	d.SageMakerEndpointConfigs = cache.New(func() ([]sagemakertypes.EndpointConfigSummary, error) {
		out, err := c.SageMaker.ListEndpointConfigs(ctx, &sagemaker.ListEndpointConfigsInput{})
		if err != nil {
			return nil, err
		}
		return out.EndpointConfigs, nil
	})
	d.SageMakerDomains = cache.New(func() ([]sagemakertypes.DomainDetails, error) {
		out, err := c.SageMaker.ListDomains(ctx, &sagemaker.ListDomainsInput{})
		if err != nil {
			return nil, err
		}
		return out.Domains, nil
	})
	d.SageMakerModels = cache.New(func() ([]sagemakertypes.ModelSummary, error) {
		out, err := c.SageMaker.ListModels(ctx, &sagemaker.ListModelsInput{})
		if err != nil {
			return nil, err
		}
		return out.Models, nil
	})
	d.SageMakerNotebookDetails = cache.New(func() (map[string]sagemakertypes.NotebookInstance, error) {
		summaries, err := d.SageMakerNotebooks.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]sagemakertypes.NotebookInstance)
		for _, nb := range summaries {
			if nb.NotebookInstanceName == nil {
				continue
			}
			desc, err := c.SageMaker.DescribeNotebookInstance(ctx, &sagemaker.DescribeNotebookInstanceInput{NotebookInstanceName: nb.NotebookInstanceName})
			if err != nil || desc == nil {
				continue
			}
			out[*nb.NotebookInstanceName] = *desc
		}
		return out, nil
	})
	d.SageMakerEndpointConfigDetails = cache.New(func() (map[string]sagemakertypes.EndpointConfig, error) {
		summaries, err := d.SageMakerEndpointConfigs.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]sagemakertypes.EndpointConfig)
		for _, ec := range summaries {
			if ec.EndpointConfigName == nil {
				continue
			}
			desc, err := c.SageMaker.DescribeEndpointConfig(ctx, &sagemaker.DescribeEndpointConfigInput{EndpointConfigName: ec.EndpointConfigName})
			if err != nil || desc == nil {
				continue
			}
			out[*ec.EndpointConfigName] = *desc
		}
		return out, nil
	})
	d.SageMakerDomainTags = cache.New(func() (map[string]map[string]string, error) {
		domains, err := d.SageMakerDomains.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, dom := range domains {
			if dom.DomainArn == nil {
				continue
			}
			resp, err := c.SageMaker.ListTags(ctx, &sagemaker.ListTagsInput{ResourceArn: dom.DomainArn})
			if err != nil {
				continue
			}
			m := make(map[string]string)
			for _, t := range resp.Tags {
				if t.Key != nil && t.Value != nil {
					m[*t.Key] = *t.Value
				}
			}
			out[*dom.DomainArn] = m
		}
		return out, nil
	})
	d.SageMakerModelDetails = cache.New(func() (map[string]sagemakertypes.Model, error) {
		models, err := d.SageMakerModels.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]sagemakertypes.Model)
		for _, m := range models {
			if m.ModelName == nil {
				continue
			}
			desc, err := c.SageMaker.DescribeModel(ctx, &sagemaker.DescribeModelInput{ModelName: m.ModelName})
			if err != nil || desc == nil {
				continue
			}
			out[*m.ModelName] = *desc
		}
		return out, nil
	})
	d.SageMakerFeatureGroups = cache.New(func() ([]sagemakertypes.FeatureGroupSummary, error) {
		out, err := c.SageMaker.ListFeatureGroups(ctx, &sagemaker.ListFeatureGroupsInput{})
		if err != nil {
			return nil, err
		}
		return out.FeatureGroupSummaries, nil
	})
	d.SageMakerFeatureGroupTags = cache.New(func() (map[string]map[string]string, error) {
		groups, err := d.SageMakerFeatureGroups.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, g := range groups {
			if g.FeatureGroupArn == nil {
				continue
			}
			resp, err := c.SageMaker.ListTags(ctx, &sagemaker.ListTagsInput{ResourceArn: g.FeatureGroupArn})
			if err != nil {
				continue
			}
			m := make(map[string]string)
			for _, t := range resp.Tags {
				if t.Key != nil && t.Value != nil {
					m[*t.Key] = *t.Value
				}
			}
			out[*g.FeatureGroupArn] = m
		}
		return out, nil
	})
	d.SageMakerImages = cache.New(func() ([]sagemakertypes.ImageSummary, error) {
		out, err := c.SageMaker.ListImages(ctx, &sagemaker.ListImagesInput{})
		if err != nil {
			return nil, err
		}
		return out.Images, nil
	})
	d.SageMakerImageDetails = cache.New(func() (map[string]sagemaker.DescribeImageOutput, error) {
		images, err := d.SageMakerImages.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]sagemaker.DescribeImageOutput)
		for _, img := range images {
			if img.ImageName == nil {
				continue
			}
			desc, err := c.SageMaker.DescribeImage(ctx, &sagemaker.DescribeImageInput{ImageName: img.ImageName})
			if err != nil || desc == nil {
				continue
			}
			out[*img.ImageName] = *desc
		}
		return out, nil
	})
	d.SageMakerImageTags = cache.New(func() (map[string]map[string]string, error) {
		images, err := d.SageMakerImages.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, img := range images {
			if img.ImageArn == nil {
				continue
			}
			resp, err := c.SageMaker.ListTags(ctx, &sagemaker.ListTagsInput{ResourceArn: img.ImageArn})
			if err != nil {
				continue
			}
			m := make(map[string]string)
			for _, t := range resp.Tags {
				if t.Key != nil && t.Value != nil {
					m[*t.Key] = *t.Value
				}
			}
			out[*img.ImageArn] = m
		}
		return out, nil
	})
	d.SageMakerAppImageConfigs = cache.New(func() ([]sagemakertypes.AppImageConfigSummary, error) {
		out, err := c.SageMaker.ListAppImageConfigs(ctx, &sagemaker.ListAppImageConfigsInput{})
		if err != nil {
			return nil, err
		}
		return out.AppImageConfigs, nil
	})
	d.SageMakerAppImageConfigTags = cache.New(func() (map[string]map[string]string, error) {
		apps, err := d.SageMakerAppImageConfigs.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, app := range apps {
			if app.AppImageConfigArn == nil {
				continue
			}
			resp, err := c.SageMaker.ListTags(ctx, &sagemaker.ListTagsInput{ResourceArn: app.AppImageConfigArn})
			if err != nil {
				continue
			}
			m := make(map[string]string)
			for _, t := range resp.Tags {
				if t.Key != nil && t.Value != nil {
					m[*t.Key] = *t.Value
				}
			}
			out[*app.AppImageConfigArn] = m
		}
		return out, nil
	})

	// Transfer
	d.TransferServers = cache.New(func() ([]transfertypes.ListedServer, error) {
		out, err := c.Transfer.ListServers(ctx, &transfer.ListServersInput{})
		if err != nil {
			return nil, err
		}
		return out.Servers, nil
	})
	d.TransferServerDetails = cache.New(func() (map[string]transfertypes.DescribedServer, error) {
		servers, err := d.TransferServers.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]transfertypes.DescribedServer)
		for _, s := range servers {
			if s.ServerId == nil {
				continue
			}
			desc, err := c.Transfer.DescribeServer(ctx, &transfer.DescribeServerInput{ServerId: s.ServerId})
			if err != nil || desc.Server == nil {
				continue
			}
			out[*s.ServerId] = *desc.Server
		}
		return out, nil
	})
	d.TransferAgreements = cache.New(func() ([]transfertypes.ListedAgreement, error) {
		out, err := c.Transfer.ListAgreements(ctx, &transfer.ListAgreementsInput{})
		if err != nil {
			return nil, err
		}
		return out.Agreements, nil
	})
	d.TransferAgreementDetails = cache.New(func() (map[string]transfertypes.DescribedAgreement, error) {
		agreements, err := d.TransferAgreements.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]transfertypes.DescribedAgreement)
		for _, a := range agreements {
			if a.AgreementId == nil {
				continue
			}
			desc, err := c.Transfer.DescribeAgreement(ctx, &transfer.DescribeAgreementInput{AgreementId: a.AgreementId})
			if err != nil || desc.Agreement == nil {
				continue
			}
			out[*a.AgreementId] = *desc.Agreement
		}
		return out, nil
	})
	d.TransferCertificates = cache.New(func() ([]transfertypes.ListedCertificate, error) {
		out, err := c.Transfer.ListCertificates(ctx, &transfer.ListCertificatesInput{})
		if err != nil {
			return nil, err
		}
		return out.Certificates, nil
	})
	d.TransferCertificateDetails = cache.New(func() (map[string]transfertypes.DescribedCertificate, error) {
		certs, err := d.TransferCertificates.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]transfertypes.DescribedCertificate)
		for _, c := range certs {
			if c.CertificateId == nil {
				continue
			}
			desc, err := c.Transfer.DescribeCertificate(ctx, &transfer.DescribeCertificateInput{CertificateId: c.CertificateId})
			if err != nil || desc.Certificate == nil {
				continue
			}
			out[*c.CertificateId] = *desc.Certificate
		}
		return out, nil
	})
	d.TransferConnectors = cache.New(func() ([]transfertypes.ListedConnector, error) {
		out, err := c.Transfer.ListConnectors(ctx, &transfer.ListConnectorsInput{})
		if err != nil {
			return nil, err
		}
		return out.Connectors, nil
	})
	d.TransferConnectorDetails = cache.New(func() (map[string]transfertypes.DescribedConnector, error) {
		connectors, err := d.TransferConnectors.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]transfertypes.DescribedConnector)
		for _, c := range connectors {
			if c.ConnectorId == nil {
				continue
			}
			desc, err := c.Transfer.DescribeConnector(ctx, &transfer.DescribeConnectorInput{ConnectorId: c.ConnectorId})
			if err != nil || desc.Connector == nil {
				continue
			}
			out[*c.ConnectorId] = *desc.Connector
		}
		return out, nil
	})
	d.TransferProfiles = cache.New(func() ([]transfertypes.ListedProfile, error) {
		out, err := c.Transfer.ListProfiles(ctx, &transfer.ListProfilesInput{})
		if err != nil {
			return nil, err
		}
		return out.Profiles, nil
	})
	d.TransferProfileDetails = cache.New(func() (map[string]transfertypes.DescribedProfile, error) {
		profiles, err := d.TransferProfiles.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]transfertypes.DescribedProfile)
		for _, p := range profiles {
			if p.ProfileId == nil {
				continue
			}
			desc, err := c.Transfer.DescribeProfile(ctx, &transfer.DescribeProfileInput{ProfileId: p.ProfileId})
			if err != nil || desc.Profile == nil {
				continue
			}
			out[*p.ProfileId] = *desc.Profile
		}
		return out, nil
	})
	d.TransferWorkflows = cache.New(func() ([]transfertypes.ListedWorkflow, error) {
		out, err := c.Transfer.ListWorkflows(ctx, &transfer.ListWorkflowsInput{})
		if err != nil {
			return nil, err
		}
		return out.Workflows, nil
	})
	d.TransferWorkflowDetails = cache.New(func() (map[string]transfertypes.DescribedWorkflow, error) {
		workflows, err := d.TransferWorkflows.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]transfertypes.DescribedWorkflow)
		for _, w := range workflows {
			if w.WorkflowId == nil {
				continue
			}
			desc, err := c.Transfer.DescribeWorkflow(ctx, &transfer.DescribeWorkflowInput{WorkflowId: w.WorkflowId})
			if err != nil || desc.Workflow == nil {
				continue
			}
			out[*w.WorkflowId] = *desc.Workflow
		}
		return out, nil
	})
	d.TransferTags = cache.New(func() (map[string]map[string]string, error) {
		out := make(map[string]map[string]string)
		collect := func(arn *string) {
			if arn == nil {
				return
			}
			tags, err := c.Transfer.ListTagsForResource(ctx, &transfer.ListTagsForResourceInput{Arn: arn})
			if err != nil {
				return
			}
			out[*arn] = tags.Tags
		}
		servers, _ := d.TransferServers.Get()
		for _, s := range servers {
			collect(s.Arn)
		}
		agreements, _ := d.TransferAgreements.Get()
		for _, a := range agreements {
			collect(a.Arn)
		}
		certs, _ := d.TransferCertificates.Get()
		for _, c := range certs {
			collect(c.Arn)
		}
		connectors, _ := d.TransferConnectors.Get()
		for _, c := range connectors {
			collect(c.Arn)
		}
		profiles, _ := d.TransferProfiles.Get()
		for _, p := range profiles {
			collect(p.Arn)
		}
		workflows, _ := d.TransferWorkflows.Get()
		for _, w := range workflows {
			collect(w.Arn)
		}
		return out, nil
	})

	// MQ
	d.MQBrokers = cache.New(func() ([]mqtypes.BrokerSummary, error) {
		out, err := c.MQ.ListBrokers(ctx, &mq.ListBrokersInput{})
		if err != nil {
			return nil, err
		}
		return out.BrokerSummaries, nil
	})
	d.MQBrokerDetails = cache.New(func() (map[string]mq.DescribeBrokerOutput, error) {
		brokers, err := d.MQBrokers.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]mq.DescribeBrokerOutput)
		for _, b := range brokers {
			if b.BrokerId == nil {
				continue
			}
			desc, err := c.MQ.DescribeBroker(ctx, &mq.DescribeBrokerInput{BrokerId: b.BrokerId})
			if err != nil || desc.BrokerId == nil {
				continue
			}
			out[*b.BrokerId] = *desc
		}
		return out, nil
	})

	// Network Firewall
	d.NetworkFirewalls = cache.New(func() ([]networkfirewall.ListFirewallsOutput, error) {
		out, err := c.NetworkFirewall.ListFirewalls(ctx, &networkfirewall.ListFirewallsInput{})
		if err != nil {
			return nil, err
		}
		return []networkfirewall.ListFirewallsOutput{*out}, nil
	})

	// WAF
	d.WAFWebACLs = cache.New(func() ([]waftypes.WebACLSummary, error) {
		out, err := c.WAF.ListWebACLs(ctx, &waf.ListWebACLsInput{Limit: 100})
		if err != nil {
			return nil, err
		}
		return out.WebACLs, nil
	})
	d.WAFRules = cache.New(func() ([]waftypes.RuleSummary, error) {
		out, err := c.WAF.ListRules(ctx, &waf.ListRulesInput{Limit: 100})
		if err != nil {
			return nil, err
		}
		return out.Rules, nil
	})
	d.WAFRuleGroups = cache.New(func() ([]waftypes.RuleGroupSummary, error) {
		out, err := c.WAF.ListRuleGroups(ctx, &waf.ListRuleGroupsInput{Limit: 100})
		if err != nil {
			return nil, err
		}
		return out.RuleGroups, nil
	})

	// WAF Regional
	d.WAFRegionalWebACLs = cache.New(func() ([]wafregionaltypes.WebACLSummary, error) {
		out, err := c.WAFRegional.ListWebACLs(ctx, &wafregional.ListWebACLsInput{Limit: 100})
		if err != nil {
			return nil, err
		}
		return out.WebACLs, nil
	})
	d.WAFRegionalRules = cache.New(func() ([]wafregionaltypes.RuleSummary, error) {
		out, err := c.WAFRegional.ListRules(ctx, &wafregional.ListRulesInput{Limit: 100})
		if err != nil {
			return nil, err
		}
		return out.Rules, nil
	})
	d.WAFRegionalRuleGroups = cache.New(func() ([]wafregionaltypes.RuleGroupSummary, error) {
		out, err := c.WAFRegional.ListRuleGroups(ctx, &wafregional.ListRuleGroupsInput{Limit: 100})
		if err != nil {
			return nil, err
		}
		return out.RuleGroups, nil
	})

	// WAFv2
	d.WAFv2WebACLs = cache.New(func() ([]wafv2types.WebACLSummary, error) {
		out, err := c.WAFv2.ListWebACLs(ctx, &wafv2.ListWebACLsInput{Scope: wafv2types.ScopeRegional})
		if err != nil {
			return nil, err
		}
		return out.WebACLs, nil
	})
	d.WAFv2RuleGroups = cache.New(func() ([]wafv2types.RuleGroupSummary, error) {
		out, err := c.WAFv2.ListRuleGroups(ctx, &wafv2.ListRuleGroupsInput{Scope: wafv2types.ScopeRegional})
		if err != nil {
			return nil, err
		}
		return out.RuleGroups, nil
	})
	d.WAFv2WebACLForResource = cache.New(func() (map[string]bool, error) {
		lbs, err := d.ELBv2LoadBalancers.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]bool)
		for _, lb := range lbs {
			if lb.LoadBalancerArn == nil {
				continue
			}
			_, err := c.WAFv2.GetWebACLForResource(ctx, &wafv2.GetWebACLForResourceInput{ResourceArn: lb.LoadBalancerArn})
			if err != nil {
				var nf *wafv2types.WAFNonexistentItemException
				if errors.As(err, &nf) {
					out[*lb.LoadBalancerArn] = false
					continue
				}
				return nil, err
			}
			out[*lb.LoadBalancerArn] = true
		}
		return out, nil
	})

	// Workspaces
	d.Workspaces = cache.New(func() ([]workspacestypes.Workspace, error) {
		out, err := c.Workspaces.DescribeWorkspaces(ctx, &workspaces.DescribeWorkspacesInput{})
		if err != nil {
			return nil, err
		}
		return out.Workspaces, nil
	})

	// ElasticBeanstalk
	d.ElasticBeanstalkApps = cache.New(func() ([]ebtypes.ApplicationDescription, error) {
		out, err := c.ElasticBeanstalk.DescribeApplications(ctx, &elasticbeanstalk.DescribeApplicationsInput{})
		if err != nil {
			return nil, err
		}
		return out.Applications, nil
	})
	d.ElasticBeanstalkEnvs = cache.New(func() ([]ebtypes.EnvironmentDescription, error) {
		out, err := c.ElasticBeanstalk.DescribeEnvironments(ctx, &elasticbeanstalk.DescribeEnvironmentsInput{})
		if err != nil {
			return nil, err
		}
		return out.Environments, nil
	})
	d.ElasticBeanstalkAppVersions = cache.New(func() ([]ebtypes.ApplicationVersionDescription, error) {
		out, err := c.ElasticBeanstalk.DescribeApplicationVersions(ctx, &elasticbeanstalk.DescribeApplicationVersionsInput{})
		if err != nil {
			return nil, err
		}
		return out.ApplicationVersions, nil
	})
}
