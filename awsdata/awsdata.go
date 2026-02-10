package awsdata

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"bptools/cache"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/account"
	accounttypes "github.com/aws/aws-sdk-go-v2/service/account/types"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	acmpcatypes "github.com/aws/aws-sdk-go-v2/service/acmpca/types"
	"github.com/aws/aws-sdk-go-v2/service/amp"
	amptypes "github.com/aws/aws-sdk-go-v2/service/amp/types"
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
	"github.com/aws/aws-sdk-go-v2/service/appstream"
	appstreamtypes "github.com/aws/aws-sdk-go-v2/service/appstream/types"
	"github.com/aws/aws-sdk-go-v2/service/appsync"
	appsynctypes "github.com/aws/aws-sdk-go-v2/service/appsync/types"
	"github.com/aws/aws-sdk-go-v2/service/athena"
	athenatypes "github.com/aws/aws-sdk-go-v2/service/athena/types"
	"github.com/aws/aws-sdk-go-v2/service/auditmanager"
	auditmanagertypes "github.com/aws/aws-sdk-go-v2/service/auditmanager/types"
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
	"github.com/aws/aws-sdk-go-v2/service/codeguruprofiler"
	codeguruprofilertypes "github.com/aws/aws-sdk-go-v2/service/codeguruprofiler/types"
	"github.com/aws/aws-sdk-go-v2/service/codegurureviewer"
	codegurureviewertypes "github.com/aws/aws-sdk-go-v2/service/codegurureviewer/types"
	"github.com/aws/aws-sdk-go-v2/service/codepipeline"
	codepipelinetypes "github.com/aws/aws-sdk-go-v2/service/codepipeline/types"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentity"
	cognitoidtypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentity/types"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	cognitoidptypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/aws/aws-sdk-go-v2/service/connect"
	connecttypes "github.com/aws/aws-sdk-go-v2/service/connect/types"
	"github.com/aws/aws-sdk-go-v2/service/customerprofiles"
	customerprofilestypes "github.com/aws/aws-sdk-go-v2/service/customerprofiles/types"
	"github.com/aws/aws-sdk-go-v2/service/databasemigrationservice"
	dmstypes "github.com/aws/aws-sdk-go-v2/service/databasemigrationservice/types"
	"github.com/aws/aws-sdk-go-v2/service/datasync"
	datasynctypes "github.com/aws/aws-sdk-go-v2/service/datasync/types"
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
	emrtypes "github.com/aws/aws-sdk-go-v2/service/emr/types"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	eventbridgetypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	"github.com/aws/aws-sdk-go-v2/service/evidently"
	evidentlytypes "github.com/aws/aws-sdk-go-v2/service/evidently/types"
	"github.com/aws/aws-sdk-go-v2/service/firehose"
	firehosetypes "github.com/aws/aws-sdk-go-v2/service/firehose/types"
	"github.com/aws/aws-sdk-go-v2/service/fis"
	fistypes "github.com/aws/aws-sdk-go-v2/service/fis/types"
	"github.com/aws/aws-sdk-go-v2/service/fms"
	fmstypes "github.com/aws/aws-sdk-go-v2/service/fms/types"
	"github.com/aws/aws-sdk-go-v2/service/frauddetector"
	fraudtypes "github.com/aws/aws-sdk-go-v2/service/frauddetector/types"
	"github.com/aws/aws-sdk-go-v2/service/fsx"
	fsxtypes "github.com/aws/aws-sdk-go-v2/service/fsx/types"
	"github.com/aws/aws-sdk-go-v2/service/globalaccelerator"
	globalacceleratortypes "github.com/aws/aws-sdk-go-v2/service/globalaccelerator/types"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	gluetypes "github.com/aws/aws-sdk-go-v2/service/glue/types"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	guarddutytypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	"github.com/aws/aws-sdk-go-v2/service/iot"
	iottypes "github.com/aws/aws-sdk-go-v2/service/iot/types"
	"github.com/aws/aws-sdk-go-v2/service/iotevents"
	ioteventstypes "github.com/aws/aws-sdk-go-v2/service/iotevents/types"
	"github.com/aws/aws-sdk-go-v2/service/iotsitewise"
	sitewisetypes "github.com/aws/aws-sdk-go-v2/service/iotsitewise/types"
	"github.com/aws/aws-sdk-go-v2/service/iottwinmaker"
	twinmakertypes "github.com/aws/aws-sdk-go-v2/service/iottwinmaker/types"
	"github.com/aws/aws-sdk-go-v2/service/iotwireless"
	iotwirelesstypes "github.com/aws/aws-sdk-go-v2/service/iotwireless/types"
	"github.com/aws/aws-sdk-go-v2/service/ivs"
	ivstypes "github.com/aws/aws-sdk-go-v2/service/ivs/types"
	"github.com/aws/aws-sdk-go-v2/service/kafka"
	kafkatypes "github.com/aws/aws-sdk-go-v2/service/kafka/types"
	"github.com/aws/aws-sdk-go-v2/service/kafkaconnect"
	kafkaconnecttypes "github.com/aws/aws-sdk-go-v2/service/kafkaconnect/types"
	"github.com/aws/aws-sdk-go-v2/service/keyspaces"
	keyspacestypes "github.com/aws/aws-sdk-go-v2/service/keyspaces/types"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	"github.com/aws/aws-sdk-go-v2/service/kinesisvideo"
	kinesisvideotypes "github.com/aws/aws-sdk-go-v2/service/kinesisvideo/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/lightsail"
	lightsailtypes "github.com/aws/aws-sdk-go-v2/service/lightsail/types"
	"github.com/aws/aws-sdk-go-v2/service/macie2"
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
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"
	resourcegroupstaggingapitypes "github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi/types"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	route53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/aws/aws-sdk-go-v2/service/route53resolver"
	resolvertype "github.com/aws/aws-sdk-go-v2/service/route53resolver/types"
	"github.com/aws/aws-sdk-go-v2/service/rum"
	rumtypes "github.com/aws/aws-sdk-go-v2/service/rum/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	sagemakertypes "github.com/aws/aws-sdk-go-v2/service/sagemaker/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/servicecatalog"
	servicecatalogtypes "github.com/aws/aws-sdk-go-v2/service/servicecatalog/types"
	"github.com/aws/aws-sdk-go-v2/service/ses"
	sestypes "github.com/aws/aws-sdk-go-v2/service/ses/types"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	sfntypes "github.com/aws/aws-sdk-go-v2/service/sfn/types"
	"github.com/aws/aws-sdk-go-v2/service/shield"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	snstypes "github.com/aws/aws-sdk-go-v2/service/sns/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
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
	CloudTrailTrails         *cache.Memo[[]cloudtrailtypes.TrailInfo]
	CloudTrailTrailDetails   *cache.Memo[map[string]cloudtrailtypes.Trail]
	CloudTrailTrailStatus    *cache.Memo[map[string]cloudtrail.GetTrailStatusOutput]
	CloudTrailEventSelectors *cache.Memo[map[string]cloudtrail.GetEventSelectorsOutput]

	// CloudWatch
	CloudWatchAlarms           *cache.Memo[[]cloudwatchtypes.MetricAlarm]
	CloudWatchLogGroups        *cache.Memo[[]logstypes.LogGroup]
	CloudWatchMetricStreams    *cache.Memo[[]cloudwatchtypes.MetricStreamEntry]
	CloudWatchMetricStreamTags *cache.Memo[map[string]map[string]string]

	// CloudFront
	CloudFrontDistributions        *cache.Memo[[]cftypescf.DistributionSummary]
	CloudFrontDistributionConfigs  *cache.Memo[map[string]cftypescf.DistributionConfig]
	CloudFrontDistributionTags     *cache.Memo[map[string]map[string]string]
	CloudFrontDistributionARNs     *cache.Memo[map[string]string]
	CloudFrontDistributionWAF      *cache.Memo[map[string]bool]
	CloudFrontS3OriginBucketExists *cache.Memo[map[string]bool]

	// CloudFormation
	CloudFormationStacks       *cache.Memo[[]cftypes.StackSummary]
	CloudFormationStackDetails *cache.Memo[map[string]cftypes.Stack]

	// ACM
	ACMCertificates       *cache.Memo[[]acmtypes.CertificateSummary]
	ACMCertificateDetails *cache.Memo[map[string]acmtypes.CertificateDetail]

	// ACM PCA
	ACMPCACertificateAuthorities   *cache.Memo[[]acmpcatypes.CertificateAuthority]
	ACMPCACertificateAuthorityTags *cache.Memo[map[string]map[string]string]

	// KMS
	KMSKeys              *cache.Memo[[]kmstypes.KeyListEntry]
	KMSKeyDetails        *cache.Memo[map[string]kmstypes.KeyMetadata]
	KMSKeyRotationStatus *cache.Memo[map[string]bool]
	KMSKeyTags           *cache.Memo[map[string]map[string]string]
	KMSKeyPolicies       *cache.Memo[map[string]string]

	// SNS
	SNSTopics          *cache.Memo[[]snstypes.Topic]
	SNSTopicAttributes *cache.Memo[map[string]map[string]string]

	// SQS
	SQSQueues          *cache.Memo[[]string]
	SQSQueueAttributes *cache.Memo[map[string]map[string]string]

	// Secrets Manager
	SecretsManagerSecrets       *cache.Memo[[]smtypes.SecretListEntry]
	SecretsManagerSecretDetails *cache.Memo[map[string]secretsmanager.DescribeSecretOutput]
	SecretsManagerSecretTags    *cache.Memo[map[string]map[string]string]

	// SSM
	SSMDocuments       *cache.Memo[[]ssmtypes.DocumentIdentifier]
	SSMDocumentDetails *cache.Memo[map[string]ssmtypes.DocumentDescription]
	SSMDocumentTags    *cache.Memo[map[string]map[string]string]
	SSMDocumentContent *cache.Memo[map[string]string]

	// Step Functions
	SFNStateMachines       *cache.Memo[[]sfntypes.StateMachineListItem]
	SFNStateMachineDetails *cache.Memo[map[string]sfn.DescribeStateMachineOutput]
	SFNStateMachineTags    *cache.Memo[map[string]map[string]string]

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
	GlueJobs             *cache.Memo[[]gluetypes.Job]
	GlueMLTransforms     *cache.Memo[[]gluetypes.MLTransform]
	GlueMLTransformTags  *cache.Memo[map[string]map[string]string]
	GlueRegistries       *cache.Memo[[]gluetypes.RegistryListItem]
	GlueRegistryPolicies *cache.Memo[map[string]string]

	// GuardDuty
	GuardDutyDetectorIDs         *cache.Memo[[]string]
	GuardDutyDetectors           *cache.Memo[map[string]guardduty.GetDetectorOutput]
	GuardDutyNonArchivedFindings *cache.Memo[map[string]int]

	// Inspector2
	Inspector2Status *cache.Memo[inspector2.BatchGetAccountStatusOutput]

	// IoT
	IoTAuthorizers                 *cache.Memo[[]iottypes.AuthorizerSummary]
	IoTAuthorizerDetails           *cache.Memo[map[string]iottypes.AuthorizerDescription]
	IoTJobTemplates                *cache.Memo[[]iottypes.JobTemplateSummary]
	IoTJobTemplateTags             *cache.Memo[map[string]map[string]string]
	IoTProvisioningTemplates       *cache.Memo[[]iottypes.ProvisioningTemplateSummary]
	IoTProvisioningTemplateDetails *cache.Memo[map[string]iot.DescribeProvisioningTemplateOutput]
	IoTProvisioningTemplateTags    *cache.Memo[map[string]map[string]string]
	IoTScheduledAudits             *cache.Memo[[]iottypes.ScheduledAuditMetadata]
	IoTScheduledAuditTags          *cache.Memo[map[string]map[string]string]

	// IoT SiteWise
	IoTSiteWiseAssetModels *cache.Memo[[]sitewisetypes.AssetModelSummary]
	IoTSiteWiseDashboards  *cache.Memo[[]sitewisetypes.DashboardSummary]
	IoTSiteWiseGateways    *cache.Memo[[]sitewisetypes.GatewaySummary]
	IoTSiteWisePortals     *cache.Memo[[]sitewisetypes.PortalSummary]
	IoTSiteWiseProjects    *cache.Memo[[]sitewisetypes.ProjectSummary]
	IoTSiteWiseTags        *cache.Memo[map[string]map[string]string]

	// IoT TwinMaker
	TwinMakerWorkspaces     *cache.Memo[[]twinmakertypes.WorkspaceSummary]
	TwinMakerComponentTypes *cache.Memo[map[string][]twinmakertypes.ComponentTypeSummary]
	TwinMakerEntities       *cache.Memo[map[string][]twinmakertypes.EntitySummary]
	TwinMakerScenes         *cache.Memo[map[string][]twinmakertypes.SceneSummary]
	TwinMakerSyncJobs       *cache.Memo[map[string][]twinmakertypes.SyncJobSummary]
	TwinMakerTags           *cache.Memo[map[string]map[string]string]

	// IVS
	IVSChannels                *cache.Memo[[]ivstypes.ChannelSummary]
	IVSChannelDetails          *cache.Memo[map[string]ivstypes.Channel]
	IVSRecordingConfigurations *cache.Memo[[]ivstypes.RecordingConfigurationSummary]
	IVSPlaybackKeyPairs        *cache.Memo[[]ivstypes.PlaybackKeyPairSummary]
	IVSTags                    *cache.Memo[map[string]map[string]string]

	// Backup
	BackupPlans                    *cache.Memo[[]backuptypes.BackupPlansListMember]
	BackupVaults                   *cache.Memo[[]backuptypes.BackupVaultListMember]
	BackupPlanDetails              *cache.Memo[map[string]backuptypes.BackupPlan]
	BackupRecoveryPoints           *cache.Memo[map[string][]backuptypes.RecoveryPointByBackupVault]
	BackupVaultLockConfigs         *cache.Memo[map[string]backup.DescribeBackupVaultOutput]
	BackupProtectedResources       *cache.Memo[map[string]backuptypes.ProtectedResource]
	BackupRecoveryPointsByResource *cache.Memo[map[string][]backuptypes.RecoveryPointByResource]

	// DocDB
	DocDBClusters  *cache.Memo[[]docdbtypes.DBCluster]
	DocDBSnapshots *cache.Memo[[]docdbtypes.DBClusterSnapshot]

	// DAX
	DAXClusters *cache.Memo[[]daxtypes.Cluster]

	// Cassandra (Keyspaces)
	CassandraKeyspaces         *cache.Memo[[]keyspacestypes.KeyspaceSummary]
	CassandraKeyspaceTags      *cache.Memo[map[string]map[string]string]
	CassandraKeyspaceARNByName *cache.Memo[map[string]string]

	// DataSync
	DataSyncTasks                        *cache.Memo[[]datasynctypes.TaskListEntry]
	DataSyncTaskDetails                  *cache.Memo[map[string]datasync.DescribeTaskOutput]
	DataSyncTaskTags                     *cache.Memo[map[string]map[string]string]
	DataSyncLocations                    *cache.Memo[[]datasynctypes.LocationListEntry]
	DataSyncLocationObjectStorageDetails *cache.Memo[map[string]datasync.DescribeLocationObjectStorageOutput]

	// Evidently
	EvidentlyProjects       *cache.Memo[[]evidentlytypes.ProjectSummary]
	EvidentlyProjectDetails *cache.Memo[map[string]evidentlytypes.Project]
	EvidentlyProjectTags    *cache.Memo[map[string]map[string]string]
	EvidentlyLaunches       *cache.Memo[map[string][]evidentlytypes.Launch]
	EvidentlyLaunchDetails  *cache.Memo[map[string]evidentlytypes.Launch]
	EvidentlyLaunchTags     *cache.Memo[map[string]map[string]string]
	EvidentlySegments       *cache.Memo[map[string][]evidentlytypes.Segment]
	EvidentlySegmentDetails *cache.Memo[map[string]evidentlytypes.Segment]
	EvidentlySegmentTags    *cache.Memo[map[string]map[string]string]

	// Fraud Detector
	FraudDetectorEntityTypes    *cache.Memo[[]fraudtypes.EntityType]
	FraudDetectorLabels         *cache.Memo[[]fraudtypes.Label]
	FraudDetectorOutcomes       *cache.Memo[[]fraudtypes.Outcome]
	FraudDetectorVariables      *cache.Memo[[]fraudtypes.Variable]
	FraudDetectorEntityTypeTags *cache.Memo[map[string]map[string]string]
	FraudDetectorLabelTags      *cache.Memo[map[string]map[string]string]
	FraudDetectorOutcomeTags    *cache.Memo[map[string]map[string]string]
	FraudDetectorVariableTags   *cache.Memo[map[string]map[string]string]

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
	CodeBuildProjects           *cache.Memo[[]codebuildtypes.Project]
	CodeBuildProjectDetails     *cache.Memo[map[string]codebuildtypes.Project]
	CodeBuildReportGroups       *cache.Memo[[]string]
	CodeBuildReportGroupDetails *cache.Memo[map[string]codebuildtypes.ReportGroup]
	CodeBuildReportGroupTags    *cache.Memo[map[string]map[string]string]

	// CodeDeploy
	CodeDeployApps                   *cache.Memo[[]string]
	CodeDeployDeploymentGroups       *cache.Memo[map[string][]string]
	CodeDeployDeploymentGroupDetails *cache.Memo[map[string]codedeploy.GetDeploymentGroupOutput]
	CodeDeployDeploymentConfigs      *cache.Memo[map[string]codedeploy.GetDeploymentConfigOutput]

	// CodePipeline
	CodePipelines       *cache.Memo[[]codepipelinetypes.PipelineSummary]
	CodePipelineDetails *cache.Memo[map[string]codepipeline.GetPipelineOutput]

	// Cognito
	CognitoUserPools           *cache.Memo[[]cognitoidptypes.UserPoolDescriptionType]
	CognitoUserPoolDetails     *cache.Memo[map[string]cognitoidptypes.UserPoolType]
	CognitoUserPoolTags        *cache.Memo[map[string]map[string]string]
	CognitoIdentityPools       *cache.Memo[[]cognitoidtypes.IdentityPoolShortDescription]
	CognitoIdentityPoolDetails *cache.Memo[map[string]cognitoidentity.DescribeIdentityPoolOutput]
	CognitoIdentityPoolRoles   *cache.Memo[map[string]cognitoidentity.GetIdentityPoolRolesOutput]

	// Account
	AccountSecurityContact *cache.Memo[*accounttypes.AlternateContact]

	// FSx
	FSxFileSystems    *cache.Memo[[]fsxtypes.FileSystem]
	FSxFileSystemTags *cache.Memo[map[string]map[string]string]

	// EMR
	EMRClusters              *cache.Memo[[]string]
	EMRClusterDetails        *cache.Memo[map[string]emrtypes.Cluster]
	EMRSecurityConfigs       *cache.Memo[[]string]
	EMRSecurityConfigDetails *cache.Memo[map[string]emr.DescribeSecurityConfigurationOutput]
	EMRBlockPublicAccess     *cache.Memo[emrtypes.BlockPublicAccessConfiguration]

	// Athena
	AthenaWorkgroups         *cache.Memo[[]athenatypes.WorkGroupSummary]
	AthenaWorkgroupDetails   *cache.Memo[map[string]athenatypes.WorkGroup]
	AthenaDataCatalogs       *cache.Memo[[]athenatypes.DataCatalog]
	AthenaPreparedStatements *cache.Memo[[]athenatypes.PreparedStatementSummary]

	// AppSync
	AppSyncAPIs                   *cache.Memo[[]appsynctypes.GraphqlApi]
	AppSyncApiCaches              *cache.Memo[map[string]*appsynctypes.ApiCache]
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

	// AppStream
	AppStreamFleets *cache.Memo[[]appstreamtypes.Fleet]

	// AMP
	AMPRuleGroupsNamespaces *cache.Memo[[]amptypes.RuleGroupsNamespaceSummary]

	// AuditManager
	AuditManagerAssessments *cache.Memo[map[string]auditmanagertypes.Assessment]

	// CodeGuru Profiler
	CodeGuruProfilingGroups *cache.Memo[map[string]codeguruprofilertypes.ProfilingGroupDescription]
	CodeGuruProfilerTags    *cache.Memo[map[string]map[string]string]

	// CodeGuru Reviewer
	CodeGuruReviewerAssociations *cache.Memo[[]codegurureviewertypes.RepositoryAssociationSummary]
	CodeGuruReviewerTags         *cache.Memo[map[string]map[string]string]

	// Connect
	ConnectInstances               *cache.Memo[[]connecttypes.InstanceSummary]
	ConnectInstanceContactFlowLogs *cache.Memo[map[string]bool]

	// CustomerProfiles
	CustomerProfilesDomains           *cache.Memo[[]customerprofilestypes.ListDomainItem]
	CustomerProfilesObjectTypes       *cache.Memo[map[string][]customerprofilestypes.ListProfileObjectTypeItem]
	CustomerProfilesObjectTypeDetails *cache.Memo[map[string]customerprofiles.GetProfileObjectTypeOutput]

	// FIS
	FISExperimentTemplates       *cache.Memo[[]fistypes.ExperimentTemplateSummary]
	FISExperimentTemplateDetails *cache.Memo[map[string]fistypes.ExperimentTemplate]

	// FMS
	FMSPolicies      *cache.Memo[[]fmstypes.PolicySummary]
	FMSPolicyDetails *cache.Memo[map[string]fmstypes.Policy]

	// SecurityHub
	SecurityHubEnabled *cache.Memo[bool]

	// SES
	SESReceiptRuleSets     *cache.Memo[map[string][]sestypes.ReceiptRule]
	SESv2ConfigurationSets *cache.Memo[map[string]sesv2.GetConfigurationSetOutput]

	// Shield
	ShieldSubscription *cache.Memo[*shield.DescribeSubscriptionOutput]
	ShieldDRTAccess    *cache.Memo[*shield.DescribeDRTAccessOutput]

	// Resource Groups Tagging API
	ResourceTagMappings *cache.Memo[[]resourcegroupstaggingapitypes.ResourceTagMapping]

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

	// EventBridge
	EventBridgeBuses           *cache.Memo[[]eventbridgetypes.EventBus]
	EventBridgeBusPolicies     *cache.Memo[map[string]string]
	EventBridgeEndpoints       *cache.Memo[[]eventbridgetypes.Endpoint]
	EventBridgeEndpointDetails *cache.Memo[map[string]eventbridge.DescribeEndpointOutput]

	// Global Accelerator
	GlobalAccelerators            *cache.Memo[[]globalacceleratortypes.Accelerator]
	GlobalAcceleratorListeners    *cache.Memo[map[string][]globalacceleratortypes.Listener]
	GlobalAcceleratorTags         *cache.Memo[map[string]map[string]string]
	GlobalAcceleratorListenerTags *cache.Memo[map[string]map[string]string]

	// IoT Device Defender custom metrics
	IoTCustomMetrics    *cache.Memo[map[string]iot.DescribeCustomMetricOutput]
	IoTCustomMetricTags *cache.Memo[map[string]map[string]string]

	// IoT Events
	IoTEventsAlarmModels    *cache.Memo[[]ioteventstypes.AlarmModelSummary]
	IoTEventsDetectorModels *cache.Memo[[]ioteventstypes.DetectorModelSummary]
	IoTEventsInputs         *cache.Memo[[]ioteventstypes.InputSummary]
	IoTEventsTags           *cache.Memo[map[string]map[string]string]

	// IoT Wireless
	IoTWirelessFuotaTasks      *cache.Memo[[]iotwirelesstypes.FuotaTask]
	IoTWirelessMulticastGroups *cache.Memo[[]iotwirelesstypes.MulticastGroup]
	IoTWirelessServiceProfiles *cache.Memo[[]iotwirelesstypes.ServiceProfile]
	IoTWirelessTags            *cache.Memo[map[string]map[string]string]

	// Macie
	MacieSession                  *cache.Memo[*macie2.GetMacieSessionOutput]
	MacieAutomatedDiscoveryConfig *cache.Memo[*macie2.GetAutomatedDiscoveryConfigurationOutput]

	// RUM
	RUMAppMonitors       *cache.Memo[[]rumtypes.AppMonitorSummary]
	RUMAppMonitorTags    *cache.Memo[map[string]map[string]string]
	RUMAppMonitorDetails *cache.Memo[map[string]rum.GetAppMonitorOutput]

	// Service Catalog
	ServiceCatalogPortfolios      *cache.Memo[[]servicecatalogtypes.PortfolioDetail]
	ServiceCatalogPortfolioTags   *cache.Memo[map[string]map[string]string]
	ServiceCatalogPortfolioShares *cache.Memo[map[string][]string]

	// MQ
	MQBrokerEngineVersions *cache.Memo[map[mqtypes.EngineType]map[string]bool]

	// CloudTrail Event Data Stores
	CloudTrailEventDataStores *cache.Memo[[]cloudtrailtypes.EventDataStore]

	// AutoScaling
	AutoScalingGroups        *cache.Memo[[]autoscalingtypes.AutoScalingGroup]
	AutoScalingLaunchConfigs *cache.Memo[[]autoscalingtypes.LaunchConfiguration]

	// Kinesis
	KinesisStreams       *cache.Memo[[]string]
	KinesisStreamDetails *cache.Memo[map[string]kinesis.DescribeStreamOutput]

	// Firehose
	FirehoseDeliveryStreams *cache.Memo[[]string]
	FirehoseDeliveryDetails *cache.Memo[map[string]firehosetypes.DeliveryStreamDescription]

	// Kinesis Video
	KinesisVideoStreams *cache.Memo[[]kinesisvideotypes.StreamInfo]

	// MSK
	MSKClusters    *cache.Memo[[]kafkatypes.Cluster]
	MSKClusterTags *cache.Memo[map[string]map[string]string]

	// MSK Connect
	MSKConnectors       *cache.Memo[[]kafkaconnecttypes.ConnectorSummary]
	MSKConnectorDetails *cache.Memo[map[string]kafkaconnect.DescribeConnectorOutput]

	// Lightsail
	LightsailBuckets      *cache.Memo[[]lightsailtypes.Bucket]
	LightsailCertificates *cache.Memo[[]lightsailtypes.CertificateSummary]
	LightsailDisks        *cache.Memo[[]lightsailtypes.Disk]

	// Route53
	Route53HostedZones         *cache.Memo[[]route53types.HostedZone]
	Route53HealthChecks        *cache.Memo[[]route53types.HealthCheck]
	Route53HostedZoneTags      *cache.Memo[map[string]map[string]string]
	Route53HealthCheckTags     *cache.Memo[map[string]map[string]string]
	Route53QueryLoggingConfigs *cache.Memo[map[string][]route53types.QueryLoggingConfig]

	// Route53 Resolver
	Route53ResolverFirewallDomainLists           *cache.Memo[[]resolvertype.FirewallDomainListMetadata]
	Route53ResolverFirewallRuleGroups            *cache.Memo[[]resolvertype.FirewallRuleGroupMetadata]
	Route53ResolverFirewallRuleGroupAssociations *cache.Memo[[]resolvertype.FirewallRuleGroupAssociation]
	Route53ResolverRules                         *cache.Memo[[]resolvertype.ResolverRule]
	Route53ResolverTags                          *cache.Memo[map[string]map[string]string]

	// SageMaker
	SageMakerNotebooks             *cache.Memo[[]sagemakertypes.NotebookInstanceSummary]
	SageMakerEndpointConfigs       *cache.Memo[[]sagemakertypes.EndpointConfigSummary]
	SageMakerDomains               *cache.Memo[[]sagemakertypes.DomainDetails]
	SageMakerModels                *cache.Memo[[]sagemakertypes.ModelSummary]
	SageMakerNotebookDetails       *cache.Memo[map[string]sagemaker.DescribeNotebookInstanceOutput]
	SageMakerEndpointConfigDetails *cache.Memo[map[string]sagemaker.DescribeEndpointConfigOutput]
	SageMakerDomainTags            *cache.Memo[map[string]map[string]string]
	SageMakerModelDetails          *cache.Memo[map[string]sagemaker.DescribeModelOutput]
	SageMakerFeatureGroups         *cache.Memo[[]sagemakertypes.FeatureGroupSummary]
	SageMakerFeatureGroupTags      *cache.Memo[map[string]map[string]string]
	SageMakerImages                *cache.Memo[[]sagemakertypes.Image]
	SageMakerImageDetails          *cache.Memo[map[string]sagemaker.DescribeImageOutput]
	SageMakerImageTags             *cache.Memo[map[string]map[string]string]
	SageMakerAppImageConfigs       *cache.Memo[[]sagemakertypes.AppImageConfigDetails]
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
	NetworkFirewalls          *cache.Memo[[]networkfirewall.ListFirewallsOutput]
	NetworkFirewallDetails    *cache.Memo[map[string]networkfirewall.DescribeFirewallOutput]
	NetworkFirewallPolicies   *cache.Memo[map[string]networkfirewall.DescribeFirewallPolicyOutput]
	NetworkFirewallLogging    *cache.Memo[map[string]networkfirewall.DescribeLoggingConfigurationOutput]
	NetworkFirewallRuleGroups *cache.Memo[map[string]networkfirewall.DescribeRuleGroupOutput]

	// WAF
	WAFWebACLs               *cache.Memo[[]waftypes.WebACLSummary]
	WAFRules                 *cache.Memo[[]waftypes.RuleSummary]
	WAFRuleGroups            *cache.Memo[[]waftypes.RuleGroupSummary]
	WAFWebACLDetails         *cache.Memo[map[string]waftypes.WebACL]
	WAFRuleDetails           *cache.Memo[map[string]waftypes.Rule]
	WAFRuleGroupDetails      *cache.Memo[map[string]waftypes.RuleGroup]
	WAFLoggingConfigurations *cache.Memo[map[string]waf.GetLoggingConfigurationOutput]

	// WAF Regional
	WAFRegionalWebACLs               *cache.Memo[[]wafregionaltypes.WebACLSummary]
	WAFRegionalRules                 *cache.Memo[[]wafregionaltypes.RuleSummary]
	WAFRegionalRuleGroups            *cache.Memo[[]wafregionaltypes.RuleGroupSummary]
	WAFRegionalWebACLDetails         *cache.Memo[map[string]wafregionaltypes.WebACL]
	WAFRegionalRuleDetails           *cache.Memo[map[string]wafregionaltypes.Rule]
	WAFRegionalRuleGroupDetails      *cache.Memo[map[string]wafregionaltypes.RuleGroup]
	WAFRegionalLoggingConfigurations *cache.Memo[map[string]wafregional.GetLoggingConfigurationOutput]

	// WAFv2
	WAFv2WebACLs           *cache.Memo[[]wafv2types.WebACLSummary]
	WAFv2RuleGroups        *cache.Memo[[]wafv2types.RuleGroupSummary]
	WAFv2WebACLForResource *cache.Memo[map[string]bool]
	WAFv2WebACLDetails     *cache.Memo[map[string]wafv2types.WebACL]
	WAFv2RuleGroupDetails  *cache.Memo[map[string]wafv2types.RuleGroup]
	WAFv2LoggingConfigs    *cache.Memo[map[string]wafv2.GetLoggingConfigurationOutput]

	// Workspaces
	Workspaces                    *cache.Memo[[]workspacestypes.Workspace]
	WorkspacesConnectionAlias     *cache.Memo[[]workspacestypes.ConnectionAlias]
	WorkspacesTags                *cache.Memo[map[string]map[string]string]
	WorkspacesConnectionAliasTags *cache.Memo[map[string]map[string]string]

	// ElasticBeanstalk
	ElasticBeanstalkApps        *cache.Memo[[]ebtypes.ApplicationDescription]
	ElasticBeanstalkEnvs        *cache.Memo[[]ebtypes.EnvironmentDescription]
	ElasticBeanstalkAppVersions *cache.Memo[[]ebtypes.ApplicationVersionDescription]
	ElasticBeanstalkEnvSettings *cache.Memo[map[string][]ebtypes.ConfigurationOptionSetting]
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
	d.AccountID = cache.New("AccountID", func() (string, error) {
		out, err := c.STS.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
		if err != nil {
			return "", err
		}
		return *out.Account, nil
	})

	// Organizations
	d.OrgAccount = cache.New("OrgAccount", func() (*organizations.DescribeOrganizationOutput, error) {
		return c.Organizations.DescribeOrganization(ctx, &organizations.DescribeOrganizationInput{})
	})

	// IAM
	d.IAMUsers = cache.New("IAMUsers", func() ([]iamtypes.User, error) {
		out, err := c.IAM.ListUsers(ctx, &iam.ListUsersInput{})
		if err != nil {
			return nil, err
		}
		return out.Users, nil
	})
	d.IAMRoles = cache.New("IAMRoles", func() ([]iamtypes.Role, error) {
		out, err := c.IAM.ListRoles(ctx, &iam.ListRolesInput{})
		if err != nil {
			return nil, err
		}
		return out.Roles, nil
	})
	d.IAMGroups = cache.New("IAMGroups", func() ([]iamtypes.Group, error) {
		out, err := c.IAM.ListGroups(ctx, &iam.ListGroupsInput{})
		if err != nil {
			return nil, err
		}
		return out.Groups, nil
	})
	d.IAMPolicies = cache.New("IAMPolicies", func() ([]iamtypes.Policy, error) {
		out, err := c.IAM.ListPolicies(ctx, &iam.ListPoliciesInput{Scope: iamtypes.PolicyScopeTypeLocal})
		if err != nil {
			return nil, err
		}
		return out.Policies, nil
	})
	d.IAMServerCertificates = cache.New("IAMServerCertificates", func() ([]iamtypes.ServerCertificateMetadata, error) {
		out, err := c.IAM.ListServerCertificates(ctx, &iam.ListServerCertificatesInput{})
		if err != nil {
			return nil, err
		}
		return out.ServerCertificateMetadataList, nil
	})
	d.IAMCredentialReport = cache.New("IAMCredentialReport", func() ([]byte, error) {
		_, _ = c.IAM.GenerateCredentialReport(ctx, &iam.GenerateCredentialReportInput{})
		out, err := c.IAM.GetCredentialReport(ctx, &iam.GetCredentialReportInput{})
		if err != nil {
			return nil, err
		}
		return out.Content, nil
	})
	d.IAMAccountPasswordPolicy = cache.New("IAMAccountPasswordPolicy", func() (*iamtypes.PasswordPolicy, error) {
		out, err := c.IAM.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{})
		if err != nil {
			return nil, err
		}
		return out.PasswordPolicy, nil
	})
	d.IAMAccountSummary = cache.New("IAMAccountSummary", func() (map[string]int32, error) {
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
	d.IAMSAMLProviders = cache.New("IAMSAMLProviders", func() ([]iamtypes.SAMLProviderListEntry, error) {
		out, err := c.IAM.ListSAMLProviders(ctx, &iam.ListSAMLProvidersInput{})
		if err != nil {
			return nil, err
		}
		return out.SAMLProviderList, nil
	})
	d.IAMOIDCProviders = cache.New("IAMOIDCProviders", func() ([]string, error) {
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
	d.IAMVirtualMFADevices = cache.New("IAMVirtualMFADevices", func() ([]iamtypes.VirtualMFADevice, error) {
		out, err := c.IAM.ListVirtualMFADevices(ctx, &iam.ListVirtualMFADevicesInput{})
		if err != nil {
			return nil, err
		}
		return out.VirtualMFADevices, nil
	})

	// EC2
	d.EC2Instances = cache.New("EC2Instances", func() ([]ec2types.Reservation, error) {
		out, err := c.EC2.DescribeInstances(ctx, &ec2.DescribeInstancesInput{})
		if err != nil {
			return nil, err
		}
		return out.Reservations, nil
	})
	d.EC2SecurityGroups = cache.New("EC2SecurityGroups", func() ([]ec2types.SecurityGroup, error) {
		out, err := c.EC2.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
		if err != nil {
			return nil, err
		}
		return out.SecurityGroups, nil
	})
	d.EC2Volumes = cache.New("EC2Volumes", func() ([]ec2types.Volume, error) {
		out, err := c.EC2.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{})
		if err != nil {
			return nil, err
		}
		return out.Volumes, nil
	})
	d.EC2VPCs = cache.New("EC2VPCs", func() ([]ec2types.Vpc, error) {
		out, err := c.EC2.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{})
		if err != nil {
			return nil, err
		}
		return out.Vpcs, nil
	})
	d.EC2Subnets = cache.New("EC2Subnets", func() ([]ec2types.Subnet, error) {
		out, err := c.EC2.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{})
		if err != nil {
			return nil, err
		}
		return out.Subnets, nil
	})
	d.EC2RouteTables = cache.New("EC2RouteTables", func() ([]ec2types.RouteTable, error) {
		out, err := c.EC2.DescribeRouteTables(ctx, &ec2.DescribeRouteTablesInput{})
		if err != nil {
			return nil, err
		}
		return out.RouteTables, nil
	})
	d.EC2NetworkACLs = cache.New("EC2NetworkACLs", func() ([]ec2types.NetworkAcl, error) {
		out, err := c.EC2.DescribeNetworkAcls(ctx, &ec2.DescribeNetworkAclsInput{})
		if err != nil {
			return nil, err
		}
		return out.NetworkAcls, nil
	})
	d.EC2InternetGateways = cache.New("EC2InternetGateways", func() ([]ec2types.InternetGateway, error) {
		out, err := c.EC2.DescribeInternetGateways(ctx, &ec2.DescribeInternetGatewaysInput{})
		if err != nil {
			return nil, err
		}
		return out.InternetGateways, nil
	})
	d.EC2NATGateways = cache.New("EC2NATGateways", func() ([]ec2types.NatGateway, error) {
		out, err := c.EC2.DescribeNatGateways(ctx, &ec2.DescribeNatGatewaysInput{})
		if err != nil {
			return nil, err
		}
		return out.NatGateways, nil
	})
	d.EC2NetworkInterfaces = cache.New("EC2NetworkInterfaces", func() ([]ec2types.NetworkInterface, error) {
		out, err := c.EC2.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{})
		if err != nil {
			return nil, err
		}
		return out.NetworkInterfaces, nil
	})
	d.EC2Addresses = cache.New("EC2Addresses", func() ([]ec2types.Address, error) {
		out, err := c.EC2.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{})
		if err != nil {
			return nil, err
		}
		return out.Addresses, nil
	})
	d.EC2Snapshots = cache.New("EC2Snapshots", func() ([]ec2types.Snapshot, error) {
		out, err := c.EC2.DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{OwnerIds: []string{"self"}})
		if err != nil {
			return nil, err
		}
		return out.Snapshots, nil
	})
	d.EC2LaunchTemplates = cache.New("EC2LaunchTemplates", func() ([]ec2types.LaunchTemplate, error) {
		out, err := c.EC2.DescribeLaunchTemplates(ctx, &ec2.DescribeLaunchTemplatesInput{})
		if err != nil {
			return nil, err
		}
		return out.LaunchTemplates, nil
	})
	d.EC2LaunchTemplateVersions = cache.New("EC2LaunchTemplateVersions", func() (map[string]ec2types.LaunchTemplateVersion, error) {
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
	d.EC2TransitGateways = cache.New("EC2TransitGateways", func() ([]ec2types.TransitGateway, error) {
		out, err := c.EC2.DescribeTransitGateways(ctx, &ec2.DescribeTransitGatewaysInput{})
		if err != nil {
			return nil, err
		}
		return out.TransitGateways, nil
	})
	d.EC2VPNConnections = cache.New("EC2VPNConnections", func() ([]ec2types.VpnConnection, error) {
		out, err := c.EC2.DescribeVpnConnections(ctx, &ec2.DescribeVpnConnectionsInput{})
		if err != nil {
			return nil, err
		}
		return out.VpnConnections, nil
	})
	d.EC2FlowLogs = cache.New("EC2FlowLogs", func() ([]ec2types.FlowLog, error) {
		out, err := c.EC2.DescribeFlowLogs(ctx, &ec2.DescribeFlowLogsInput{})
		if err != nil {
			return nil, err
		}
		return out.FlowLogs, nil
	})
	d.EC2VPCEndpoints = cache.New("EC2VPCEndpoints", func() ([]ec2types.VpcEndpoint, error) {
		out, err := c.EC2.DescribeVpcEndpoints(ctx, &ec2.DescribeVpcEndpointsInput{})
		if err != nil {
			return nil, err
		}
		return out.VpcEndpoints, nil
	})
	d.EC2VPCPeeringConnections = cache.New("EC2VPCPeeringConnections", func() ([]ec2types.VpcPeeringConnection, error) {
		out, err := c.EC2.DescribeVpcPeeringConnections(ctx, &ec2.DescribeVpcPeeringConnectionsInput{})
		if err != nil {
			return nil, err
		}
		return out.VpcPeeringConnections, nil
	})
	d.EC2PrefixLists = cache.New("EC2PrefixLists", func() ([]ec2types.ManagedPrefixList, error) {
		out, err := c.EC2.DescribeManagedPrefixLists(ctx, &ec2.DescribeManagedPrefixListsInput{})
		if err != nil {
			return nil, err
		}
		return out.PrefixLists, nil
	})
	d.EC2Fleets = cache.New("EC2Fleets", func() ([]ec2types.FleetData, error) {
		out, err := c.EC2.DescribeFleets(ctx, &ec2.DescribeFleetsInput{})
		if err != nil {
			return nil, err
		}
		return out.Fleets, nil
	})
	d.EC2CapacityReservations = cache.New("EC2CapacityReservations", func() ([]ec2types.CapacityReservation, error) {
		out, err := c.EC2.DescribeCapacityReservations(ctx, &ec2.DescribeCapacityReservationsInput{})
		if err != nil {
			return nil, err
		}
		return out.CapacityReservations, nil
	})
	d.EC2DHCPOptions = cache.New("EC2DHCPOptions", func() ([]ec2types.DhcpOptions, error) {
		out, err := c.EC2.DescribeDhcpOptions(ctx, &ec2.DescribeDhcpOptionsInput{})
		if err != nil {
			return nil, err
		}
		return out.DhcpOptions, nil
	})
	d.EC2ClientVPNEndpoints = cache.New("EC2ClientVPNEndpoints", func() ([]ec2types.ClientVpnEndpoint, error) {
		out, err := c.EC2.DescribeClientVpnEndpoints(ctx, &ec2.DescribeClientVpnEndpointsInput{})
		if err != nil {
			return nil, err
		}
		return out.ClientVpnEndpoints, nil
	})
	d.EC2EBSEncryptionByDefault = cache.New("EC2EBSEncryptionByDefault", func() (bool, error) {
		out, err := c.EC2.GetEbsEncryptionByDefault(ctx, &ec2.GetEbsEncryptionByDefaultInput{})
		if err != nil {
			return false, err
		}
		if out.EbsEncryptionByDefault != nil {
			return *out.EbsEncryptionByDefault, nil
		}
		return false, nil
	})
	d.EC2EBSSnapshotBlockPublicAccess = cache.New("EC2EBSSnapshotBlockPublicAccess", func() (string, error) {
		out, err := c.EC2.GetSnapshotBlockPublicAccessState(ctx, &ec2.GetSnapshotBlockPublicAccessStateInput{})
		if err != nil {
			return "", err
		}
		return string(out.State), nil
	})

	// S3
	d.S3Buckets = cache.New("S3Buckets", func() ([]s3types.Bucket, error) {
		out, err := c.S3.ListBuckets(ctx, &s3.ListBucketsInput{})
		if err != nil {
			return nil, err
		}
		return out.Buckets, nil
	})

	// RDS
	d.RDSDBInstances = cache.New("RDSDBInstances", func() ([]rdstypes.DBInstance, error) {
		out, err := c.RDS.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{})
		if err != nil {
			return nil, err
		}
		return out.DBInstances, nil
	})
	d.RDSDBClusters = cache.New("RDSDBClusters", func() ([]rdstypes.DBCluster, error) {
		out, err := c.RDS.DescribeDBClusters(ctx, &rds.DescribeDBClustersInput{})
		if err != nil {
			return nil, err
		}
		return out.DBClusters, nil
	})
	d.RDSSnapshots = cache.New("RDSSnapshots", func() ([]rdstypes.DBSnapshot, error) {
		out, err := c.RDS.DescribeDBSnapshots(ctx, &rds.DescribeDBSnapshotsInput{})
		if err != nil {
			return nil, err
		}
		return out.DBSnapshots, nil
	})
	d.RDSOptionGroups = cache.New("RDSOptionGroups", func() ([]rdstypes.OptionGroup, error) {
		out, err := c.RDS.DescribeOptionGroups(ctx, &rds.DescribeOptionGroupsInput{})
		if err != nil {
			return nil, err
		}
		return out.OptionGroupsList, nil
	})
	d.RDSEventSubs = cache.New("RDSEventSubs", func() ([]rdstypes.EventSubscription, error) {
		out, err := c.RDS.DescribeEventSubscriptions(ctx, &rds.DescribeEventSubscriptionsInput{})
		if err != nil {
			return nil, err
		}
		return out.EventSubscriptionsList, nil
	})
	d.RDSProxies = cache.New("RDSProxies", func() ([]rdstypes.DBProxy, error) {
		out, err := c.RDS.DescribeDBProxies(ctx, &rds.DescribeDBProxiesInput{})
		if err != nil {
			return nil, err
		}
		return out.DBProxies, nil
	})
	d.RDSDBSubnetGroups = cache.New("RDSDBSubnetGroups", func() ([]rdstypes.DBSubnetGroup, error) {
		out, err := c.RDS.DescribeDBSubnetGroups(ctx, &rds.DescribeDBSubnetGroupsInput{})
		if err != nil {
			return nil, err
		}
		return out.DBSubnetGroups, nil
	})
	d.RDSEventSubTags = cache.New("RDSEventSubTags", func() (map[string]map[string]string, error) {
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
	d.RDSOptionGroupTags = cache.New("RDSOptionGroupTags", func() (map[string]map[string]string, error) {
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
	d.RDSDBParamValues = cache.New("RDSDBParamValues", func() (map[string]map[string]string, error) {
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
	d.LambdaFunctions = cache.New("LambdaFunctions", func() ([]lambdatypes.FunctionConfiguration, error) {
		out, err := c.Lambda.ListFunctions(ctx, &lambda.ListFunctionsInput{})
		if err != nil {
			return nil, err
		}
		return out.Functions, nil
	})

	// DynamoDB
	d.DynamoDBTableNames = cache.New("DynamoDBTableNames", func() ([]string, error) {
		out, err := c.DynamoDB.ListTables(ctx, &dynamodb.ListTablesInput{})
		if err != nil {
			return nil, err
		}
		return out.TableNames, nil
	})
	d.DynamoDBTables = cache.New("DynamoDBTables", func() (map[string]dynamodbtypes.TableDescription, error) {
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
	d.DynamoDBPITR = cache.New("DynamoDBPITR", func() (map[string]bool, error) {
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
	d.DynamoDBAutoScaling = cache.New("DynamoDBAutoScaling", func() (map[string]bool, error) {
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
	d.ECSClusters = cache.New("ECSClusters", func() ([]string, error) {
		out, err := c.ECS.ListClusters(ctx, &ecs.ListClustersInput{})
		if err != nil {
			return nil, err
		}
		return out.ClusterArns, nil
	})
	d.ECSTaskDefinitions = cache.New("ECSTaskDefinitions", func() ([]string, error) {
		out, err := c.ECS.ListTaskDefinitions(ctx, &ecs.ListTaskDefinitionsInput{})
		if err != nil {
			return nil, err
		}
		return out.TaskDefinitionArns, nil
	})
	d.ECSClusterDetails = cache.New("ECSClusterDetails", func() (map[string]ecstypes.Cluster, error) {
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
	d.ECSTaskDefDetails = cache.New("ECSTaskDefDetails", func() (map[string]ecstypes.TaskDefinition, error) {
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
	d.ECSCapacityProviders = cache.New("ECSCapacityProviders", func() ([]ecstypes.CapacityProvider, error) {
		out, err := c.ECS.DescribeCapacityProviders(ctx, &ecs.DescribeCapacityProvidersInput{})
		if err != nil {
			return nil, err
		}
		return out.CapacityProviders, nil
	})
	d.ECSCapacityProviderTags = cache.New("ECSCapacityProviderTags", func() (map[string]map[string]string, error) {
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
	d.ECSServicesByCluster = cache.New("ECSServicesByCluster", func() (map[string][]ecstypes.Service, error) {
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
	d.EKSClusterNames = cache.New("EKSClusterNames", func() ([]string, error) {
		out, err := c.EKS.ListClusters(ctx, &eks.ListClustersInput{})
		if err != nil {
			return nil, err
		}
		return out.Clusters, nil
	})
	d.EKSClusters = cache.New("EKSClusters", func() (map[string]ekstypes.Cluster, error) {
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
	d.EKSAddons = cache.New("EKSAddons", func() (map[string][]ekstypes.Addon, error) {
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
	d.EKSFargateProfiles = cache.New("EKSFargateProfiles", func() (map[string][]ekstypes.FargateProfile, error) {
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
	d.ElastiCacheClusters = cache.New("ElastiCacheClusters", func() ([]elasticachetypes.CacheCluster, error) {
		out, err := c.ElastiCache.DescribeCacheClusters(ctx, &elasticache.DescribeCacheClustersInput{})
		if err != nil {
			return nil, err
		}
		return out.CacheClusters, nil
	})
	d.ElastiCacheReplGroups = cache.New("ElastiCacheReplGroups", func() ([]elasticachetypes.ReplicationGroup, error) {
		out, err := c.ElastiCache.DescribeReplicationGroups(ctx, &elasticache.DescribeReplicationGroupsInput{})
		if err != nil {
			return nil, err
		}
		return out.ReplicationGroups, nil
	})
	d.ElastiCacheSubnetGroups = cache.New("ElastiCacheSubnetGroups", func() ([]elasticachetypes.CacheSubnetGroup, error) {
		out, err := c.ElastiCache.DescribeCacheSubnetGroups(ctx, &elasticache.DescribeCacheSubnetGroupsInput{})
		if err != nil {
			return nil, err
		}
		return out.CacheSubnetGroups, nil
	})

	// CloudTrail
	d.CloudTrailTrails = cache.New("CloudTrailTrails", func() ([]cloudtrailtypes.TrailInfo, error) {
		out, err := c.CloudTrail.ListTrails(ctx, &cloudtrail.ListTrailsInput{})
		if err != nil {
			return nil, err
		}
		return out.Trails, nil
	})
	d.CloudTrailTrailDetails = cache.New("CloudTrailTrailDetails", func() (map[string]cloudtrailtypes.Trail, error) {
		trails, err := d.CloudTrailTrails.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]cloudtrailtypes.Trail)
		var names []string
		for _, t := range trails {
			if t.TrailARN != nil {
				names = append(names, *t.TrailARN)
			} else if t.Name != nil {
				names = append(names, *t.Name)
			}
		}
		if len(names) == 0 {
			return out, nil
		}
		resp, err := c.CloudTrail.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{TrailNameList: names})
		if err != nil {
			return nil, err
		}
		for _, t := range resp.TrailList {
			if t.TrailARN != nil {
				out[*t.TrailARN] = t
			} else if t.Name != nil {
				out[*t.Name] = t
			}
		}
		return out, nil
	})
	d.CloudTrailTrailStatus = cache.New("CloudTrailTrailStatus", func() (map[string]cloudtrail.GetTrailStatusOutput, error) {
		trails, err := d.CloudTrailTrails.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]cloudtrail.GetTrailStatusOutput)
		for _, t := range trails {
			var name *string
			if t.TrailARN != nil {
				name = t.TrailARN
			} else if t.Name != nil {
				name = t.Name
			}
			if name == nil {
				continue
			}
			resp, err := c.CloudTrail.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{Name: name})
			if err != nil {
				continue
			}
			out[*name] = *resp
		}
		return out, nil
	})
	d.CloudTrailEventSelectors = cache.New("CloudTrailEventSelectors", func() (map[string]cloudtrail.GetEventSelectorsOutput, error) {
		trails, err := d.CloudTrailTrails.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]cloudtrail.GetEventSelectorsOutput)
		for _, t := range trails {
			var name *string
			if t.TrailARN != nil {
				name = t.TrailARN
			} else if t.Name != nil {
				name = t.Name
			}
			if name == nil {
				continue
			}
			resp, err := c.CloudTrail.GetEventSelectors(ctx, &cloudtrail.GetEventSelectorsInput{TrailName: name})
			if err != nil {
				continue
			}
			out[*name] = *resp
		}
		return out, nil
	})

	// CloudWatch
	d.CloudWatchAlarms = cache.New("CloudWatchAlarms", func() ([]cloudwatchtypes.MetricAlarm, error) {
		out, err := c.CloudWatch.DescribeAlarms(ctx, &cloudwatch.DescribeAlarmsInput{})
		if err != nil {
			return nil, err
		}
		return out.MetricAlarms, nil
	})
	d.CloudWatchLogGroups = cache.New("CloudWatchLogGroups", func() ([]logstypes.LogGroup, error) {
		out, err := c.CloudWatchLogs.DescribeLogGroups(ctx, &cloudwatchlogs.DescribeLogGroupsInput{})
		if err != nil {
			return nil, err
		}
		return out.LogGroups, nil
	})
	d.CloudWatchMetricStreams = cache.New("CloudWatchMetricStreams", func() ([]cloudwatchtypes.MetricStreamEntry, error) {
		out, err := c.CloudWatch.ListMetricStreams(ctx, &cloudwatch.ListMetricStreamsInput{})
		if err != nil {
			return nil, err
		}
		return out.Entries, nil
	})
	d.CloudWatchMetricStreamTags = cache.New("CloudWatchMetricStreamTags", func() (map[string]map[string]string, error) {
		streams, err := d.CloudWatchMetricStreams.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, s := range streams {
			if s.Arn == nil {
				continue
			}
			resp, err := c.CloudWatch.ListTagsForResource(ctx, &cloudwatch.ListTagsForResourceInput{ResourceARN: s.Arn})
			if err != nil {
				continue
			}
			tags := make(map[string]string)
			for _, t := range resp.Tags {
				if t.Key != nil && t.Value != nil {
					tags[*t.Key] = *t.Value
				}
			}
			out[*s.Arn] = tags
		}
		return out, nil
	})

	// CloudFront
	d.CloudFrontDistributions = cache.New("CloudFrontDistributions", func() ([]cftypescf.DistributionSummary, error) {
		out, err := c.CloudFront.ListDistributions(ctx, &cloudfront.ListDistributionsInput{})
		if err != nil {
			return nil, err
		}
		if out.DistributionList == nil {
			return nil, nil
		}
		return out.DistributionList.Items, nil
	})
	d.CloudFrontDistributionConfigs = cache.New("CloudFrontDistributionConfigs", func() (map[string]cftypescf.DistributionConfig, error) {
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
	d.CloudFrontDistributionARNs = cache.New("CloudFrontDistributionARNs", func() (map[string]string, error) {
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
	d.CloudFrontDistributionTags = cache.New("CloudFrontDistributionTags", func() (map[string]map[string]string, error) {
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
	d.CloudFrontDistributionWAF = cache.New("CloudFrontDistributionWAF", func() (map[string]bool, error) {
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
	d.CloudFrontS3OriginBucketExists = cache.New("CloudFrontS3OriginBucketExists", func() (map[string]bool, error) {
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
	d.CloudFormationStacks = cache.New("CloudFormationStacks", func() ([]cftypes.StackSummary, error) {
		out, err := c.CloudFormation.ListStacks(ctx, &cloudformation.ListStacksInput{})
		if err != nil {
			return nil, err
		}
		return out.StackSummaries, nil
	})
	d.CloudFormationStackDetails = cache.New("CloudFormationStackDetails", func() (map[string]cftypes.Stack, error) {
		summaries, err := d.CloudFormationStacks.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]cftypes.Stack)
		for _, s := range summaries {
			name := s.StackName
			if name == nil || *name == "" {
				continue
			}
			resp, err := c.CloudFormation.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{StackName: name})
			if err != nil {
				continue
			}
			for _, st := range resp.Stacks {
				if st.StackId != nil {
					out[*st.StackId] = st
				} else if st.StackName != nil {
					out[*st.StackName] = st
				}
			}
		}
		return out, nil
	})

	// ACM
	d.ACMCertificates = cache.New("ACMCertificates", func() ([]acmtypes.CertificateSummary, error) {
		out, err := c.ACM.ListCertificates(ctx, &acm.ListCertificatesInput{})
		if err != nil {
			return nil, err
		}
		return out.CertificateSummaryList, nil
	})
	d.ACMCertificateDetails = cache.New("ACMCertificateDetails", func() (map[string]acmtypes.CertificateDetail, error) {
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
	d.ACMPCACertificateAuthorities = cache.New("ACMPCACertificateAuthorities", func() ([]acmpcatypes.CertificateAuthority, error) {
		out, err := c.ACMPCA.ListCertificateAuthorities(ctx, &acmpca.ListCertificateAuthoritiesInput{})
		if err != nil {
			return nil, err
		}
		return out.CertificateAuthorities, nil
	})
	d.ACMPCACertificateAuthorityTags = cache.New("ACMPCACertificateAuthorityTags", func() (map[string]map[string]string, error) {
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
	d.KMSKeys = cache.New("KMSKeys", func() ([]kmstypes.KeyListEntry, error) {
		out, err := c.KMS.ListKeys(ctx, &kms.ListKeysInput{})
		if err != nil {
			return nil, err
		}
		return out.Keys, nil
	})
	d.KMSKeyDetails = cache.New("KMSKeyDetails", func() (map[string]kmstypes.KeyMetadata, error) {
		keys, err := d.KMSKeys.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]kmstypes.KeyMetadata)
		for _, k := range keys {
			if k.KeyId == nil {
				continue
			}
			desc, err := c.KMS.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: k.KeyId})
			if err != nil || desc.KeyMetadata == nil {
				continue
			}
			out[*k.KeyId] = *desc.KeyMetadata
		}
		return out, nil
	})
	d.KMSKeyRotationStatus = cache.New("KMSKeyRotationStatus", func() (map[string]bool, error) {
		keys, err := d.KMSKeys.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]bool)
		for _, k := range keys {
			if k.KeyId == nil {
				continue
			}
			resp, err := c.KMS.GetKeyRotationStatus(ctx, &kms.GetKeyRotationStatusInput{KeyId: k.KeyId})
			if err != nil {
				continue
			}
			out[*k.KeyId] = resp.KeyRotationEnabled
		}
		return out, nil
	})
	d.KMSKeyTags = cache.New("KMSKeyTags", func() (map[string]map[string]string, error) {
		keys, err := d.KMSKeys.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, k := range keys {
			if k.KeyId == nil {
				continue
			}
			resp, err := c.KMS.ListResourceTags(ctx, &kms.ListResourceTagsInput{KeyId: k.KeyId})
			if err != nil {
				continue
			}
			m := make(map[string]string)
			for _, t := range resp.Tags {
				if t.TagKey != nil && t.TagValue != nil {
					m[*t.TagKey] = *t.TagValue
				}
			}
			out[*k.KeyId] = m
		}
		return out, nil
	})
	d.KMSKeyPolicies = cache.New("KMSKeyPolicies", func() (map[string]string, error) {
		keys, err := d.KMSKeys.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]string)
		for _, k := range keys {
			if k.KeyId == nil {
				continue
			}
			resp, err := c.KMS.GetKeyPolicy(ctx, &kms.GetKeyPolicyInput{KeyId: k.KeyId, PolicyName: aws.String("default")})
			if err != nil || resp.Policy == nil {
				continue
			}
			out[*k.KeyId] = *resp.Policy
		}
		return out, nil
	})

	// SNS
	d.SNSTopics = cache.New("SNSTopics", func() ([]snstypes.Topic, error) {
		out, err := c.SNS.ListTopics(ctx, &sns.ListTopicsInput{})
		if err != nil {
			return nil, err
		}
		return out.Topics, nil
	})
	d.SNSTopicAttributes = cache.New("SNSTopicAttributes", func() (map[string]map[string]string, error) {
		topics, err := d.SNSTopics.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, t := range topics {
			if t.TopicArn == nil {
				continue
			}
			resp, err := c.SNS.GetTopicAttributes(ctx, &sns.GetTopicAttributesInput{TopicArn: t.TopicArn})
			if err != nil {
				continue
			}
			out[*t.TopicArn] = resp.Attributes
		}
		return out, nil
	})

	// SQS
	d.SQSQueues = cache.New("SQSQueues", func() ([]string, error) {
		out, err := c.SQS.ListQueues(ctx, &sqs.ListQueuesInput{})
		if err != nil {
			return nil, err
		}
		return out.QueueUrls, nil
	})
	d.SQSQueueAttributes = cache.New("SQSQueueAttributes", func() (map[string]map[string]string, error) {
		queues, err := d.SQSQueues.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, q := range queues {
			resp, err := c.SQS.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{QueueUrl: &q, AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNameAll}})
			if err != nil {
				continue
			}
			out[q] = resp.Attributes
		}
		return out, nil
	})

	// Secrets Manager
	d.SecretsManagerSecrets = cache.New("SecretsManagerSecrets", func() ([]smtypes.SecretListEntry, error) {
		out, err := c.SecretsManager.ListSecrets(ctx, &secretsmanager.ListSecretsInput{})
		if err != nil {
			return nil, err
		}
		return out.SecretList, nil
	})
	d.SecretsManagerSecretDetails = cache.New("SecretsManagerSecretDetails", func() (map[string]secretsmanager.DescribeSecretOutput, error) {
		secrets, err := d.SecretsManagerSecrets.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]secretsmanager.DescribeSecretOutput)
		for _, s := range secrets {
			if s.ARN == nil {
				continue
			}
			desc, err := c.SecretsManager.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{SecretId: s.ARN})
			if err != nil {
				continue
			}
			out[*s.ARN] = *desc
		}
		return out, nil
	})
	d.SecretsManagerSecretTags = cache.New("SecretsManagerSecretTags", func() (map[string]map[string]string, error) {
		secrets, err := d.SecretsManagerSecrets.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, s := range secrets {
			if s.ARN == nil {
				continue
			}
			resp, err := c.SecretsManager.ListSecretVersionIds(ctx, &secretsmanager.ListSecretVersionIdsInput{SecretId: s.ARN})
			if err != nil {
				continue
			}
			m := make(map[string]string)
			_ = resp
			// Secrets Manager doesn't have ListTagsForResource; use DescribeSecret tags.
			desc, err := c.SecretsManager.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{SecretId: s.ARN})
			if err == nil {
				for _, t := range desc.Tags {
					if t.Key != nil && t.Value != nil {
						m[*t.Key] = *t.Value
					}
				}
			}
			out[*s.ARN] = m
		}
		return out, nil
	})

	// SSM
	d.SSMDocuments = cache.New("SSMDocuments", func() ([]ssmtypes.DocumentIdentifier, error) {
		out, err := c.SSM.ListDocuments(ctx, &ssm.ListDocumentsInput{})
		if err != nil {
			return nil, err
		}
		return out.DocumentIdentifiers, nil
	})
	d.SSMDocumentDetails = cache.New("SSMDocumentDetails", func() (map[string]ssmtypes.DocumentDescription, error) {
		docs, err := d.SSMDocuments.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]ssmtypes.DocumentDescription)
		for _, doc := range docs {
			if doc.Name == nil {
				continue
			}
			desc, err := c.SSM.DescribeDocument(ctx, &ssm.DescribeDocumentInput{Name: doc.Name})
			if err != nil || desc.Document == nil {
				continue
			}
			out[*doc.Name] = *desc.Document
		}
		return out, nil
	})
	d.SSMDocumentTags = cache.New("SSMDocumentTags", func() (map[string]map[string]string, error) {
		docs, err := d.SSMDocuments.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, doc := range docs {
			if doc.Name == nil {
				continue
			}
			resp, err := c.SSM.ListTagsForResource(ctx, &ssm.ListTagsForResourceInput{ResourceType: ssmtypes.ResourceTypeForTaggingDocument, ResourceId: doc.Name})
			if err != nil {
				continue
			}
			m := make(map[string]string)
			for _, t := range resp.TagList {
				if t.Key != nil && t.Value != nil {
					m[*t.Key] = *t.Value
				}
			}
			out[*doc.Name] = m
		}
		return out, nil
	})
	d.SSMDocumentContent = cache.New("SSMDocumentContent", func() (map[string]string, error) {
		docs, err := d.SSMDocuments.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]string)
		for _, doc := range docs {
			if doc.Name == nil {
				continue
			}
			resp, err := c.SSM.GetDocument(ctx, &ssm.GetDocumentInput{Name: doc.Name, DocumentVersion: aws.String("$LATEST")})
			if err != nil || resp.Content == nil {
				continue
			}
			out[*doc.Name] = *resp.Content
		}
		return out, nil
	})

	// Step Functions
	d.SFNStateMachines = cache.New("SFNStateMachines", func() ([]sfntypes.StateMachineListItem, error) {
		out, err := c.SFN.ListStateMachines(ctx, &sfn.ListStateMachinesInput{})
		if err != nil {
			return nil, err
		}
		return out.StateMachines, nil
	})
	d.SFNStateMachineDetails = cache.New("SFNStateMachineDetails", func() (map[string]sfn.DescribeStateMachineOutput, error) {
		items, err := d.SFNStateMachines.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]sfn.DescribeStateMachineOutput)
		for _, m := range items {
			if m.StateMachineArn == nil {
				continue
			}
			desc, err := c.SFN.DescribeStateMachine(ctx, &sfn.DescribeStateMachineInput{StateMachineArn: m.StateMachineArn})
			if err != nil || desc == nil {
				continue
			}
			out[*m.StateMachineArn] = *desc
		}
		return out, nil
	})
	d.SFNStateMachineTags = cache.New("SFNStateMachineTags", func() (map[string]map[string]string, error) {
		items, err := d.SFNStateMachines.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, m := range items {
			if m.StateMachineArn == nil {
				continue
			}
			resp, err := c.SFN.ListTagsForResource(ctx, &sfn.ListTagsForResourceInput{ResourceArn: m.StateMachineArn})
			if err != nil {
				continue
			}
			mm := make(map[string]string)
			for _, t := range resp.Tags {
				if t.Key != nil && t.Value != nil {
					mm[*t.Key] = *t.Value
				}
			}
			out[*m.StateMachineArn] = mm
		}
		return out, nil
	})

	// Redshift
	d.RedshiftClusters = cache.New("RedshiftClusters", func() ([]redshifttypes.Cluster, error) {
		out, err := c.Redshift.DescribeClusters(ctx, &redshift.DescribeClustersInput{})
		if err != nil {
			return nil, err
		}
		return out.Clusters, nil
	})
	d.RedshiftParamGroups = cache.New("RedshiftParamGroups", func() ([]redshifttypes.ClusterParameterGroup, error) {
		out, err := c.Redshift.DescribeClusterParameterGroups(ctx, &redshift.DescribeClusterParameterGroupsInput{})
		if err != nil {
			return nil, err
		}
		return out.ParameterGroups, nil
	})
	d.RedshiftClusterSubnetGroups = cache.New("RedshiftClusterSubnetGroups", func() ([]redshifttypes.ClusterSubnetGroup, error) {
		out, err := c.Redshift.DescribeClusterSubnetGroups(ctx, &redshift.DescribeClusterSubnetGroupsInput{})
		if err != nil {
			return nil, err
		}
		return out.ClusterSubnetGroups, nil
	})
	d.RedshiftLoggingStatus = cache.New("RedshiftLoggingStatus", func() (map[string]redshift.DescribeLoggingStatusOutput, error) {
		clusters, err := d.RedshiftClusters.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]redshift.DescribeLoggingStatusOutput)
		for _, cl := range clusters {
			if cl.ClusterIdentifier == nil {
				continue
			}
			ls, err := c.Redshift.DescribeLoggingStatus(ctx, &redshift.DescribeLoggingStatusInput{ClusterIdentifier: cl.ClusterIdentifier})
			if err != nil {
				continue
			}
			out[*cl.ClusterIdentifier] = *ls
		}
		return out, nil
	})
	d.RedshiftParamGroupTags = cache.New("RedshiftParamGroupTags", func() (map[string]map[string]string, error) {
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
	d.RedshiftParamValues = cache.New("RedshiftParamValues", func() (map[string]map[string]string, error) {
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
	d.RedshiftServerlessWorkgroups = cache.New("RedshiftServerlessWorkgroups", func() ([]rsstypes.Workgroup, error) {
		out, err := c.RedshiftServerless.ListWorkgroups(ctx, &redshiftserverless.ListWorkgroupsInput{})
		if err != nil {
			return nil, err
		}
		return out.Workgroups, nil
	})
	d.RedshiftServerlessNamespaces = cache.New("RedshiftServerlessNamespaces", func() ([]rsstypes.Namespace, error) {
		out, err := c.RedshiftServerless.ListNamespaces(ctx, &redshiftserverless.ListNamespacesInput{})
		if err != nil {
			return nil, err
		}
		return out.Namespaces, nil
	})

	// EFS
	d.EFSFileSystems = cache.New("EFSFileSystems", func() ([]efstypes.FileSystemDescription, error) {
		out, err := c.EFS.DescribeFileSystems(ctx, &efs.DescribeFileSystemsInput{})
		if err != nil {
			return nil, err
		}
		return out.FileSystems, nil
	})
	d.EFSAccessPoints = cache.New("EFSAccessPoints", func() ([]efstypes.AccessPointDescription, error) {
		out, err := c.EFS.DescribeAccessPoints(ctx, &efs.DescribeAccessPointsInput{})
		if err != nil {
			return nil, err
		}
		return out.AccessPoints, nil
	})
	d.EFSMountTargets = cache.New("EFSMountTargets", func() (map[string][]efstypes.MountTargetDescription, error) {
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
	d.EFSBackupPolicies = cache.New("EFSBackupPolicies", func() (map[string]bool, error) {
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
	d.EFSFileSystemTags = cache.New("EFSFileSystemTags", func() (map[string]map[string]string, error) {
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
	d.ELBClassicLBs = cache.New("ELBClassicLBs", func() ([]elbtypes.LoadBalancerDescription, error) {
		out, err := c.ELB.DescribeLoadBalancers(ctx, &elasticloadbalancing.DescribeLoadBalancersInput{})
		if err != nil {
			return nil, err
		}
		return out.LoadBalancerDescriptions, nil
	})
	d.ELBClassicTags = cache.New("ELBClassicTags", func() (map[string]map[string]string, error) {
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
	d.ELBClassicAttributes = cache.New("ELBClassicAttributes", func() (map[string]elbtypes.LoadBalancerAttributes, error) {
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
	d.ELBClassicPolicies = cache.New("ELBClassicPolicies", func() (map[string][]elbtypes.PolicyDescription, error) {
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
	d.ELBv2LoadBalancers = cache.New("ELBv2LoadBalancers", func() ([]elbv2types.LoadBalancer, error) {
		out, err := c.ELBv2.DescribeLoadBalancers(ctx, &elasticloadbalancingv2.DescribeLoadBalancersInput{})
		if err != nil {
			return nil, err
		}
		return out.LoadBalancers, nil
	})
	d.ELBv2Listeners = cache.New("ELBv2Listeners", func() ([]elbv2types.Listener, error) {
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
	d.ELBv2TargetGroups = cache.New("ELBv2TargetGroups", func() ([]elbv2types.TargetGroup, error) {
		out, err := c.ELBv2.DescribeTargetGroups(ctx, &elasticloadbalancingv2.DescribeTargetGroupsInput{})
		if err != nil {
			return nil, err
		}
		return out.TargetGroups, nil
	})
	d.ELBv2Tags = cache.New("ELBv2Tags", func() (map[string]map[string]string, error) {
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
	d.ELBv2LBAttributes = cache.New("ELBv2LBAttributes", func() (map[string]map[string]string, error) {
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
	d.ECRRepositories = cache.New("ECRRepositories", func() ([]ecrtypes.Repository, error) {
		out, err := c.ECR.DescribeRepositories(ctx, &ecr.DescribeRepositoriesInput{})
		if err != nil {
			return nil, err
		}
		return out.Repositories, nil
	})

	// Neptune
	d.NeptuneClusters = cache.New("NeptuneClusters", func() ([]neptunetypes.DBCluster, error) {
		out, err := c.Neptune.DescribeDBClusters(ctx, &neptune.DescribeDBClustersInput{})
		if err != nil {
			return nil, err
		}
		return out.DBClusters, nil
	})
	d.NeptuneSnapshots = cache.New("NeptuneSnapshots", func() ([]neptunetypes.DBClusterSnapshot, error) {
		out, err := c.Neptune.DescribeDBClusterSnapshots(ctx, &neptune.DescribeDBClusterSnapshotsInput{})
		if err != nil {
			return nil, err
		}
		return out.DBClusterSnapshots, nil
	})

	// OpenSearch
	d.OpenSearchDomains = cache.New("OpenSearchDomains", func() ([]opentypes.DomainStatus, error) {
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
	d.ElasticsearchDomains = cache.New("ElasticsearchDomains", func() ([]estypes.ElasticsearchDomainStatus, error) {
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
	d.GlueJobs = cache.New("GlueJobs", func() ([]gluetypes.Job, error) {
		out, err := c.Glue.GetJobs(ctx, &glue.GetJobsInput{})
		if err != nil {
			return nil, err
		}
		return out.Jobs, nil
	})
	d.GlueMLTransforms = cache.New("GlueMLTransforms", func() ([]gluetypes.MLTransform, error) {
		out, err := c.Glue.GetMLTransforms(ctx, &glue.GetMLTransformsInput{})
		if err != nil {
			return nil, err
		}
		return out.Transforms, nil
	})
	d.GlueMLTransformTags = cache.New("GlueMLTransformTags", func() (map[string]map[string]string, error) {
		transforms, err := d.GlueMLTransforms.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, t := range transforms {
			if t.TransformId == nil {
				continue
			}
			resp, err := c.Glue.GetTags(ctx, &glue.GetTagsInput{ResourceArn: t.TransformId})
			if err != nil {
				continue
			}
			out[*t.TransformId] = resp.Tags
		}
		return out, nil
	})
	d.GlueRegistries = cache.New("GlueRegistries", func() ([]gluetypes.RegistryListItem, error) {
		out, err := c.Glue.ListRegistries(ctx, &glue.ListRegistriesInput{})
		if err != nil {
			return nil, err
		}
		return out.Registries, nil
	})
	d.GlueRegistryPolicies = cache.New("GlueRegistryPolicies", func() (map[string]string, error) {
		regs, err := d.GlueRegistries.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]string)
		for _, r := range regs {
			if r.RegistryArn == nil {
				continue
			}
			pol, err := c.Glue.GetResourcePolicy(ctx, &glue.GetResourcePolicyInput{ResourceArn: r.RegistryArn})
			if err != nil || pol.PolicyInJson == nil {
				continue
			}
			out[*r.RegistryArn] = *pol.PolicyInJson
		}
		return out, nil
	})

	// GuardDuty
	d.GuardDutyDetectorIDs = cache.New("GuardDutyDetectorIDs", func() ([]string, error) {
		out, err := c.GuardDuty.ListDetectors(ctx, &guardduty.ListDetectorsInput{})
		if err != nil {
			return nil, err
		}
		return out.DetectorIds, nil
	})
	d.GuardDutyDetectors = cache.New("GuardDutyDetectors", func() (map[string]guardduty.GetDetectorOutput, error) {
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

	// Inspector2
	d.Inspector2Status = cache.New("Inspector2Status", func() (inspector2.BatchGetAccountStatusOutput, error) {
		out, err := c.Inspector2.BatchGetAccountStatus(ctx, &inspector2.BatchGetAccountStatusInput{})
		if err != nil {
			return inspector2.BatchGetAccountStatusOutput{}, err
		}
		return *out, nil
	})

	// IoT
	d.IoTAuthorizers = cache.New("IoTAuthorizers", func() ([]iottypes.AuthorizerSummary, error) {
		out, err := c.IoT.ListAuthorizers(ctx, &iot.ListAuthorizersInput{})
		if err != nil {
			return nil, err
		}
		return out.Authorizers, nil
	})
	d.IoTAuthorizerDetails = cache.New("IoTAuthorizerDetails", func() (map[string]iottypes.AuthorizerDescription, error) {
		items, err := d.IoTAuthorizers.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]iottypes.AuthorizerDescription)
		for _, a := range items {
			if a.AuthorizerName == nil {
				continue
			}
			desc, err := c.IoT.DescribeAuthorizer(ctx, &iot.DescribeAuthorizerInput{AuthorizerName: a.AuthorizerName})
			if err != nil || desc.AuthorizerDescription == nil {
				continue
			}
			out[*a.AuthorizerName] = *desc.AuthorizerDescription
		}
		return out, nil
	})

	// IoT SiteWise
	d.IoTSiteWiseAssetModels = cache.New("IoTSiteWiseAssetModels", func() ([]sitewisetypes.AssetModelSummary, error) {
		out, err := c.IoTSiteWise.ListAssetModels(ctx, &iotsitewise.ListAssetModelsInput{})
		if err != nil {
			return nil, err
		}
		return out.AssetModelSummaries, nil
	})
	d.IoTSiteWiseDashboards = cache.New("IoTSiteWiseDashboards", func() ([]sitewisetypes.DashboardSummary, error) {
		out, err := c.IoTSiteWise.ListDashboards(ctx, &iotsitewise.ListDashboardsInput{})
		if err != nil {
			return nil, err
		}
		return out.DashboardSummaries, nil
	})
	d.IoTSiteWiseGateways = cache.New("IoTSiteWiseGateways", func() ([]sitewisetypes.GatewaySummary, error) {
		out, err := c.IoTSiteWise.ListGateways(ctx, &iotsitewise.ListGatewaysInput{})
		if err != nil {
			return nil, err
		}
		return out.GatewaySummaries, nil
	})
	d.IoTSiteWisePortals = cache.New("IoTSiteWisePortals", func() ([]sitewisetypes.PortalSummary, error) {
		out, err := c.IoTSiteWise.ListPortals(ctx, &iotsitewise.ListPortalsInput{})
		if err != nil {
			return nil, err
		}
		return out.PortalSummaries, nil
	})
	d.IoTSiteWiseProjects = cache.New("IoTSiteWiseProjects", func() ([]sitewisetypes.ProjectSummary, error) {
		out, err := c.IoTSiteWise.ListProjects(ctx, &iotsitewise.ListProjectsInput{})
		if err != nil {
			return nil, err
		}
		return out.ProjectSummaries, nil
	})
	d.IoTSiteWiseTags = cache.New("IoTSiteWiseTags", func() (map[string]map[string]string, error) {
		out := make(map[string]map[string]string)
		collect := func(arn *string) {
			if arn == nil {
				return
			}
			resp, err := c.IoTSiteWise.ListTagsForResource(ctx, &iotsitewise.ListTagsForResourceInput{ResourceArn: arn})
			if err != nil {
				return
			}
			out[*arn] = resp.Tags
		}
		assets, _ := d.IoTSiteWiseAssetModels.Get()
		for _, a := range assets {
			collect(a.Arn)
		}
		// DashboardSummary, GatewaySummary, PortalSummary, and ProjectSummary
		// do not have Arn fields, so we cannot collect tags for them.
		return out, nil
	})

	// IoT TwinMaker
	d.TwinMakerWorkspaces = cache.New("TwinMakerWorkspaces", func() ([]twinmakertypes.WorkspaceSummary, error) {
		out, err := c.IoTTwinMaker.ListWorkspaces(ctx, &iottwinmaker.ListWorkspacesInput{})
		if err != nil {
			return nil, err
		}
		return out.WorkspaceSummaries, nil
	})
	d.TwinMakerComponentTypes = cache.New("TwinMakerComponentTypes", func() (map[string][]twinmakertypes.ComponentTypeSummary, error) {
		workspaces, err := d.TwinMakerWorkspaces.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string][]twinmakertypes.ComponentTypeSummary)
		for _, ws := range workspaces {
			if ws.WorkspaceId == nil {
				continue
			}
			resp, err := c.IoTTwinMaker.ListComponentTypes(ctx, &iottwinmaker.ListComponentTypesInput{WorkspaceId: ws.WorkspaceId})
			if err != nil {
				continue
			}
			out[*ws.WorkspaceId] = resp.ComponentTypeSummaries
		}
		return out, nil
	})

	// IVS
	d.IVSChannels = cache.New("IVSChannels", func() ([]ivstypes.ChannelSummary, error) {
		out, err := c.IVS.ListChannels(ctx, &ivs.ListChannelsInput{})
		if err != nil {
			return nil, err
		}
		return out.Channels, nil
	})
	d.IVSChannelDetails = cache.New("IVSChannelDetails", func() (map[string]ivstypes.Channel, error) {
		channels, err := d.IVSChannels.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]ivstypes.Channel)
		for _, ch := range channels {
			if ch.Arn == nil {
				continue
			}
			desc, err := c.IVS.GetChannel(ctx, &ivs.GetChannelInput{Arn: ch.Arn})
			if err != nil || desc.Channel == nil {
				continue
			}
			out[*ch.Arn] = *desc.Channel
		}
		return out, nil
	})
	d.IVSRecordingConfigurations = cache.New("IVSRecordingConfigurations", func() ([]ivstypes.RecordingConfigurationSummary, error) {
		out, err := c.IVS.ListRecordingConfigurations(ctx, &ivs.ListRecordingConfigurationsInput{})
		if err != nil {
			return nil, err
		}
		return out.RecordingConfigurations, nil
	})
	d.IVSPlaybackKeyPairs = cache.New("IVSPlaybackKeyPairs", func() ([]ivstypes.PlaybackKeyPairSummary, error) {
		out, err := c.IVS.ListPlaybackKeyPairs(ctx, &ivs.ListPlaybackKeyPairsInput{})
		if err != nil {
			return nil, err
		}
		return out.KeyPairs, nil
	})
	d.IVSTags = cache.New("IVSTags", func() (map[string]map[string]string, error) {
		out := make(map[string]map[string]string)
		collect := func(arn *string) {
			if arn == nil {
				return
			}
			resp, err := c.IVS.ListTagsForResource(ctx, &ivs.ListTagsForResourceInput{ResourceArn: arn})
			if err != nil {
				return
			}
			out[*arn] = resp.Tags
		}
		channels, _ := d.IVSChannels.Get()
		for _, ch := range channels {
			collect(ch.Arn)
		}
		rec, _ := d.IVSRecordingConfigurations.Get()
		for _, r := range rec {
			collect(r.Arn)
		}
		pairs, _ := d.IVSPlaybackKeyPairs.Get()
		for _, p := range pairs {
			collect(p.Arn)
		}
		return out, nil
	})
	d.TwinMakerEntities = cache.New("TwinMakerEntities", func() (map[string][]twinmakertypes.EntitySummary, error) {
		workspaces, err := d.TwinMakerWorkspaces.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string][]twinmakertypes.EntitySummary)
		for _, ws := range workspaces {
			if ws.WorkspaceId == nil {
				continue
			}
			resp, err := c.IoTTwinMaker.ListEntities(ctx, &iottwinmaker.ListEntitiesInput{WorkspaceId: ws.WorkspaceId})
			if err != nil {
				continue
			}
			out[*ws.WorkspaceId] = resp.EntitySummaries
		}
		return out, nil
	})
	d.TwinMakerScenes = cache.New("TwinMakerScenes", func() (map[string][]twinmakertypes.SceneSummary, error) {
		workspaces, err := d.TwinMakerWorkspaces.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string][]twinmakertypes.SceneSummary)
		for _, ws := range workspaces {
			if ws.WorkspaceId == nil {
				continue
			}
			resp, err := c.IoTTwinMaker.ListScenes(ctx, &iottwinmaker.ListScenesInput{WorkspaceId: ws.WorkspaceId})
			if err != nil {
				continue
			}
			out[*ws.WorkspaceId] = resp.SceneSummaries
		}
		return out, nil
	})
	d.TwinMakerSyncJobs = cache.New("TwinMakerSyncJobs", func() (map[string][]twinmakertypes.SyncJobSummary, error) {
		workspaces, err := d.TwinMakerWorkspaces.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string][]twinmakertypes.SyncJobSummary)
		for _, ws := range workspaces {
			if ws.WorkspaceId == nil {
				continue
			}
			resp, err := c.IoTTwinMaker.ListSyncJobs(ctx, &iottwinmaker.ListSyncJobsInput{WorkspaceId: ws.WorkspaceId})
			if err != nil {
				continue
			}
			out[*ws.WorkspaceId] = resp.SyncJobSummaries
		}
		return out, nil
	})
	d.TwinMakerTags = cache.New("TwinMakerTags", func() (map[string]map[string]string, error) {
		out := make(map[string]map[string]string)
		collect := func(arn *string) {
			if arn == nil {
				return
			}
			resp, err := c.IoTTwinMaker.ListTagsForResource(ctx, &iottwinmaker.ListTagsForResourceInput{ResourceARN: arn})
			if err != nil {
				return
			}
			out[*arn] = resp.Tags
		}
		workspaces, _ := d.TwinMakerWorkspaces.Get()
		for _, ws := range workspaces {
			collect(ws.Arn)
		}
		comp, _ := d.TwinMakerComponentTypes.Get()
		for _, items := range comp {
			for _, it := range items {
				collect(it.Arn)
			}
		}
		ents, _ := d.TwinMakerEntities.Get()
		for _, items := range ents {
			for _, it := range items {
				collect(it.Arn)
			}
		}
		scenes, _ := d.TwinMakerScenes.Get()
		for _, items := range scenes {
			for _, it := range items {
				collect(it.Arn)
			}
		}
		syncs, _ := d.TwinMakerSyncJobs.Get()
		for _, items := range syncs {
			for _, it := range items {
				collect(it.Arn)
			}
		}
		return out, nil
	})
	d.IoTJobTemplates = cache.New("IoTJobTemplates", func() ([]iottypes.JobTemplateSummary, error) {
		out, err := c.IoT.ListJobTemplates(ctx, &iot.ListJobTemplatesInput{})
		if err != nil {
			return nil, err
		}
		return out.JobTemplates, nil
	})
	d.IoTJobTemplateTags = cache.New("IoTJobTemplateTags", func() (map[string]map[string]string, error) {
		items, err := d.IoTJobTemplates.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, jt := range items {
			if jt.JobTemplateArn == nil {
				continue
			}
			resp, err := c.IoT.ListTagsForResource(ctx, &iot.ListTagsForResourceInput{ResourceArn: jt.JobTemplateArn})
			if err != nil {
				continue
			}
			m := make(map[string]string)
			for _, t := range resp.Tags {
				if t.Key != nil && t.Value != nil {
					m[*t.Key] = *t.Value
				}
			}
			out[*jt.JobTemplateArn] = m
		}
		return out, nil
	})
	d.IoTProvisioningTemplates = cache.New("IoTProvisioningTemplates", func() ([]iottypes.ProvisioningTemplateSummary, error) {
		out, err := c.IoT.ListProvisioningTemplates(ctx, &iot.ListProvisioningTemplatesInput{})
		if err != nil {
			return nil, err
		}
		return out.Templates, nil
	})
	d.IoTProvisioningTemplateDetails = cache.New("IoTProvisioningTemplateDetails", func() (map[string]iot.DescribeProvisioningTemplateOutput, error) {
		items, err := d.IoTProvisioningTemplates.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]iot.DescribeProvisioningTemplateOutput)
		for _, it := range items {
			if it.TemplateName == nil {
				continue
			}
			desc, err := c.IoT.DescribeProvisioningTemplate(ctx, &iot.DescribeProvisioningTemplateInput{TemplateName: it.TemplateName})
			if err != nil || desc.TemplateName == nil {
				continue
			}
			out[*it.TemplateName] = *desc
		}
		return out, nil
	})
	d.IoTProvisioningTemplateTags = cache.New("IoTProvisioningTemplateTags", func() (map[string]map[string]string, error) {
		items, err := d.IoTProvisioningTemplates.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, it := range items {
			if it.TemplateArn == nil {
				continue
			}
			resp, err := c.IoT.ListTagsForResource(ctx, &iot.ListTagsForResourceInput{ResourceArn: it.TemplateArn})
			if err != nil {
				continue
			}
			m := make(map[string]string)
			for _, t := range resp.Tags {
				if t.Key != nil && t.Value != nil {
					m[*t.Key] = *t.Value
				}
			}
			out[*it.TemplateArn] = m
		}
		return out, nil
	})
	d.IoTScheduledAudits = cache.New("IoTScheduledAudits", func() ([]iottypes.ScheduledAuditMetadata, error) {
		out, err := c.IoT.ListScheduledAudits(ctx, &iot.ListScheduledAuditsInput{})
		if err != nil {
			return nil, err
		}
		return out.ScheduledAudits, nil
	})
	d.IoTScheduledAuditTags = cache.New("IoTScheduledAuditTags", func() (map[string]map[string]string, error) {
		items, err := d.IoTScheduledAudits.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, it := range items {
			if it.ScheduledAuditArn == nil {
				continue
			}
			resp, err := c.IoT.ListTagsForResource(ctx, &iot.ListTagsForResourceInput{ResourceArn: it.ScheduledAuditArn})
			if err != nil {
				continue
			}
			m := make(map[string]string)
			for _, t := range resp.Tags {
				if t.Key != nil && t.Value != nil {
					m[*t.Key] = *t.Value
				}
			}
			out[*it.ScheduledAuditArn] = m
		}
		return out, nil
	})
	d.GuardDutyNonArchivedFindings = cache.New("GuardDutyNonArchivedFindings", func() (map[string]int, error) {
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
	d.BackupPlans = cache.New("BackupPlans", func() ([]backuptypes.BackupPlansListMember, error) {
		out, err := c.Backup.ListBackupPlans(ctx, &backup.ListBackupPlansInput{})
		if err != nil {
			return nil, err
		}
		return out.BackupPlansList, nil
	})
	d.BackupVaults = cache.New("BackupVaults", func() ([]backuptypes.BackupVaultListMember, error) {
		out, err := c.Backup.ListBackupVaults(ctx, &backup.ListBackupVaultsInput{})
		if err != nil {
			return nil, err
		}
		return out.BackupVaultList, nil
	})
	d.BackupPlanDetails = cache.New("BackupPlanDetails", func() (map[string]backuptypes.BackupPlan, error) {
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
	d.BackupRecoveryPoints = cache.New("BackupRecoveryPoints", func() (map[string][]backuptypes.RecoveryPointByBackupVault, error) {
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
	d.BackupVaultLockConfigs = cache.New("BackupVaultLockConfigs", func() (map[string]backup.DescribeBackupVaultOutput, error) {
		vaults, err := d.BackupVaults.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]backup.DescribeBackupVaultOutput)
		for _, v := range vaults {
			if v.BackupVaultName == nil {
				continue
			}
			desc, err := c.Backup.DescribeBackupVault(ctx, &backup.DescribeBackupVaultInput{BackupVaultName: v.BackupVaultName})
			if err != nil || desc == nil {
				continue
			}
			out[*v.BackupVaultName] = *desc
		}
		return out, nil
	})
	d.BackupProtectedResources = cache.New("BackupProtectedResources", func() (map[string]backuptypes.ProtectedResource, error) {
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
	d.BackupRecoveryPointsByResource = cache.New("BackupRecoveryPointsByResource", func() (map[string][]backuptypes.RecoveryPointByResource, error) {
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
	d.DocDBClusters = cache.New("DocDBClusters", func() ([]docdbtypes.DBCluster, error) {
		out, err := c.DocDB.DescribeDBClusters(ctx, &docdb.DescribeDBClustersInput{})
		if err != nil {
			return nil, err
		}
		return out.DBClusters, nil
	})
	d.DocDBSnapshots = cache.New("DocDBSnapshots", func() ([]docdbtypes.DBClusterSnapshot, error) {
		out, err := c.DocDB.DescribeDBClusterSnapshots(ctx, &docdb.DescribeDBClusterSnapshotsInput{})
		if err != nil {
			return nil, err
		}
		return out.DBClusterSnapshots, nil
	})

	// DAX
	d.DAXClusters = cache.New("DAXClusters", func() ([]daxtypes.Cluster, error) {
		out, err := c.DAX.DescribeClusters(ctx, &dax.DescribeClustersInput{})
		if err != nil {
			return nil, err
		}
		return out.Clusters, nil
	})

	// Cassandra (Keyspaces)
	d.CassandraKeyspaces = cache.New("CassandraKeyspaces", func() ([]keyspacestypes.KeyspaceSummary, error) {
		out, err := c.Keyspaces.ListKeyspaces(ctx, &keyspaces.ListKeyspacesInput{})
		if err != nil {
			return nil, err
		}
		return out.Keyspaces, nil
	})
	d.CassandraKeyspaceARNByName = cache.New("CassandraKeyspaceARNByName", func() (map[string]string, error) {
		keyspacesList, err := d.CassandraKeyspaces.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]string)
		for _, ks := range keyspacesList {
			if ks.KeyspaceName == nil {
				continue
			}
			desc, err := c.Keyspaces.GetKeyspace(ctx, &keyspaces.GetKeyspaceInput{KeyspaceName: ks.KeyspaceName})
			if err != nil || desc == nil || desc.ResourceArn == nil {
				continue
			}
			out[*ks.KeyspaceName] = *desc.ResourceArn
		}
		return out, nil
	})
	d.CassandraKeyspaceTags = cache.New("CassandraKeyspaceTags", func() (map[string]map[string]string, error) {
		arnByName, err := d.CassandraKeyspaceARNByName.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for name, arn := range arnByName {
			arn := arn
			tags, err := c.Keyspaces.ListTagsForResource(ctx, &keyspaces.ListTagsForResourceInput{ResourceArn: &arn})
			if err != nil {
				continue
			}
			m := make(map[string]string)
			for _, t := range tags.Tags {
				if t.Key != nil && t.Value != nil {
					m[*t.Key] = *t.Value
				}
			}
			out[name] = m
		}
		return out, nil
	})

	// DataSync
	d.DataSyncTasks = cache.New("DataSyncTasks", func() ([]datasynctypes.TaskListEntry, error) {
		out, err := c.DataSync.ListTasks(ctx, &datasync.ListTasksInput{})
		if err != nil {
			return nil, err
		}
		return out.Tasks, nil
	})
	d.DataSyncTaskDetails = cache.New("DataSyncTaskDetails", func() (map[string]datasync.DescribeTaskOutput, error) {
		tasks, err := d.DataSyncTasks.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]datasync.DescribeTaskOutput)
		for _, t := range tasks {
			if t.TaskArn == nil {
				continue
			}
			desc, err := c.DataSync.DescribeTask(ctx, &datasync.DescribeTaskInput{TaskArn: t.TaskArn})
			if err != nil {
				continue
			}
			out[*t.TaskArn] = *desc
		}
		return out, nil
	})

	// Evidently
	d.EvidentlyProjects = cache.New("EvidentlyProjects", func() ([]evidentlytypes.ProjectSummary, error) {
		out, err := c.Evidently.ListProjects(ctx, &evidently.ListProjectsInput{})
		if err != nil {
			return nil, err
		}
		return out.Projects, nil
	})
	d.EvidentlyProjectDetails = cache.New("EvidentlyProjectDetails", func() (map[string]evidentlytypes.Project, error) {
		projects, err := d.EvidentlyProjects.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]evidentlytypes.Project)
		for _, p := range projects {
			if p.Arn == nil {
				continue
			}
			desc, err := c.Evidently.GetProject(ctx, &evidently.GetProjectInput{Project: p.Arn})
			if err != nil || desc.Project == nil {
				continue
			}
			out[*p.Arn] = *desc.Project
		}
		return out, nil
	})

	// Fraud Detector
	d.FraudDetectorEntityTypes = cache.New("FraudDetectorEntityTypes", func() ([]fraudtypes.EntityType, error) {
		out, err := c.FraudDetector.GetEntityTypes(ctx, &frauddetector.GetEntityTypesInput{})
		if err != nil {
			return nil, err
		}
		return out.EntityTypes, nil
	})
	d.FraudDetectorLabels = cache.New("FraudDetectorLabels", func() ([]fraudtypes.Label, error) {
		out, err := c.FraudDetector.GetLabels(ctx, &frauddetector.GetLabelsInput{})
		if err != nil {
			return nil, err
		}
		return out.Labels, nil
	})
	d.FraudDetectorOutcomes = cache.New("FraudDetectorOutcomes", func() ([]fraudtypes.Outcome, error) {
		out, err := c.FraudDetector.GetOutcomes(ctx, &frauddetector.GetOutcomesInput{})
		if err != nil {
			return nil, err
		}
		return out.Outcomes, nil
	})
	d.FraudDetectorVariables = cache.New("FraudDetectorVariables", func() ([]fraudtypes.Variable, error) {
		out, err := c.FraudDetector.GetVariables(ctx, &frauddetector.GetVariablesInput{})
		if err != nil {
			return nil, err
		}
		return out.Variables, nil
	})
	d.FraudDetectorEntityTypeTags = cache.New("FraudDetectorEntityTypeTags", func() (map[string]map[string]string, error) {
		items, err := d.FraudDetectorEntityTypes.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, it := range items {
			if it.Arn == nil {
				continue
			}
			resp, err := c.FraudDetector.ListTagsForResource(ctx, &frauddetector.ListTagsForResourceInput{ResourceARN: it.Arn})
			if err != nil {
				continue
			}
			m := make(map[string]string)
			for _, t := range resp.Tags {
				if t.Key != nil && t.Value != nil {
					m[*t.Key] = *t.Value
				}
			}
			out[*it.Arn] = m
		}
		return out, nil
	})
	d.FraudDetectorLabelTags = cache.New("FraudDetectorLabelTags", func() (map[string]map[string]string, error) {
		items, err := d.FraudDetectorLabels.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, it := range items {
			if it.Arn == nil {
				continue
			}
			resp, err := c.FraudDetector.ListTagsForResource(ctx, &frauddetector.ListTagsForResourceInput{ResourceARN: it.Arn})
			if err != nil {
				continue
			}
			m := make(map[string]string)
			for _, t := range resp.Tags {
				if t.Key != nil && t.Value != nil {
					m[*t.Key] = *t.Value
				}
			}
			out[*it.Arn] = m
		}
		return out, nil
	})
	d.FraudDetectorOutcomeTags = cache.New("FraudDetectorOutcomeTags", func() (map[string]map[string]string, error) {
		items, err := d.FraudDetectorOutcomes.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, it := range items {
			if it.Arn == nil {
				continue
			}
			resp, err := c.FraudDetector.ListTagsForResource(ctx, &frauddetector.ListTagsForResourceInput{ResourceARN: it.Arn})
			if err != nil {
				continue
			}
			m := make(map[string]string)
			for _, t := range resp.Tags {
				if t.Key != nil && t.Value != nil {
					m[*t.Key] = *t.Value
				}
			}
			out[*it.Arn] = m
		}
		return out, nil
	})
	d.FraudDetectorVariableTags = cache.New("FraudDetectorVariableTags", func() (map[string]map[string]string, error) {
		items, err := d.FraudDetectorVariables.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, it := range items {
			if it.Arn == nil {
				continue
			}
			resp, err := c.FraudDetector.ListTagsForResource(ctx, &frauddetector.ListTagsForResourceInput{ResourceARN: it.Arn})
			if err != nil {
				continue
			}
			m := make(map[string]string)
			for _, t := range resp.Tags {
				if t.Key != nil && t.Value != nil {
					m[*t.Key] = *t.Value
				}
			}
			out[*it.Arn] = m
		}
		return out, nil
	})
	d.EvidentlyProjectTags = cache.New("EvidentlyProjectTags", func() (map[string]map[string]string, error) {
		projects, err := d.EvidentlyProjects.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, p := range projects {
			if p.Arn == nil {
				continue
			}
			resp, err := c.Evidently.ListTagsForResource(ctx, &evidently.ListTagsForResourceInput{ResourceArn: p.Arn})
			if err != nil {
				continue
			}
			out[*p.Arn] = resp.Tags
		}
		return out, nil
	})
	d.EvidentlyLaunches = cache.New("EvidentlyLaunches", func() (map[string][]evidentlytypes.Launch, error) {
		projects, err := d.EvidentlyProjects.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string][]evidentlytypes.Launch)
		for _, p := range projects {
			if p.Arn == nil {
				continue
			}
			resp, err := c.Evidently.ListLaunches(ctx, &evidently.ListLaunchesInput{Project: p.Arn})
			if err != nil {
				continue
			}
			out[*p.Arn] = resp.Launches
		}
		return out, nil
	})
	d.EvidentlyLaunchDetails = cache.New("EvidentlyLaunchDetails", func() (map[string]evidentlytypes.Launch, error) {
		launches, err := d.EvidentlyLaunches.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]evidentlytypes.Launch)
		for proj, items := range launches {
			for _, l := range items {
				if l.Arn == nil {
					continue
				}
				desc, err := c.Evidently.GetLaunch(ctx, &evidently.GetLaunchInput{Launch: l.Arn, Project: &proj})
				if err != nil || desc.Launch == nil {
					continue
				}
				out[*l.Arn] = *desc.Launch
			}
		}
		return out, nil
	})
	d.EvidentlyLaunchTags = cache.New("EvidentlyLaunchTags", func() (map[string]map[string]string, error) {
		launches, err := d.EvidentlyLaunches.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, items := range launches {
			for _, l := range items {
				if l.Arn == nil {
					continue
				}
				resp, err := c.Evidently.ListTagsForResource(ctx, &evidently.ListTagsForResourceInput{ResourceArn: l.Arn})
				if err != nil {
					continue
				}
				out[*l.Arn] = resp.Tags
			}
		}
		return out, nil
	})
	d.EvidentlySegments = cache.New("EvidentlySegments", func() (map[string][]evidentlytypes.Segment, error) {
		out := make(map[string][]evidentlytypes.Segment)
		resp, err := c.Evidently.ListSegments(ctx, &evidently.ListSegmentsInput{})
		if err != nil {
			return nil, err
		}
		out["global"] = resp.Segments
		return out, nil
	})
	d.EvidentlySegmentDetails = cache.New("EvidentlySegmentDetails", func() (map[string]evidentlytypes.Segment, error) {
		segs, err := d.EvidentlySegments.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]evidentlytypes.Segment)
		for _, items := range segs {
			for _, s := range items {
				if s.Arn == nil {
					continue
				}
				desc, err := c.Evidently.GetSegment(ctx, &evidently.GetSegmentInput{Segment: s.Arn})
				if err != nil || desc.Segment == nil {
					continue
				}
				out[*s.Arn] = *desc.Segment
			}
		}
		return out, nil
	})
	d.EvidentlySegmentTags = cache.New("EvidentlySegmentTags", func() (map[string]map[string]string, error) {
		segs, err := d.EvidentlySegments.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, items := range segs {
			for _, s := range items {
				if s.Arn == nil {
					continue
				}
				resp, err := c.Evidently.ListTagsForResource(ctx, &evidently.ListTagsForResourceInput{ResourceArn: s.Arn})
				if err != nil {
					continue
				}
				out[*s.Arn] = resp.Tags
			}
		}
		return out, nil
	})
	d.DataSyncTaskTags = cache.New("DataSyncTaskTags", func() (map[string]map[string]string, error) {
		tasks, err := d.DataSyncTasks.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, t := range tasks {
			if t.TaskArn == nil {
				continue
			}
			resp, err := c.DataSync.ListTagsForResource(ctx, &datasync.ListTagsForResourceInput{ResourceArn: t.TaskArn})
			if err != nil {
				continue
			}
			m := make(map[string]string)
			for _, tag := range resp.Tags {
				if tag.Key != nil && tag.Value != nil {
					m[*tag.Key] = *tag.Value
				}
			}
			out[*t.TaskArn] = m
		}
		return out, nil
	})
	d.DataSyncLocations = cache.New("DataSyncLocations", func() ([]datasynctypes.LocationListEntry, error) {
		out, err := c.DataSync.ListLocations(ctx, &datasync.ListLocationsInput{})
		if err != nil {
			return nil, err
		}
		return out.Locations, nil
	})
	d.DataSyncLocationObjectStorageDetails = cache.New("DataSyncLocationObjectStorageDetails", func() (map[string]datasync.DescribeLocationObjectStorageOutput, error) {
		locs, err := d.DataSyncLocations.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]datasync.DescribeLocationObjectStorageOutput)
		for _, l := range locs {
			if l.LocationArn == nil || l.LocationUri == nil {
				continue
			}
			if !strings.HasPrefix(*l.LocationUri, "object-storage://") {
				continue
			}
			desc, err := c.DataSync.DescribeLocationObjectStorage(ctx, &datasync.DescribeLocationObjectStorageInput{LocationArn: l.LocationArn})
			if err != nil {
				continue
			}
			out[*l.LocationArn] = *desc
		}
		return out, nil
	})

	// DMS
	d.DMSReplicationInstances = cache.New("DMSReplicationInstances", func() ([]dmstypes.ReplicationInstance, error) {
		out, err := c.DMS.DescribeReplicationInstances(ctx, &databasemigrationservice.DescribeReplicationInstancesInput{})
		if err != nil {
			return nil, err
		}
		return out.ReplicationInstances, nil
	})
	d.DMSEndpoints = cache.New("DMSEndpoints", func() ([]dmstypes.Endpoint, error) {
		out, err := c.DMS.DescribeEndpoints(ctx, &databasemigrationservice.DescribeEndpointsInput{})
		if err != nil {
			return nil, err
		}
		return out.Endpoints, nil
	})
	d.DMSReplicationTasks = cache.New("DMSReplicationTasks", func() ([]dmstypes.ReplicationTask, error) {
		out, err := c.DMS.DescribeReplicationTasks(ctx, &databasemigrationservice.DescribeReplicationTasksInput{})
		if err != nil {
			return nil, err
		}
		return out.ReplicationTasks, nil
	})
	d.DMSEndpointTags = cache.New("DMSEndpointTags", func() (map[string]map[string]string, error) {
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
	d.DMSReplicationTaskTags = cache.New("DMSReplicationTaskTags", func() (map[string]map[string]string, error) {
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
	d.BatchComputeEnvs = cache.New("BatchComputeEnvs", func() ([]batchtypes.ComputeEnvironmentDetail, error) {
		out, err := c.Batch.DescribeComputeEnvironments(ctx, &batch.DescribeComputeEnvironmentsInput{})
		if err != nil {
			return nil, err
		}
		return out.ComputeEnvironments, nil
	})
	d.BatchJobQueues = cache.New("BatchJobQueues", func() ([]batchtypes.JobQueueDetail, error) {
		out, err := c.Batch.DescribeJobQueues(ctx, &batch.DescribeJobQueuesInput{})
		if err != nil {
			return nil, err
		}
		return out.JobQueues, nil
	})
	d.BatchSchedulingPolicies = cache.New("BatchSchedulingPolicies", func() ([]batchtypes.SchedulingPolicyListingDetail, error) {
		out, err := c.Batch.ListSchedulingPolicies(ctx, &batch.ListSchedulingPoliciesInput{})
		if err != nil {
			return nil, err
		}
		return out.SchedulingPolicies, nil
	})
	d.BatchComputeEnvTags = cache.New("BatchComputeEnvTags", func() (map[string]map[string]string, error) {
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
	d.BatchJobQueueTags = cache.New("BatchJobQueueTags", func() (map[string]map[string]string, error) {
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
	d.BatchSchedulingPolicyTags = cache.New("BatchSchedulingPolicyTags", func() (map[string]map[string]string, error) {
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
	d.CodeBuildProjects = cache.New("CodeBuildProjects", func() ([]codebuildtypes.Project, error) {
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
	d.CodeBuildProjectDetails = cache.New("CodeBuildProjectDetails", func() (map[string]codebuildtypes.Project, error) {
		projects, err := d.CodeBuildProjects.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]codebuildtypes.Project)
		for _, p := range projects {
			if p.Name == nil {
				continue
			}
			out[*p.Name] = p
		}
		return out, nil
	})
	d.CodeBuildReportGroups = cache.New("CodeBuildReportGroups", func() ([]string, error) {
		out, err := c.CodeBuild.ListReportGroups(ctx, &codebuild.ListReportGroupsInput{})
		if err != nil {
			return nil, err
		}
		return out.ReportGroups, nil
	})
	d.CodeBuildReportGroupDetails = cache.New("CodeBuildReportGroupDetails", func() (map[string]codebuildtypes.ReportGroup, error) {
		names, err := d.CodeBuildReportGroups.Get()
		if err != nil {
			return nil, err
		}
		if len(names) == 0 {
			return map[string]codebuildtypes.ReportGroup{}, nil
		}
		out := make(map[string]codebuildtypes.ReportGroup)
		resp, err := c.CodeBuild.BatchGetReportGroups(ctx, &codebuild.BatchGetReportGroupsInput{ReportGroupArns: names})
		if err != nil {
			return nil, err
		}
		for _, rg := range resp.ReportGroups {
			if rg.Arn == nil {
				continue
			}
			out[*rg.Arn] = rg
		}
		return out, nil
	})
	d.CodeBuildReportGroupTags = cache.New("CodeBuildReportGroupTags", func() (map[string]map[string]string, error) {
		groups, err := d.CodeBuildReportGroupDetails.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for arn, rg := range groups {
			m := make(map[string]string)
			for _, t := range rg.Tags {
				if t.Key != nil && t.Value != nil {
					m[*t.Key] = *t.Value
				}
			}
			out[arn] = m
		}
		return out, nil
	})

	// CodeDeploy
	d.CodeDeployApps = cache.New("CodeDeployApps", func() ([]string, error) {
		out, err := c.CodeDeploy.ListApplications(ctx, &codedeploy.ListApplicationsInput{})
		if err != nil {
			return nil, err
		}
		return out.Applications, nil
	})
	d.CodeDeployDeploymentGroups = cache.New("CodeDeployDeploymentGroups", func() (map[string][]string, error) {
		apps, err := d.CodeDeployApps.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string][]string)
		for _, app := range apps {
			resp, err := c.CodeDeploy.ListDeploymentGroups(ctx, &codedeploy.ListDeploymentGroupsInput{ApplicationName: &app})
			if err != nil {
				continue
			}
			out[app] = resp.DeploymentGroups
		}
		return out, nil
	})
	d.CodeDeployDeploymentGroupDetails = cache.New("CodeDeployDeploymentGroupDetails", func() (map[string]codedeploy.GetDeploymentGroupOutput, error) {
		groups, err := d.CodeDeployDeploymentGroups.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]codedeploy.GetDeploymentGroupOutput)
		for app, names := range groups {
			for _, name := range names {
				resp, err := c.CodeDeploy.GetDeploymentGroup(ctx, &codedeploy.GetDeploymentGroupInput{ApplicationName: &app, DeploymentGroupName: &name})
				if err != nil {
					continue
				}
				key := app + ":" + name
				out[key] = *resp
			}
		}
		return out, nil
	})
	d.CodeDeployDeploymentConfigs = cache.New("CodeDeployDeploymentConfigs", func() (map[string]codedeploy.GetDeploymentConfigOutput, error) {
		groups, err := d.CodeDeployDeploymentGroupDetails.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]codedeploy.GetDeploymentConfigOutput)
		for _, g := range groups {
			if g.DeploymentGroupInfo == nil || g.DeploymentGroupInfo.DeploymentConfigName == nil {
				continue
			}
			name := *g.DeploymentGroupInfo.DeploymentConfigName
			if _, ok := out[name]; ok {
				continue
			}
			resp, err := c.CodeDeploy.GetDeploymentConfig(ctx, &codedeploy.GetDeploymentConfigInput{DeploymentConfigName: &name})
			if err != nil {
				continue
			}
			out[name] = *resp
		}
		return out, nil
	})

	// CodePipeline
	d.CodePipelines = cache.New("CodePipelines", func() ([]codepipelinetypes.PipelineSummary, error) {
		out, err := c.CodePipeline.ListPipelines(ctx, &codepipeline.ListPipelinesInput{})
		if err != nil {
			return nil, err
		}
		return out.Pipelines, nil
	})
	d.CodePipelineDetails = cache.New("CodePipelineDetails", func() (map[string]codepipeline.GetPipelineOutput, error) {
		pipes, err := d.CodePipelines.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]codepipeline.GetPipelineOutput)
		for _, p := range pipes {
			if p.Name == nil {
				continue
			}
			resp, err := c.CodePipeline.GetPipeline(ctx, &codepipeline.GetPipelineInput{Name: p.Name})
			if err != nil {
				continue
			}
			out[*p.Name] = *resp
		}
		return out, nil
	})

	// Cognito
	d.CognitoUserPools = cache.New("CognitoUserPools", func() ([]cognitoidptypes.UserPoolDescriptionType, error) {
		out, err := c.CognitoIDP.ListUserPools(ctx, &cognitoidentityprovider.ListUserPoolsInput{MaxResults: aws.Int32(60)})
		if err != nil {
			return nil, err
		}
		return out.UserPools, nil
	})
	d.CognitoUserPoolDetails = cache.New("CognitoUserPoolDetails", func() (map[string]cognitoidptypes.UserPoolType, error) {
		pools, err := d.CognitoUserPools.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]cognitoidptypes.UserPoolType)
		for _, p := range pools {
			if p.Id == nil {
				continue
			}
			desc, err := c.CognitoIDP.DescribeUserPool(ctx, &cognitoidentityprovider.DescribeUserPoolInput{UserPoolId: p.Id})
			if err != nil || desc.UserPool == nil {
				continue
			}
			out[*p.Id] = *desc.UserPool
		}
		return out, nil
	})
	d.CognitoUserPoolTags = cache.New("CognitoUserPoolTags", func() (map[string]map[string]string, error) {
		pools, err := d.CognitoUserPoolDetails.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, p := range pools {
			if p.Arn == nil {
				continue
			}
			resp, err := c.CognitoIDP.ListTagsForResource(ctx, &cognitoidentityprovider.ListTagsForResourceInput{ResourceArn: p.Arn})
			if err != nil {
				continue
			}
			out[*p.Arn] = resp.Tags
		}
		return out, nil
	})
	d.CognitoIdentityPools = cache.New("CognitoIdentityPools", func() ([]cognitoidtypes.IdentityPoolShortDescription, error) {
		out, err := c.CognitoIdentity.ListIdentityPools(ctx, &cognitoidentity.ListIdentityPoolsInput{MaxResults: aws.Int32(60)})
		if err != nil {
			return nil, err
		}
		return out.IdentityPools, nil
	})
	d.CognitoIdentityPoolDetails = cache.New("CognitoIdentityPoolDetails", func() (map[string]cognitoidentity.DescribeIdentityPoolOutput, error) {
		pools, err := d.CognitoIdentityPools.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]cognitoidentity.DescribeIdentityPoolOutput)
		for _, p := range pools {
			if p.IdentityPoolId == nil {
				continue
			}
			desc, err := c.CognitoIdentity.DescribeIdentityPool(ctx, &cognitoidentity.DescribeIdentityPoolInput{IdentityPoolId: p.IdentityPoolId})
			if err != nil {
				continue
			}
			out[*p.IdentityPoolId] = *desc
		}
		return out, nil
	})
	d.CognitoIdentityPoolRoles = cache.New("CognitoIdentityPoolRoles", func() (map[string]cognitoidentity.GetIdentityPoolRolesOutput, error) {
		pools, err := d.CognitoIdentityPools.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]cognitoidentity.GetIdentityPoolRolesOutput)
		for _, p := range pools {
			if p.IdentityPoolId == nil {
				continue
			}
			resp, err := c.CognitoIdentity.GetIdentityPoolRoles(ctx, &cognitoidentity.GetIdentityPoolRolesInput{IdentityPoolId: p.IdentityPoolId})
			if err != nil {
				continue
			}
			out[*p.IdentityPoolId] = *resp
		}
		return out, nil
	})

	// FSx
	d.FSxFileSystems = cache.New("FSxFileSystems", func() ([]fsxtypes.FileSystem, error) {
		out, err := c.FSx.DescribeFileSystems(ctx, &fsx.DescribeFileSystemsInput{})
		if err != nil {
			return nil, err
		}
		return out.FileSystems, nil
	})
	d.FSxFileSystemTags = cache.New("FSxFileSystemTags", func() (map[string]map[string]string, error) {
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
	d.EMRClusters = cache.New("EMRClusters", func() ([]string, error) {
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
	d.EMRClusterDetails = cache.New("EMRClusterDetails", func() (map[string]emrtypes.Cluster, error) {
		ids, err := d.EMRClusters.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]emrtypes.Cluster)
		for _, id := range ids {
			resp, err := c.EMR.DescribeCluster(ctx, &emr.DescribeClusterInput{ClusterId: &id})
			if err != nil || resp.Cluster == nil {
				continue
			}
			out[id] = *resp.Cluster
		}
		return out, nil
	})
	d.EMRSecurityConfigs = cache.New("EMRSecurityConfigs", func() ([]string, error) {
		out, err := c.EMR.ListSecurityConfigurations(ctx, &emr.ListSecurityConfigurationsInput{})
		if err != nil {
			return nil, err
		}
		var names []string
		for _, sc := range out.SecurityConfigurations {
			if sc.Name != nil {
				names = append(names, *sc.Name)
			}
		}
		return names, nil
	})
	d.EMRSecurityConfigDetails = cache.New("EMRSecurityConfigDetails", func() (map[string]emr.DescribeSecurityConfigurationOutput, error) {
		names, err := d.EMRSecurityConfigs.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]emr.DescribeSecurityConfigurationOutput)
		for _, name := range names {
			resp, err := c.EMR.DescribeSecurityConfiguration(ctx, &emr.DescribeSecurityConfigurationInput{Name: &name})
			if err != nil {
				continue
			}
			out[name] = *resp
		}
		return out, nil
	})
	d.EMRBlockPublicAccess = cache.New("EMRBlockPublicAccess", func() (emrtypes.BlockPublicAccessConfiguration, error) {
		out, err := c.EMR.GetBlockPublicAccessConfiguration(ctx, &emr.GetBlockPublicAccessConfigurationInput{})
		if err != nil {
			return emrtypes.BlockPublicAccessConfiguration{}, err
		}
		if out.BlockPublicAccessConfiguration == nil {
			return emrtypes.BlockPublicAccessConfiguration{}, nil
		}
		return *out.BlockPublicAccessConfiguration, nil
	})

	// Athena
	d.AthenaWorkgroups = cache.New("AthenaWorkgroups", func() ([]athenatypes.WorkGroupSummary, error) {
		out, err := c.Athena.ListWorkGroups(ctx, &athena.ListWorkGroupsInput{})
		if err != nil {
			return nil, err
		}
		return out.WorkGroups, nil
	})
	d.AthenaWorkgroupDetails = cache.New("AthenaWorkgroupDetails", func() (map[string]athenatypes.WorkGroup, error) {
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
	d.AthenaDataCatalogs = cache.New("AthenaDataCatalogs", func() ([]athenatypes.DataCatalog, error) {
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
	d.AthenaPreparedStatements = cache.New("AthenaPreparedStatements", func() ([]athenatypes.PreparedStatementSummary, error) {
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
	d.AppSyncAPIs = cache.New("AppSyncAPIs", func() ([]appsynctypes.GraphqlApi, error) {
		out, err := c.AppSync.ListGraphqlApis(ctx, &appsync.ListGraphqlApisInput{})
		if err != nil {
			return nil, err
		}
		return out.GraphqlApis, nil
	})
	d.AppSyncApiCaches = cache.New("AppSyncApiCaches", func() (map[string]*appsynctypes.ApiCache, error) {
		apis, err := d.AppSyncAPIs.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]*appsynctypes.ApiCache)
		for _, api := range apis {
			if api.ApiId == nil || api.Arn == nil {
				continue
			}
			resp, err := c.AppSync.GetApiCache(ctx, &appsync.GetApiCacheInput{ApiId: api.ApiId})
			if err != nil || resp == nil {
				continue
			}
			if resp.ApiCache != nil {
				out[*api.Arn] = resp.ApiCache
			}
		}
		return out, nil
	})
	d.AppSyncTags = cache.New("AppSyncTags", func() (map[string]map[string]string, error) {
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
	d.AppSyncWAFv2WebACLForResource = cache.New("AppSyncWAFv2WebACLForResource", func() (map[string]bool, error) {
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
	d.APIGatewayRestAPIs = cache.New("APIGatewayRestAPIs", func() ([]apigwtypes.RestApi, error) {
		out, err := c.APIGateway.GetRestApis(ctx, &apigateway.GetRestApisInput{})
		if err != nil {
			return nil, err
		}
		return out.Items, nil
	})
	d.APIGatewayStages = cache.New("APIGatewayStages", func() (map[string][]apigwtypes.Stage, error) {
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
	d.APIGatewayTags = cache.New("APIGatewayTags", func() (map[string]map[string]string, error) {
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
	d.APIGatewayStageTags = cache.New("APIGatewayStageTags", func() (map[string]map[string]string, error) {
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
	d.APIGatewayDomainNames = cache.New("APIGatewayDomainNames", func() ([]apigwtypes.DomainName, error) {
		out, err := c.APIGateway.GetDomainNames(ctx, &apigateway.GetDomainNamesInput{})
		if err != nil {
			return nil, err
		}
		return out.Items, nil
	})
	d.APIGatewayStageWAF = cache.New("APIGatewayStageWAF", func() (map[string]bool, error) {
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
	d.APIGatewayV2APIs = cache.New("APIGatewayV2APIs", func() ([]apigwv2types.Api, error) {
		out, err := c.APIGatewayV2.GetApis(ctx, &apigatewayv2.GetApisInput{})
		if err != nil {
			return nil, err
		}
		return out.Items, nil
	})
	d.APIGatewayV2Stages = cache.New("APIGatewayV2Stages", func() (map[string][]apigwv2types.Stage, error) {
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
	d.APIGatewayV2Routes = cache.New("APIGatewayV2Routes", func() (map[string][]apigwv2types.Route, error) {
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
	d.APIGatewayV2Tags = cache.New("APIGatewayV2Tags", func() (map[string]map[string]string, error) {
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
	d.AmplifyApps = cache.New("AmplifyApps", func() ([]amplifytypes.App, error) {
		out, err := c.Amplify.ListApps(ctx, &amplify.ListAppsInput{})
		if err != nil {
			return nil, err
		}
		return out.Apps, nil
	})
	d.AmplifyBranches = cache.New("AmplifyBranches", func() (map[string][]amplifytypes.Branch, error) {
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
	d.AmplifyAppTags = cache.New("AmplifyAppTags", func() (map[string]map[string]string, error) {
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
	d.AmplifyBranchTags = cache.New("AmplifyBranchTags", func() (map[string]map[string]string, error) {
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
	d.AppConfigApplications = cache.New("AppConfigApplications", func() ([]appconfigtypes.Application, error) {
		out, err := c.AppConfig.ListApplications(ctx, &appconfig.ListApplicationsInput{})
		if err != nil {
			return nil, err
		}
		return out.Items, nil
	})
	d.AppConfigEnvironments = cache.New("AppConfigEnvironments", func() (map[string][]appconfigtypes.Environment, error) {
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
	d.AppConfigProfiles = cache.New("AppConfigProfiles", func() (map[string][]appconfigtypes.ConfigurationProfileSummary, error) {
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
	d.AppConfigDeploymentStrategies = cache.New("AppConfigDeploymentStrategies", func() ([]appconfigtypes.DeploymentStrategy, error) {
		out, err := c.AppConfig.ListDeploymentStrategies(ctx, &appconfig.ListDeploymentStrategiesInput{})
		if err != nil {
			return nil, err
		}
		return out.Items, nil
	})
	d.AppConfigExtensionAssociations = cache.New("AppConfigExtensionAssociations", func() ([]appconfigtypes.ExtensionAssociationSummary, error) {
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

	d.AppConfigHostedConfigVersions = cache.New("AppConfigHostedConfigVersions", func() (map[string][]appconfigtypes.HostedConfigurationVersionSummary, error) {
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
	d.AppFlowFlows = cache.New("AppFlowFlows", func() ([]appflowtypes.FlowDefinition, error) {
		out, err := c.AppFlow.ListFlows(ctx, &appflow.ListFlowsInput{})
		if err != nil {
			return nil, err
		}
		return out.Flows, nil
	})
	d.AppFlowFlowDetails = cache.New("AppFlowFlowDetails", func() (map[string]appflow.DescribeFlowOutput, error) {
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
	d.AppFlowTags = cache.New("AppFlowTags", func() (map[string]map[string]string, error) {
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
	d.AppRunnerServices = cache.New("AppRunnerServices", func() ([]apprunnertypes.ServiceSummary, error) {
		out, err := c.AppRunner.ListServices(ctx, &apprunner.ListServicesInput{})
		if err != nil {
			return nil, err
		}
		return out.ServiceSummaryList, nil
	})
	d.AppRunnerVPCConnectors = cache.New("AppRunnerVPCConnectors", func() ([]apprunnertypes.VpcConnector, error) {
		out, err := c.AppRunner.ListVpcConnectors(ctx, &apprunner.ListVpcConnectorsInput{})
		if err != nil {
			return nil, err
		}
		return out.VpcConnectors, nil
	})
	d.AppRunnerServiceDetails = cache.New("AppRunnerServiceDetails", func() (map[string]apprunnertypes.Service, error) {
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
	d.AppRunnerServiceTags = cache.New("AppRunnerServiceTags", func() (map[string]map[string]string, error) {
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
			m := make(map[string]string)
			for _, t := range tags.Tags {
				if t.Key != nil && t.Value != nil {
					m[*t.Key] = *t.Value
				}
			}
			out[*svc.ServiceArn] = m
		}
		return out, nil
	})
	d.AppRunnerVPCConnectorTags = cache.New("AppRunnerVPCConnectorTags", func() (map[string]map[string]string, error) {
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
			m := make(map[string]string)
			for _, t := range tags.Tags {
				if t.Key != nil && t.Value != nil {
					m[*t.Key] = *t.Value
				}
			}
			out[*vc.VpcConnectorArn] = m
		}
		return out, nil
	})

	// AppStream
	d.AppStreamFleets = cache.New("AppStreamFleets", func() ([]appstreamtypes.Fleet, error) {
		out, err := c.AppStream.DescribeFleets(ctx, &appstream.DescribeFleetsInput{})
		if err != nil {
			return nil, err
		}
		return out.Fleets, nil
	})

	// AMP
	d.AMPRuleGroupsNamespaces = cache.New("AMPRuleGroupsNamespaces", func() ([]amptypes.RuleGroupsNamespaceSummary, error) {
		out, err := c.AMP.ListRuleGroupsNamespaces(ctx, &amp.ListRuleGroupsNamespacesInput{})
		if err != nil {
			return nil, err
		}
		return out.RuleGroupsNamespaces, nil
	})

	// AuditManager
	d.AuditManagerAssessments = cache.New("AuditManagerAssessments", func() (map[string]auditmanagertypes.Assessment, error) {
		out := make(map[string]auditmanagertypes.Assessment)
		list, err := c.AuditManager.ListAssessments(ctx, &auditmanager.ListAssessmentsInput{})
		if err != nil {
			return nil, err
		}
		for _, item := range list.AssessmentMetadata {
			if item.Id == nil {
				continue
			}
			assess, err := c.AuditManager.GetAssessment(ctx, &auditmanager.GetAssessmentInput{AssessmentId: item.Id})
			if err != nil || assess.Assessment == nil {
				continue
			}
			out[*item.Id] = *assess.Assessment
		}
		return out, nil
	})

	// CodeGuru Profiler
	d.CodeGuruProfilingGroups = cache.New("CodeGuruProfilingGroups", func() (map[string]codeguruprofilertypes.ProfilingGroupDescription, error) {
		out := make(map[string]codeguruprofilertypes.ProfilingGroupDescription)
		list, err := c.CodeGuruProfiler.ListProfilingGroups(ctx, &codeguruprofiler.ListProfilingGroupsInput{})
		if err != nil {
			return nil, err
		}
		for _, name := range list.ProfilingGroupNames {
			grp, err := c.CodeGuruProfiler.DescribeProfilingGroup(ctx, &codeguruprofiler.DescribeProfilingGroupInput{ProfilingGroupName: &name})
			if err != nil || grp.ProfilingGroup == nil {
				continue
			}
			key := name
			if grp.ProfilingGroup.Name != nil {
				key = *grp.ProfilingGroup.Name
			}
			out[key] = *grp.ProfilingGroup
		}
		return out, nil
	})
	d.CodeGuruProfilerTags = cache.New("CodeGuruProfilerTags", func() (map[string]map[string]string, error) {
		groups, err := d.CodeGuruProfilingGroups.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, g := range groups {
			if g.Arn == nil {
				continue
			}
			tags, err := c.CodeGuruProfiler.ListTagsForResource(ctx, &codeguruprofiler.ListTagsForResourceInput{ResourceArn: g.Arn})
			if err != nil {
				continue
			}
			out[*g.Arn] = tags.Tags
		}
		return out, nil
	})

	// CodeGuru Reviewer
	d.CodeGuruReviewerAssociations = cache.New("CodeGuruReviewerAssociations", func() ([]codegurureviewertypes.RepositoryAssociationSummary, error) {
		out, err := c.CodeGuruReviewer.ListRepositoryAssociations(ctx, &codegurureviewer.ListRepositoryAssociationsInput{})
		if err != nil {
			return nil, err
		}
		return out.RepositoryAssociationSummaries, nil
	})
	d.CodeGuruReviewerTags = cache.New("CodeGuruReviewerTags", func() (map[string]map[string]string, error) {
		assocs, err := d.CodeGuruReviewerAssociations.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, a := range assocs {
			if a.AssociationArn == nil {
				continue
			}
			tags, err := c.CodeGuruReviewer.ListTagsForResource(ctx, &codegurureviewer.ListTagsForResourceInput{ResourceArn: a.AssociationArn})
			if err != nil {
				continue
			}
			out[*a.AssociationArn] = tags.Tags
		}
		return out, nil
	})

	// Connect
	d.ConnectInstances = cache.New("ConnectInstances", func() ([]connecttypes.InstanceSummary, error) {
		out, err := c.Connect.ListInstances(ctx, &connect.ListInstancesInput{})
		if err != nil {
			return nil, err
		}
		return out.InstanceSummaryList, nil
	})
	d.ConnectInstanceContactFlowLogs = cache.New("ConnectInstanceContactFlowLogs", func() (map[string]bool, error) {
		instances, err := d.ConnectInstances.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]bool)
		for _, inst := range instances {
			if inst.Id == nil {
				continue
			}
			attr, err := c.Connect.DescribeInstanceAttribute(ctx, &connect.DescribeInstanceAttributeInput{
				InstanceId:    inst.Id,
				AttributeType: connecttypes.InstanceAttributeTypeContactflowLogs,
			})
			if err != nil || attr.Attribute == nil || attr.Attribute.Value == nil {
				continue
			}
			out[*inst.Id] = strings.EqualFold(*attr.Attribute.Value, "true")
		}
		return out, nil
	})

	// CustomerProfiles
	d.CustomerProfilesDomains = cache.New("CustomerProfilesDomains", func() ([]customerprofilestypes.ListDomainItem, error) {
		out, err := c.CustomerProfiles.ListDomains(ctx, &customerprofiles.ListDomainsInput{})
		if err != nil {
			return nil, err
		}
		return out.Items, nil
	})
	d.CustomerProfilesObjectTypes = cache.New("CustomerProfilesObjectTypes", func() (map[string][]customerprofilestypes.ListProfileObjectTypeItem, error) {
		domains, err := d.CustomerProfilesDomains.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string][]customerprofilestypes.ListProfileObjectTypeItem)
		for _, dom := range domains {
			if dom.DomainName == nil {
				continue
			}
			resp, err := c.CustomerProfiles.ListProfileObjectTypes(ctx, &customerprofiles.ListProfileObjectTypesInput{DomainName: dom.DomainName})
			if err != nil {
				continue
			}
			out[*dom.DomainName] = resp.Items
		}
		return out, nil
	})
	d.CustomerProfilesObjectTypeDetails = cache.New("CustomerProfilesObjectTypeDetails", func() (map[string]customerprofiles.GetProfileObjectTypeOutput, error) {
		objectTypes, err := d.CustomerProfilesObjectTypes.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]customerprofiles.GetProfileObjectTypeOutput)
		for domain, items := range objectTypes {
			for _, item := range items {
				if item.ObjectTypeName == nil {
					continue
				}
				resp, err := c.CustomerProfiles.GetProfileObjectType(ctx, &customerprofiles.GetProfileObjectTypeInput{
					DomainName:     aws.String(domain),
					ObjectTypeName: item.ObjectTypeName,
				})
				if err != nil {
					continue
				}
				key := domain + ":" + *item.ObjectTypeName
				out[key] = *resp
			}
		}
		return out, nil
	})

	// FIS
	d.FISExperimentTemplates = cache.New("FISExperimentTemplates", func() ([]fistypes.ExperimentTemplateSummary, error) {
		out, err := c.FIS.ListExperimentTemplates(ctx, &fis.ListExperimentTemplatesInput{})
		if err != nil {
			return nil, err
		}
		return out.ExperimentTemplates, nil
	})
	d.FISExperimentTemplateDetails = cache.New("FISExperimentTemplateDetails", func() (map[string]fistypes.ExperimentTemplate, error) {
		templates, err := d.FISExperimentTemplates.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]fistypes.ExperimentTemplate)
		for _, t := range templates {
			if t.Id == nil {
				continue
			}
			resp, err := c.FIS.GetExperimentTemplate(ctx, &fis.GetExperimentTemplateInput{Id: t.Id})
			if err != nil || resp.ExperimentTemplate == nil {
				continue
			}
			out[*t.Id] = *resp.ExperimentTemplate
		}
		return out, nil
	})

	// FMS
	d.FMSPolicies = cache.New("FMSPolicies", func() ([]fmstypes.PolicySummary, error) {
		out, err := c.FMS.ListPolicies(ctx, &fms.ListPoliciesInput{})
		if err != nil {
			return nil, err
		}
		return out.PolicyList, nil
	})
	d.FMSPolicyDetails = cache.New("FMSPolicyDetails", func() (map[string]fmstypes.Policy, error) {
		policies, err := d.FMSPolicies.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]fmstypes.Policy)
		for _, p := range policies {
			if p.PolicyId == nil {
				continue
			}
			resp, err := c.FMS.GetPolicy(ctx, &fms.GetPolicyInput{PolicyId: p.PolicyId})
			if err != nil || resp.Policy == nil {
				continue
			}
			out[*p.PolicyId] = *resp.Policy
		}
		return out, nil
	})

	// SecurityHub
	d.SecurityHubEnabled = cache.New("SecurityHubEnabled", func() (bool, error) {
		_, err := c.SecurityHub.DescribeHub(ctx, &securityhub.DescribeHubInput{})
		if err != nil {
			if strings.Contains(err.Error(), "InvalidAccessException") || strings.Contains(err.Error(), "ResourceNotFoundException") {
				return false, nil
			}
			return false, err
		}
		return true, nil
	})

	// SES
	d.SESReceiptRuleSets = cache.New("SESReceiptRuleSets", func() (map[string][]sestypes.ReceiptRule, error) {
		out := make(map[string][]sestypes.ReceiptRule)
		list, err := c.SES.ListReceiptRuleSets(ctx, &ses.ListReceiptRuleSetsInput{})
		if err != nil {
			return nil, err
		}
		for _, set := range list.RuleSets {
			if set.Name == nil {
				continue
			}
			desc, err := c.SES.DescribeReceiptRuleSet(ctx, &ses.DescribeReceiptRuleSetInput{RuleSetName: set.Name})
			if err != nil {
				continue
			}
			out[*set.Name] = desc.Rules
		}
		return out, nil
	})
	d.SESv2ConfigurationSets = cache.New("SESv2ConfigurationSets", func() (map[string]sesv2.GetConfigurationSetOutput, error) {
		out := make(map[string]sesv2.GetConfigurationSetOutput)
		list, err := c.SESv2.ListConfigurationSets(ctx, &sesv2.ListConfigurationSetsInput{})
		if err != nil {
			return nil, err
		}
		for _, name := range list.ConfigurationSets {
			resp, err := c.SESv2.GetConfigurationSet(ctx, &sesv2.GetConfigurationSetInput{ConfigurationSetName: &name})
			if err != nil {
				continue
			}
			out[name] = *resp
		}
		return out, nil
	})

	// Shield
	d.ShieldSubscription = cache.New("ShieldSubscription", func() (*shield.DescribeSubscriptionOutput, error) {
		out, err := c.Shield.DescribeSubscription(ctx, &shield.DescribeSubscriptionInput{})
		if err != nil {
			return nil, err
		}
		return out, nil
	})
	d.ShieldDRTAccess = cache.New("ShieldDRTAccess", func() (*shield.DescribeDRTAccessOutput, error) {
		out, err := c.Shield.DescribeDRTAccess(ctx, &shield.DescribeDRTAccessInput{})
		if err != nil {
			return nil, err
		}
		return out, nil
	})

	// Resource Groups Tagging API
	d.ResourceTagMappings = cache.New("ResourceTagMappings", func() ([]resourcegroupstaggingapitypes.ResourceTagMapping, error) {
		var out []resourcegroupstaggingapitypes.ResourceTagMapping
		p := resourcegroupstaggingapi.NewGetResourcesPaginator(c.ResourceGroupsTagging, &resourcegroupstaggingapi.GetResourcesInput{})
		for p.HasMorePages() {
			page, err := p.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			out = append(out, page.ResourceTagMappingList...)
		}
		return out, nil
	})

	// Account
	d.AccountSecurityContact = cache.New("AccountSecurityContact", func() (*accounttypes.AlternateContact, error) {
		out, err := c.Account.GetAlternateContact(ctx, &account.GetAlternateContactInput{
			AlternateContactType: accounttypes.AlternateContactTypeSecurity,
		})
		if err != nil {
			if strings.Contains(err.Error(), "ResourceNotFoundException") || strings.Contains(err.Error(), "AccessDeniedException") {
				return nil, nil
			}
			return nil, err
		}
		return out.AlternateContact, nil
	})

	// EventBridge
	d.EventBridgeBuses = cache.New("EventBridgeBuses", func() ([]eventbridgetypes.EventBus, error) {
		out, err := c.EventBridge.ListEventBuses(ctx, &eventbridge.ListEventBusesInput{})
		if err != nil {
			return nil, err
		}
		return out.EventBuses, nil
	})
	d.EventBridgeBusPolicies = cache.New("EventBridgeBusPolicies", func() (map[string]string, error) {
		buses, err := d.EventBridgeBuses.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]string)
		for _, b := range buses {
			if b.Name == nil {
				continue
			}
			desc, err := c.EventBridge.DescribeEventBus(ctx, &eventbridge.DescribeEventBusInput{Name: b.Name})
			if err != nil {
				continue
			}
			if desc.Policy != nil {
				out[*b.Name] = *desc.Policy
			}
		}
		return out, nil
	})
	d.EventBridgeEndpoints = cache.New("EventBridgeEndpoints", func() ([]eventbridgetypes.Endpoint, error) {
		out, err := c.EventBridge.ListEndpoints(ctx, &eventbridge.ListEndpointsInput{})
		if err != nil {
			return nil, err
		}
		return out.Endpoints, nil
	})
	d.EventBridgeEndpointDetails = cache.New("EventBridgeEndpointDetails", func() (map[string]eventbridge.DescribeEndpointOutput, error) {
		endpoints, err := d.EventBridgeEndpoints.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]eventbridge.DescribeEndpointOutput)
		for _, e := range endpoints {
			if e.Name == nil {
				continue
			}
			desc, err := c.EventBridge.DescribeEndpoint(ctx, &eventbridge.DescribeEndpointInput{Name: e.Name})
			if err != nil {
				continue
			}
			out[*e.Name] = *desc
		}
		return out, nil
	})

	// Global Accelerator
	d.GlobalAccelerators = cache.New("GlobalAccelerators", func() ([]globalacceleratortypes.Accelerator, error) {
		out, err := c.GlobalAccelerator.ListAccelerators(ctx, &globalaccelerator.ListAcceleratorsInput{})
		if err != nil {
			return nil, err
		}
		return out.Accelerators, nil
	})
	d.GlobalAcceleratorListeners = cache.New("GlobalAcceleratorListeners", func() (map[string][]globalacceleratortypes.Listener, error) {
		accels, err := d.GlobalAccelerators.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string][]globalacceleratortypes.Listener)
		for _, a := range accels {
			if a.AcceleratorArn == nil {
				continue
			}
			resp, err := c.GlobalAccelerator.ListListeners(ctx, &globalaccelerator.ListListenersInput{AcceleratorArn: a.AcceleratorArn})
			if err != nil {
				continue
			}
			out[*a.AcceleratorArn] = resp.Listeners
		}
		return out, nil
	})
	d.GlobalAcceleratorTags = cache.New("GlobalAcceleratorTags", func() (map[string]map[string]string, error) {
		accels, err := d.GlobalAccelerators.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, a := range accels {
			if a.AcceleratorArn == nil {
				continue
			}
			tags, err := c.GlobalAccelerator.ListTagsForResource(ctx, &globalaccelerator.ListTagsForResourceInput{ResourceArn: a.AcceleratorArn})
			if err != nil {
				continue
			}
			m := make(map[string]string)
			for _, t := range tags.Tags {
				if t.Key != nil && t.Value != nil {
					m[*t.Key] = *t.Value
				}
			}
			out[*a.AcceleratorArn] = m
		}
		return out, nil
	})
	d.GlobalAcceleratorListenerTags = cache.New("GlobalAcceleratorListenerTags", func() (map[string]map[string]string, error) {
		listeners, err := d.GlobalAcceleratorListeners.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, ls := range listeners {
			for _, l := range ls {
				if l.ListenerArn == nil {
					continue
				}
				tags, err := c.GlobalAccelerator.ListTagsForResource(ctx, &globalaccelerator.ListTagsForResourceInput{ResourceArn: l.ListenerArn})
				if err != nil {
					continue
				}
				m := make(map[string]string)
				for _, t := range tags.Tags {
					if t.Key != nil && t.Value != nil {
						m[*t.Key] = *t.Value
					}
				}
				out[*l.ListenerArn] = m
			}
		}
		return out, nil
	})

	// IoT Device Defender custom metrics
	d.IoTCustomMetrics = cache.New("IoTCustomMetrics", func() (map[string]iot.DescribeCustomMetricOutput, error) {
		out := make(map[string]iot.DescribeCustomMetricOutput)
		list, err := c.IoT.ListCustomMetrics(ctx, &iot.ListCustomMetricsInput{})
		if err != nil {
			return nil, err
		}
		for _, name := range list.MetricNames {
			desc, err := c.IoT.DescribeCustomMetric(ctx, &iot.DescribeCustomMetricInput{MetricName: &name})
			if err != nil || desc == nil || desc.MetricArn == nil {
				continue
			}
			out[*desc.MetricArn] = *desc
		}
		return out, nil
	})
	d.IoTCustomMetricTags = cache.New("IoTCustomMetricTags", func() (map[string]map[string]string, error) {
		metrics, err := d.IoTCustomMetrics.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for arn := range metrics {
			if arn == "" {
				continue
			}
			tags, err := c.IoT.ListTagsForResource(ctx, &iot.ListTagsForResourceInput{ResourceArn: &arn})
			if err != nil {
				continue
			}
			m := make(map[string]string)
			for _, t := range tags.Tags {
				if t.Key != nil && t.Value != nil {
					m[*t.Key] = *t.Value
				}
			}
			out[arn] = m
		}
		return out, nil
	})

	// IoT Events
	d.IoTEventsAlarmModels = cache.New("IoTEventsAlarmModels", func() ([]ioteventstypes.AlarmModelSummary, error) {
		out, err := c.IoTEvents.ListAlarmModels(ctx, &iotevents.ListAlarmModelsInput{})
		if err != nil {
			return nil, err
		}
		return out.AlarmModelSummaries, nil
	})
	d.IoTEventsDetectorModels = cache.New("IoTEventsDetectorModels", func() ([]ioteventstypes.DetectorModelSummary, error) {
		out, err := c.IoTEvents.ListDetectorModels(ctx, &iotevents.ListDetectorModelsInput{})
		if err != nil {
			return nil, err
		}
		return out.DetectorModelSummaries, nil
	})
	d.IoTEventsInputs = cache.New("IoTEventsInputs", func() ([]ioteventstypes.InputSummary, error) {
		out, err := c.IoTEvents.ListInputs(ctx, &iotevents.ListInputsInput{})
		if err != nil {
			return nil, err
		}
		return out.InputSummaries, nil
	})
	d.IoTEventsTags = cache.New("IoTEventsTags", func() (map[string]map[string]string, error) {
		out := make(map[string]map[string]string)
		convertTags := func(tags []ioteventstypes.Tag) map[string]string {
			m := make(map[string]string)
			for _, t := range tags {
				if t.Key != nil && t.Value != nil {
					m[*t.Key] = *t.Value
				}
			}
			return m
		}
		alarms, _ := d.IoTEventsAlarmModels.Get()
		for _, a := range alarms {
			if a.AlarmModelName == nil {
				continue
			}
			desc, err := c.IoTEvents.DescribeAlarmModel(ctx, &iotevents.DescribeAlarmModelInput{AlarmModelName: a.AlarmModelName})
			if err != nil || desc.AlarmModelArn == nil {
				continue
			}
			tags, err := c.IoTEvents.ListTagsForResource(ctx, &iotevents.ListTagsForResourceInput{ResourceArn: desc.AlarmModelArn})
			if err == nil {
				out[*desc.AlarmModelArn] = convertTags(tags.Tags)
			}
		}
		dets, _ := d.IoTEventsDetectorModels.Get()
		for _, a := range dets {
			if a.DetectorModelName == nil {
				continue
			}
			desc, err := c.IoTEvents.DescribeDetectorModel(ctx, &iotevents.DescribeDetectorModelInput{DetectorModelName: a.DetectorModelName})
			if err != nil || desc.DetectorModel == nil || desc.DetectorModel.DetectorModelConfiguration == nil || desc.DetectorModel.DetectorModelConfiguration.DetectorModelArn == nil {
				continue
			}
			arn := desc.DetectorModel.DetectorModelConfiguration.DetectorModelArn
			tags, err := c.IoTEvents.ListTagsForResource(ctx, &iotevents.ListTagsForResourceInput{ResourceArn: arn})
			if err == nil {
				out[*arn] = convertTags(tags.Tags)
			}
		}
		inputs, _ := d.IoTEventsInputs.Get()
		for _, a := range inputs {
			if a.InputArn == nil {
				continue
			}
			tags, err := c.IoTEvents.ListTagsForResource(ctx, &iotevents.ListTagsForResourceInput{ResourceArn: a.InputArn})
			if err == nil {
				out[*a.InputArn] = convertTags(tags.Tags)
			}
		}
		return out, nil
	})

	// IoT Wireless
	d.IoTWirelessFuotaTasks = cache.New("IoTWirelessFuotaTasks", func() ([]iotwirelesstypes.FuotaTask, error) {
		out, err := c.IoTWireless.ListFuotaTasks(ctx, &iotwireless.ListFuotaTasksInput{})
		if err != nil {
			return nil, err
		}
		return out.FuotaTaskList, nil
	})
	d.IoTWirelessMulticastGroups = cache.New("IoTWirelessMulticastGroups", func() ([]iotwirelesstypes.MulticastGroup, error) {
		out, err := c.IoTWireless.ListMulticastGroups(ctx, &iotwireless.ListMulticastGroupsInput{})
		if err != nil {
			return nil, err
		}
		return out.MulticastGroupList, nil
	})
	d.IoTWirelessServiceProfiles = cache.New("IoTWirelessServiceProfiles", func() ([]iotwirelesstypes.ServiceProfile, error) {
		out, err := c.IoTWireless.ListServiceProfiles(ctx, &iotwireless.ListServiceProfilesInput{})
		if err != nil {
			return nil, err
		}
		return out.ServiceProfileList, nil
	})
	d.IoTWirelessTags = cache.New("IoTWirelessTags", func() (map[string]map[string]string, error) {
		out := make(map[string]map[string]string)
		convertWirelessTags := func(tags []iotwirelesstypes.Tag) map[string]string {
			m := make(map[string]string)
			for _, t := range tags {
				if t.Key != nil && t.Value != nil {
					m[*t.Key] = *t.Value
				}
			}
			return m
		}
		fuota, _ := d.IoTWirelessFuotaTasks.Get()
		for _, f := range fuota {
			if f.Arn == nil {
				continue
			}
			tags, err := c.IoTWireless.ListTagsForResource(ctx, &iotwireless.ListTagsForResourceInput{ResourceArn: f.Arn})
			if err == nil {
				out[*f.Arn] = convertWirelessTags(tags.Tags)
			}
		}
		mg, _ := d.IoTWirelessMulticastGroups.Get()
		for _, g := range mg {
			if g.Arn == nil {
				continue
			}
			tags, err := c.IoTWireless.ListTagsForResource(ctx, &iotwireless.ListTagsForResourceInput{ResourceArn: g.Arn})
			if err == nil {
				out[*g.Arn] = convertWirelessTags(tags.Tags)
			}
		}
		sp, _ := d.IoTWirelessServiceProfiles.Get()
		for _, s := range sp {
			if s.Arn == nil {
				continue
			}
			tags, err := c.IoTWireless.ListTagsForResource(ctx, &iotwireless.ListTagsForResourceInput{ResourceArn: s.Arn})
			if err == nil {
				out[*s.Arn] = convertWirelessTags(tags.Tags)
			}
		}
		return out, nil
	})

	// Macie
	d.MacieSession = cache.New("MacieSession", func() (*macie2.GetMacieSessionOutput, error) {
		out, err := c.Macie2.GetMacieSession(ctx, &macie2.GetMacieSessionInput{})
		if err != nil {
			return nil, err
		}
		return out, nil
	})
	d.MacieAutomatedDiscoveryConfig = cache.New("MacieAutomatedDiscoveryConfig", func() (*macie2.GetAutomatedDiscoveryConfigurationOutput, error) {
		out, err := c.Macie2.GetAutomatedDiscoveryConfiguration(ctx, &macie2.GetAutomatedDiscoveryConfigurationInput{})
		if err != nil {
			return nil, err
		}
		return out, nil
	})

	// RUM
	d.RUMAppMonitors = cache.New("RUMAppMonitors", func() ([]rumtypes.AppMonitorSummary, error) {
		out, err := c.RUM.ListAppMonitors(ctx, &rum.ListAppMonitorsInput{})
		if err != nil {
			return nil, err
		}
		return out.AppMonitorSummaries, nil
	})
	d.RUMAppMonitorTags = cache.New("RUMAppMonitorTags", func() (map[string]map[string]string, error) {
		monitors, err := d.RUMAppMonitors.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, m := range monitors {
			if m.Name == nil {
				continue
			}
			// AppMonitorSummary has no Arn; use Name as key.
			// Tags can be retrieved from GetAppMonitor details via the AppMonitor.Tags field.
			out[*m.Name] = map[string]string{}
		}
		return out, nil
	})
	d.RUMAppMonitorDetails = cache.New("RUMAppMonitorDetails", func() (map[string]rum.GetAppMonitorOutput, error) {
		monitors, err := d.RUMAppMonitors.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]rum.GetAppMonitorOutput)
		for _, m := range monitors {
			if m.Name == nil {
				continue
			}
			resp, err := c.RUM.GetAppMonitor(ctx, &rum.GetAppMonitorInput{Name: m.Name})
			if err != nil {
				continue
			}
			out[*m.Name] = *resp
		}
		return out, nil
	})

	// Service Catalog
	d.ServiceCatalogPortfolios = cache.New("ServiceCatalogPortfolios", func() ([]servicecatalogtypes.PortfolioDetail, error) {
		out, err := c.ServiceCatalog.ListPortfolios(ctx, &servicecatalog.ListPortfoliosInput{})
		if err != nil {
			return nil, err
		}
		return out.PortfolioDetails, nil
	})
	d.ServiceCatalogPortfolioTags = cache.New("ServiceCatalogPortfolioTags", func() (map[string]map[string]string, error) {
		ports, err := d.ServiceCatalogPortfolios.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, p := range ports {
			if p.Id == nil {
				continue
			}
			if p.ARN == nil {
				continue
			}
			desc, err := c.ServiceCatalog.DescribePortfolio(ctx, &servicecatalog.DescribePortfolioInput{Id: p.Id})
			if err != nil {
				continue
			}
			m := make(map[string]string)
			for _, t := range desc.Tags {
				if t.Key != nil && t.Value != nil {
					m[*t.Key] = *t.Value
				}
			}
			out[*p.Id] = m
		}
		return out, nil
	})
	d.ServiceCatalogPortfolioShares = cache.New("ServiceCatalogPortfolioShares", func() (map[string][]string, error) {
		ports, err := d.ServiceCatalogPortfolios.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string][]string)
		for _, p := range ports {
			if p.Id == nil {
				continue
			}
			share, err := c.ServiceCatalog.ListPortfolioAccess(ctx, &servicecatalog.ListPortfolioAccessInput{PortfolioId: p.Id})
			if err != nil {
				continue
			}
			out[*p.Id] = share.AccountIds
		}
		return out, nil
	})

	// MQ
	d.MQBrokerEngineVersions = cache.New("MQBrokerEngineVersions", func() (map[mqtypes.EngineType]map[string]bool, error) {
		out := make(map[mqtypes.EngineType]map[string]bool)
		for _, et := range []mqtypes.EngineType{mqtypes.EngineTypeActivemq, mqtypes.EngineTypeRabbitmq} {
			etStr := string(et)
			resp, err := c.MQ.DescribeBrokerEngineTypes(ctx, &mq.DescribeBrokerEngineTypesInput{EngineType: &etStr})
			if err != nil {
				continue
			}
			m := make(map[string]bool)
			for _, t := range resp.BrokerEngineTypes {
				for _, v := range t.EngineVersions {
					if v.Name != nil {
						m[*v.Name] = true
					}
				}
			}
			out[et] = m
		}
		return out, nil
	})

	// CloudTrail Event Data Stores
	d.CloudTrailEventDataStores = cache.New("CloudTrailEventDataStores", func() ([]cloudtrailtypes.EventDataStore, error) {
		out, err := c.CloudTrail.ListEventDataStores(ctx, &cloudtrail.ListEventDataStoresInput{})
		if err != nil {
			return nil, err
		}
		return out.EventDataStores, nil
	})

	// AppIntegrations
	d.AppIntegrationsEventIntegrations = cache.New("AppIntegrationsEventIntegrations", func() ([]appintegrationstypes.EventIntegration, error) {
		out, err := c.AppIntegrations.ListEventIntegrations(ctx, &appintegrations.ListEventIntegrationsInput{})
		if err != nil {
			return nil, err
		}
		return out.EventIntegrations, nil
	})
	d.AppIntegrationsTags = cache.New("AppIntegrationsTags", func() (map[string]map[string]string, error) {
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
	d.AppMeshMeshes = cache.New("AppMeshMeshes", func() ([]appmeshtypes.MeshRef, error) {
		out, err := c.AppMesh.ListMeshes(ctx, &appmesh.ListMeshesInput{})
		if err != nil {
			return nil, err
		}
		return out.Meshes, nil
	})
	d.AppMeshMeshDetails = cache.New("AppMeshMeshDetails", func() (map[string]appmeshtypes.MeshData, error) {
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
	d.AppMeshVirtualNodes = cache.New("AppMeshVirtualNodes", func() (map[string][]appmeshtypes.VirtualNodeRef, error) {
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
	d.AppMeshVirtualNodeDetails = cache.New("AppMeshVirtualNodeDetails", func() (map[string]appmeshtypes.VirtualNodeData, error) {
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
	d.AppMeshVirtualRouters = cache.New("AppMeshVirtualRouters", func() (map[string][]appmeshtypes.VirtualRouterRef, error) {
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
	d.AppMeshVirtualServices = cache.New("AppMeshVirtualServices", func() (map[string][]appmeshtypes.VirtualServiceRef, error) {
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
	d.AppMeshVirtualGateways = cache.New("AppMeshVirtualGateways", func() (map[string][]appmeshtypes.VirtualGatewayRef, error) {
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
	d.AppMeshVirtualGatewayDetails = cache.New("AppMeshVirtualGatewayDetails", func() (map[string]appmeshtypes.VirtualGatewayData, error) {
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
	d.AppMeshRoutes = cache.New("AppMeshRoutes", func() (map[string][]appmeshtypes.RouteRef, error) {
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
	d.AppMeshGatewayRoutes = cache.New("AppMeshGatewayRoutes", func() (map[string][]appmeshtypes.GatewayRouteRef, error) {
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
	d.AppMeshTags = cache.New("AppMeshTags", func() (map[string]map[string]string, error) {
		meshes, err := d.AppMeshMeshes.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		collectMeshTags := func(arn *string) {
			if arn == nil {
				return
			}
			tags, err := c.AppMesh.ListTagsForResource(ctx, &appmesh.ListTagsForResourceInput{ResourceArn: arn})
			if err != nil {
				return
			}
			m := make(map[string]string)
			for _, t := range tags.Tags {
				if t.Key != nil && t.Value != nil {
					m[*t.Key] = *t.Value
				}
			}
			out[*arn] = m
		}
		for _, m := range meshes {
			collectMeshTags(m.Arn)
		}
		vns, _ := d.AppMeshVirtualNodes.Get()
		for _, items := range vns {
			for _, vn := range items {
				collectMeshTags(vn.Arn)
			}
		}
		vrs, _ := d.AppMeshVirtualRouters.Get()
		for _, items := range vrs {
			for _, vr := range items {
				collectMeshTags(vr.Arn)
			}
		}
		vss, _ := d.AppMeshVirtualServices.Get()
		for _, items := range vss {
			for _, vs := range items {
				collectMeshTags(vs.Arn)
			}
		}
		vgs, _ := d.AppMeshVirtualGateways.Get()
		for _, items := range vgs {
			for _, vg := range items {
				collectMeshTags(vg.Arn)
			}
		}
		routes, _ := d.AppMeshRoutes.Get()
		for _, items := range routes {
			for _, r := range items {
				collectMeshTags(r.Arn)
			}
		}
		gwRoutes, _ := d.AppMeshGatewayRoutes.Get()
		for _, items := range gwRoutes {
			for _, r := range items {
				collectMeshTags(r.Arn)
			}
		}
		return out, nil
	})

	// AutoScaling
	d.AutoScalingGroups = cache.New("AutoScalingGroups", func() ([]autoscalingtypes.AutoScalingGroup, error) {
		out, err := c.AutoScaling.DescribeAutoScalingGroups(ctx, &autoscaling.DescribeAutoScalingGroupsInput{})
		if err != nil {
			return nil, err
		}
		return out.AutoScalingGroups, nil
	})
	d.AutoScalingLaunchConfigs = cache.New("AutoScalingLaunchConfigs", func() ([]autoscalingtypes.LaunchConfiguration, error) {
		out, err := c.AutoScaling.DescribeLaunchConfigurations(ctx, &autoscaling.DescribeLaunchConfigurationsInput{})
		if err != nil {
			return nil, err
		}
		return out.LaunchConfigurations, nil
	})

	// Kinesis
	d.KinesisStreams = cache.New("KinesisStreams", func() ([]string, error) {
		out, err := c.Kinesis.ListStreams(ctx, &kinesis.ListStreamsInput{})
		if err != nil {
			return nil, err
		}
		return out.StreamNames, nil
	})
	d.KinesisStreamDetails = cache.New("KinesisStreamDetails", func() (map[string]kinesis.DescribeStreamOutput, error) {
		streams, err := d.KinesisStreams.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]kinesis.DescribeStreamOutput)
		for _, name := range streams {
			desc, err := c.Kinesis.DescribeStream(ctx, &kinesis.DescribeStreamInput{StreamName: &name})
			if err != nil {
				continue
			}
			out[name] = *desc
		}
		return out, nil
	})

	// Firehose
	d.FirehoseDeliveryStreams = cache.New("FirehoseDeliveryStreams", func() ([]string, error) {
		out, err := c.Firehose.ListDeliveryStreams(ctx, &firehose.ListDeliveryStreamsInput{})
		if err != nil {
			return nil, err
		}
		return out.DeliveryStreamNames, nil
	})
	d.FirehoseDeliveryDetails = cache.New("FirehoseDeliveryDetails", func() (map[string]firehosetypes.DeliveryStreamDescription, error) {
		streams, err := d.FirehoseDeliveryStreams.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]firehosetypes.DeliveryStreamDescription)
		for _, name := range streams {
			desc, err := c.Firehose.DescribeDeliveryStream(ctx, &firehose.DescribeDeliveryStreamInput{DeliveryStreamName: &name})
			if err != nil || desc.DeliveryStreamDescription == nil {
				continue
			}
			out[name] = *desc.DeliveryStreamDescription
		}
		return out, nil
	})

	// Kinesis Video
	d.KinesisVideoStreams = cache.New("KinesisVideoStreams", func() ([]kinesisvideotypes.StreamInfo, error) {
		out, err := c.KinesisVideo.ListStreams(ctx, &kinesisvideo.ListStreamsInput{})
		if err != nil {
			return nil, err
		}
		return out.StreamInfoList, nil
	})

	// MSK
	d.MSKClusters = cache.New("MSKClusters", func() ([]kafkatypes.Cluster, error) {
		out, err := c.Kafka.ListClustersV2(ctx, &kafka.ListClustersV2Input{})
		if err != nil {
			return nil, err
		}
		return out.ClusterInfoList, nil
	})
	d.MSKClusterTags = cache.New("MSKClusterTags", func() (map[string]map[string]string, error) {
		clusters, err := d.MSKClusters.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, cinfo := range clusters {
			if cinfo.ClusterArn == nil {
				continue
			}
			resp, err := c.Kafka.ListTagsForResource(ctx, &kafka.ListTagsForResourceInput{ResourceArn: cinfo.ClusterArn})
			if err != nil {
				continue
			}
			out[*cinfo.ClusterArn] = resp.Tags
		}
		return out, nil
	})

	// MSK Connect
	d.MSKConnectors = cache.New("MSKConnectors", func() ([]kafkaconnecttypes.ConnectorSummary, error) {
		out, err := c.KafkaConnect.ListConnectors(ctx, &kafkaconnect.ListConnectorsInput{})
		if err != nil {
			return nil, err
		}
		return out.Connectors, nil
	})
	d.MSKConnectorDetails = cache.New("MSKConnectorDetails", func() (map[string]kafkaconnect.DescribeConnectorOutput, error) {
		connectors, err := d.MSKConnectors.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]kafkaconnect.DescribeConnectorOutput)
		for _, csum := range connectors {
			if csum.ConnectorArn == nil {
				continue
			}
			desc, err := c.KafkaConnect.DescribeConnector(ctx, &kafkaconnect.DescribeConnectorInput{ConnectorArn: csum.ConnectorArn})
			if err != nil || desc == nil {
				continue
			}
			out[*csum.ConnectorArn] = *desc
		}
		return out, nil
	})

	// Lightsail
	d.LightsailBuckets = cache.New("LightsailBuckets", func() ([]lightsailtypes.Bucket, error) {
		out, err := c.Lightsail.GetBuckets(ctx, &lightsail.GetBucketsInput{})
		if err != nil {
			return nil, err
		}
		return out.Buckets, nil
	})
	d.LightsailCertificates = cache.New("LightsailCertificates", func() ([]lightsailtypes.CertificateSummary, error) {
		out, err := c.Lightsail.GetCertificates(ctx, &lightsail.GetCertificatesInput{})
		if err != nil {
			return nil, err
		}
		return out.Certificates, nil
	})
	d.LightsailDisks = cache.New("LightsailDisks", func() ([]lightsailtypes.Disk, error) {
		out, err := c.Lightsail.GetDisks(ctx, &lightsail.GetDisksInput{})
		if err != nil {
			return nil, err
		}
		return out.Disks, nil
	})

	// Route53
	d.Route53HostedZones = cache.New("Route53HostedZones", func() ([]route53types.HostedZone, error) {
		out, err := c.Route53.ListHostedZones(ctx, &route53.ListHostedZonesInput{})
		if err != nil {
			return nil, err
		}
		return out.HostedZones, nil
	})
	d.Route53HealthChecks = cache.New("Route53HealthChecks", func() ([]route53types.HealthCheck, error) {
		out, err := c.Route53.ListHealthChecks(ctx, &route53.ListHealthChecksInput{})
		if err != nil {
			return nil, err
		}
		return out.HealthChecks, nil
	})
	d.Route53HostedZoneTags = cache.New("Route53HostedZoneTags", func() (map[string]map[string]string, error) {
		zones, err := d.Route53HostedZones.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, z := range zones {
			if z.Id == nil {
				continue
			}
			resp, err := c.Route53.ListTagsForResource(ctx, &route53.ListTagsForResourceInput{ResourceType: route53types.TagResourceTypeHostedzone, ResourceId: z.Id})
			if err != nil {
				continue
			}
			m := make(map[string]string)
			for _, t := range resp.ResourceTagSet.Tags {
				if t.Key != nil && t.Value != nil {
					m[*t.Key] = *t.Value
				}
			}
			out[*z.Id] = m
		}
		return out, nil
	})
	d.Route53HealthCheckTags = cache.New("Route53HealthCheckTags", func() (map[string]map[string]string, error) {
		hcs, err := d.Route53HealthChecks.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, hc := range hcs {
			if hc.Id == nil {
				continue
			}
			resp, err := c.Route53.ListTagsForResource(ctx, &route53.ListTagsForResourceInput{ResourceType: route53types.TagResourceTypeHealthcheck, ResourceId: hc.Id})
			if err != nil {
				continue
			}
			m := make(map[string]string)
			for _, t := range resp.ResourceTagSet.Tags {
				if t.Key != nil && t.Value != nil {
					m[*t.Key] = *t.Value
				}
			}
			out[*hc.Id] = m
		}
		return out, nil
	})
	d.Route53QueryLoggingConfigs = cache.New("Route53QueryLoggingConfigs", func() (map[string][]route53types.QueryLoggingConfig, error) {
		zones, err := d.Route53HostedZones.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string][]route53types.QueryLoggingConfig)
		for _, z := range zones {
			if z.Id == nil {
				continue
			}
			resp, err := c.Route53.ListQueryLoggingConfigs(ctx, &route53.ListQueryLoggingConfigsInput{HostedZoneId: z.Id})
			if err != nil {
				continue
			}
			out[*z.Id] = resp.QueryLoggingConfigs
		}
		return out, nil
	})

	// Route53 Resolver
	d.Route53ResolverFirewallDomainLists = cache.New("Route53ResolverFirewallDomainLists", func() ([]resolvertype.FirewallDomainListMetadata, error) {
		out, err := c.Route53Resolver.ListFirewallDomainLists(ctx, &route53resolver.ListFirewallDomainListsInput{})
		if err != nil {
			return nil, err
		}
		return out.FirewallDomainLists, nil
	})
	d.Route53ResolverFirewallRuleGroups = cache.New("Route53ResolverFirewallRuleGroups", func() ([]resolvertype.FirewallRuleGroupMetadata, error) {
		out, err := c.Route53Resolver.ListFirewallRuleGroups(ctx, &route53resolver.ListFirewallRuleGroupsInput{})
		if err != nil {
			return nil, err
		}
		return out.FirewallRuleGroups, nil
	})
	d.Route53ResolverFirewallRuleGroupAssociations = cache.New("Route53ResolverFirewallRuleGroupAssociations", func() ([]resolvertype.FirewallRuleGroupAssociation, error) {
		out, err := c.Route53Resolver.ListFirewallRuleGroupAssociations(ctx, &route53resolver.ListFirewallRuleGroupAssociationsInput{})
		if err != nil {
			return nil, err
		}
		return out.FirewallRuleGroupAssociations, nil
	})
	d.Route53ResolverRules = cache.New("Route53ResolverRules", func() ([]resolvertype.ResolverRule, error) {
		out, err := c.Route53Resolver.ListResolverRules(ctx, &route53resolver.ListResolverRulesInput{})
		if err != nil {
			return nil, err
		}
		return out.ResolverRules, nil
	})
	d.Route53ResolverTags = cache.New("Route53ResolverTags", func() (map[string]map[string]string, error) {
		out := make(map[string]map[string]string)
		collect := func(arn *string) {
			if arn == nil {
				return
			}
			resp, err := c.Route53Resolver.ListTagsForResource(ctx, &route53resolver.ListTagsForResourceInput{ResourceArn: arn})
			if err != nil {
				return
			}
			m := make(map[string]string)
			for _, t := range resp.Tags {
				if t.Key != nil && t.Value != nil {
					m[*t.Key] = *t.Value
				}
			}
			out[*arn] = m
		}
		dls, _ := d.Route53ResolverFirewallDomainLists.Get()
		for _, d := range dls {
			collect(d.Arn)
		}
		rgs, _ := d.Route53ResolverFirewallRuleGroups.Get()
		for _, r := range rgs {
			collect(r.Arn)
		}
		assocs, _ := d.Route53ResolverFirewallRuleGroupAssociations.Get()
		for _, a := range assocs {
			collect(a.Arn)
		}
		rules, _ := d.Route53ResolverRules.Get()
		for _, r := range rules {
			collect(r.Arn)
		}
		return out, nil
	})

	// SageMaker
	d.SageMakerNotebooks = cache.New("SageMakerNotebooks", func() ([]sagemakertypes.NotebookInstanceSummary, error) {
		out, err := c.SageMaker.ListNotebookInstances(ctx, &sagemaker.ListNotebookInstancesInput{})
		if err != nil {
			return nil, err
		}
		return out.NotebookInstances, nil
	})
	d.SageMakerEndpointConfigs = cache.New("SageMakerEndpointConfigs", func() ([]sagemakertypes.EndpointConfigSummary, error) {
		out, err := c.SageMaker.ListEndpointConfigs(ctx, &sagemaker.ListEndpointConfigsInput{})
		if err != nil {
			return nil, err
		}
		return out.EndpointConfigs, nil
	})
	d.SageMakerDomains = cache.New("SageMakerDomains", func() ([]sagemakertypes.DomainDetails, error) {
		out, err := c.SageMaker.ListDomains(ctx, &sagemaker.ListDomainsInput{})
		if err != nil {
			return nil, err
		}
		return out.Domains, nil
	})
	d.SageMakerModels = cache.New("SageMakerModels", func() ([]sagemakertypes.ModelSummary, error) {
		out, err := c.SageMaker.ListModels(ctx, &sagemaker.ListModelsInput{})
		if err != nil {
			return nil, err
		}
		return out.Models, nil
	})
	d.SageMakerNotebookDetails = cache.New("SageMakerNotebookDetails", func() (map[string]sagemaker.DescribeNotebookInstanceOutput, error) {
		summaries, err := d.SageMakerNotebooks.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]sagemaker.DescribeNotebookInstanceOutput)
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
	d.SageMakerEndpointConfigDetails = cache.New("SageMakerEndpointConfigDetails", func() (map[string]sagemaker.DescribeEndpointConfigOutput, error) {
		summaries, err := d.SageMakerEndpointConfigs.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]sagemaker.DescribeEndpointConfigOutput)
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
	d.SageMakerDomainTags = cache.New("SageMakerDomainTags", func() (map[string]map[string]string, error) {
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
	d.SageMakerModelDetails = cache.New("SageMakerModelDetails", func() (map[string]sagemaker.DescribeModelOutput, error) {
		models, err := d.SageMakerModels.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]sagemaker.DescribeModelOutput)
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
	d.SageMakerFeatureGroups = cache.New("SageMakerFeatureGroups", func() ([]sagemakertypes.FeatureGroupSummary, error) {
		out, err := c.SageMaker.ListFeatureGroups(ctx, &sagemaker.ListFeatureGroupsInput{})
		if err != nil {
			return nil, err
		}
		return out.FeatureGroupSummaries, nil
	})
	d.SageMakerFeatureGroupTags = cache.New("SageMakerFeatureGroupTags", func() (map[string]map[string]string, error) {
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
	d.SageMakerImages = cache.New("SageMakerImages", func() ([]sagemakertypes.Image, error) {
		out, err := c.SageMaker.ListImages(ctx, &sagemaker.ListImagesInput{})
		if err != nil {
			return nil, err
		}
		return out.Images, nil
	})
	d.SageMakerImageDetails = cache.New("SageMakerImageDetails", func() (map[string]sagemaker.DescribeImageOutput, error) {
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
	d.SageMakerImageTags = cache.New("SageMakerImageTags", func() (map[string]map[string]string, error) {
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
	d.SageMakerAppImageConfigs = cache.New("SageMakerAppImageConfigs", func() ([]sagemakertypes.AppImageConfigDetails, error) {
		out, err := c.SageMaker.ListAppImageConfigs(ctx, &sagemaker.ListAppImageConfigsInput{})
		if err != nil {
			return nil, err
		}
		return out.AppImageConfigs, nil
	})
	d.SageMakerAppImageConfigTags = cache.New("SageMakerAppImageConfigTags", func() (map[string]map[string]string, error) {
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
	d.TransferServers = cache.New("TransferServers", func() ([]transfertypes.ListedServer, error) {
		out, err := c.Transfer.ListServers(ctx, &transfer.ListServersInput{})
		if err != nil {
			return nil, err
		}
		return out.Servers, nil
	})
	d.TransferServerDetails = cache.New("TransferServerDetails", func() (map[string]transfertypes.DescribedServer, error) {
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
	d.TransferAgreements = cache.New("TransferAgreements", func() ([]transfertypes.ListedAgreement, error) {
		out, err := c.Transfer.ListAgreements(ctx, &transfer.ListAgreementsInput{})
		if err != nil {
			return nil, err
		}
		return out.Agreements, nil
	})
	d.TransferAgreementDetails = cache.New("TransferAgreementDetails", func() (map[string]transfertypes.DescribedAgreement, error) {
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
	d.TransferCertificates = cache.New("TransferCertificates", func() ([]transfertypes.ListedCertificate, error) {
		out, err := c.Transfer.ListCertificates(ctx, &transfer.ListCertificatesInput{})
		if err != nil {
			return nil, err
		}
		return out.Certificates, nil
	})
	d.TransferCertificateDetails = cache.New("TransferCertificateDetails", func() (map[string]transfertypes.DescribedCertificate, error) {
		certs, err := d.TransferCertificates.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]transfertypes.DescribedCertificate)
		for _, cert := range certs {
			if cert.CertificateId == nil {
				continue
			}
			desc, err := c.Transfer.DescribeCertificate(ctx, &transfer.DescribeCertificateInput{CertificateId: cert.CertificateId})
			if err != nil || desc.Certificate == nil {
				continue
			}
			out[*cert.CertificateId] = *desc.Certificate
		}
		return out, nil
	})
	d.TransferConnectors = cache.New("TransferConnectors", func() ([]transfertypes.ListedConnector, error) {
		out, err := c.Transfer.ListConnectors(ctx, &transfer.ListConnectorsInput{})
		if err != nil {
			return nil, err
		}
		return out.Connectors, nil
	})
	d.TransferConnectorDetails = cache.New("TransferConnectorDetails", func() (map[string]transfertypes.DescribedConnector, error) {
		connectors, err := d.TransferConnectors.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]transfertypes.DescribedConnector)
		for _, conn := range connectors {
			if conn.ConnectorId == nil {
				continue
			}
			desc, err := c.Transfer.DescribeConnector(ctx, &transfer.DescribeConnectorInput{ConnectorId: conn.ConnectorId})
			if err != nil || desc.Connector == nil {
				continue
			}
			out[*conn.ConnectorId] = *desc.Connector
		}
		return out, nil
	})
	d.TransferProfiles = cache.New("TransferProfiles", func() ([]transfertypes.ListedProfile, error) {
		out, err := c.Transfer.ListProfiles(ctx, &transfer.ListProfilesInput{})
		if err != nil {
			return nil, err
		}
		return out.Profiles, nil
	})
	d.TransferProfileDetails = cache.New("TransferProfileDetails", func() (map[string]transfertypes.DescribedProfile, error) {
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
	d.TransferWorkflows = cache.New("TransferWorkflows", func() ([]transfertypes.ListedWorkflow, error) {
		out, err := c.Transfer.ListWorkflows(ctx, &transfer.ListWorkflowsInput{})
		if err != nil {
			return nil, err
		}
		return out.Workflows, nil
	})
	d.TransferWorkflowDetails = cache.New("TransferWorkflowDetails", func() (map[string]transfertypes.DescribedWorkflow, error) {
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
	d.TransferTags = cache.New("TransferTags", func() (map[string]map[string]string, error) {
		out := make(map[string]map[string]string)
		collect := func(arn *string) {
			if arn == nil {
				return
			}
			tags, err := c.Transfer.ListTagsForResource(ctx, &transfer.ListTagsForResourceInput{Arn: arn})
			if err != nil {
				return
			}
			m := make(map[string]string)
			for _, t := range tags.Tags {
				if t.Key != nil && t.Value != nil {
					m[*t.Key] = *t.Value
				}
			}
			out[*arn] = m
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
		for _, cert := range certs {
			collect(cert.Arn)
		}
		connectors, _ := d.TransferConnectors.Get()
		for _, conn := range connectors {
			collect(conn.Arn)
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
	d.MQBrokers = cache.New("MQBrokers", func() ([]mqtypes.BrokerSummary, error) {
		out, err := c.MQ.ListBrokers(ctx, &mq.ListBrokersInput{})
		if err != nil {
			return nil, err
		}
		return out.BrokerSummaries, nil
	})
	d.MQBrokerDetails = cache.New("MQBrokerDetails", func() (map[string]mq.DescribeBrokerOutput, error) {
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
	d.NetworkFirewalls = cache.New("NetworkFirewalls", func() ([]networkfirewall.ListFirewallsOutput, error) {
		out, err := c.NetworkFirewall.ListFirewalls(ctx, &networkfirewall.ListFirewallsInput{})
		if err != nil {
			return nil, err
		}
		return []networkfirewall.ListFirewallsOutput{*out}, nil
	})
	d.NetworkFirewallDetails = cache.New("NetworkFirewallDetails", func() (map[string]networkfirewall.DescribeFirewallOutput, error) {
		lists, err := d.NetworkFirewalls.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]networkfirewall.DescribeFirewallOutput)
		for _, list := range lists {
			for _, fw := range list.Firewalls {
				if fw.FirewallArn == nil {
					continue
				}
				desc, err := c.NetworkFirewall.DescribeFirewall(ctx, &networkfirewall.DescribeFirewallInput{FirewallArn: fw.FirewallArn})
				if err != nil || desc == nil {
					continue
				}
				out[*fw.FirewallArn] = *desc
			}
		}
		return out, nil
	})
	d.NetworkFirewallPolicies = cache.New("NetworkFirewallPolicies", func() (map[string]networkfirewall.DescribeFirewallPolicyOutput, error) {
		details, err := d.NetworkFirewallDetails.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]networkfirewall.DescribeFirewallPolicyOutput)
		for _, dsc := range details {
			if dsc.Firewall == nil || dsc.Firewall.FirewallPolicyArn == nil {
				continue
			}
			resp, err := c.NetworkFirewall.DescribeFirewallPolicy(ctx, &networkfirewall.DescribeFirewallPolicyInput{FirewallPolicyArn: dsc.Firewall.FirewallPolicyArn})
			if err != nil || resp == nil {
				continue
			}
			out[*dsc.Firewall.FirewallPolicyArn] = *resp
		}
		return out, nil
	})
	d.NetworkFirewallLogging = cache.New("NetworkFirewallLogging", func() (map[string]networkfirewall.DescribeLoggingConfigurationOutput, error) {
		lists, err := d.NetworkFirewalls.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]networkfirewall.DescribeLoggingConfigurationOutput)
		for _, list := range lists {
			for _, fw := range list.Firewalls {
				if fw.FirewallArn == nil {
					continue
				}
				resp, err := c.NetworkFirewall.DescribeLoggingConfiguration(ctx, &networkfirewall.DescribeLoggingConfigurationInput{FirewallArn: fw.FirewallArn})
				if err != nil || resp == nil {
					continue
				}
				out[*fw.FirewallArn] = *resp
			}
		}
		return out, nil
	})
	d.NetworkFirewallRuleGroups = cache.New("NetworkFirewallRuleGroups", func() (map[string]networkfirewall.DescribeRuleGroupOutput, error) {
		policies, err := d.NetworkFirewallPolicies.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]networkfirewall.DescribeRuleGroupOutput)
		for _, pol := range policies {
			if pol.FirewallPolicy == nil {
				continue
			}
			for _, ref := range pol.FirewallPolicy.StatelessRuleGroupReferences {
				if ref.ResourceArn == nil {
					continue
				}
				if _, ok := out[*ref.ResourceArn]; ok {
					continue
				}
				resp, err := c.NetworkFirewall.DescribeRuleGroup(ctx, &networkfirewall.DescribeRuleGroupInput{RuleGroupArn: ref.ResourceArn})
				if err != nil || resp == nil {
					continue
				}
				out[*ref.ResourceArn] = *resp
			}
			for _, ref := range pol.FirewallPolicy.StatefulRuleGroupReferences {
				if ref.ResourceArn == nil {
					continue
				}
				if _, ok := out[*ref.ResourceArn]; ok {
					continue
				}
				resp, err := c.NetworkFirewall.DescribeRuleGroup(ctx, &networkfirewall.DescribeRuleGroupInput{RuleGroupArn: ref.ResourceArn})
				if err != nil || resp == nil {
					continue
				}
				out[*ref.ResourceArn] = *resp
			}
		}
		return out, nil
	})

	// WAF
	d.WAFWebACLs = cache.New("WAFWebACLs", func() ([]waftypes.WebACLSummary, error) {
		out, err := c.WAF.ListWebACLs(ctx, &waf.ListWebACLsInput{Limit: 100})
		if err != nil {
			return nil, err
		}
		return out.WebACLs, nil
	})
	d.WAFRules = cache.New("WAFRules", func() ([]waftypes.RuleSummary, error) {
		out, err := c.WAF.ListRules(ctx, &waf.ListRulesInput{Limit: 100})
		if err != nil {
			return nil, err
		}
		return out.Rules, nil
	})
	d.WAFRuleGroups = cache.New("WAFRuleGroups", func() ([]waftypes.RuleGroupSummary, error) {
		out, err := c.WAF.ListRuleGroups(ctx, &waf.ListRuleGroupsInput{Limit: 100})
		if err != nil {
			return nil, err
		}
		return out.RuleGroups, nil
	})
	d.WAFWebACLDetails = cache.New("WAFWebACLDetails", func() (map[string]waftypes.WebACL, error) {
		acls, err := d.WAFWebACLs.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]waftypes.WebACL)
		for _, a := range acls {
			if a.WebACLId == nil {
				continue
			}
			resp, err := c.WAF.GetWebACL(ctx, &waf.GetWebACLInput{WebACLId: a.WebACLId})
			if err != nil || resp.WebACL == nil {
				continue
			}
			out[*a.WebACLId] = *resp.WebACL
		}
		return out, nil
	})
	d.WAFRuleDetails = cache.New("WAFRuleDetails", func() (map[string]waftypes.Rule, error) {
		rules, err := d.WAFRules.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]waftypes.Rule)
		for _, r := range rules {
			if r.RuleId == nil {
				continue
			}
			resp, err := c.WAF.GetRule(ctx, &waf.GetRuleInput{RuleId: r.RuleId})
			if err != nil || resp.Rule == nil {
				continue
			}
			out[*r.RuleId] = *resp.Rule
		}
		return out, nil
	})
	d.WAFRuleGroupDetails = cache.New("WAFRuleGroupDetails", func() (map[string]waftypes.RuleGroup, error) {
		rgs, err := d.WAFRuleGroups.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]waftypes.RuleGroup)
		for _, rg := range rgs {
			if rg.RuleGroupId == nil {
				continue
			}
			resp, err := c.WAF.GetRuleGroup(ctx, &waf.GetRuleGroupInput{RuleGroupId: rg.RuleGroupId})
			if err != nil || resp.RuleGroup == nil {
				continue
			}
			out[*rg.RuleGroupId] = *resp.RuleGroup
		}
		return out, nil
	})
	d.WAFLoggingConfigurations = cache.New("WAFLoggingConfigurations", func() (map[string]waf.GetLoggingConfigurationOutput, error) {
		acls, err := d.WAFWebACLs.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]waf.GetLoggingConfigurationOutput)
		for _, a := range acls {
			if a.WebACLId == nil {
				continue
			}
			resp, err := c.WAF.GetLoggingConfiguration(ctx, &waf.GetLoggingConfigurationInput{ResourceArn: a.WebACLId})
			if err != nil {
				continue
			}
			out[*a.WebACLId] = *resp
		}
		return out, nil
	})

	// WAF Regional
	d.WAFRegionalWebACLs = cache.New("WAFRegionalWebACLs", func() ([]wafregionaltypes.WebACLSummary, error) {
		out, err := c.WAFRegional.ListWebACLs(ctx, &wafregional.ListWebACLsInput{Limit: 100})
		if err != nil {
			return nil, err
		}
		return out.WebACLs, nil
	})
	d.WAFRegionalRules = cache.New("WAFRegionalRules", func() ([]wafregionaltypes.RuleSummary, error) {
		out, err := c.WAFRegional.ListRules(ctx, &wafregional.ListRulesInput{Limit: 100})
		if err != nil {
			return nil, err
		}
		return out.Rules, nil
	})
	d.WAFRegionalRuleGroups = cache.New("WAFRegionalRuleGroups", func() ([]wafregionaltypes.RuleGroupSummary, error) {
		out, err := c.WAFRegional.ListRuleGroups(ctx, &wafregional.ListRuleGroupsInput{Limit: 100})
		if err != nil {
			return nil, err
		}
		return out.RuleGroups, nil
	})
	d.WAFRegionalWebACLDetails = cache.New("WAFRegionalWebACLDetails", func() (map[string]wafregionaltypes.WebACL, error) {
		acls, err := d.WAFRegionalWebACLs.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]wafregionaltypes.WebACL)
		for _, a := range acls {
			if a.WebACLId == nil {
				continue
			}
			resp, err := c.WAFRegional.GetWebACL(ctx, &wafregional.GetWebACLInput{WebACLId: a.WebACLId})
			if err != nil || resp.WebACL == nil {
				continue
			}
			out[*a.WebACLId] = *resp.WebACL
		}
		return out, nil
	})
	d.WAFRegionalRuleDetails = cache.New("WAFRegionalRuleDetails", func() (map[string]wafregionaltypes.Rule, error) {
		rules, err := d.WAFRegionalRules.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]wafregionaltypes.Rule)
		for _, r := range rules {
			if r.RuleId == nil {
				continue
			}
			resp, err := c.WAFRegional.GetRule(ctx, &wafregional.GetRuleInput{RuleId: r.RuleId})
			if err != nil || resp.Rule == nil {
				continue
			}
			out[*r.RuleId] = *resp.Rule
		}
		return out, nil
	})
	d.WAFRegionalRuleGroupDetails = cache.New("WAFRegionalRuleGroupDetails", func() (map[string]wafregionaltypes.RuleGroup, error) {
		rgs, err := d.WAFRegionalRuleGroups.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]wafregionaltypes.RuleGroup)
		for _, rg := range rgs {
			if rg.RuleGroupId == nil {
				continue
			}
			resp, err := c.WAFRegional.GetRuleGroup(ctx, &wafregional.GetRuleGroupInput{RuleGroupId: rg.RuleGroupId})
			if err != nil || resp.RuleGroup == nil {
				continue
			}
			out[*rg.RuleGroupId] = *resp.RuleGroup
		}
		return out, nil
	})
	d.WAFRegionalLoggingConfigurations = cache.New("WAFRegionalLoggingConfigurations", func() (map[string]wafregional.GetLoggingConfigurationOutput, error) {
		acls, err := d.WAFRegionalWebACLs.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]wafregional.GetLoggingConfigurationOutput)
		for _, a := range acls {
			if a.WebACLId == nil {
				continue
			}
			resp, err := c.WAFRegional.GetLoggingConfiguration(ctx, &wafregional.GetLoggingConfigurationInput{ResourceArn: a.WebACLId})
			if err != nil {
				continue
			}
			out[*a.WebACLId] = *resp
		}
		return out, nil
	})

	// WAFv2
	d.WAFv2WebACLs = cache.New("WAFv2WebACLs", func() ([]wafv2types.WebACLSummary, error) {
		out, err := c.WAFv2.ListWebACLs(ctx, &wafv2.ListWebACLsInput{Scope: wafv2types.ScopeRegional})
		if err != nil {
			return nil, err
		}
		return out.WebACLs, nil
	})
	d.WAFv2RuleGroups = cache.New("WAFv2RuleGroups", func() ([]wafv2types.RuleGroupSummary, error) {
		out, err := c.WAFv2.ListRuleGroups(ctx, &wafv2.ListRuleGroupsInput{Scope: wafv2types.ScopeRegional})
		if err != nil {
			return nil, err
		}
		return out.RuleGroups, nil
	})
	d.WAFv2WebACLDetails = cache.New("WAFv2WebACLDetails", func() (map[string]wafv2types.WebACL, error) {
		acls, err := d.WAFv2WebACLs.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]wafv2types.WebACL)
		for _, a := range acls {
			if a.Id == nil || a.Name == nil {
				continue
			}
			resp, err := c.WAFv2.GetWebACL(ctx, &wafv2.GetWebACLInput{Id: a.Id, Name: a.Name, Scope: wafv2types.ScopeRegional})
			if err != nil || resp.WebACL == nil {
				continue
			}
			out[*a.ARN] = *resp.WebACL
		}
		return out, nil
	})
	d.WAFv2RuleGroupDetails = cache.New("WAFv2RuleGroupDetails", func() (map[string]wafv2types.RuleGroup, error) {
		rgs, err := d.WAFv2RuleGroups.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]wafv2types.RuleGroup)
		for _, rg := range rgs {
			if rg.Id == nil || rg.Name == nil {
				continue
			}
			resp, err := c.WAFv2.GetRuleGroup(ctx, &wafv2.GetRuleGroupInput{Id: rg.Id, Name: rg.Name, Scope: wafv2types.ScopeRegional})
			if err != nil || resp.RuleGroup == nil {
				continue
			}
			out[*rg.ARN] = *resp.RuleGroup
		}
		return out, nil
	})
	d.WAFv2LoggingConfigs = cache.New("WAFv2LoggingConfigs", func() (map[string]wafv2.GetLoggingConfigurationOutput, error) {
		acls, err := d.WAFv2WebACLs.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]wafv2.GetLoggingConfigurationOutput)
		for _, a := range acls {
			if a.ARN == nil {
				continue
			}
			resp, err := c.WAFv2.GetLoggingConfiguration(ctx, &wafv2.GetLoggingConfigurationInput{ResourceArn: a.ARN})
			if err != nil {
				continue
			}
			out[*a.ARN] = *resp
		}
		return out, nil
	})
	d.WAFv2WebACLForResource = cache.New("WAFv2WebACLForResource", func() (map[string]bool, error) {
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
	d.Workspaces = cache.New("Workspaces", func() ([]workspacestypes.Workspace, error) {
		out, err := c.Workspaces.DescribeWorkspaces(ctx, &workspaces.DescribeWorkspacesInput{})
		if err != nil {
			return nil, err
		}
		return out.Workspaces, nil
	})
	d.WorkspacesConnectionAlias = cache.New("WorkspacesConnectionAlias", func() ([]workspacestypes.ConnectionAlias, error) {
		out, err := c.Workspaces.DescribeConnectionAliases(ctx, &workspaces.DescribeConnectionAliasesInput{})
		if err != nil {
			return nil, err
		}
		return out.ConnectionAliases, nil
	})
	d.WorkspacesTags = cache.New("WorkspacesTags", func() (map[string]map[string]string, error) {
		items, err := d.Workspaces.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, w := range items {
			if w.WorkspaceId == nil {
				continue
			}
			resp, err := c.Workspaces.DescribeTags(ctx, &workspaces.DescribeTagsInput{ResourceId: w.WorkspaceId})
			if err != nil {
				continue
			}
			m := make(map[string]string)
			for _, t := range resp.TagList {
				if t.Key != nil && t.Value != nil {
					m[*t.Key] = *t.Value
				}
			}
			out[*w.WorkspaceId] = m
		}
		return out, nil
	})
	d.WorkspacesConnectionAliasTags = cache.New("WorkspacesConnectionAliasTags", func() (map[string]map[string]string, error) {
		items, err := d.WorkspacesConnectionAlias.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string]map[string]string)
		for _, a := range items {
			if a.AliasId == nil {
				continue
			}
			resp, err := c.Workspaces.DescribeTags(ctx, &workspaces.DescribeTagsInput{ResourceId: a.AliasId})
			if err != nil {
				continue
			}
			m := make(map[string]string)
			for _, t := range resp.TagList {
				if t.Key != nil && t.Value != nil {
					m[*t.Key] = *t.Value
				}
			}
			out[*a.AliasId] = m
		}
		return out, nil
	})

	// ElasticBeanstalk
	d.ElasticBeanstalkApps = cache.New("ElasticBeanstalkApps", func() ([]ebtypes.ApplicationDescription, error) {
		out, err := c.ElasticBeanstalk.DescribeApplications(ctx, &elasticbeanstalk.DescribeApplicationsInput{})
		if err != nil {
			return nil, err
		}
		return out.Applications, nil
	})
	d.ElasticBeanstalkEnvs = cache.New("ElasticBeanstalkEnvs", func() ([]ebtypes.EnvironmentDescription, error) {
		out, err := c.ElasticBeanstalk.DescribeEnvironments(ctx, &elasticbeanstalk.DescribeEnvironmentsInput{})
		if err != nil {
			return nil, err
		}
		return out.Environments, nil
	})
	d.ElasticBeanstalkAppVersions = cache.New("ElasticBeanstalkAppVersions", func() ([]ebtypes.ApplicationVersionDescription, error) {
		out, err := c.ElasticBeanstalk.DescribeApplicationVersions(ctx, &elasticbeanstalk.DescribeApplicationVersionsInput{})
		if err != nil {
			return nil, err
		}
		return out.ApplicationVersions, nil
	})
	d.ElasticBeanstalkEnvSettings = cache.New("ElasticBeanstalkEnvSettings", func() (map[string][]ebtypes.ConfigurationOptionSetting, error) {
		envs, err := d.ElasticBeanstalkEnvs.Get()
		if err != nil {
			return nil, err
		}
		out := make(map[string][]ebtypes.ConfigurationOptionSetting)
		for _, env := range envs {
			if env.EnvironmentName == nil || env.ApplicationName == nil {
				continue
			}
			resp, err := c.ElasticBeanstalk.DescribeConfigurationSettings(ctx, &elasticbeanstalk.DescribeConfigurationSettingsInput{
				ApplicationName: env.ApplicationName,
				EnvironmentName: env.EnvironmentName,
			})
			if err != nil {
				continue
			}
			for _, cfg := range resp.ConfigurationSettings {
				if cfg.EnvironmentName != nil {
					out[*cfg.EnvironmentName] = cfg.OptionSettings
				}
			}
		}
		return out, nil
	})
}
