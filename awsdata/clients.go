package awsdata

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	"github.com/aws/aws-sdk-go-v2/service/account"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	"github.com/aws/aws-sdk-go-v2/service/amp"
	"github.com/aws/aws-sdk-go-v2/service/amplify"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	"github.com/aws/aws-sdk-go-v2/service/appconfig"
	"github.com/aws/aws-sdk-go-v2/service/appflow"
	"github.com/aws/aws-sdk-go-v2/service/appintegrations"
	"github.com/aws/aws-sdk-go-v2/service/applicationautoscaling"
	"github.com/aws/aws-sdk-go-v2/service/appmesh"
	"github.com/aws/aws-sdk-go-v2/service/apprunner"
	"github.com/aws/aws-sdk-go-v2/service/appstream"
	"github.com/aws/aws-sdk-go-v2/service/appsync"
	"github.com/aws/aws-sdk-go-v2/service/athena"
	"github.com/aws/aws-sdk-go-v2/service/auditmanager"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/aws/aws-sdk-go-v2/service/backup"
	"github.com/aws/aws-sdk-go-v2/service/batch"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	"github.com/aws/aws-sdk-go-v2/service/codedeploy"
	"github.com/aws/aws-sdk-go-v2/service/codeguruprofiler"
	"github.com/aws/aws-sdk-go-v2/service/codegurureviewer"
	"github.com/aws/aws-sdk-go-v2/service/codepipeline"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentity"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/connect"
	"github.com/aws/aws-sdk-go-v2/service/customerprofiles"
	"github.com/aws/aws-sdk-go-v2/service/databasemigrationservice"
	"github.com/aws/aws-sdk-go-v2/service/datasync"
	"github.com/aws/aws-sdk-go-v2/service/dax"
	"github.com/aws/aws-sdk-go-v2/service/docdb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	"github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/elasticsearchservice"
	"github.com/aws/aws-sdk-go-v2/service/emr"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	"github.com/aws/aws-sdk-go-v2/service/evidently"
	"github.com/aws/aws-sdk-go-v2/service/firehose"
	"github.com/aws/aws-sdk-go-v2/service/fis"
	"github.com/aws/aws-sdk-go-v2/service/fms"
	"github.com/aws/aws-sdk-go-v2/service/frauddetector"
	"github.com/aws/aws-sdk-go-v2/service/fsx"
	"github.com/aws/aws-sdk-go-v2/service/globalaccelerator"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	"github.com/aws/aws-sdk-go-v2/service/iot"
	"github.com/aws/aws-sdk-go-v2/service/iotevents"
	"github.com/aws/aws-sdk-go-v2/service/iotsitewise"
	"github.com/aws/aws-sdk-go-v2/service/iottwinmaker"
	"github.com/aws/aws-sdk-go-v2/service/iotwireless"
	"github.com/aws/aws-sdk-go-v2/service/ivs"
	"github.com/aws/aws-sdk-go-v2/service/kafka"
	"github.com/aws/aws-sdk-go-v2/service/kafkaconnect"
	"github.com/aws/aws-sdk-go-v2/service/keyspaces"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	"github.com/aws/aws-sdk-go-v2/service/kinesisvideo"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lightsail"
	"github.com/aws/aws-sdk-go-v2/service/macie2"
	"github.com/aws/aws-sdk-go-v2/service/mq"
	"github.com/aws/aws-sdk-go-v2/service/neptune"
	"github.com/aws/aws-sdk-go-v2/service/networkfirewall"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
	"github.com/aws/aws-sdk-go-v2/service/redshiftserverless"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53resolver"
	"github.com/aws/aws-sdk-go-v2/service/rum"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/servicecatalog"
	"github.com/aws/aws-sdk-go-v2/service/ses"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	"github.com/aws/aws-sdk-go-v2/service/shield"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/storagegateway"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/transfer"
	"github.com/aws/aws-sdk-go-v2/service/waf"
	"github.com/aws/aws-sdk-go-v2/service/wafregional"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	"github.com/aws/aws-sdk-go-v2/service/workspaces"
)

// Clients holds all AWS SDK clients.
type Clients struct {
	AccessAnalyzer         *accessanalyzer.Client
	ACM                    *acm.Client
	ACMPCA                 *acmpca.Client
	AMP                    *amp.Client
	Amplify                *amplify.Client
	Account                *account.Client
	APIGateway             *apigateway.Client
	APIGatewayV2           *apigatewayv2.Client
	AppConfig              *appconfig.Client
	AppFlow                *appflow.Client
	AppIntegrations        *appintegrations.Client
	ApplicationAutoScaling *applicationautoscaling.Client
	AppMesh                *appmesh.Client
	AppRunner              *apprunner.Client
	AppStream              *appstream.Client
	AppSync                *appsync.Client
	Athena                 *athena.Client
	AuditManager           *auditmanager.Client
	AutoScaling            *autoscaling.Client
	Backup                 *backup.Client
	Batch                  *batch.Client
	CloudFormation         *cloudformation.Client
	CloudFront             *cloudfront.Client
	CloudTrail             *cloudtrail.Client
	CloudWatch             *cloudwatch.Client
	CloudWatchLogs         *cloudwatchlogs.Client
	CodeBuild              *codebuild.Client
	CodeDeploy             *codedeploy.Client
	CodeGuruProfiler       *codeguruprofiler.Client
	CodeGuruReviewer       *codegurureviewer.Client
	CodePipeline           *codepipeline.Client
	CognitoIdentity        *cognitoidentity.Client
	CognitoIDP             *cognitoidentityprovider.Client
	Connect                *connect.Client
	CustomerProfiles       *customerprofiles.Client
	DataSync               *datasync.Client
	DAX                    *dax.Client
	DMS                    *databasemigrationservice.Client
	DocDB                  *docdb.Client
	DynamoDB               *dynamodb.Client
	EC2                    *ec2.Client
	ECR                    *ecr.Client
	ECS                    *ecs.Client
	EFS                    *efs.Client
	EKS                    *eks.Client
	ElastiCache            *elasticache.Client
	ElasticBeanstalk       *elasticbeanstalk.Client
	ELB                    *elasticloadbalancing.Client
	ELBv2                  *elasticloadbalancingv2.Client
	Elasticsearch          *elasticsearchservice.Client
	EMR                    *emr.Client
	Evidently              *evidently.Client
	EventBridge            *eventbridge.Client
	Firehose               *firehose.Client
	FIS                    *fis.Client
	FMS                    *fms.Client
	FraudDetector          *frauddetector.Client
	FSx                    *fsx.Client
	GlobalAccelerator      *globalaccelerator.Client
	Glue                   *glue.Client
	GuardDuty              *guardduty.Client
	IAM                    *iam.Client
	Inspector2             *inspector2.Client
	IoT                    *iot.Client
	IoTEvents              *iotevents.Client
	IoTSiteWise            *iotsitewise.Client
	IoTTwinMaker           *iottwinmaker.Client
	IoTWireless            *iotwireless.Client
	IVS                    *ivs.Client
	Kafka                  *kafka.Client
	KafkaConnect           *kafkaconnect.Client
	Keyspaces              *keyspaces.Client
	Kinesis                *kinesis.Client
	KinesisVideo           *kinesisvideo.Client
	KMS                    *kms.Client
	Lambda                 *lambda.Client
	Lightsail              *lightsail.Client
	Macie2                 *macie2.Client
	MQ                     *mq.Client
	Neptune                *neptune.Client
	NetworkFirewall        *networkfirewall.Client
	OpenSearch             *opensearch.Client
	Organizations          *organizations.Client
	RDS                    *rds.Client
	Redshift               *redshift.Client
	RedshiftServerless     *redshiftserverless.Client
	ResourceGroupsTagging  *resourcegroupstaggingapi.Client
	Route53                *route53.Client
	Route53Resolver        *route53resolver.Client
	RUM                    *rum.Client
	S3                     *s3.Client
	S3Control              *s3control.Client
	SageMaker              *sagemaker.Client
	SecretsManager         *secretsmanager.Client
	SecurityHub            *securityhub.Client
	SES                    *ses.Client
	SESv2                  *sesv2.Client
	SFN                    *sfn.Client
	Shield                 *shield.Client
	ServiceCatalog         *servicecatalog.Client
	SNS                    *sns.Client
	SQS                    *sqs.Client
	SSM                    *ssm.Client
	STS                    *sts.Client
	StorageGateway         *storagegateway.Client
	Transfer               *transfer.Client
	WAF                    *waf.Client
	WAFRegional            *wafregional.Client
	WAFv2                  *wafv2.Client
	Workspaces             *workspaces.Client
}

// NewClients constructs all AWS SDK clients from the default config.
func NewClients(ctx context.Context) (*Clients, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	return &Clients{
		AccessAnalyzer:         accessanalyzer.NewFromConfig(cfg),
		ACM:                    acm.NewFromConfig(cfg),
		ACMPCA:                 acmpca.NewFromConfig(cfg),
		AMP:                    amp.NewFromConfig(cfg),
		Amplify:                amplify.NewFromConfig(cfg),
		Account:                account.NewFromConfig(cfg),
		APIGateway:             apigateway.NewFromConfig(cfg),
		APIGatewayV2:           apigatewayv2.NewFromConfig(cfg),
		AppConfig:              appconfig.NewFromConfig(cfg),
		AppFlow:                appflow.NewFromConfig(cfg),
		AppIntegrations:        appintegrations.NewFromConfig(cfg),
		ApplicationAutoScaling: applicationautoscaling.NewFromConfig(cfg),
		AppMesh:                appmesh.NewFromConfig(cfg),
		AppRunner:              apprunner.NewFromConfig(cfg),
		AppStream:              appstream.NewFromConfig(cfg),
		AppSync:                appsync.NewFromConfig(cfg),
		Athena:                 athena.NewFromConfig(cfg),
		AuditManager:           auditmanager.NewFromConfig(cfg),
		AutoScaling:            autoscaling.NewFromConfig(cfg),
		Backup:                 backup.NewFromConfig(cfg),
		Batch:                  batch.NewFromConfig(cfg),
		CloudFormation:         cloudformation.NewFromConfig(cfg),
		CloudFront:             cloudfront.NewFromConfig(cfg),
		CloudTrail:             cloudtrail.NewFromConfig(cfg),
		CloudWatch:             cloudwatch.NewFromConfig(cfg),
		CloudWatchLogs:         cloudwatchlogs.NewFromConfig(cfg),
		CodeBuild:              codebuild.NewFromConfig(cfg),
		CodeDeploy:             codedeploy.NewFromConfig(cfg),
		CodeGuruProfiler:       codeguruprofiler.NewFromConfig(cfg),
		CodeGuruReviewer:       codegurureviewer.NewFromConfig(cfg),
		CodePipeline:           codepipeline.NewFromConfig(cfg),
		CognitoIdentity:        cognitoidentity.NewFromConfig(cfg),
		CognitoIDP:             cognitoidentityprovider.NewFromConfig(cfg),
		Connect:                connect.NewFromConfig(cfg),
		CustomerProfiles:       customerprofiles.NewFromConfig(cfg),
		DataSync:               datasync.NewFromConfig(cfg),
		DAX:                    dax.NewFromConfig(cfg),
		DMS:                    databasemigrationservice.NewFromConfig(cfg),
		DocDB:                  docdb.NewFromConfig(cfg),
		DynamoDB:               dynamodb.NewFromConfig(cfg),
		EC2:                    ec2.NewFromConfig(cfg),
		ECR:                    ecr.NewFromConfig(cfg),
		ECS:                    ecs.NewFromConfig(cfg),
		EFS:                    efs.NewFromConfig(cfg),
		EKS:                    eks.NewFromConfig(cfg),
		ElastiCache:            elasticache.NewFromConfig(cfg),
		ElasticBeanstalk:       elasticbeanstalk.NewFromConfig(cfg),
		ELB:                    elasticloadbalancing.NewFromConfig(cfg),
		ELBv2:                  elasticloadbalancingv2.NewFromConfig(cfg),
		Elasticsearch:          elasticsearchservice.NewFromConfig(cfg),
		EMR:                    emr.NewFromConfig(cfg),
		Evidently:              evidently.NewFromConfig(cfg),
		EventBridge:            eventbridge.NewFromConfig(cfg),
		Firehose:               firehose.NewFromConfig(cfg),
		FIS:                    fis.NewFromConfig(cfg),
		FMS:                    fms.NewFromConfig(cfg),
		FraudDetector:          frauddetector.NewFromConfig(cfg),
		FSx:                    fsx.NewFromConfig(cfg),
		GlobalAccelerator:      globalaccelerator.NewFromConfig(cfg),
		Glue:                   glue.NewFromConfig(cfg),
		GuardDuty:              guardduty.NewFromConfig(cfg),
		IAM:                    iam.NewFromConfig(cfg),
		Inspector2:             inspector2.NewFromConfig(cfg),
		IoT:                    iot.NewFromConfig(cfg),
		IoTEvents:              iotevents.NewFromConfig(cfg),
		IoTSiteWise:            iotsitewise.NewFromConfig(cfg),
		IoTTwinMaker:           iottwinmaker.NewFromConfig(cfg),
		IoTWireless:            iotwireless.NewFromConfig(cfg),
		IVS:                    ivs.NewFromConfig(cfg),
		Kafka:                  kafka.NewFromConfig(cfg),
		KafkaConnect:           kafkaconnect.NewFromConfig(cfg),
		Keyspaces:              keyspaces.NewFromConfig(cfg),
		Kinesis:                kinesis.NewFromConfig(cfg),
		KinesisVideo:           kinesisvideo.NewFromConfig(cfg),
		KMS:                    kms.NewFromConfig(cfg),
		Lambda:                 lambda.NewFromConfig(cfg),
		Lightsail:              lightsail.NewFromConfig(cfg),
		Macie2:                 macie2.NewFromConfig(cfg),
		MQ:                     mq.NewFromConfig(cfg),
		Neptune:                neptune.NewFromConfig(cfg),
		NetworkFirewall:        networkfirewall.NewFromConfig(cfg),
		OpenSearch:             opensearch.NewFromConfig(cfg),
		Organizations:          organizations.NewFromConfig(cfg),
		RDS:                    rds.NewFromConfig(cfg),
		Redshift:               redshift.NewFromConfig(cfg),
		RedshiftServerless:     redshiftserverless.NewFromConfig(cfg),
		ResourceGroupsTagging:  resourcegroupstaggingapi.NewFromConfig(cfg),
		Route53:                route53.NewFromConfig(cfg),
		Route53Resolver:        route53resolver.NewFromConfig(cfg),
		RUM:                    rum.NewFromConfig(cfg),
		S3:                     s3.NewFromConfig(cfg),
		S3Control:              s3control.NewFromConfig(cfg),
		SageMaker:              sagemaker.NewFromConfig(cfg),
		SecretsManager:         secretsmanager.NewFromConfig(cfg),
		SecurityHub:            securityhub.NewFromConfig(cfg),
		SES:                    ses.NewFromConfig(cfg),
		SESv2:                  sesv2.NewFromConfig(cfg),
		SFN:                    sfn.NewFromConfig(cfg),
		Shield:                 shield.NewFromConfig(cfg),
		ServiceCatalog:         servicecatalog.NewFromConfig(cfg),
		SNS:                    sns.NewFromConfig(cfg),
		SQS:                    sqs.NewFromConfig(cfg),
		SSM:                    ssm.NewFromConfig(cfg),
		STS:                    sts.NewFromConfig(cfg),
		StorageGateway:         storagegateway.NewFromConfig(cfg),
		Transfer:               transfer.NewFromConfig(cfg),
		WAF:                    waf.NewFromConfig(cfg),
		WAFRegional:            wafregional.NewFromConfig(cfg),
		WAFv2:                  wafv2.NewFromConfig(cfg),
		Workspaces:             workspaces.NewFromConfig(cfg),
	}, nil
}
