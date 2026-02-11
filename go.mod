module bptools

go 1.25.6

require (
	github.com/aws/aws-sdk-go-v2 v1.41.1
	github.com/aws/aws-sdk-go-v2/config v1.32.7
	github.com/aws/aws-sdk-go-v2/service/accessanalyzer v1.45.8
	github.com/aws/aws-sdk-go-v2/service/account v1.30.1
	github.com/aws/aws-sdk-go-v2/service/acm v1.37.19
	github.com/aws/aws-sdk-go-v2/service/acmpca v1.46.8
	github.com/aws/aws-sdk-go-v2/service/amp v1.42.5
	github.com/aws/aws-sdk-go-v2/service/amplify v1.38.10
	github.com/aws/aws-sdk-go-v2/service/apigateway v1.38.4
	github.com/aws/aws-sdk-go-v2/service/apigatewayv2 v1.33.5
	github.com/aws/aws-sdk-go-v2/service/appconfig v1.43.9
	github.com/aws/aws-sdk-go-v2/service/appflow v1.51.8
	github.com/aws/aws-sdk-go-v2/service/appintegrations v1.37.3
	github.com/aws/aws-sdk-go-v2/service/applicationautoscaling v1.41.10
	github.com/aws/aws-sdk-go-v2/service/appmesh v1.35.8
	github.com/aws/aws-sdk-go-v2/service/apprunner v1.39.10
	github.com/aws/aws-sdk-go-v2/service/appstream v1.53.2
	github.com/aws/aws-sdk-go-v2/service/appsync v1.53.1
	github.com/aws/aws-sdk-go-v2/service/athena v1.57.0
	github.com/aws/aws-sdk-go-v2/service/auditmanager v1.46.8
	github.com/aws/aws-sdk-go-v2/service/autoscaling v1.64.0
	github.com/aws/aws-sdk-go-v2/service/backup v1.54.6
	github.com/aws/aws-sdk-go-v2/service/batch v1.59.0
	github.com/aws/aws-sdk-go-v2/service/cloudformation v1.71.5
	github.com/aws/aws-sdk-go-v2/service/cloudfront v1.60.0
	github.com/aws/aws-sdk-go-v2/service/cloudtrail v1.55.5
	github.com/aws/aws-sdk-go-v2/service/cloudwatch v1.53.1
	github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs v1.63.1
	github.com/aws/aws-sdk-go-v2/service/codebuild v1.68.9
	github.com/aws/aws-sdk-go-v2/service/codedeploy v1.35.9
	github.com/aws/aws-sdk-go-v2/service/codeguruprofiler v1.29.16
	github.com/aws/aws-sdk-go-v2/service/codegurureviewer v1.34.16
	github.com/aws/aws-sdk-go-v2/service/codepipeline v1.46.17
	github.com/aws/aws-sdk-go-v2/service/cognitoidentity v1.33.18
	github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider v1.58.0
	github.com/aws/aws-sdk-go-v2/service/connect v1.160.0
	github.com/aws/aws-sdk-go-v2/service/customerprofiles v1.55.3
	github.com/aws/aws-sdk-go-v2/service/databasemigrationservice v1.61.5
	github.com/aws/aws-sdk-go-v2/service/datasync v1.57.1
	github.com/aws/aws-sdk-go-v2/service/dax v1.29.12
	github.com/aws/aws-sdk-go-v2/service/docdb v1.48.9
	github.com/aws/aws-sdk-go-v2/service/dynamodb v1.55.0
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.285.0
	github.com/aws/aws-sdk-go-v2/service/ecr v1.55.1
	github.com/aws/aws-sdk-go-v2/service/ecs v1.71.0
	github.com/aws/aws-sdk-go-v2/service/efs v1.41.10
	github.com/aws/aws-sdk-go-v2/service/eks v1.77.1
	github.com/aws/aws-sdk-go-v2/service/elasticache v1.51.9
	github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk v1.33.19
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing v1.33.19
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2 v1.54.6
	github.com/aws/aws-sdk-go-v2/service/elasticsearchservice v1.37.19
	github.com/aws/aws-sdk-go-v2/service/emr v1.57.5
	github.com/aws/aws-sdk-go-v2/service/eventbridge v1.45.18
	github.com/aws/aws-sdk-go-v2/service/evidently v1.29.0
	github.com/aws/aws-sdk-go-v2/service/firehose v1.42.9
	github.com/aws/aws-sdk-go-v2/service/fis v1.37.16
	github.com/aws/aws-sdk-go-v2/service/fms v1.44.17
	github.com/aws/aws-sdk-go-v2/service/frauddetector v1.41.8
	github.com/aws/aws-sdk-go-v2/service/fsx v1.65.3
	github.com/aws/aws-sdk-go-v2/service/globalaccelerator v1.35.11
	github.com/aws/aws-sdk-go-v2/service/glue v1.137.0
	github.com/aws/aws-sdk-go-v2/service/guardduty v1.73.0
	github.com/aws/aws-sdk-go-v2/service/iam v1.53.2
	github.com/aws/aws-sdk-go-v2/service/inspector2 v1.46.2
	github.com/aws/aws-sdk-go-v2/service/iot v1.72.1
	github.com/aws/aws-sdk-go-v2/service/iotevents v1.33.9
	github.com/aws/aws-sdk-go-v2/service/iotsitewise v1.52.14
	github.com/aws/aws-sdk-go-v2/service/iottwinmaker v1.29.17
	github.com/aws/aws-sdk-go-v2/service/iotwireless v1.54.5
	github.com/aws/aws-sdk-go-v2/service/ivs v1.48.10
	github.com/aws/aws-sdk-go-v2/service/kafka v1.46.7
	github.com/aws/aws-sdk-go-v2/service/kafkaconnect v1.29.2
	github.com/aws/aws-sdk-go-v2/service/keyspaces v1.25.0
	github.com/aws/aws-sdk-go-v2/service/kinesis v1.43.0
	github.com/aws/aws-sdk-go-v2/service/kinesisvideo v1.33.4
	github.com/aws/aws-sdk-go-v2/service/kms v1.49.5
	github.com/aws/aws-sdk-go-v2/service/lambda v1.88.0
	github.com/aws/aws-sdk-go-v2/service/lightsail v1.50.11
	github.com/aws/aws-sdk-go-v2/service/macie2 v1.50.9
	github.com/aws/aws-sdk-go-v2/service/mq v1.34.15
	github.com/aws/aws-sdk-go-v2/service/neptune v1.43.9
	github.com/aws/aws-sdk-go-v2/service/networkfirewall v1.59.3
	github.com/aws/aws-sdk-go-v2/service/opensearch v1.57.1
	github.com/aws/aws-sdk-go-v2/service/organizations v1.50.2
	github.com/aws/aws-sdk-go-v2/service/rds v1.114.0
	github.com/aws/aws-sdk-go-v2/service/redshift v1.62.1
	github.com/aws/aws-sdk-go-v2/service/redshiftserverless v1.34.0
	github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi v1.31.6
	github.com/aws/aws-sdk-go-v2/service/route53 v1.62.1
	github.com/aws/aws-sdk-go-v2/service/route53resolver v1.42.1
	github.com/aws/aws-sdk-go-v2/service/rum v1.30.5
	github.com/aws/aws-sdk-go-v2/service/s3 v1.96.0
	github.com/aws/aws-sdk-go-v2/service/s3control v1.68.0
	github.com/aws/aws-sdk-go-v2/service/sagemaker v1.232.0
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.41.1
	github.com/aws/aws-sdk-go-v2/service/securityhub v1.67.3
	github.com/aws/aws-sdk-go-v2/service/servicecatalog v1.39.8
	github.com/aws/aws-sdk-go-v2/service/ses v1.34.18
	github.com/aws/aws-sdk-go-v2/service/sesv2 v1.59.1
	github.com/aws/aws-sdk-go-v2/service/sfn v1.40.6
	github.com/aws/aws-sdk-go-v2/service/shield v1.34.17
	github.com/aws/aws-sdk-go-v2/service/sns v1.39.11
	github.com/aws/aws-sdk-go-v2/service/sqs v1.42.21
	github.com/aws/aws-sdk-go-v2/service/ssm v1.67.8
	github.com/aws/aws-sdk-go-v2/service/storagegateway v1.43.10
	github.com/aws/aws-sdk-go-v2/service/sts v1.41.6
	github.com/aws/aws-sdk-go-v2/service/transfer v1.69.0
	github.com/aws/aws-sdk-go-v2/service/waf v1.30.16
	github.com/aws/aws-sdk-go-v2/service/wafregional v1.30.17
	github.com/aws/aws-sdk-go-v2/service/wafv2 v1.70.7
	github.com/aws/aws-sdk-go-v2/service/workspaces v1.66.0
	github.com/aws/smithy-go v1.24.0
	github.com/charmbracelet/bubbles v0.21.0
	github.com/charmbracelet/bubbletea v1.3.10
	github.com/charmbracelet/lipgloss v1.1.0
)

require (
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.4 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.19.7 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.17 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.17 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.17 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.4 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.17 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.9.8 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/endpoint-discovery v1.11.17 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.17 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.19.17 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.0.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.30.9 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.35.13 // indirect
	github.com/aymanbagabas/go-osc52/v2 v2.0.1 // indirect
	github.com/charmbracelet/colorprofile v0.3.2 // indirect
	github.com/charmbracelet/harmonica v0.2.0 // indirect
	github.com/charmbracelet/x/ansi v0.10.1 // indirect
	github.com/charmbracelet/x/cellbuf v0.0.13 // indirect
	github.com/charmbracelet/x/term v0.2.1 // indirect
	github.com/erikgeiser/coninput v0.0.0-20211004153227-1c3628e74d0f // indirect
	github.com/lucasb-eyer/go-colorful v1.2.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-localereader v0.0.1 // indirect
	github.com/mattn/go-runewidth v0.0.16 // indirect
	github.com/muesli/ansi v0.0.0-20230316100256-276c6243b2f6 // indirect
	github.com/muesli/cancelreader v0.2.2 // indirect
	github.com/muesli/termenv v0.16.0 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/xo/terminfo v0.0.0-20220910002029-abceb7e1c41e // indirect
	golang.org/x/exp v0.0.0-20231006140011-7918f672742d // indirect
	golang.org/x/sys v0.36.0 // indirect
	golang.org/x/text v0.23.0 // indirect
)
