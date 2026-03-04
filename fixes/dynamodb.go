package fixes

import (
	"fmt"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamodbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// ── dynamodb-pitr-enabled ─────────────────────────────────────────────────────

type dynamoDBPITRFix struct{ clients *awsdata.Clients }

func (f *dynamoDBPITRFix) CheckID() string          { return "dynamodb-pitr-enabled" }
func (f *dynamoDBPITRFix) Description() string      { return "Enable point-in-time recovery on DynamoDB table" }
func (f *dynamoDBPITRFix) Impact() fix.ImpactType   { return fix.ImpactNone }
func (f *dynamoDBPITRFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *dynamoDBPITRFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.DynamoDB.DescribeContinuousBackups(fctx.Ctx, &dynamodb.DescribeContinuousBackupsInput{
		TableName: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe continuous backups: " + err.Error()
		return base
	}
	if out.ContinuousBackupsDescription != nil &&
		out.ContinuousBackupsDescription.PointInTimeRecoveryDescription != nil &&
		out.ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus == dynamodbtypes.PointInTimeRecoveryStatusEnabled {
		base.Status = fix.FixSkipped
		base.Message = "PITR already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable point-in-time recovery on table %s", resourceID)}
		return base
	}

	_, err = f.clients.DynamoDB.UpdateContinuousBackups(fctx.Ctx, &dynamodb.UpdateContinuousBackupsInput{
		TableName: aws.String(resourceID),
		PointInTimeRecoverySpecification: &dynamodbtypes.PointInTimeRecoverySpecification{
			PointInTimeRecoveryEnabled: aws.Bool(true),
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update continuous backups: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled point-in-time recovery on table %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── dynamodb-table-deletion-protection-enabled ────────────────────────────────

type dynamoDBDeletionProtectionFix struct{ clients *awsdata.Clients }

func (f *dynamoDBDeletionProtectionFix) CheckID() string          { return "dynamodb-table-deletion-protection-enabled" }
func (f *dynamoDBDeletionProtectionFix) Description() string      { return "Enable deletion protection on DynamoDB table" }
func (f *dynamoDBDeletionProtectionFix) Impact() fix.ImpactType   { return fix.ImpactNone }
func (f *dynamoDBDeletionProtectionFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *dynamoDBDeletionProtectionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.DynamoDB.DescribeTable(fctx.Ctx, &dynamodb.DescribeTableInput{
		TableName: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe table: " + err.Error()
		return base
	}
	if out.Table != nil && out.Table.DeletionProtectionEnabled != nil && *out.Table.DeletionProtectionEnabled {
		base.Status = fix.FixSkipped
		base.Message = "deletion protection already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable deletion protection on table %s", resourceID)}
		return base
	}

	_, err = f.clients.DynamoDB.UpdateTable(fctx.Ctx, &dynamodb.UpdateTableInput{
		TableName:                 aws.String(resourceID),
		DeletionProtectionEnabled: aws.Bool(true),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update table: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled deletion protection on table %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── dynamodb-table-encryption-enabled ────────────────────────────────────────

type dynamoDBSSEFix struct{ clients *awsdata.Clients }

func (f *dynamoDBSSEFix) CheckID() string          { return "dynamodb-table-encryption-enabled" }
func (f *dynamoDBSSEFix) Description() string      { return "Enable server-side encryption on DynamoDB table" }
func (f *dynamoDBSSEFix) Impact() fix.ImpactType   { return fix.ImpactNone }
func (f *dynamoDBSSEFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *dynamoDBSSEFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.DynamoDB.DescribeTable(fctx.Ctx, &dynamodb.DescribeTableInput{
		TableName: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe table: " + err.Error()
		return base
	}
	if out.Table != nil && out.Table.SSEDescription != nil &&
		(out.Table.SSEDescription.Status == dynamodbtypes.SSEStatusEnabled ||
			out.Table.SSEDescription.Status == dynamodbtypes.SSEStatusEnabling) {
		base.Status = fix.FixSkipped
		base.Message = "SSE already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable SSE (AWS managed key) on DynamoDB table %s", resourceID)}
		return base
	}

	_, err = f.clients.DynamoDB.UpdateTable(fctx.Ctx, &dynamodb.UpdateTableInput{
		TableName: aws.String(resourceID),
		SSESpecification: &dynamodbtypes.SSESpecification{
			Enabled: aws.Bool(true),
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update table SSE: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled SSE (AWS managed key) on DynamoDB table %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}

// ── dynamodb-table-encrypted-kms ──────────────────────────────────────────────

type dynamoDBKMSEncryptionFix struct{ clients *awsdata.Clients }

func (f *dynamoDBKMSEncryptionFix) CheckID() string { return "dynamodb-table-encrypted-kms" }
func (f *dynamoDBKMSEncryptionFix) Description() string {
	return "Enable AWS KMS encryption on DynamoDB table"
}
func (f *dynamoDBKMSEncryptionFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *dynamoDBKMSEncryptionFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *dynamoDBKMSEncryptionFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.DynamoDB.DescribeTable(fctx.Ctx, &dynamodb.DescribeTableInput{
		TableName: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe table: " + err.Error()
		return base
	}
	if out.Table != nil && out.Table.SSEDescription != nil &&
		out.Table.SSEDescription.SSEType == dynamodbtypes.SSETypeKms {
		base.Status = fix.FixSkipped
		base.Message = "KMS encryption already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable KMS encryption on DynamoDB table %s", resourceID)}
		return base
	}

	_, err = f.clients.DynamoDB.UpdateTable(fctx.Ctx, &dynamodb.UpdateTableInput{
		TableName: aws.String(resourceID),
		SSESpecification: &dynamodbtypes.SSESpecification{
			Enabled: aws.Bool(true),
			SSEType: dynamodbtypes.SSETypeKms,
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update table: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled KMS encryption on DynamoDB table %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}
