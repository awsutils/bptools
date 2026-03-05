package fixes

import (
	"encoding/json"
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

const defaultReservedLambdaConcurrency int32 = 10

type lambdaConcurrencyFix struct{ clients *awsdata.Clients }

func (f *lambdaConcurrencyFix) CheckID() string { return "lambda-concurrency-check" }
func (f *lambdaConcurrencyFix) Description() string {
	return "Set Lambda function reserved concurrency"
}
func (f *lambdaConcurrencyFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *lambdaConcurrencyFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *lambdaConcurrencyFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	name := strings.TrimSpace(resourceID)
	if name == "" {
		base.Status = fix.FixFailed
		base.Message = "missing function name"
		return base
	}

	out, err := f.clients.Lambda.GetFunctionConcurrency(fctx.Ctx, &lambda.GetFunctionConcurrencyInput{
		FunctionName: aws.String(name),
	})
	if err == nil && out.ReservedConcurrentExecutions != nil && *out.ReservedConcurrentExecutions > 0 {
		base.Status = fix.FixSkipped
		base.Message = "reserved concurrency already configured"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would set reserved concurrency=%d on Lambda function %s", defaultReservedLambdaConcurrency, name)}
		return base
	}

	_, err = f.clients.Lambda.PutFunctionConcurrency(fctx.Ctx, &lambda.PutFunctionConcurrencyInput{
		FunctionName:                 aws.String(name),
		ReservedConcurrentExecutions: aws.Int32(defaultReservedLambdaConcurrency),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "put function concurrency: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{fmt.Sprintf("set reserved concurrency=%d on Lambda function %s", defaultReservedLambdaConcurrency, name)}
	return base
}

type lambdaPublicAccessFix struct{ clients *awsdata.Clients }

func (f *lambdaPublicAccessFix) CheckID() string { return "lambda-function-public-access-prohibited" }
func (f *lambdaPublicAccessFix) Description() string {
	return "Remove public-invoke statements from Lambda function policy"
}
func (f *lambdaPublicAccessFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *lambdaPublicAccessFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

type lambdaPolicyDocument struct {
	Statement []struct {
		Sid       string      `json:"Sid"`
		Effect    string      `json:"Effect"`
		Principal interface{} `json:"Principal"`
		Condition interface{} `json:"Condition"`
	} `json:"Statement"`
}

func lambdaPrincipalIsPublic(p interface{}) bool {
	switch v := p.(type) {
	case string:
		return strings.TrimSpace(v) == "*"
	case map[string]interface{}:
		awsPrincipal, ok := v["AWS"]
		if !ok {
			return false
		}
		switch ap := awsPrincipal.(type) {
		case string:
			return strings.TrimSpace(ap) == "*"
		case []interface{}:
			for _, item := range ap {
				if s, ok := item.(string); ok && strings.TrimSpace(s) == "*" {
					return true
				}
			}
		}
	}
	return false
}

func (f *lambdaPublicAccessFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	name := strings.TrimSpace(resourceID)
	if name == "" {
		base.Status = fix.FixFailed
		base.Message = "missing function name"
		return base
	}

	policyOut, err := f.clients.Lambda.GetPolicy(fctx.Ctx, &lambda.GetPolicyInput{
		FunctionName: aws.String(name),
	})
	if err != nil {
		// No policy usually means no public access to remove.
		if strings.Contains(err.Error(), "ResourceNotFoundException") {
			base.Status = fix.FixSkipped
			base.Message = "no resource policy found"
			return base
		}
		base.Status = fix.FixFailed
		base.Message = "get policy: " + err.Error()
		return base
	}
	if policyOut.Policy == nil || strings.TrimSpace(*policyOut.Policy) == "" {
		base.Status = fix.FixSkipped
		base.Message = "empty resource policy"
		return base
	}

	var doc lambdaPolicyDocument
	if err := json.Unmarshal([]byte(*policyOut.Policy), &doc); err != nil {
		base.Status = fix.FixFailed
		base.Message = "parse policy document: " + err.Error()
		return base
	}

	toRemove := make([]string, 0)
	for _, stmt := range doc.Statement {
		if !strings.EqualFold(stmt.Effect, "Allow") {
			continue
		}
		if stmt.Condition != nil {
			continue
		}
		if !lambdaPrincipalIsPublic(stmt.Principal) {
			continue
		}
		if strings.TrimSpace(stmt.Sid) == "" {
			base.Status = fix.FixFailed
			base.Message = "found public statement without Sid; cannot safely remove"
			return base
		}
		toRemove = append(toRemove, stmt.Sid)
	}
	if len(toRemove) == 0 {
		base.Status = fix.FixSkipped
		base.Message = "no public policy statements found"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		for _, sid := range toRemove {
			base.Steps = append(base.Steps, "would remove Lambda policy statement Sid="+sid)
		}
		return base
	}

	for _, sid := range toRemove {
		_, err := f.clients.Lambda.RemovePermission(fctx.Ctx, &lambda.RemovePermissionInput{
			FunctionName: aws.String(name),
			StatementId:  aws.String(sid),
		})
		if err != nil {
			base.Status = fix.FixFailed
			base.Message = "remove permission " + sid + ": " + err.Error()
			return base
		}
		base.Steps = append(base.Steps, "removed Lambda policy statement Sid="+sid)
	}
	base.Status = fix.FixApplied
	return base
}

type lambdaDLQFix struct{ clients *awsdata.Clients }

func (f *lambdaDLQFix) CheckID() string             { return "lambda-dlq-check" }
func (f *lambdaDLQFix) Description() string         { return "Configure Lambda dead-letter queue (SQS)" }
func (f *lambdaDLQFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *lambdaDLQFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func lambdaSanitizeQueueName(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	n = strings.ReplaceAll(n, ":", "-")
	n = strings.ReplaceAll(n, "/", "-")
	n = strings.ReplaceAll(n, " ", "-")
	if len(n) > 60 {
		n = n[:60]
	}
	n = strings.Trim(n, "-")
	if n == "" {
		n = "function"
	}
	return "bptools-lambda-dlq-" + n
}

func (f *lambdaDLQFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	name := strings.TrimSpace(resourceID)
	if name == "" {
		base.Status = fix.FixFailed
		base.Message = "missing function name"
		return base
	}

	cfg, err := f.clients.Lambda.GetFunctionConfiguration(fctx.Ctx, &lambda.GetFunctionConfigurationInput{
		FunctionName: aws.String(name),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get function configuration: " + err.Error()
		return base
	}
	if cfg.DeadLetterConfig != nil && cfg.DeadLetterConfig.TargetArn != nil && strings.TrimSpace(*cfg.DeadLetterConfig.TargetArn) != "" {
		base.Status = fix.FixSkipped
		base.Message = "dead-letter queue already configured"
		return base
	}

	queueName := lambdaSanitizeQueueName(name)
	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{
			"would create or reuse SQS queue " + queueName,
			"would set Lambda dead-letter queue target to that SQS queue",
		}
		return base
	}

	createOut, err := f.clients.SQS.CreateQueue(fctx.Ctx, &sqs.CreateQueueInput{
		QueueName: aws.String(queueName),
		Attributes: map[string]string{
			string(sqstypes.QueueAttributeNameSqsManagedSseEnabled): "true",
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "create queue: " + err.Error()
		return base
	}
	if createOut.QueueUrl == nil || strings.TrimSpace(*createOut.QueueUrl) == "" {
		base.Status = fix.FixFailed
		base.Message = "create queue: missing queue URL"
		return base
	}

	attrOut, err := f.clients.SQS.GetQueueAttributes(fctx.Ctx, &sqs.GetQueueAttributesInput{
		QueueUrl: createOut.QueueUrl,
		AttributeNames: []sqstypes.QueueAttributeName{
			sqstypes.QueueAttributeNameQueueArn,
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get queue ARN: " + err.Error()
		return base
	}
	queueARN := strings.TrimSpace(attrOut.Attributes[string(sqstypes.QueueAttributeNameQueueArn)])
	if queueARN == "" {
		base.Status = fix.FixFailed
		base.Message = "queue ARN not returned"
		return base
	}

	_, err = f.clients.Lambda.UpdateFunctionConfiguration(fctx.Ctx, &lambda.UpdateFunctionConfigurationInput{
		FunctionName: aws.String(name),
		DeadLetterConfig: &lambdatypes.DeadLetterConfig{
			TargetArn: aws.String(queueARN),
		},
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update function dead-letter config: " + err.Error()
		return base
	}
	base.Status = fix.FixApplied
	base.Steps = []string{
		"created or reused SQS queue " + queueName,
		"set Lambda dead-letter queue target to " + queueARN,
	}
	return base
}
