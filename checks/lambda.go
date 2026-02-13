package checks

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"bptools/awsdata"
	"bptools/checker"

	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

func funcName(f lambdatypes.FunctionConfiguration) string {
	if f.FunctionName != nil {
		return *f.FunctionName
	}
	if f.FunctionArn != nil {
		return *f.FunctionArn
	}
	return "unknown"
}

// RegisterLambdaChecks registers all Lambda best-practice checks.
func RegisterLambdaChecks(d *awsdata.Data) {
	// lambda-function-description
	checker.Register(DescriptionCheck(
		"lambda-function-description",
		"Checks if AWS Lambda functions have a description. The rule is NON_COMPLIANT if configuration.description does not exist or is an empty string.",
		"lambda", d,
		func(d *awsdata.Data) ([]DescriptionResource, error) {
			funcs, err := d.LambdaFunctions.Get()
			if err != nil {
				return nil, err
			}
			var out []DescriptionResource
			for _, f := range funcs {
				out = append(out, DescriptionResource{
					ID:             funcName(f),
					HasDescription: f.Description != nil && *f.Description != "",
				})
			}
			return out, nil
		},
	))

	// lambda-function-xray-enabled
	checker.Register(EnabledCheck(
		"lambda-function-xray-enabled",
		"Checks if AWS X-Ray is enabled on AWS Lambda functions.The rule is NON_COMPLIANT if X-Ray tracing is disabled for a Lambda function.",
		"lambda", d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			funcs, err := d.LambdaFunctions.Get()
			if err != nil {
				return nil, err
			}
			var out []EnabledResource
			for _, f := range funcs {
				out = append(out, EnabledResource{
					ID:      funcName(f),
					Enabled: f.TracingConfig != nil && f.TracingConfig.Mode == lambdatypes.TracingModeActive,
				})
			}
			return out, nil
		},
	))

	// lambda-inside-vpc
	checker.Register(ConfigCheck(
		"lambda-inside-vpc",
		"Checks if a Lambda function is allowed access to a virtual private cloud (VPC). The rule is NON_COMPLIANT if the Lambda function is not VPC enabled.",
		"lambda", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			funcs, err := d.LambdaFunctions.Get()
			if err != nil {
				return nil, err
			}
			var out []ConfigResource
			for _, f := range funcs {
				inVpc := f.VpcConfig != nil && len(f.VpcConfig.SubnetIds) > 0
				detail := "Function is deployed inside a VPC"
				if !inVpc {
					detail = "Function is not deployed inside a VPC"
				}
				out = append(out, ConfigResource{
					ID:      funcName(f),
					Passing: inVpc,
					Detail:  detail,
				})
			}
			return out, nil
		},
	))

	// lambda-vpc-multi-az-check
	checker.Register(ConfigCheck(
		"lambda-vpc-multi-az-check",
		"Checks if Lambda has more than 1 availability zone associated. The rule is NON_COMPLIANT if only 1 availability zone is associated with the Lambda or the number of availability zones associated is less than number specified in the optional parameter.",
		"lambda", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			funcs, err := d.LambdaFunctions.Get()
			if err != nil {
				return nil, err
			}
			subnets, err := d.EC2Subnets.Get()
			if err != nil {
				return nil, err
			}
			subnetAZ := make(map[string]string)
			for _, subnet := range subnets {
				if subnet.SubnetId == nil || subnet.AvailabilityZone == nil {
					continue
				}
				subnetAZ[*subnet.SubnetId] = *subnet.AvailabilityZone
			}
			var out []ConfigResource
			for _, f := range funcs {
				if f.VpcConfig == nil || len(f.VpcConfig.SubnetIds) == 0 {
					out = append(out, ConfigResource{
						ID:      funcName(f),
						Passing: false,
						Detail:  "Function is not in a VPC",
					})
					continue
				}
				azs := make(map[string]bool)
				for _, subnetID := range f.VpcConfig.SubnetIds {
					if az, ok := subnetAZ[subnetID]; ok {
						azs[az] = true
					}
				}
				multiAz := len(azs) >= 2
				detail := fmt.Sprintf("Function spans %d AZ(s)", len(azs))
				out = append(out, ConfigResource{
					ID:      funcName(f),
					Passing: multiAz,
					Detail:  detail,
				})
			}
			return out, nil
		},
	))

	// lambda-dlq-check
	checker.Register(ConfigCheck(
		"lambda-dlq-check",
		"Checks whether an AWS Lambda function is configured with a dead-letter queue. The rule is NON_COMPLIANT if the Lambda function is not configured with a dead-letter queue.",
		"lambda", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			funcs, err := d.LambdaFunctions.Get()
			if err != nil {
				return nil, err
			}
			var out []ConfigResource
			for _, f := range funcs {
				hasDlq := f.DeadLetterConfig != nil && f.DeadLetterConfig.TargetArn != nil && *f.DeadLetterConfig.TargetArn != ""
				detail := "Dead-letter queue is configured"
				if !hasDlq {
					detail = "No dead-letter queue configured"
				}
				out = append(out, ConfigResource{
					ID:      funcName(f),
					Passing: hasDlq,
					Detail:  detail,
				})
			}
			return out, nil
		},
	))

	// lambda-function-settings-check
	checker.Register(ConfigCheck(
		"lambda-function-settings-check",
		"Checks if the AWS Lambda function settings for runtime, role, timeout, and memory size match the expected values. The rule ignores functions with the 'Image' package type and functions with runtime set to 'OS-only Runtime'. The rule is NON_COMPLIANT if the Lambda function settings do not match the expected values.",
		"lambda", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			funcs, err := d.LambdaFunctions.Get()
			if err != nil {
				return nil, err
			}
			allowedRuntimes := lambdaParseCSV(strings.TrimSpace(os.Getenv("BPTOOLS_LAMBDA_ALLOWED_RUNTIMES")))
			allowedRoles := lambdaParseCSV(strings.TrimSpace(os.Getenv("BPTOOLS_LAMBDA_ALLOWED_ROLE_ARNS")))
			maxTimeout := lambdaParseInt32Env("BPTOOLS_LAMBDA_MAX_TIMEOUT_SECONDS")
			minMemory := lambdaParseInt32Env("BPTOOLS_LAMBDA_MIN_MEMORY_MB")
			maxMemory := lambdaParseInt32Env("BPTOOLS_LAMBDA_MAX_MEMORY_MB")
			if maxTimeout == nil {
				defaultTimeout := int32(900)
				maxTimeout = &defaultTimeout
			}
			if minMemory == nil {
				defaultMinMemory := int32(128)
				minMemory = &defaultMinMemory
			}
			if maxMemory == nil {
				defaultMaxMemory := int32(10240)
				maxMemory = &defaultMaxMemory
			}
			allowedRuntimeSet := make(map[string]bool, len(allowedRuntimes))
			for _, runtime := range allowedRuntimes {
				allowedRuntimeSet[strings.ToLower(runtime)] = true
			}
			allowedRoleSet := make(map[string]bool, len(allowedRoles))
			for _, role := range allowedRoles {
				allowedRoleSet[strings.ToLower(role)] = true
			}
			var out []ConfigResource
			for _, f := range funcs {
				ok := true
				var issues []string
				runtime := strings.TrimSpace(strings.ToLower(string(f.Runtime)))
				role := ""
				if f.Role != nil {
					role = strings.TrimSpace(strings.ToLower(*f.Role))
				}
				timeout := int32(0)
				if f.Timeout != nil {
					timeout = *f.Timeout
				}
				memory := int32(0)
				if f.MemorySize != nil {
					memory = *f.MemorySize
				}
				if len(allowedRuntimeSet) > 0 && !allowedRuntimeSet[runtime] {
					ok = false
					issues = append(issues, fmt.Sprintf("runtime '%s' not in allowed list", string(f.Runtime)))
				}
				if len(allowedRoleSet) > 0 && !allowedRoleSet[role] {
					ok = false
					issues = append(issues, fmt.Sprintf("role '%s' not in allowed list", role))
				}
				if maxTimeout != nil && timeout > *maxTimeout {
					ok = false
					issues = append(issues, fmt.Sprintf("timeout %d exceeds max %d", timeout, *maxTimeout))
				}
				if minMemory != nil && memory < *minMemory {
					ok = false
					issues = append(issues, fmt.Sprintf("memory %d below min %d", memory, *minMemory))
				}
				if maxMemory != nil && memory > *maxMemory {
					ok = false
					issues = append(issues, fmt.Sprintf("memory %d exceeds max %d", memory, *maxMemory))
				}
				detail := "Function settings comply with configured policy"
				if len(issues) > 0 {
					detail = strings.Join(issues, "; ")
				}
				out = append(out, ConfigResource{
					ID:      funcName(f),
					Passing: ok,
					Detail:  detail,
				})
			}
			return out, nil
		},
	))

	// lambda-concurrency-check
	checker.Register(&BaseCheck{
		CheckID: "lambda-concurrency-check",
		Desc:    "Checks if the Lambda function is configured with a function-level concurrent execution limit. The rule is NON_COMPLIANT if the Lambda function is not configured with a function-level concurrent execution limit.",
		Svc:     "lambda",
		RunFunc: func() []checker.Result {
			funcs, err := d.LambdaFunctions.Get()
			if err != nil {
				return []checker.Result{{CheckID: "lambda-concurrency-check", Status: checker.StatusError, Message: err.Error()}}
			}
			if len(funcs) == 0 {
				return []checker.Result{{CheckID: "lambda-concurrency-check", Status: checker.StatusSkip, Message: "No resources found"}}
			}
			var results []checker.Result
			for _, f := range funcs {
				name := funcName(f)
				out, err := d.Clients.Lambda.GetFunctionConcurrency(d.Ctx, &lambda.GetFunctionConcurrencyInput{
					FunctionName: f.FunctionName,
				})
				if err != nil {
					results = append(results, checker.Result{CheckID: "lambda-concurrency-check", ResourceID: name, Status: checker.StatusError, Message: err.Error()})
					continue
				}
				if out.ReservedConcurrentExecutions != nil && *out.ReservedConcurrentExecutions > 0 {
					results = append(results, checker.Result{
						CheckID:    "lambda-concurrency-check",
						ResourceID: name,
						Status:     checker.StatusPass,
						Message:    fmt.Sprintf("Reserved concurrency set to %d", *out.ReservedConcurrentExecutions),
					})
				} else {
					results = append(results, checker.Result{
						CheckID:    "lambda-concurrency-check",
						ResourceID: name,
						Status:     checker.StatusFail,
						Message:    "No reserved concurrency configured",
					})
				}
			}
			return results
		},
	})

	// lambda-function-public-access-prohibited
	checker.Register(&BaseCheck{
		CheckID: "lambda-function-public-access-prohibited",
		Desc:    "Checks if the Lambda function is configured with a function-level concurrent execution limit. The rule is NON_COMPLIANT if the Lambda function is not configured with a function-level concurrent execution limit.",
		Svc:     "lambda",
		RunFunc: func() []checker.Result {
			funcs, err := d.LambdaFunctions.Get()
			if err != nil {
				return []checker.Result{{CheckID: "lambda-function-public-access-prohibited", Status: checker.StatusError, Message: err.Error()}}
			}
			if len(funcs) == 0 {
				return []checker.Result{{CheckID: "lambda-function-public-access-prohibited", Status: checker.StatusSkip, Message: "No resources found"}}
			}
			var results []checker.Result
			for _, f := range funcs {
				name := funcName(f)
				out, err := d.Clients.Lambda.GetPolicy(d.Ctx, &lambda.GetPolicyInput{
					FunctionName: f.FunctionName,
				})
				if err != nil {
					// No policy means no public access
					if strings.Contains(err.Error(), "ResourceNotFoundException") {
						results = append(results, checker.Result{
							CheckID:    "lambda-function-public-access-prohibited",
							ResourceID: name,
							Status:     checker.StatusPass,
							Message:    "No resource policy found",
						})
					} else {
						results = append(results, checker.Result{
							CheckID:    "lambda-function-public-access-prohibited",
							ResourceID: name,
							Status:     checker.StatusError,
							Message:    err.Error(),
						})
					}
					continue
				}
				public := isLambdaPolicyPublic(out.Policy)
				if public {
					results = append(results, checker.Result{
						CheckID:    "lambda-function-public-access-prohibited",
						ResourceID: name,
						Status:     checker.StatusFail,
						Message:    "Function policy allows public access",
					})
				} else {
					results = append(results, checker.Result{
						CheckID:    "lambda-function-public-access-prohibited",
						ResourceID: name,
						Status:     checker.StatusPass,
						Message:    "Function policy does not allow public access",
					})
				}
			}
			return results
		},
	})
}

func lambdaParseCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func lambdaParseInt32Env(name string) *int32 {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return nil
	}
	val := int32(parsed)
	return &val
}

// isLambdaPolicyPublic checks whether a Lambda resource policy allows public invocation.
func isLambdaPolicyPublic(policy *string) bool {
	if policy == nil || *policy == "" {
		return false
	}
	var doc struct {
		Statement []struct {
			Effect    string      `json:"Effect"`
			Principal interface{} `json:"Principal"`
			Condition interface{} `json:"Condition"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(*policy), &doc); err != nil {
		return false
	}
	for _, stmt := range doc.Statement {
		if stmt.Effect != "Allow" {
			continue
		}
		if stmt.Condition != nil {
			continue
		}
		switch p := stmt.Principal.(type) {
		case string:
			if p == "*" {
				return true
			}
		case map[string]interface{}:
			if aws, ok := p["AWS"]; ok {
				switch v := aws.(type) {
				case string:
					if v == "*" {
						return true
					}
				case []interface{}:
					for _, item := range v {
						if s, ok := item.(string); ok && s == "*" {
							return true
						}
					}
				}
			}
		}
	}
	return false
}
