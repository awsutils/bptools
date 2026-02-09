package checks

import (
	"encoding/json"
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/checker"

	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

// deprecatedRuntimes lists Lambda runtimes that are deprecated.
var deprecatedRuntimes = map[lambdatypes.Runtime]bool{
	lambdatypes.RuntimeNodejs:       true,
	lambdatypes.RuntimeNodejs43:     true,
	lambdatypes.RuntimeNodejs43Edge: true,
	lambdatypes.RuntimeNodejs610:    true,
	lambdatypes.RuntimeNodejs810:    true,
	lambdatypes.RuntimeNodejs10x:    true,
	lambdatypes.RuntimeNodejs12x:    true,
	lambdatypes.RuntimeNodejs14x:    true,
	lambdatypes.RuntimeNodejs16x:    true,
	lambdatypes.RuntimePython27:     true,
	lambdatypes.RuntimePython36:     true,
	lambdatypes.RuntimeJava8:        true,
	lambdatypes.RuntimeDotnetcore10: true,
	lambdatypes.RuntimeDotnetcore20: true,
	lambdatypes.RuntimeDotnetcore21: true,
	lambdatypes.RuntimeDotnetcore31: true,
	lambdatypes.RuntimeDotnet6:      true,
	lambdatypes.RuntimeRuby25:       true,
	lambdatypes.RuntimeRuby27:       true,
}

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
		"Lambda functions should have a description",
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
		"Lambda functions should have X-Ray tracing enabled",
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
		"Lambda functions should be deployed inside a VPC",
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
		"Lambda functions in a VPC should span multiple availability zones",
		"lambda", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			funcs, err := d.LambdaFunctions.Get()
			if err != nil {
				return nil, err
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
				multiAz := len(f.VpcConfig.SubnetIds) >= 2
				detail := fmt.Sprintf("Function has %d subnet(s)", len(f.VpcConfig.SubnetIds))
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
		"Lambda functions should have a dead-letter queue configured",
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
		"Lambda functions should not use deprecated runtimes",
		"lambda", d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			funcs, err := d.LambdaFunctions.Get()
			if err != nil {
				return nil, err
			}
			var out []ConfigResource
			for _, f := range funcs {
				deprecated := deprecatedRuntimes[f.Runtime]
				detail := fmt.Sprintf("Runtime %s is supported", string(f.Runtime))
				if deprecated {
					detail = fmt.Sprintf("Runtime %s is deprecated", string(f.Runtime))
				}
				out = append(out, ConfigResource{
					ID:      funcName(f),
					Passing: !deprecated,
					Detail:  detail,
				})
			}
			return out, nil
		},
	))

	// lambda-concurrency-check
	checker.Register(&BaseCheck{
		CheckID: "lambda-concurrency-check",
		Desc:    "Lambda functions should have reserved concurrency configured",
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
		Desc:    "Lambda function policies should not allow public access",
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
