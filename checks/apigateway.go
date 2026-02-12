package checks

import (
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/checker"

	apigwtypes "github.com/aws/aws-sdk-go-v2/service/apigateway/types"
	apigwv2types "github.com/aws/aws-sdk-go-v2/service/apigatewayv2/types"
)

func apigwStageARN(d *awsdata.Data, apiID, stage string) string {
	region := d.Clients.APIGateway.Options().Region
	return fmt.Sprintf("arn:aws:apigateway:%s::/restapis/%s/stages/%s", region, apiID, stage)
}

// RegisterAPIGatewayChecks registers API Gateway v1, v2, and api-gw checks.
func RegisterAPIGatewayChecks(d *awsdata.Data) {
	// apigateway-stage-access-logs-enabled
	checker.Register(LoggingCheck(
		"apigateway-stage-access-logs-enabled",
		"This rule checks access logging is enabled for API Gateway stage.",
		"apigateway",
		d,
		func(d *awsdata.Data) ([]LoggingResource, error) {
			stages, err := d.APIGatewayStages.Get()
			if err != nil {
				return nil, err
			}
			var res []LoggingResource
			for apiID, items := range stages {
				for _, st := range items {
					if st.StageName == nil {
						continue
					}
					ok := st.AccessLogSettings != nil && st.AccessLogSettings.DestinationArn != nil && *st.AccessLogSettings.DestinationArn != ""
					res = append(res, LoggingResource{ID: apiID + ":" + *st.StageName, Logging: ok})
				}
			}
			return res, nil
		},
	))

	// apigateway-stage-description
	checker.Register(DescriptionCheck(
		"apigateway-stage-description",
		"This rule checks descriptions for API Gateway stage exist.",
		"apigateway",
		d,
		func(d *awsdata.Data) ([]DescriptionResource, error) {
			stages, err := d.APIGatewayStages.Get()
			if err != nil {
				return nil, err
			}
			var res []DescriptionResource
			for apiID, items := range stages {
				for _, st := range items {
					if st.StageName == nil {
						continue
					}
					res = append(res, DescriptionResource{ID: apiID + ":" + *st.StageName, Description: st.Description})
				}
			}
			return res, nil
		},
	))

	// apigatewayv2-stage-description
	checker.Register(DescriptionCheck(
		"apigatewayv2-stage-description",
		"This rule checks descriptions for API Gateway v2 stage exist.",
		"apigatewayv2",
		d,
		func(d *awsdata.Data) ([]DescriptionResource, error) {
			stages, err := d.APIGatewayV2Stages.Get()
			if err != nil {
				return nil, err
			}
			var res []DescriptionResource
			for apiID, items := range stages {
				for _, st := range items {
					if st.StageName == nil {
						continue
					}
					res = append(res, DescriptionResource{ID: apiID + ":" + *st.StageName, Description: st.Description})
				}
			}
			return res, nil
		},
	))

	// api-gwv2-access-logs-enabled
	checker.Register(LoggingCheck(
		"api-gwv2-access-logs-enabled",
		"This rule checks access logging is enabled for API gwv2.",
		"apigatewayv2",
		d,
		func(d *awsdata.Data) ([]LoggingResource, error) {
			stages, err := d.APIGatewayV2Stages.Get()
			if err != nil {
				return nil, err
			}
			var res []LoggingResource
			for apiID, items := range stages {
				for _, st := range items {
					if st.StageName == nil {
						continue
					}
					ok := st.AccessLogSettings != nil && st.AccessLogSettings.DestinationArn != nil && *st.AccessLogSettings.DestinationArn != ""
					res = append(res, LoggingResource{ID: apiID + ":" + *st.StageName, Logging: ok})
				}
			}
			return res, nil
		},
	))

	// api-gwv2-authorization-type-configured
	checker.Register(ConfigCheck(
		"api-gwv2-authorization-type-configured",
		"This rule checks API gwv2 authorization type configured.",
		"apigatewayv2",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			routes, err := d.APIGatewayV2Routes.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for apiID, items := range routes {
				for _, r := range items {
					id := apiID
					if r.RouteId != nil {
						id = apiID + ":" + *r.RouteId
					}
					auth := r.AuthorizationType
					ok := auth != apigwv2types.AuthorizationTypeNone
					res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("AuthorizationType: %s", auth)})
				}
			}
			return res, nil
		},
	))

	// api-gwv2-stage-default-route-detailed-metrics-enabled
	checker.Register(EnabledCheck(
		"api-gwv2-stage-default-route-detailed-metrics-enabled",
		"This rule checks enabled state for API gwv2 stage default route detailed metrics.",
		"apigatewayv2",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			stages, err := d.APIGatewayV2Stages.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for apiID, items := range stages {
				for _, st := range items {
					if st.StageName == nil {
						continue
					}
					ok := st.DefaultRouteSettings != nil && st.DefaultRouteSettings.DetailedMetricsEnabled != nil && *st.DefaultRouteSettings.DetailedMetricsEnabled
					res = append(res, EnabledResource{ID: apiID + ":" + *st.StageName, Enabled: ok})
				}
			}
			return res, nil
		},
	))

	// api-gw-associated-with-waf
	checker.Register(EnabledCheck(
		"api-gw-associated-with-waf",
		"This rule checks API Gateway associated with WAF.",
		"apigateway",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			stages, err := d.APIGatewayStages.Get()
			if err != nil {
				return nil, err
			}
			waf, err := d.APIGatewayStageWAF.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for apiID, items := range stages {
				for _, st := range items {
					if st.StageName == nil {
						continue
					}
					arn := apigwStageARN(d, apiID, *st.StageName)
					res = append(res, EnabledResource{ID: apiID + ":" + *st.StageName, Enabled: waf[arn]})
				}
			}
			return res, nil
		},
	))

	// api-gw-cache-enabled-and-encrypted
	checker.Register(ConfigCheck(
		"api-gw-cache-enabled-and-encrypted",
		"This rule checks API Gateway cache enabled and encrypted.",
		"apigateway",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			stages, err := d.APIGatewayStages.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for apiID, items := range stages {
				for _, st := range items {
					if st.StageName == nil {
						continue
					}
					cacheEnabled := st.CacheClusterEnabled
					allMethodsCacheEncrypted := len(st.MethodSettings) > 0
					for _, ms := range st.MethodSettings {
						if !(ms.CachingEnabled && ms.CacheDataEncrypted) {
							allMethodsCacheEncrypted = false
							break
						}
					}
					ok := cacheEnabled && allMethodsCacheEncrypted
					res = append(res, ConfigResource{
						ID:      apiID + ":" + *st.StageName,
						Passing: ok,
						Detail:  fmt.Sprintf("CacheClusterEnabled: %v, all methods cache+encrypt: %v", cacheEnabled, allMethodsCacheEncrypted),
					})
				}
			}
			return res, nil
		},
	))

	// api-gw-endpoint-type-check
	checker.Register(ConfigCheck(
		"api-gw-endpoint-type-check",
		"This rule checks configuration for API Gateway endpoint type.",
		"apigateway",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			apis, err := d.APIGatewayRestAPIs.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, api := range apis {
				id := "unknown"
				if api.Id != nil {
					id = *api.Id
				}
				ok := false
				for _, t := range api.EndpointConfiguration.Types {
					if t == apigwtypes.EndpointTypeRegional || t == apigwtypes.EndpointTypePrivate {
						ok = true
					}
				}
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("Endpoint types: %v", api.EndpointConfiguration.Types)})
			}
			return res, nil
		},
	))

	// api-gw-execution-logging-enabled
	checker.Register(LoggingCheck(
		"api-gw-execution-logging-enabled",
		"This rule checks logging is enabled for API Gateway execution.",
		"apigateway",
		d,
		func(d *awsdata.Data) ([]LoggingResource, error) {
			stages, err := d.APIGatewayStages.Get()
			if err != nil {
				return nil, err
			}
			var res []LoggingResource
			for apiID, items := range stages {
				for _, st := range items {
					if st.StageName == nil {
						continue
					}
					logging := len(st.MethodSettings) > 0
					for _, ms := range st.MethodSettings {
						if ms.LoggingLevel == nil {
							logging = false
							break
						}
						level := strings.ToUpper(*ms.LoggingLevel)
						if level != "ERROR" && level != "INFO" {
							logging = false
							break
						}
					}
					res = append(res, LoggingResource{ID: apiID + ":" + *st.StageName, Logging: logging})
				}
			}
			return res, nil
		},
	))

	// api-gw-rest-api-tagged
	checker.Register(TaggedCheck(
		"api-gw-rest-api-tagged",
		"This rule checks tagging for API Gateway rest API exist.",
		"apigateway",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			apis, err := d.APIGatewayRestAPIs.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.APIGatewayTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, api := range apis {
				if api.Id == nil {
					continue
				}
				res = append(res, TaggedResource{ID: *api.Id, Tags: tags[*api.Id]})
			}
			return res, nil
		},
	))

	// api-gw-ssl-enabled
	checker.Register(ConfigCheck(
		"api-gw-ssl-enabled",
		"This rule checks enabled state for API Gateway SSL.",
		"apigateway",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			stages, err := d.APIGatewayStages.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for apiID, items := range stages {
				for _, st := range items {
					if st.StageName == nil {
						continue
					}
					id := apiID + ":" + *st.StageName
					ok := st.ClientCertificateId != nil && *st.ClientCertificateId != ""
					res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("ClientCertificateId configured: %v", ok)})
				}
			}
			return res, nil
		},
	))

	// api-gw-stage-tagged
	checker.Register(TaggedCheck(
		"api-gw-stage-tagged",
		"This rule checks tagging for API Gateway stage exist.",
		"apigateway",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			stages, err := d.APIGatewayStages.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.APIGatewayStageTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for apiID, items := range stages {
				for _, st := range items {
					if st.StageName == nil {
						continue
					}
					arn := apigwStageARN(d, apiID, *st.StageName)
					res = append(res, TaggedResource{ID: apiID + ":" + *st.StageName, Tags: tags[arn]})
				}
			}
			return res, nil
		},
	))

	// api-gw-xray-enabled
	checker.Register(EnabledCheck(
		"api-gw-xray-enabled",
		"This rule checks X-Ray tracing is enabled for API Gateway.",
		"apigateway",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			stages, err := d.APIGatewayStages.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for apiID, items := range stages {
				for _, st := range items {
					if st.StageName == nil {
						continue
					}
					res = append(res, EnabledResource{ID: apiID + ":" + *st.StageName, Enabled: st.TracingEnabled})
				}
			}
			return res, nil
		},
	))
}
