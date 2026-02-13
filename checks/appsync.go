package checks

import (
	"fmt"

	"bptools/awsdata"
	"bptools/checker"

	appsynctypes "github.com/aws/aws-sdk-go-v2/service/appsync/types"
)

func RegisterAppSyncChecks(d *awsdata.Data) {
	// appsync-associated-with-waf
	checker.Register(EnabledCheck(
		"appsync-associated-with-waf",
		"Checks if AWS AppSync APIs are associated with AWS WAFv2 web access control lists (ACLs). The rule is NON_COMPLIANT for an AWS AppSync API if it is not associated with a web ACL.",
		"appsync",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			apis, err := d.AppSyncAPIs.Get()
			if err != nil {
				return nil, err
			}
			waf, err := d.AppSyncWAFv2WebACLForResource.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, api := range apis {
				if api.Arn == nil {
					continue
				}
				res = append(res, EnabledResource{ID: *api.Arn, Enabled: waf[*api.Arn]})
			}
			return res, nil
		},
	))

	// appsync-authorization-check
	checker.Register(ConfigCheck(
		"appsync-authorization-check",
		"Checks if an AWS AppSync API is using allowed authorization mechanisms. The rule is NON_COMPLIANT if an unapproved authorization mechanism is being used.",
		"appsync",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			apis, err := d.AppSyncAPIs.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, api := range apis {
				id := "unknown"
				if api.Arn != nil {
					id = *api.Arn
				}
				ok := api.AuthenticationType != appsynctypes.AuthenticationTypeApiKey
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("AuthType: %s", api.AuthenticationType)})
			}
			return res, nil
		},
	))

	// appsync-cache-ct-encryption-at-rest
	checker.Register(EnabledCheck(
		"appsync-cache-ct-encryption-at-rest",
		"Checks if an AWS AppSync API cache has encryption at rest enabled. This rule is NON_COMPLIANT if 'AtRestEncryptionEnabled' is false.",
		"appsync",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			apis, err := d.AppSyncAPIs.Get()
			if err != nil {
				return nil, err
			}
			caches, err := d.AppSyncApiCaches.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, api := range apis {
				id := "unknown"
				var cache *appsynctypes.ApiCache
				if api.Arn != nil {
					id = *api.Arn
					cache = caches[*api.Arn]
				}
				enabled := cache != nil && cache.AtRestEncryptionEnabled
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	// appsync-cache-ct-encryption-in-transit
	checker.Register(EnabledCheck(
		"appsync-cache-ct-encryption-in-transit",
		"Checks if an AWS AppSync API cache has encryption in transit enabled. The rule is NON_COMPLIANT if 'TransitEncryptionEnabled' is false.",
		"appsync",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			apis, err := d.AppSyncAPIs.Get()
			if err != nil {
				return nil, err
			}
			caches, err := d.AppSyncApiCaches.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, api := range apis {
				id := "unknown"
				var cache *appsynctypes.ApiCache
				if api.Arn != nil {
					id = *api.Arn
					cache = caches[*api.Arn]
				}
				enabled := cache != nil && cache.TransitEncryptionEnabled
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	// appsync-cache-encryption-at-rest
	checker.Register(EnabledCheck(
		"appsync-cache-encryption-at-rest",
		"Checks if an AWS AppSync API cache has encryption at rest enabled. This rule is NON_COMPLIANT if 'AtRestEncryptionEnabled' is false.",
		"appsync",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			apis, err := d.AppSyncAPIs.Get()
			if err != nil {
				return nil, err
			}
			caches, err := d.AppSyncApiCaches.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, api := range apis {
				id := "unknown"
				var cache *appsynctypes.ApiCache
				if api.Arn != nil {
					id = *api.Arn
					cache = caches[*api.Arn]
				}
				enabled := cache != nil && cache.AtRestEncryptionEnabled
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	// appsync-graphql-api-xray-enabled
	checker.Register(EnabledCheck(
		"appsync-graphql-api-xray-enabled",
		"Checks if AWS AppSync GraphQL APIs have AWS X-Ray tracing enabled. The rule is NON_COMPLIANT if configuration.XrayEnabled is false.",
		"appsync",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			apis, err := d.AppSyncAPIs.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for _, api := range apis {
				id := "unknown"
				if api.Arn != nil {
					id = *api.Arn
				}
				res = append(res, EnabledResource{ID: id, Enabled: api.XrayEnabled})
			}
			return res, nil
		},
	))

	// appsync-logging-enabled
	checker.Register(LoggingCheck(
		"appsync-logging-enabled",
		"Checks if an AWS AppSync API has field level logging enabled. The rule is NON_COMPLIANT if field level logging is not enabled, or if the field logging levels for the AppSync API do not match the values specified in the 'fieldLoggingLevel' parameter.",
		"appsync",
		d,
		func(d *awsdata.Data) ([]LoggingResource, error) {
			apis, err := d.AppSyncAPIs.Get()
			if err != nil {
				return nil, err
			}
			var res []LoggingResource
			for _, api := range apis {
				id := "unknown"
				if api.Arn != nil {
					id = *api.Arn
				}
				logging := api.LogConfig != nil && api.LogConfig.FieldLogLevel != appsynctypes.FieldLogLevelNone
				res = append(res, LoggingResource{ID: id, Logging: logging})
			}
			return res, nil
		},
	))
}
