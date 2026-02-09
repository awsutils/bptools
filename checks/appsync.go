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
		"This rule checks AppSync associated with WAF.",
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
		"This rule checks AppSync authorization check.",
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
		"This rule checks AppSync cache CT encryption at rest.",
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
				enabled := api.AtRestEncryptionEnabled
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	// appsync-cache-ct-encryption-in-transit
	checker.Register(EnabledCheck(
		"appsync-cache-ct-encryption-in-transit",
		"This rule checks AppSync cache CT encryption in transit.",
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
				enabled := api.TransitEncryptionEnabled
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	// appsync-cache-encryption-at-rest
	checker.Register(EnabledCheck(
		"appsync-cache-encryption-at-rest",
		"This rule checks AppSync cache encryption at rest.",
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
				enabled := api.AtRestEncryptionEnabled
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	// appsync-graphql-api-xray-enabled
	checker.Register(EnabledCheck(
		"appsync-graphql-api-xray-enabled",
		"This rule checks AppSync GraphQL API X-Ray enabled.",
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
		"This rule checks AppSync logging enabled.",
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
