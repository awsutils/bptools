package checks

import (
	"fmt"

	"bptools/awsdata"
	"bptools/checker"

	mqtypes "github.com/aws/aws-sdk-go-v2/service/mq/types"
)

func RegisterMQChecks(d *awsdata.Data) {
	checker.Register(ConfigCheck(
		"active-mq-supported-version",
		"Checks if an Amazon MQ ActiveMQ broker is running on a specified minimum supported engine version. The rule is NON_COMPLIANT if the ActiveMQ broker is not running on the minimum supported engine version that you specify.",
		"mq",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			brokers, err := d.MQBrokerDetails.Get()
			if err != nil {
				return nil, err
			}
			versions, err := d.MQBrokerEngineVersions.Get()
			if err != nil {
				return nil, err
			}
			supported := versions[mqtypes.EngineTypeActivemq]
			var res []ConfigResource
			for id, b := range brokers {
				if b.EngineType != mqtypes.EngineTypeActivemq {
					continue
				}
				ok := false
				if b.EngineVersion != nil {
					ok = supported[*b.EngineVersion]
				}
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("EngineVersion: %v", b.EngineVersion)})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"rabbit-mq-supported-version",
		"Checks if an Amazon MQ RabbitMQ broker is running on a specified minimum supported engine version. The rule is NON_COMPLIANT if the RabbitMQ broker is not running on the minimum supported engine version that you specify.",
		"mq",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			brokers, err := d.MQBrokerDetails.Get()
			if err != nil {
				return nil, err
			}
			versions, err := d.MQBrokerEngineVersions.Get()
			if err != nil {
				return nil, err
			}
			supported := versions[mqtypes.EngineTypeRabbitmq]
			var res []ConfigResource
			for id, b := range brokers {
				if b.EngineType != mqtypes.EngineTypeRabbitmq {
					continue
				}
				ok := false
				if b.EngineVersion != nil {
					ok = supported[*b.EngineVersion]
				}
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("EngineVersion: %v", b.EngineVersion)})
			}
			return res, nil
		},
	))
	// mq-automatic-minor-version-upgrade-enabled + mq-auto-minor-version-upgrade-enabled
	for _, id := range []string{"mq-automatic-minor-version-upgrade-enabled", "mq-auto-minor-version-upgrade-enabled"} {
		cid := id
		checker.Register(ConfigCheck(
			cid,
			"This rule checks MQ auto minor version upgrade.",
			"mq",
			d,
			func(d *awsdata.Data) ([]ConfigResource, error) {
				brokers, err := d.MQBrokerDetails.Get()
				if err != nil {
					return nil, err
				}
				var res []ConfigResource
				for id, b := range brokers {
					ok := b.AutoMinorVersionUpgrade != nil && *b.AutoMinorVersionUpgrade
					res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("AutoMinorVersionUpgrade: %v", b.AutoMinorVersionUpgrade)})
				}
				return res, nil
			},
		))
	}

	// mq-broker-general-logging-enabled
	checker.Register(LoggingCheck(
		"mq-broker-general-logging-enabled",
		"Checks if Amazon MQ brokers have general logging enabled. The rule is NON_COMPLIANT if configuration.Logs.General is false.",
		"mq",
		d,
		func(d *awsdata.Data) ([]LoggingResource, error) {
			brokers, err := d.MQBrokerDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []LoggingResource
			for id, b := range brokers {
				logging := b.Logs != nil && b.Logs.General != nil && *b.Logs.General
				res = append(res, LoggingResource{ID: id, Logging: logging})
			}
			return res, nil
		},
	))

	// mq-cloudwatch-audit-logging-enabled + mq-cloudwatch-audit-log-enabled
	for _, id := range []string{"mq-cloudwatch-audit-logging-enabled", "mq-cloudwatch-audit-log-enabled"} {
		cid := id
		checker.Register(LoggingCheck(
			cid,
			"This rule checks MQ audit logging enabled.",
			"mq",
			d,
			func(d *awsdata.Data) ([]LoggingResource, error) {
				brokers, err := d.MQBrokerDetails.Get()
				if err != nil {
					return nil, err
				}
				var res []LoggingResource
				for id, b := range brokers {
					logging := b.Logs != nil && b.Logs.Audit != nil && *b.Logs.Audit
					res = append(res, LoggingResource{ID: id, Logging: logging})
				}
				return res, nil
			},
		))
	}

	// mq-no-public-access
	checker.Register(ConfigCheck(
		"mq-no-public-access",
		"Checks if Amazon MQ brokers are not publicly accessible. The rule is NON_COMPLIANT if the 'PubliclyAccessible' field is set to true for an Amazon MQ broker.",
		"mq",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			brokers, err := d.MQBrokerDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for id, b := range brokers {
				public := b.PubliclyAccessible != nil && *b.PubliclyAccessible
				res = append(res, ConfigResource{ID: id, Passing: !public, Detail: fmt.Sprintf("Public: %v", public)})
			}
			return res, nil
		},
	))

	// mq-active-deployment-mode + mq-rabbit-deployment-mode
	checker.Register(ConfigCheck(
		"mq-active-deployment-mode",
		"Checks the deployment mode configured for Amazon MQ ActiveMQ broker engine. The rule is NON_COMPLIANT if the default single-instance broker mode is being used.",
		"mq",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			brokers, err := d.MQBrokerDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for id, b := range brokers {
				if b.EngineType != mqtypes.EngineTypeActivemq {
					continue
				}
				ok := b.DeploymentMode == mqtypes.DeploymentModeActiveStandbyMultiAz
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("DeploymentMode: %s", b.DeploymentMode)})
			}
			return res, nil
		},
	))
	checker.Register(ConfigCheck(
		"mq-rabbit-deployment-mode",
		"Checks the deployment mode configured for the Amazon MQ RabbitMQ broker engine. The rule is NON_COMPLIANT if the default single-instance broker mode is being used.",
		"mq",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			brokers, err := d.MQBrokerDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for id, b := range brokers {
				if b.EngineType != mqtypes.EngineTypeRabbitmq {
					continue
				}
				ok := b.DeploymentMode == mqtypes.DeploymentModeClusterMultiAz
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("DeploymentMode: %s", b.DeploymentMode)})
			}
			return res, nil
		},
	))

	// mq-active-broker-ldap-authentication
	checker.Register(ConfigCheck(
		"mq-active-broker-ldap-authentication",
		"Checks if Amazon MQ ActiveMQ brokers use the LDAP authentication strategy to secure the broker. The rule is NON_COMPLIANT if configuration.AuthenticationStrategy is not 'ldap'.",
		"mq",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			brokers, err := d.MQBrokerDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for id, b := range brokers {
				if b.EngineType != mqtypes.EngineTypeActivemq {
					continue
				}
				ok := b.AuthenticationStrategy == mqtypes.AuthenticationStrategyLdap
				res = append(res, ConfigResource{
					ID:      id,
					Passing: ok,
					Detail:  fmt.Sprintf("AuthenticationStrategy: %s", b.AuthenticationStrategy),
				})
			}
			return res, nil
		},
	))

	// mq-active-single-instance-broker-storage-type-efs
	checker.Register(ConfigCheck(
		"mq-active-single-instance-broker-storage-type-efs",
		"Checks if an Amazon MQ for ActiveMQ single-instance broker using the mq.m5 instance type family is configured with Amazon Elastic File System (EFS) for broker storage. The rule is NON_COMPLIANT if configuration.StorageType is not 'efs'.",
		"mq",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			brokers, err := d.MQBrokerDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for id, b := range brokers {
				if b.EngineType != mqtypes.EngineTypeActivemq || b.DeploymentMode != mqtypes.DeploymentModeSingleInstance {
					continue
				}
				ok := b.StorageType == mqtypes.BrokerStorageTypeEfs
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: fmt.Sprintf("StorageType: %s", b.StorageType)})
			}
			return res, nil
		},
	))
}
