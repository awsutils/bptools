package checks

import (
	"fmt"

	"bptools/awsdata"
	"bptools/checker"

	mqtypes "github.com/aws/aws-sdk-go-v2/service/mq/types"
)

func RegisterMQChecks(d *awsdata.Data) {
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
		"This rule checks MQ broker general logging enabled.",
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
		"This rule checks MQ no public access.",
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
		"This rule checks MQ ActiveMQ deployment mode.",
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
		"This rule checks MQ RabbitMQ deployment mode.",
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
		"This rule checks MQ ActiveMQ LDAP authentication.",
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
				ok := b.LdapServerMetadata != nil
				res = append(res, ConfigResource{ID: id, Passing: ok, Detail: "LDAP configured"})
			}
			return res, nil
		},
	))

	// mq-active-single-instance-broker-storage-type-efs
	checker.Register(ConfigCheck(
		"mq-active-single-instance-broker-storage-type-efs",
		"This rule checks MQ ActiveMQ single instance storage type EFS.",
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
