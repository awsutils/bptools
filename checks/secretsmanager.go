package checks

import (
	"time"

	"bptools/awsdata"
	"bptools/checker"
)

// RegisterSecretsManagerChecks registers Secrets Manager checks.
func RegisterSecretsManagerChecks(d *awsdata.Data) {
	checker.Register(EnabledCheck(
		"secretsmanager-rotation-enabled-check",
		"This rule checks configuration for secretsmanager rotation enabled.",
		"secretsmanager",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			secrets, err := d.SecretsManagerSecretDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for arn, s := range secrets {
				enabled := s.RotationEnabled != nil && *s.RotationEnabled
				res = append(res, EnabledResource{ID: arn, Enabled: enabled})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"secretsmanager-scheduled-rotation-success-check",
		"This rule checks configuration for secretsmanager scheduled rotation success.",
		"secretsmanager",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			secrets, err := d.SecretsManagerSecretDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for arn, s := range secrets {
				ok := s.LastRotatedDate != nil
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: "LastRotatedDate present"})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"secretsmanager-secret-periodic-rotation",
		"This rule checks secretsmanager secret periodic rotation.",
		"secretsmanager",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			secrets, err := d.SecretsManagerSecretDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for arn, s := range secrets {
				ok := false
				if s.LastRotatedDate != nil {
					ok = time.Since(*s.LastRotatedDate) < 90*24*time.Hour
				}
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: "Rotated within 90 days"})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"secretsmanager-secret-unused",
		"This rule checks secretsmanager secret unused.",
		"secretsmanager",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			secrets, err := d.SecretsManagerSecretDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for arn, s := range secrets {
				ok := s.LastAccessedDate != nil && time.Since(*s.LastAccessedDate) < 90*24*time.Hour
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: "Accessed within 90 days"})
			}
			return res, nil
		},
	))

	checker.Register(EncryptionCheck(
		"secretsmanager-using-cmk",
		"This rule checks secretsmanager using CMK.",
		"secretsmanager",
		d,
		func(d *awsdata.Data) ([]EncryptionResource, error) {
			secrets, err := d.SecretsManagerSecretDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []EncryptionResource
			for arn, s := range secrets {
				encrypted := s.KmsKeyId != nil && *s.KmsKeyId != ""
				res = append(res, EncryptionResource{ID: arn, Encrypted: encrypted})
			}
			return res, nil
		},
	))
}
