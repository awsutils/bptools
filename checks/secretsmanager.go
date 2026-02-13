package checks

import (
	"strings"
	"time"

	"bptools/awsdata"
	"bptools/checker"
)

// RegisterSecretsManagerChecks registers Secrets Manager checks.
func RegisterSecretsManagerChecks(d *awsdata.Data) {
	checker.Register(EnabledCheck(
		"secretsmanager-rotation-enabled-check",
		"Checks if AWS Secrets Manager secret has rotation enabled. The rule also checks an optional maximumAllowedRotationFrequency parameter. If the parameter is specified, the rotation frequency of the secret is compared with the maximum allowed frequency. The rule is NON_COMPLIANT if the secret is not scheduled for rotation. The rule is also NON_COMPLIANT if the rotation frequency is higher than the number specified in the maximumAllowedRotationFrequency parameter.",
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
		"Checks if AWS Secrets Manager secrets rotated successfully according to the rotation schedule. Secrets Manager calculates the date the rotation should happen. The rule is NON_COMPLIANT if the date passes and the secret isn't rotated.",
		"secretsmanager",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			secrets, err := d.SecretsManagerSecretDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for arn, s := range secrets {
				rotationEnabled := s.RotationEnabled != nil && *s.RotationEnabled
				ok := true
				detail := "Rotation not enabled"
				if rotationEnabled {
					if s.NextRotationDate == nil {
						ok = false
						detail = "Rotation enabled but NextRotationDate missing"
					} else if s.NextRotationDate.Before(time.Now()) {
						ok = false
						detail = "Rotation enabled and next rotation is overdue"
					} else {
						ok = true
						detail = "Rotation schedule is current"
					}
				}
				res = append(res, ConfigResource{ID: arn, Passing: ok, Detail: detail})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"secretsmanager-secret-periodic-rotation",
		"Checks if AWS Secrets Manager secrets have been rotated in the past specified number of days. The rule is NON_COMPLIANT if a secret has not been rotated for more than maxDaysSinceRotation number of days. The default value is 90 days.",
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
		"Checks if AWS Secrets Manager secrets have been accessed within a specified number of days. The rule is NON_COMPLIANT if a secret has not been accessed in 'unusedForDays' number of days. The default value is 90 days.",
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
		"Checks if all secrets in AWS Secrets Manager are encrypted using the AWS managed key (aws/secretsmanager) or a customer managed key that was created in AWS Key Management Service (AWS KMS). The rule is COMPLIANT if a secret is encrypted using a customer managed key. This rule is NON_COMPLIANT if a secret is encrypted using aws/secretsmanager.",
		"secretsmanager",
		d,
		func(d *awsdata.Data) ([]EncryptionResource, error) {
			secrets, err := d.SecretsManagerSecretDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []EncryptionResource
			for arn, s := range secrets {
				encrypted := false
				if s.KmsKeyId != nil {
					kms := strings.TrimSpace(strings.ToLower(*s.KmsKeyId))
					encrypted = kms != "" && !strings.Contains(kms, "alias/aws/secretsmanager")
				}
				res = append(res, EncryptionResource{ID: arn, Encrypted: encrypted})
			}
			return res, nil
		},
	))
}
