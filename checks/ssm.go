package checks

import (
	"fmt"
	"os"
	"strings"

	"bptools/awsdata"
	"bptools/checker"

	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// RegisterSSMChecks registers SSM checks.
func RegisterSSMChecks(d *awsdata.Data) {
	checker.Register(ConfigCheck(
		"ssm-automation-block-public-sharing",
		"This rule checks SSM automation block public sharing.",
		"ssm",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			settingID := "/ssm/documents/console/public-sharing-permission"
			out, err := d.Clients.SSM.GetServiceSetting(d.Ctx, &ssm.GetServiceSettingInput{SettingId: &settingID})
			if err != nil {
				return []ConfigResource{{ID: "account", Passing: false, Detail: fmt.Sprintf("GetServiceSetting failed: %v", err)}}, nil
			}
			blocked := out.ServiceSetting != nil && out.ServiceSetting.SettingValue != nil && strings.EqualFold(*out.ServiceSetting.SettingValue, "true")
			return []ConfigResource{{ID: "account", Passing: blocked, Detail: fmt.Sprintf("Public sharing blocked: %v", blocked)}}, nil
		},
	))

	checker.Register(LoggingCheck(
		"ssm-automation-logging-enabled",
		"This rule checks SSM automation logging enabled.",
		"ssm",
		d,
		func(d *awsdata.Data) ([]LoggingResource, error) {
			destinationSettingID := strings.TrimSpace(os.Getenv("BPTOOLS_SSM_AUTOMATION_LOGGING_DESTINATION_SETTING_ID"))
			if destinationSettingID == "" {
				destinationSettingID = "/ssm/automation/customer-script-log-destination"
			}
			destinationOut, err := d.Clients.SSM.GetServiceSetting(d.Ctx, &ssm.GetServiceSettingInput{SettingId: &destinationSettingID})
			if err != nil {
				return []LoggingResource{{ID: "account", Logging: false}}, nil
			}
			destinationValue := ""
			if destinationOut.ServiceSetting != nil && destinationOut.ServiceSetting.SettingValue != nil {
				destinationValue = strings.TrimSpace(*destinationOut.ServiceSetting.SettingValue)
			}
			logGroupSettingID := strings.TrimSpace(os.Getenv("BPTOOLS_SSM_AUTOMATION_LOGGING_LOG_GROUP_SETTING_ID"))
			if logGroupSettingID == "" {
				logGroupSettingID = "/ssm/automation/customer-script-log-group-name"
			}
			logGroupOut, err := d.Clients.SSM.GetServiceSetting(d.Ctx, &ssm.GetServiceSettingInput{SettingId: &logGroupSettingID})
			if err != nil {
				return []LoggingResource{{ID: "account", Logging: false}}, nil
			}
			logGroupValue := ""
			if logGroupOut.ServiceSetting != nil && logGroupOut.ServiceSetting.SettingValue != nil {
				logGroupValue = strings.TrimSpace(*logGroupOut.ServiceSetting.SettingValue)
			}
			enabled := strings.EqualFold(destinationValue, "CloudWatchLogGroup") && logGroupValue != ""
			return []LoggingResource{{ID: "account", Logging: enabled}}, nil
		},
	))

	checker.Register(ConfigCheck(
		"ssm-document-not-public",
		"This rule checks SSM document not public.",
		"ssm",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			docs, err := d.SSMDocuments.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, doc := range docs {
				name := "unknown"
				if doc.Name != nil {
					name = *doc.Name
				}
				if doc.Name == nil || strings.TrimSpace(*doc.Name) == "" {
					res = append(res, ConfigResource{ID: name, Passing: false, Detail: "Missing document name"})
					continue
				}
				out, err := d.Clients.SSM.DescribeDocumentPermission(d.Ctx, &ssm.DescribeDocumentPermissionInput{
					Name:           doc.Name,
					PermissionType: ssmtypes.DocumentPermissionTypeShare,
				})
				if err != nil {
					res = append(res, ConfigResource{ID: name, Passing: false, Detail: fmt.Sprintf("DescribeDocumentPermission failed: %v", err)})
					continue
				}
				public := false
				for _, accountID := range out.AccountIds {
					if strings.EqualFold(accountID, "all") || strings.EqualFold(accountID, "*") {
						public = true
						break
					}
				}
				res = append(res, ConfigResource{ID: name, Passing: !public, Detail: fmt.Sprintf("Public share enabled: %v", public)})
			}
			return res, nil
		},
	))

	checker.Register(TaggedCheck(
		"ssm-document-tagged",
		"This rule checks tagging for SSM document exist.",
		"ssm",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			docs, err := d.SSMDocuments.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.SSMDocumentTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, doc := range docs {
				id := "unknown"
				if doc.Name != nil {
					id = *doc.Name
				}
				res = append(res, TaggedResource{ID: id, Tags: tags[id]})
			}
			return res, nil
		},
	))
}
