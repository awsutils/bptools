package checks

import (
	"fmt"
	"strings"

	"bptools/awsdata"
	"bptools/checker"

	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cloudtrailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// RegisterCloudTrailChecks registers CloudTrail checks.
func RegisterCloudTrailChecks(d *awsdata.Data) {
	checker.Register(EnabledCheck(
		"cloudtrail-enabled",
		"This rule checks enabled state for CloudTrail.",
		"cloudtrail",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			statuses, err := d.CloudTrailTrailStatus.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for name, st := range statuses {
				enabled := st.IsLogging != nil && *st.IsLogging
				res = append(res, EnabledResource{ID: name, Enabled: enabled})
			}
			return res, nil
		},
	))

	checker.Register(EnabledCheck(
		"cloud-trail-cloud-watch-logs-enabled",
		"This rule checks enabled state for cloud trail cloud watch logs.",
		"cloudtrail",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			trails, err := d.CloudTrailTrailDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for id, t := range trails {
				enabled := t.CloudWatchLogsLogGroupArn != nil && *t.CloudWatchLogsLogGroupArn != ""
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	checker.Register(EnabledCheck(
		"cloud-trail-encryption-enabled",
		"This rule checks enabled state for cloud trail encryption.",
		"cloudtrail",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			trails, err := d.CloudTrailTrailDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for id, t := range trails {
				enabled := t.KmsKeyId != nil && *t.KmsKeyId != ""
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	checker.Register(EnabledCheck(
		"cloud-trail-log-file-validation-enabled",
		"This rule checks enabled state for cloud trail log file validation.",
		"cloudtrail",
		d,
		func(d *awsdata.Data) ([]EnabledResource, error) {
			trails, err := d.CloudTrailTrailDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []EnabledResource
			for id, t := range trails {
				enabled := t.LogFileValidationEnabled != nil && *t.LogFileValidationEnabled
				res = append(res, EnabledResource{ID: id, Enabled: enabled})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"cloudtrail-security-trail-enabled",
		"This rule checks cloudtrail security trail enabled.",
		"cloudtrail",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			trails, err := d.CloudTrailTrailDetails.Get()
			if err != nil {
				return nil, err
			}
			statuses, err := d.CloudTrailTrailStatus.Get()
			if err != nil {
				return nil, err
			}
			events, err := d.CloudTrailEventSelectors.Get()
			if err != nil {
				return nil, err
			}
			if len(trails) == 0 {
				return []ConfigResource{{ID: "account", Passing: false, Detail: "No CloudTrail trails found"}}, nil
			}
			for id, t := range trails {
				st, hasStatus := getTrailStatus(statuses, id, t)
				if !hasStatus || st.IsLogging == nil || !*st.IsLogging {
					continue
				}
				ev, hasEvents := getTrailEventSelectors(events, id, t)
				if !hasEvents {
					continue
				}
				if (t.IsMultiRegionTrail != nil && *t.IsMultiRegionTrail) &&
					(t.IncludeGlobalServiceEvents != nil && *t.IncludeGlobalServiceEvents) &&
					(t.LogFileValidationEnabled != nil && *t.LogFileValidationEnabled) &&
					(t.KmsKeyId != nil && *t.KmsKeyId != "") &&
					(t.CloudWatchLogsLogGroupArn != nil && *t.CloudWatchLogsLogGroupArn != "") &&
					hasManagementEventsAllReadWrite(ev.EventSelectors, ev.AdvancedEventSelectors) {
					return []ConfigResource{{ID: "account", Passing: true, Detail: fmt.Sprintf("Compliant security trail found: %s", id)}}, nil
				}
			}
			return []ConfigResource{{ID: "account", Passing: false, Detail: "No trail meets required security-trail conditions"}}, nil
		},
	))

	checker.Register(ConfigCheck(
		"cloudtrail-s3-dataevents-enabled",
		"This rule checks cloudtrail s3 dataevents enabled.",
		"cloudtrail",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			trails, err := d.CloudTrailTrailDetails.Get()
			if err != nil {
				return nil, err
			}
			statuses, err := d.CloudTrailTrailStatus.Get()
			if err != nil {
				return nil, err
			}
			events, err := d.CloudTrailEventSelectors.Get()
			if err != nil {
				return nil, err
			}
			if len(trails) == 0 {
				return []ConfigResource{{ID: "account", Passing: false, Detail: "No CloudTrail trails found"}}, nil
			}
			for id, t := range trails {
				st, hasStatus := getTrailStatus(statuses, id, t)
				if !hasStatus || st.IsLogging == nil || !*st.IsLogging {
					continue
				}
				ev, hasEvents := getTrailEventSelectors(events, id, t)
				if !hasEvents {
					continue
				}
				if hasS3DataEvents(ev.EventSelectors, ev.AdvancedEventSelectors) {
					return []ConfigResource{{ID: "account", Passing: true, Detail: fmt.Sprintf("S3 data events enabled on trail: %s", id)}}, nil
				}
			}
			return []ConfigResource{{ID: "account", Passing: false, Detail: "No logging trail has S3 data events enabled"}}, nil
		},
	))

	checker.Register(ConfigCheck(
		"cloudtrail-all-read-s3-data-event-check",
		"This rule checks cloudtrail all read s3 data event check.",
		"cloudtrail",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			trails, err := d.CloudTrailTrailDetails.Get()
			if err != nil {
				return nil, err
			}
			statuses, err := d.CloudTrailTrailStatus.Get()
			if err != nil {
				return nil, err
			}
			events, err := d.CloudTrailEventSelectors.Get()
			if err != nil {
				return nil, err
			}
			if len(trails) == 0 {
				return []ConfigResource{{ID: "account", Passing: false, Detail: "No CloudTrail trails found"}}, nil
			}
			for id, t := range trails {
				if t.IsMultiRegionTrail == nil || !*t.IsMultiRegionTrail {
					continue
				}
				st, hasStatus := getTrailStatus(statuses, id, t)
				if !hasStatus || st.IsLogging == nil || !*st.IsLogging {
					continue
				}
				ev, hasEvents := getTrailEventSelectors(events, id, t)
				if !hasEvents {
					continue
				}
				if s3DataEventReadWrite(ev.EventSelectors, ev.AdvancedEventSelectors, cloudtrailtypes.ReadWriteTypeReadOnly) {
					return []ConfigResource{{ID: "account", Passing: true, Detail: fmt.Sprintf("All-read S3 data events found on multi-region trail: %s", id)}}, nil
				}
			}
			return []ConfigResource{{ID: "account", Passing: false, Detail: "No multi-region logging trail captures all-read S3 data events"}}, nil
		},
	))

	checker.Register(ConfigCheck(
		"cloudtrail-all-write-s3-data-event-check",
		"This rule checks cloudtrail all write s3 data event check.",
		"cloudtrail",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			trails, err := d.CloudTrailTrailDetails.Get()
			if err != nil {
				return nil, err
			}
			statuses, err := d.CloudTrailTrailStatus.Get()
			if err != nil {
				return nil, err
			}
			events, err := d.CloudTrailEventSelectors.Get()
			if err != nil {
				return nil, err
			}
			if len(trails) == 0 {
				return []ConfigResource{{ID: "account", Passing: false, Detail: "No CloudTrail trails found"}}, nil
			}
			for id, t := range trails {
				if t.IsMultiRegionTrail == nil || !*t.IsMultiRegionTrail {
					continue
				}
				st, hasStatus := getTrailStatus(statuses, id, t)
				if !hasStatus || st.IsLogging == nil || !*st.IsLogging {
					continue
				}
				ev, hasEvents := getTrailEventSelectors(events, id, t)
				if !hasEvents {
					continue
				}
				if s3DataEventReadWrite(ev.EventSelectors, ev.AdvancedEventSelectors, cloudtrailtypes.ReadWriteTypeWriteOnly) {
					return []ConfigResource{{ID: "account", Passing: true, Detail: fmt.Sprintf("All-write S3 data events found on multi-region trail: %s", id)}}, nil
				}
			}
			return []ConfigResource{{ID: "account", Passing: false, Detail: "No multi-region logging trail captures all-write S3 data events"}}, nil
		},
	))

	checker.Register(LoggingCheck(
		"cloudtrail-s3-bucket-access-logging",
		"This rule checks cloudtrail s3 bucket access logging.",
		"cloudtrail",
		d,
		func(d *awsdata.Data) ([]LoggingResource, error) {
			trails, err := d.CloudTrailTrailDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []LoggingResource
			for id, t := range trails {
				bucket := ""
				if t.S3BucketName != nil {
					bucket = *t.S3BucketName
				}
				if bucket == "" {
					res = append(res, LoggingResource{ID: id, Logging: false})
					continue
				}
				out, err := d.Clients.S3.GetBucketLogging(d.Ctx, &s3.GetBucketLoggingInput{Bucket: &bucket})
				logging := err == nil && out.LoggingEnabled != nil
				res = append(res, LoggingResource{ID: id, Logging: logging})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"cloudtrail-s3-bucket-public-access-prohibited",
		"This rule checks cloudtrail s3 bucket public access prohibited.",
		"cloudtrail",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			trails, err := d.CloudTrailTrailDetails.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for id, t := range trails {
				bucket := ""
				if t.S3BucketName != nil {
					bucket = *t.S3BucketName
				}
				if bucket == "" {
					res = append(res, ConfigResource{ID: id, Passing: false, Detail: "No bucket configured"})
					continue
				}
				out, err := d.Clients.S3.GetPublicAccessBlock(d.Ctx, &s3.GetPublicAccessBlockInput{Bucket: &bucket})
				blocked := err == nil && out.PublicAccessBlockConfiguration != nil &&
					out.PublicAccessBlockConfiguration.BlockPublicAcls != nil && *out.PublicAccessBlockConfiguration.BlockPublicAcls &&
					out.PublicAccessBlockConfiguration.IgnorePublicAcls != nil && *out.PublicAccessBlockConfiguration.IgnorePublicAcls &&
					out.PublicAccessBlockConfiguration.BlockPublicPolicy != nil && *out.PublicAccessBlockConfiguration.BlockPublicPolicy &&
					out.PublicAccessBlockConfiguration.RestrictPublicBuckets != nil && *out.PublicAccessBlockConfiguration.RestrictPublicBuckets
				res = append(res, ConfigResource{ID: id, Passing: blocked, Detail: fmt.Sprintf("Public access blocked: %v", blocked)})
			}
			return res, nil
		},
	))

	checker.Register(ConfigCheck(
		"event-data-store-cmk-encryption-enabled",
		"This rule checks event data store cmk encryption enabled.",
		"cloudtrail",
		d,
		func(d *awsdata.Data) ([]ConfigResource, error) {
			stores, err := d.CloudTrailEventDataStores.Get()
			if err != nil {
				return nil, err
			}
			var res []ConfigResource
			for _, s := range stores {
				id := "unknown"
				if s.EventDataStoreArn != nil {
					id = *s.EventDataStoreArn
				}
				if s.EventDataStoreArn == nil {
					res = append(res, ConfigResource{ID: id, Passing: false, Detail: "Missing event data store ARN"})
					continue
				}
				out, err := d.Clients.CloudTrail.GetEventDataStore(d.Ctx, &cloudtrail.GetEventDataStoreInput{EventDataStore: s.EventDataStoreArn})
				if err != nil {
					res = append(res, ConfigResource{ID: id, Passing: false, Detail: fmt.Sprintf("GetEventDataStore failed: %v", err)})
					continue
				}
				kmsConfigured := out.KmsKeyId != nil && *out.KmsKeyId != ""
				res = append(res, ConfigResource{ID: id, Passing: kmsConfigured, Detail: fmt.Sprintf("KmsKeyId configured: %v", kmsConfigured)})
			}
			return res, nil
		},
	))
}

func hasS3DataEvents(selectors []cloudtrailtypes.EventSelector, advanced []cloudtrailtypes.AdvancedEventSelector) bool {
	for _, s := range selectors {
		for _, r := range s.DataResources {
			if r.Type != nil && strings.EqualFold(*r.Type, "AWS::S3::Object") {
				return true
			}
		}
	}
	for _, s := range advanced {
		if advancedSelectorIsS3Data(s) {
			return true
		}
	}
	return false
}

func s3DataEventReadWrite(selectors []cloudtrailtypes.EventSelector, advanced []cloudtrailtypes.AdvancedEventSelector, want cloudtrailtypes.ReadWriteType) bool {
	for _, s := range selectors {
		if !selectorCoversAllS3Objects(s.DataResources) {
			continue
		}
		for _, r := range s.DataResources {
			if r.Type == nil || !strings.EqualFold(*r.Type, "AWS::S3::Object") {
				continue
			}
			if s.ReadWriteType == "" || s.ReadWriteType == cloudtrailtypes.ReadWriteTypeAll || s.ReadWriteType == want {
				return true
			}
		}
	}
	for _, s := range advanced {
		if advancedSelectorMatchesS3ReadWrite(s, want) {
			return true
		}
	}
	return false
}

func getTrailStatus(statuses map[string]cloudtrail.GetTrailStatusOutput, id string, trail cloudtrailtypes.Trail) (cloudtrail.GetTrailStatusOutput, bool) {
	for _, key := range trailLookupKeys(id, trail) {
		if st, ok := statuses[key]; ok {
			return st, true
		}
	}
	return cloudtrail.GetTrailStatusOutput{}, false
}

func getTrailEventSelectors(events map[string]cloudtrail.GetEventSelectorsOutput, id string, trail cloudtrailtypes.Trail) (cloudtrail.GetEventSelectorsOutput, bool) {
	for _, key := range trailLookupKeys(id, trail) {
		if ev, ok := events[key]; ok {
			return ev, true
		}
	}
	return cloudtrail.GetEventSelectorsOutput{}, false
}

func trailLookupKeys(id string, trail cloudtrailtypes.Trail) []string {
	keys := []string{id}
	if trail.TrailARN != nil {
		keys = append(keys, *trail.TrailARN)
	}
	if trail.Name != nil {
		keys = append(keys, *trail.Name)
	}
	uniq := make([]string, 0, len(keys))
	seen := map[string]struct{}{}
	for _, key := range keys {
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		uniq = append(uniq, key)
	}
	return uniq
}

func hasManagementEventsAllReadWrite(selectors []cloudtrailtypes.EventSelector, advanced []cloudtrailtypes.AdvancedEventSelector) bool {
	for _, s := range selectors {
		includeManagement := s.IncludeManagementEvents == nil || *s.IncludeManagementEvents
		if !includeManagement {
			continue
		}
		if len(s.ExcludeManagementEventSources) > 0 {
			continue
		}
		if s.ReadWriteType == "" || s.ReadWriteType == cloudtrailtypes.ReadWriteTypeAll {
			return true
		}
	}
	for _, s := range advanced {
		if advancedSelectorMatchesManagementAllReadWrite(s) {
			return true
		}
	}
	return false
}

func selectorCoversAllS3Objects(resources []cloudtrailtypes.DataResource) bool {
	for _, r := range resources {
		if r.Type == nil || !strings.EqualFold(*r.Type, "AWS::S3::Object") {
			continue
		}
		for _, v := range r.Values {
			if s3SelectorValueRepresentsAllObjects(v) {
				return true
			}
		}
	}
	return false
}

func advancedSelectorIsS3Data(selector cloudtrailtypes.AdvancedEventSelector) bool {
	hasDataCategory := false
	hasS3Type := false
	for _, field := range selector.FieldSelectors {
		if field.Field == nil {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(*field.Field))
		switch name {
		case "eventcategory":
			hasDataCategory = hasCaseInsensitive(field.Equals, "data")
		case "resources.type":
			hasS3Type = hasCaseInsensitive(field.Equals, "aws::s3::object")
		}
	}
	return hasDataCategory && hasS3Type
}

func advancedSelectorMatchesS3ReadWrite(selector cloudtrailtypes.AdvancedEventSelector, want cloudtrailtypes.ReadWriteType) bool {
	if !advancedSelectorIsS3Data(selector) {
		return false
	}

	hasAllS3ARN := false
	readOnlyFieldPresent := false
	readOnlyTrue := false
	readOnlyFalse := false

	for _, field := range selector.FieldSelectors {
		if field.Field == nil {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(*field.Field))
		switch name {
		case "resources.arn":
			if hasS3AllResourcesSelector(field.Equals, field.StartsWith) {
				hasAllS3ARN = true
			}
		case "readonly":
			readOnlyFieldPresent = true
			readOnlyTrue = hasCaseInsensitive(field.Equals, "true")
			readOnlyFalse = hasCaseInsensitive(field.Equals, "false")
		case "eventcategory", "resources.type":
		default:
			if len(field.Equals) > 0 || len(field.NotEquals) > 0 || len(field.StartsWith) > 0 || len(field.NotStartsWith) > 0 || len(field.EndsWith) > 0 || len(field.NotEndsWith) > 0 {
				return false
			}
		}
	}
	if !hasAllS3ARN {
		return false
	}

	if !readOnlyFieldPresent {
		return true
	}
	if want == cloudtrailtypes.ReadWriteTypeReadOnly {
		return readOnlyTrue
	}
	if want == cloudtrailtypes.ReadWriteTypeWriteOnly {
		return readOnlyFalse
	}
	return readOnlyTrue && readOnlyFalse
}

func s3SelectorValueRepresentsAllObjects(value string) bool {
	v := strings.ToLower(strings.TrimSpace(value))
	switch v {
	case "arn:aws:s3", "arn:aws:s3:::", "arn:aws:s3:::*", "arn:aws:s3:::/*":
		return true
	default:
		return false
	}
}

func advancedSelectorMatchesManagementAllReadWrite(selector cloudtrailtypes.AdvancedEventSelector) bool {
	hasManagementCategory := false
	readOnlyFieldPresent := false
	readOnlyTrue := false
	readOnlyFalse := false
	for _, field := range selector.FieldSelectors {
		if field.Field == nil {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(*field.Field))
		switch name {
		case "eventcategory":
			hasManagementCategory = hasCaseInsensitive(field.Equals, "management")
		case "readonly":
			readOnlyFieldPresent = true
			readOnlyTrue = hasCaseInsensitive(field.Equals, "true")
			readOnlyFalse = hasCaseInsensitive(field.Equals, "false")
		default:
			if len(field.Equals) > 0 || len(field.NotEquals) > 0 || len(field.StartsWith) > 0 || len(field.NotStartsWith) > 0 || len(field.EndsWith) > 0 || len(field.NotEndsWith) > 0 {
				return false
			}
		}
	}
	if !hasManagementCategory {
		return false
	}
	return !readOnlyFieldPresent || (readOnlyTrue && readOnlyFalse)
}

func hasS3AllResourcesSelector(equals []string, startsWith []string) bool {
	for _, value := range equals {
		if s3SelectorValueRepresentsAllObjects(value) {
			return true
		}
	}
	for _, value := range startsWith {
		v := strings.ToLower(strings.TrimSpace(value))
		if v == "arn:aws:s3" || v == "arn:aws:s3:::" {
			return true
		}
	}
	return false
}

func hasCaseInsensitive(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), want) {
			return true
		}
	}
	return false
}
