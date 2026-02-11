package checks

import (
	"bptools/awsdata"
	"bptools/checker"
)

// BaseCheck provides a reusable base for checks.
type BaseCheck struct {
	CheckID string
	Desc    string
	Svc     string
	RunFunc func() []checker.Result
}

func (b *BaseCheck) ID() string          { return b.CheckID }
func (b *BaseCheck) Description() string { return b.Desc }
func (b *BaseCheck) Service() string     { return b.Svc }
func (b *BaseCheck) Run() []checker.Result {
	r := b.RunFunc()
	if r == nil {
		r = []checker.Result{}
	}
	return r
}

// TaggedResource is a resource with an identifier and tags map.
type TaggedResource struct {
	ID   string
	Tags map[string]string
}

// TaggedCheck creates a check that verifies resources have tags.
func TaggedCheck(id, desc, svc string, d *awsdata.Data, listFn func(*awsdata.Data) ([]TaggedResource, error)) checker.Check {
	return &BaseCheck{
		CheckID: id,
		Desc:    desc,
		Svc:     svc,
		RunFunc: func() []checker.Result {
			resources, err := listFn(d)
			if err != nil {
				return []checker.Result{{CheckID: id, Status: checker.StatusError, Message: err.Error()}}
			}
			if len(resources) == 0 {
				return []checker.Result{{CheckID: id, Status: checker.StatusSkip, Message: "No resources found"}}
			}
			var results []checker.Result
			for _, r := range resources {
				if len(r.Tags) > 0 {
					results = append(results, checker.Result{CheckID: id, ResourceID: r.ID, Status: checker.StatusPass, Message: "Resource is tagged"})
				} else {
					results = append(results, checker.Result{CheckID: id, ResourceID: r.ID, Status: checker.StatusFail, Message: "Resource has no tags"})
				}
			}
			return results
		},
	}
}

// EnabledResource represents a resource with an enabled status.
type EnabledResource struct {
	ID      string
	Enabled bool
}

// EnabledCheck creates a check that verifies a feature is enabled on resources.
func EnabledCheck(id, desc, svc string, d *awsdata.Data, listFn func(*awsdata.Data) ([]EnabledResource, error)) checker.Check {
	return &BaseCheck{
		CheckID: id,
		Desc:    desc,
		Svc:     svc,
		RunFunc: func() []checker.Result {
			resources, err := listFn(d)
			if err != nil {
				return []checker.Result{{CheckID: id, Status: checker.StatusError, Message: err.Error()}}
			}
			if len(resources) == 0 {
				return []checker.Result{{CheckID: id, Status: checker.StatusSkip, Message: "No resources found"}}
			}
			var results []checker.Result
			for _, r := range resources {
				if r.Enabled {
					results = append(results, checker.Result{CheckID: id, ResourceID: r.ID, Status: checker.StatusPass, Message: "Feature is enabled"})
				} else {
					results = append(results, checker.Result{CheckID: id, ResourceID: r.ID, Status: checker.StatusFail, Message: "Feature is not enabled"})
				}
			}
			return results
		},
	}
}

// LoggingResource represents a resource with logging status.
type LoggingResource struct {
	ID      string
	Logging bool
}

// LoggingCheck creates a check that verifies logging is enabled.
func LoggingCheck(id, desc, svc string, d *awsdata.Data, listFn func(*awsdata.Data) ([]LoggingResource, error)) checker.Check {
	return &BaseCheck{
		CheckID: id,
		Desc:    desc,
		Svc:     svc,
		RunFunc: func() []checker.Result {
			resources, err := listFn(d)
			if err != nil {
				return []checker.Result{{CheckID: id, Status: checker.StatusError, Message: err.Error()}}
			}
			if len(resources) == 0 {
				return []checker.Result{{CheckID: id, Status: checker.StatusSkip, Message: "No resources found"}}
			}
			var results []checker.Result
			for _, r := range resources {
				if r.Logging {
					results = append(results, checker.Result{CheckID: id, ResourceID: r.ID, Status: checker.StatusPass, Message: "Logging is enabled"})
				} else {
					results = append(results, checker.Result{CheckID: id, ResourceID: r.ID, Status: checker.StatusFail, Message: "Logging is not enabled"})
				}
			}
			return results
		},
	}
}

// DescriptionResource represents a resource with a description check.
type DescriptionResource struct {
	ID             string
	Description    *string
	HasDescription bool
}

// DescriptionCheck creates a check that verifies resources have descriptions.
func DescriptionCheck(id, desc, svc string, d *awsdata.Data, listFn func(*awsdata.Data) ([]DescriptionResource, error)) checker.Check {
	return &BaseCheck{
		CheckID: id,
		Desc:    desc,
		Svc:     svc,
		RunFunc: func() []checker.Result {
			resources, err := listFn(d)
			if err != nil {
				return []checker.Result{{CheckID: id, Status: checker.StatusError, Message: err.Error()}}
			}
			if len(resources) == 0 {
				return []checker.Result{{CheckID: id, Status: checker.StatusSkip, Message: "No resources found"}}
			}
			var results []checker.Result
			for _, r := range resources {
				if r.HasDescription || (r.Description != nil && *r.Description != "") {
					results = append(results, checker.Result{CheckID: id, ResourceID: r.ID, Status: checker.StatusPass, Message: "Resource has a description"})
				} else {
					results = append(results, checker.Result{CheckID: id, ResourceID: r.ID, Status: checker.StatusFail, Message: "Resource has no description"})
				}
			}
			return results
		},
	}
}

// EncryptionResource represents a resource with encryption status.
type EncryptionResource struct {
	ID        string
	Encrypted bool
}

// EncryptionCheck creates a check that verifies encryption.
func EncryptionCheck(id, desc, svc string, d *awsdata.Data, listFn func(*awsdata.Data) ([]EncryptionResource, error)) checker.Check {
	return &BaseCheck{
		CheckID: id,
		Desc:    desc,
		Svc:     svc,
		RunFunc: func() []checker.Result {
			resources, err := listFn(d)
			if err != nil {
				return []checker.Result{{CheckID: id, Status: checker.StatusError, Message: err.Error()}}
			}
			if len(resources) == 0 {
				return []checker.Result{{CheckID: id, Status: checker.StatusSkip, Message: "No resources found"}}
			}
			var results []checker.Result
			for _, r := range resources {
				if r.Encrypted {
					results = append(results, checker.Result{CheckID: id, ResourceID: r.ID, Status: checker.StatusPass, Message: "Encryption is enabled"})
				} else {
					results = append(results, checker.Result{CheckID: id, ResourceID: r.ID, Status: checker.StatusFail, Message: "Encryption is not enabled"})
				}
			}
			return results
		},
	}
}

// ConfigResource represents a resource with a configuration check.
type ConfigResource struct {
	ID      string
	Passing bool
	Detail  string
}

// ConfigCheck creates a check that verifies configuration.
func ConfigCheck(id, desc, svc string, d *awsdata.Data, listFn func(*awsdata.Data) ([]ConfigResource, error)) checker.Check {
	return &BaseCheck{
		CheckID: id,
		Desc:    desc,
		Svc:     svc,
		RunFunc: func() []checker.Result {
			resources, err := listFn(d)
			if err != nil {
				return []checker.Result{{CheckID: id, Status: checker.StatusError, Message: err.Error()}}
			}
			if len(resources) == 0 {
				return []checker.Result{{CheckID: id, Status: checker.StatusSkip, Message: "No resources found"}}
			}
			var results []checker.Result
			for _, r := range resources {
				if r.Passing {
					results = append(results, checker.Result{CheckID: id, ResourceID: r.ID, Status: checker.StatusPass, Message: r.Detail})
				} else {
					results = append(results, checker.Result{CheckID: id, ResourceID: r.ID, Status: checker.StatusFail, Message: r.Detail})
				}
			}
			return results
		},
	}
}

// SingleCheck creates a check with a single pass/fail result (e.g., account-level checks).
func SingleCheck(id, desc, svc string, d *awsdata.Data, checkFn func(*awsdata.Data) (bool, string, error)) checker.Check {
	return &BaseCheck{
		CheckID: id,
		Desc:    desc,
		Svc:     svc,
		RunFunc: func() []checker.Result {
			pass, msg, err := checkFn(d)
			if err != nil {
				return []checker.Result{{CheckID: id, ResourceID: "account", Status: checker.StatusError, Message: err.Error()}}
			}
			status := checker.StatusFail
			if pass {
				status = checker.StatusPass
			}
			return []checker.Result{{CheckID: id, ResourceID: "account", Status: status, Message: msg}}
		},
	}
}
