package fixes

import (
	"fmt"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rum"
)

// ── rum-app-monitor-cloudwatch-logs-enabled ───────────────────────────────────

type rumCWLoggingFix struct{ clients *awsdata.Clients }

func (f *rumCWLoggingFix) CheckID() string { return "rum-app-monitor-cloudwatch-logs-enabled" }
func (f *rumCWLoggingFix) Description() string {
	return "Enable CloudWatch Logs on CloudWatch RUM app monitor"
}
func (f *rumCWLoggingFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *rumCWLoggingFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *rumCWLoggingFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	out, err := f.clients.RUM.GetAppMonitor(fctx.Ctx, &rum.GetAppMonitorInput{
		Name: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get app monitor: " + err.Error()
		return base
	}
	if out.AppMonitor != nil && out.AppMonitor.DataStorage != nil &&
		out.AppMonitor.DataStorage.CwLog != nil &&
		out.AppMonitor.DataStorage.CwLog.CwLogEnabled != nil &&
		*out.AppMonitor.DataStorage.CwLog.CwLogEnabled {
		base.Status = fix.FixSkipped
		base.Message = "CloudWatch Logs already enabled"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would enable CloudWatch Logs on RUM app monitor %s", resourceID)}
		return base
	}

	_, err = f.clients.RUM.UpdateAppMonitor(fctx.Ctx, &rum.UpdateAppMonitorInput{
		Name:         aws.String(resourceID),
		CwLogEnabled: aws.Bool(true),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update app monitor: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("enabled CloudWatch Logs on RUM app monitor %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}
