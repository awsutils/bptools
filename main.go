package main

import (
	"context"
	"flag"
	"os"
	"runtime"
	"strings"

	"bptools/awsdata"
	"bptools/checker"
	"bptools/checks"
	"bptools/progress"
	"bptools/runstate"
)

func main() {
	var (
		concurrency = flag.Int("concurrency", 20, "Number of concurrent checks")
		ids         = flag.String("ids", "", "Comma-separated list of check IDs to run")
		services    = flag.String("services", "", "Comma-separated list of services to run")
		prefetch    = flag.Bool("prefetch", true, "Prefetch all AWS data caches before running checks")
	)
	flag.Parse()

	ctx := context.Background()
	clients, err := awsdata.NewClients(ctx)
	if err != nil {
		fatal(err)
	}
	data := awsdata.New(ctx, clients)
	tracker := progress.New(os.Stderr)

	registerAllChecks(data)

	all := checker.All()
	idSet := parseSet(*ids)
	svcSet := parseSet(*services)
	filtered := checker.Filter(all, idSet, svcSet)

	conc := *concurrency
	if conc < 1 {
		conc = 1
	}
	if conc > runtime.NumCPU()*2 {
		conc = runtime.NumCPU() * 2
	}

	if *prefetch && len(idSet) == 0 && len(svcSet) == 0 {
		data.PrefetchAllWithHooks(conc, tracker.PrefetchHooks())
	} else if *prefetch && len(svcSet) > 0 {
		data.PrefetchFilteredWithHooks(svcSet, conc, tracker.PrefetchHooks())
	}

	ruleDescriptions := make(map[string]string, len(filtered))
	for _, check := range filtered {
		ruleDescriptions[check.ID()] = check.Description()
	}

	results := checker.RunAllWithHooks(filtered, conc, tracker.RunHooks())
	tracker.ShowResults(results, ruleDescriptions)
	for action := range tracker.Actions() {
		if action != progress.ActionRecheckFailedErrored {
			continue
		}
		recheck := failedErroredChecks(filtered, results)
		if len(recheck) == 0 {
			continue
		}
		failedIDs := failedErroredCheckIDs(results)
		recheckMemoNames := runstate.MemoNamesForChecks(failedIDs)
		if len(recheckMemoNames) > 0 {
			data.ClearMemoNames(recheckMemoNames)
			data.PrefetchMemoNamesWithHooks(recheckMemoNames, conc, tracker.PrefetchHooks())
		} else {
			recheckServices := serviceSetForChecks(recheck)
			if len(recheckServices) > 0 {
				data.ClearFilteredCaches(recheckServices)
				data.PrefetchFilteredWithHooks(recheckServices, conc, tracker.PrefetchHooks())
			}
		}
		recheckDescriptions := make(map[string]string, len(recheck))
		for _, check := range recheck {
			recheckDescriptions[check.ID()] = check.Description()
		}
		results = checker.RunAllWithHooks(recheck, conc, tracker.RunHooks())
		tracker.ShowResults(results, recheckDescriptions)
	}
	tracker.Wait()
}

func registerAllChecks(d *awsdata.Data) {
	checks.RegisterAccountChecks(d)
	checks.RegisterACMChecks(d)
	checks.RegisterACMPcaChecks(d)
	checks.RegisterALBChecks(d)
	checks.RegisterAmplifyChecks(d)
	checks.RegisterAMPChecks(d)
	checks.RegisterAppConfigChecks(d)
	checks.RegisterAppFlowChecks(d)
	checks.RegisterAppIntegrationsChecks(d)
	checks.RegisterAppMeshChecks(d)
	checks.RegisterAppRunnerChecks(d)
	checks.RegisterAppStreamChecks(d)
	checks.RegisterAppSyncChecks(d)
	checks.RegisterAPIGatewayChecks(d)
	checks.RegisterAthenaChecks(d)
	checks.RegisterAuditManagerChecks(d)
	checks.RegisterAutoScalingChecks(d)
	checks.RegisterBackupChecks(d)
	checks.RegisterBatchChecks(d)
	checks.RegisterCassandraChecks(d)
	checks.RegisterCloudFormationChecks(d)
	checks.RegisterCloudFrontChecks(d)
	checks.RegisterCloudTrailChecks(d)
	checks.RegisterCloudWatchChecks(d)
	checks.RegisterCodeBuildChecks(d)
	checks.RegisterCodeDeployChecks(d)
	checks.RegisterCodeGuruChecks(d)
	checks.RegisterCodePipelineChecks(d)
	checks.RegisterCognitoChecks(d)
	checks.RegisterConnectChecks(d)
	checks.RegisterCustomerProfilesChecks(d)
	checks.RegisterDAXChecks(d)
	checks.RegisterDataSyncChecks(d)
	checks.RegisterDMSChecks(d)
	checks.RegisterDocDBChecks(d)
	checks.RegisterDynamoDBChecks(d)
	checks.RegisterEC2Checks(d)
	checks.RegisterECSChecks(d)
	checks.RegisterEFSChecks(d)
	checks.RegisterEKSChecks(d)
	checks.RegisterELBChecks(d)
	checks.RegisterElastiCacheChecks(d)
	checks.RegisterElasticBeanstalkChecks(d)
	checks.RegisterElasticsearchChecks(d)
	checks.RegisterEMRChecks(d)
	checks.RegisterEvidentlyChecks(d)
	checks.RegisterEventBridgeChecks(d)
	checks.RegisterFISChecks(d)
	checks.RegisterFMSChecks(d)
	checks.RegisterFraudDetectorChecks(d)
	checks.RegisterFSxChecks(d)
	checks.RegisterGlueChecks(d)
	checks.RegisterGlobalAcceleratorChecks(d)
	checks.RegisterGuardDutyChecks(d)
	checks.RegisterIAMChecks(d)
	checks.RegisterInspectorChecks(d)
	checks.RegisterIoTChecks(d)
	checks.RegisterIoTSiteWiseChecks(d)
	checks.RegisterIoTTwinMakerChecks(d)
	checks.RegisterIoTExtraChecks(d)
	checks.RegisterIVSChecks(d)
	checks.RegisterKinesisChecks(d)
	checks.RegisterLambdaChecks(d)
	checks.RegisterLightsailChecks(d)
	checks.RegisterMacieChecks(d)
	checks.RegisterMiscSecurityChecks(d)
	checks.RegisterMQChecks(d)
	checks.RegisterMSKChecks(d)
	checks.RegisterNeptuneChecks(d)
	checks.RegisterNetFWChecks(d)
	checks.RegisterNLBChecks(d)
	checks.RegisterOpenSearchChecks(d)
	checks.RegisterRDSChecks(d)
	checks.RegisterRedshiftChecks(d)
	checks.RegisterRUMChecks(d)
	checks.RegisterRoute53Checks(d)
	checks.RegisterS3Checks(d)
	checks.RegisterSageMakerChecks(d)
	checks.RegisterSecretsManagerChecks(d)
	checks.RegisterSecurityHubChecks(d)
	checks.RegisterServiceCatalogChecks(d)
	checks.RegisterShieldChecks(d)
	checks.RegisterSSMChecks(d)
	checks.RegisterTaggingChecks(d)
	checks.RegisterTransferChecks(d)
	checks.RegisterVPCChecks(d)
	checks.RegisterWAFChecks(d)
	checks.RegisterWorkspacesChecks(d)
	checks.RegisterRemainingChecks(d)
}

func parseSet(s string) map[string]bool {
	out := make(map[string]bool)
	for _, v := range strings.Split(s, ",") {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		out[v] = true
	}
	return out
}

func failedErroredChecks(checks []checker.Check, results []checker.Result) []checker.Check {
	ids := failedErroredCheckIDs(results)
	if len(ids) == 0 {
		return nil
	}
	var out []checker.Check
	for _, check := range checks {
		if ids[check.ID()] {
			out = append(out, check)
		}
	}
	return out
}

func failedErroredCheckIDs(results []checker.Result) map[string]bool {
	out := make(map[string]bool)
	for _, result := range results {
		if result.Status != checker.StatusFail && result.Status != checker.StatusError {
			continue
		}
		out[result.CheckID] = true
	}
	return out
}

func serviceSetForChecks(checks []checker.Check) map[string]bool {
	out := make(map[string]bool)
	for _, check := range checks {
		service := strings.TrimSpace(check.Service())
		if service == "" {
			continue
		}
		out[service] = true
	}
	return out
}

func fatal(err error) {
	_ = err
	os.Exit(1)
}
