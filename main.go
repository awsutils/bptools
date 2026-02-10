package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"time"

	"bptools/awsdata"
	"bptools/checker"
	"bptools/checks"
	"bptools/output"
)

func main() {
	var (
		format      = flag.String("format", "text", "Output format: text|json|csv")
		concurrency = flag.Int("concurrency", 4, "Number of concurrent checks")
		ids         = flag.String("ids", "", "Comma-separated list of check IDs to run")
		services    = flag.String("services", "", "Comma-separated list of services to run")
		safe        = flag.Bool("safe", true, "Cap concurrency when running all checks")
		stream      = flag.Bool("stream", true, "Stream results instead of buffering all in memory")
		logLevel    = flag.String("log-level", "warn", "Log level: debug|info|warn|error")
	)
	flag.Parse()

	var level slog.Level
	level.UnmarshalText([]byte(*logLevel))
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	ctx := context.Background()
	clients, err := awsdata.NewClients(ctx)
	if err != nil {
		fatal(err)
	}
	data := awsdata.New(ctx, clients)

	registerAllChecks(data)

	all := checker.All()
	idSet := parseSet(*ids)
	svcSet := parseSet(*services)
	filtered := checker.Filter(all, idSet, svcSet)

	conc := *concurrency
	if *safe && len(idSet) == 0 && len(svcSet) == 0 {
		if conc > 4 {
			conc = 4
		}
		fmt.Fprintln(os.Stderr, "running all checks; concurrency capped to", conc, "(use -services/-ids or -safe=false to override)")
	}
	if conc < 1 {
		conc = 1
	}
	if conc > runtime.NumCPU()*2 {
		conc = runtime.NumCPU() * 2
	}

	slog.Info("startup", "format", *format, "concurrency", conc, "checks", len(filtered), "ids", *ids, "services", *services)

	if *stream {
		if err := runAndStream(filtered, output.ParseFormat(*format), os.Stdout); err != nil {
			fatal(err)
		}
		return
	}

	results := checker.RunAll(filtered, conc)
	if err := output.Write(os.Stdout, results, output.ParseFormat(*format)); err != nil {
		fatal(err)
	}
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

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func runAndStream(checks []checker.Check, format output.Format, w io.Writer) error {
	switch format {
	case output.CSV:
		return streamCSV(checks, w)
	case output.JSON:
		return streamJSON(checks, w)
	default:
		return streamText(checks, w)
	}
}

func streamText(checks []checker.Check, w io.Writer) error {
	for _, c := range checks {
		start := time.Now()
		slog.Debug("stream check start", "id", c.ID())
		results := c.Run()
		slog.Info("stream check done", "id", c.ID(), "results", len(results), "duration", time.Since(start))
		for _, r := range results {
			if _, err := fmt.Fprintf(w, "[%s] %s: %s - %s\n", r.Status, r.CheckID, r.ResourceID, r.Message); err != nil {
				return err
			}
		}
	}
	return nil
}

func streamCSV(checks []checker.Check, w io.Writer) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"check_id", "resource_id", "status", "message"}); err != nil {
		return err
	}
	for _, c := range checks {
		start := time.Now()
		slog.Debug("stream check start", "id", c.ID())
		results := c.Run()
		slog.Info("stream check done", "id", c.ID(), "results", len(results), "duration", time.Since(start))
		for _, r := range results {
			if err := cw.Write([]string{r.CheckID, r.ResourceID, string(r.Status), r.Message}); err != nil {
				return err
			}
		}
	}
	cw.Flush()
	return cw.Error()
}

func streamJSON(checks []checker.Check, w io.Writer) error {
	enc := json.NewEncoder(w)
	if _, err := io.WriteString(w, "["); err != nil {
		return err
	}
	first := true
	for _, c := range checks {
		start := time.Now()
		slog.Debug("stream check start", "id", c.ID())
		results := c.Run()
		slog.Info("stream check done", "id", c.ID(), "results", len(results), "duration", time.Since(start))
		for _, r := range results {
			if !first {
				if _, err := io.WriteString(w, ","); err != nil {
					return err
				}
			}
			first = false
			b, err := json.Marshal(r)
			if err != nil {
				return err
			}
			if _, err := w.Write(b); err != nil {
				return err
			}
		}
	}
	if _, err := io.WriteString(w, "]"); err != nil {
		return err
	}
	_ = enc
	return nil
}
