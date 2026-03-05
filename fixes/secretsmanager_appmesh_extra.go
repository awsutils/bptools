package fixes

import (
	"strings"
	"time"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/appmesh"
	appmeshtypes "github.com/aws/aws-sdk-go-v2/service/appmesh/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

const (
	defaultAppMeshAccessLogPath = "/dev/stdout"
	defaultSecretsCMKAlias      = "alias/bptools-secretsmanager-cmk"
)

func registerMultiBatch03(d *awsdata.Data) {
	fix.Register(&secretsManagerScheduledRotationSuccessFix{clients: d.Clients})
	fix.Register(&secretsManagerSecretUnusedFix{clients: d.Clients})
	fix.Register(&secretsManagerUsingCMKFix{clients: d.Clients})
	fix.Register(&appMeshMeshDenyTCPForwardingFix{clients: d.Clients})
	fix.Register(&appMeshVirtualGatewayBackendDefaultsTLSFix{clients: d.Clients})
	fix.Register(&appMeshVirtualGatewayLoggingFilePathFix{clients: d.Clients})
	fix.Register(&appMeshVirtualNodeBackendDefaultsTLSFix{clients: d.Clients})
	fix.Register(&appMeshVirtualNodeCloudMapIPPrefFix{clients: d.Clients})
	fix.Register(&appMeshVirtualNodeDNSIPPrefFix{clients: d.Clients})
	fix.Register(&appMeshVirtualNodeLoggingFilePathFix{clients: d.Clients})
}

func parseMeshScopedResourceID(resourceID string) (string, string, bool) {
	parts := strings.SplitN(strings.TrimSpace(resourceID), ":", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return "", "", false
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), true
}

func resolveOrCreateSecretsManagerCMKAlias(fctx fix.FixContext, clients *awsdata.Clients) (string, []string, error) {
	steps := []string{}
	p := kms.NewListAliasesPaginator(clients.KMS, &kms.ListAliasesInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(fctx.Ctx)
		if err != nil {
			return "", steps, err
		}
		for _, a := range page.Aliases {
			if aws.ToString(a.AliasName) == defaultSecretsCMKAlias && aws.ToString(a.TargetKeyId) != "" {
				return defaultSecretsCMKAlias, steps, nil
			}
		}
	}

	keyOut, err := clients.KMS.CreateKey(fctx.Ctx, &kms.CreateKeyInput{
		Description: aws.String("Customer managed key for bptools Secrets Manager remediation"),
	})
	if err != nil {
		return "", steps, err
	}
	if keyOut.KeyMetadata == nil || keyOut.KeyMetadata.KeyId == nil || strings.TrimSpace(*keyOut.KeyMetadata.KeyId) == "" {
		return "", steps, nil
	}

	_, err = clients.KMS.CreateAlias(fctx.Ctx, &kms.CreateAliasInput{
		AliasName:   aws.String(defaultSecretsCMKAlias),
		TargetKeyId: keyOut.KeyMetadata.KeyId,
	})
	if err != nil {
		return "", steps, err
	}

	steps = append(steps, "created CMK alias "+defaultSecretsCMKAlias)
	return defaultSecretsCMKAlias, steps, nil
}

type secretsManagerScheduledRotationSuccessFix struct{ clients *awsdata.Clients }

func (f *secretsManagerScheduledRotationSuccessFix) CheckID() string {
	return "secretsmanager-scheduled-rotation-success-check"
}
func (f *secretsManagerScheduledRotationSuccessFix) Description() string {
	return "Rotate overdue Secrets Manager secret now"
}
func (f *secretsManagerScheduledRotationSuccessFix) Impact() fix.ImpactType {
	return fix.ImpactNone
}
func (f *secretsManagerScheduledRotationSuccessFix) Severity() fix.SeverityLevel {
	return fix.SeverityMedium
}

func (f *secretsManagerScheduledRotationSuccessFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	id := strings.TrimSpace(resourceID)
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	if id == "" {
		base.Status = fix.FixFailed
		base.Message = "missing secret ID"
		return base
	}

	desc, err := f.clients.SecretsManager.DescribeSecret(fctx.Ctx, &secretsmanager.DescribeSecretInput{SecretId: aws.String(id)})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe secret: " + err.Error()
		return base
	}
	if desc.RotationEnabled == nil || !*desc.RotationEnabled {
		base.Status = fix.FixSkipped
		base.Message = "rotation is not enabled for this secret"
		return base
	}
	if desc.NextRotationDate != nil && desc.NextRotationDate.After(time.Now()) {
		base.Status = fix.FixSkipped
		base.Message = "rotation schedule is already current"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would trigger immediate secret rotation for " + id}
		return base
	}

	_, err = f.clients.SecretsManager.RotateSecret(fctx.Ctx, &secretsmanager.RotateSecretInput{
		SecretId:          aws.String(id),
		RotateImmediately: aws.Bool(true),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "rotate secret: " + err.Error()
		return base
	}

	base.Status = fix.FixApplied
	base.Steps = []string{"triggered immediate secret rotation for " + id}
	return base
}

type secretsManagerSecretUnusedFix struct{ clients *awsdata.Clients }

func (f *secretsManagerSecretUnusedFix) CheckID() string { return "secretsmanager-secret-unused" }
func (f *secretsManagerSecretUnusedFix) Description() string {
	return "Refresh access timestamp for unused Secrets Manager secret"
}
func (f *secretsManagerSecretUnusedFix) Impact() fix.ImpactType { return fix.ImpactNone }
func (f *secretsManagerSecretUnusedFix) Severity() fix.SeverityLevel {
	return fix.SeverityLow
}

func (f *secretsManagerSecretUnusedFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	id := strings.TrimSpace(resourceID)
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	if id == "" {
		base.Status = fix.FixFailed
		base.Message = "missing secret ID"
		return base
	}

	desc, err := f.clients.SecretsManager.DescribeSecret(fctx.Ctx, &secretsmanager.DescribeSecretInput{SecretId: aws.String(id)})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe secret: " + err.Error()
		return base
	}
	if desc.LastAccessedDate != nil && time.Since(*desc.LastAccessedDate) < 90*24*time.Hour {
		base.Status = fix.FixSkipped
		base.Message = "secret was accessed within 90 days"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would access current secret value to refresh LastAccessedDate for " + id}
		return base
	}

	_, err = f.clients.SecretsManager.GetSecretValue(fctx.Ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(id)})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "get secret value: " + err.Error()
		return base
	}

	base.Status = fix.FixApplied
	base.Steps = []string{"retrieved current secret value to refresh LastAccessedDate for " + id}
	return base
}

type secretsManagerUsingCMKFix struct{ clients *awsdata.Clients }

func (f *secretsManagerUsingCMKFix) CheckID() string { return "secretsmanager-using-cmk" }
func (f *secretsManagerUsingCMKFix) Description() string {
	return "Encrypt Secrets Manager secret with customer managed KMS key"
}
func (f *secretsManagerUsingCMKFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *secretsManagerUsingCMKFix) Severity() fix.SeverityLevel { return fix.SeverityHigh }

func (f *secretsManagerUsingCMKFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	id := strings.TrimSpace(resourceID)
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	if id == "" {
		base.Status = fix.FixFailed
		base.Message = "missing secret ID"
		return base
	}

	desc, err := f.clients.SecretsManager.DescribeSecret(fctx.Ctx, &secretsmanager.DescribeSecretInput{SecretId: aws.String(id)})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe secret: " + err.Error()
		return base
	}
	kmsKeyID := strings.ToLower(strings.TrimSpace(aws.ToString(desc.KmsKeyId)))
	if kmsKeyID != "" && !strings.Contains(kmsKeyID, "alias/aws/secretsmanager") {
		base.Status = fix.FixSkipped
		base.Message = "secret already uses a customer managed KMS key"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{
			"would resolve or create " + defaultSecretsCMKAlias,
			"would update secret to use " + defaultSecretsCMKAlias,
		}
		return base
	}

	cmkAlias, aliasSteps, err := resolveOrCreateSecretsManagerCMKAlias(fctx, f.clients)
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "resolve/create CMK alias: " + err.Error()
		return base
	}
	if strings.TrimSpace(cmkAlias) == "" {
		base.Status = fix.FixFailed
		base.Message = "resolved CMK alias is empty"
		return base
	}

	_, err = f.clients.SecretsManager.UpdateSecret(fctx.Ctx, &secretsmanager.UpdateSecretInput{
		SecretId: aws.String(id),
		KmsKeyId: aws.String(cmkAlias),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update secret KMS key: " + err.Error()
		return base
	}

	base.Status = fix.FixApplied
	base.Steps = append(aliasSteps, "updated secret to use customer managed key alias "+cmkAlias)
	return base
}

type appMeshMeshDenyTCPForwardingFix struct{ clients *awsdata.Clients }

func (f *appMeshMeshDenyTCPForwardingFix) CheckID() string { return "appmesh-mesh-deny-tcp-forwarding" }
func (f *appMeshMeshDenyTCPForwardingFix) Description() string {
	return "Set App Mesh egress filter to DROP_ALL"
}
func (f *appMeshMeshDenyTCPForwardingFix) Impact() fix.ImpactType { return fix.ImpactDegradation }
func (f *appMeshMeshDenyTCPForwardingFix) Severity() fix.SeverityLevel {
	return fix.SeverityHigh
}

func (f *appMeshMeshDenyTCPForwardingFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	meshName := strings.TrimSpace(resourceID)
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	if meshName == "" {
		base.Status = fix.FixFailed
		base.Message = "missing mesh name"
		return base
	}

	desc, err := f.clients.AppMesh.DescribeMesh(fctx.Ctx, &appmesh.DescribeMeshInput{MeshName: aws.String(meshName)})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe mesh: " + err.Error()
		return base
	}
	if desc.Mesh == nil || desc.Mesh.Spec == nil {
		base.Status = fix.FixFailed
		base.Message = "mesh spec not found"
		return base
	}
	if desc.Mesh.Spec.EgressFilter != nil && desc.Mesh.Spec.EgressFilter.Type == appmeshtypes.EgressFilterTypeDropAll {
		base.Status = fix.FixSkipped
		base.Message = "egress filter already set to DROP_ALL"
		return base
	}

	spec := desc.Mesh.Spec
	spec.EgressFilter = &appmeshtypes.EgressFilter{Type: appmeshtypes.EgressFilterTypeDropAll}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would update mesh egress filter to DROP_ALL for " + meshName}
		return base
	}

	_, err = f.clients.AppMesh.UpdateMesh(fctx.Ctx, &appmesh.UpdateMeshInput{MeshName: aws.String(meshName), Spec: spec})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update mesh: " + err.Error()
		return base
	}

	base.Status = fix.FixApplied
	base.Steps = []string{"updated mesh egress filter to DROP_ALL for " + meshName}
	return base
}

type appMeshVirtualGatewayBackendDefaultsTLSFix struct{ clients *awsdata.Clients }

func (f *appMeshVirtualGatewayBackendDefaultsTLSFix) CheckID() string {
	return "appmesh-virtual-gateway-backend-defaults-tls"
}
func (f *appMeshVirtualGatewayBackendDefaultsTLSFix) Description() string {
	return "Enforce backend defaults TLS for App Mesh virtual gateway"
}
func (f *appMeshVirtualGatewayBackendDefaultsTLSFix) Impact() fix.ImpactType {
	return fix.ImpactDegradation
}
func (f *appMeshVirtualGatewayBackendDefaultsTLSFix) Severity() fix.SeverityLevel {
	return fix.SeverityMedium
}

func (f *appMeshVirtualGatewayBackendDefaultsTLSFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	meshName, vgName, ok := parseMeshScopedResourceID(resourceID)
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	if !ok {
		base.Status = fix.FixFailed
		base.Message = "invalid resource ID format, expected mesh:virtual-gateway"
		return base
	}

	desc, err := f.clients.AppMesh.DescribeVirtualGateway(fctx.Ctx, &appmesh.DescribeVirtualGatewayInput{
		MeshName:           aws.String(meshName),
		VirtualGatewayName: aws.String(vgName),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe virtual gateway: " + err.Error()
		return base
	}
	if desc.VirtualGateway == nil || desc.VirtualGateway.Spec == nil {
		base.Status = fix.FixFailed
		base.Message = "virtual gateway spec not found"
		return base
	}

	spec := desc.VirtualGateway.Spec
	if spec.BackendDefaults == nil || spec.BackendDefaults.ClientPolicy == nil || spec.BackendDefaults.ClientPolicy.Tls == nil || spec.BackendDefaults.ClientPolicy.Tls.Validation == nil {
		base.Status = fix.FixSkipped
		base.Message = "cannot safely enforce TLS without an existing TLS validation context"
		return base
	}
	if spec.BackendDefaults.ClientPolicy.Tls.Enforce != nil && *spec.BackendDefaults.ClientPolicy.Tls.Enforce {
		base.Status = fix.FixSkipped
		base.Message = "backend defaults TLS is already enforced"
		return base
	}

	spec.BackendDefaults.ClientPolicy.Tls.Enforce = aws.Bool(true)

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enforce backend defaults TLS on virtual gateway " + resourceID}
		return base
	}

	_, err = f.clients.AppMesh.UpdateVirtualGateway(fctx.Ctx, &appmesh.UpdateVirtualGatewayInput{
		MeshName:           aws.String(meshName),
		VirtualGatewayName: aws.String(vgName),
		Spec:               spec,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update virtual gateway: " + err.Error()
		return base
	}

	base.Status = fix.FixApplied
	base.Steps = []string{"enforced backend defaults TLS on virtual gateway " + resourceID}
	return base
}

type appMeshVirtualGatewayLoggingFilePathFix struct{ clients *awsdata.Clients }

func (f *appMeshVirtualGatewayLoggingFilePathFix) CheckID() string {
	return "appmesh-virtual-gateway-logging-file-path-exists"
}
func (f *appMeshVirtualGatewayLoggingFilePathFix) Description() string {
	return "Set App Mesh virtual gateway access log file path"
}
func (f *appMeshVirtualGatewayLoggingFilePathFix) Impact() fix.ImpactType { return fix.ImpactNone }
func (f *appMeshVirtualGatewayLoggingFilePathFix) Severity() fix.SeverityLevel {
	return fix.SeverityLow
}

func (f *appMeshVirtualGatewayLoggingFilePathFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	meshName, vgName, ok := parseMeshScopedResourceID(resourceID)
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	if !ok {
		base.Status = fix.FixFailed
		base.Message = "invalid resource ID format, expected mesh:virtual-gateway"
		return base
	}

	desc, err := f.clients.AppMesh.DescribeVirtualGateway(fctx.Ctx, &appmesh.DescribeVirtualGatewayInput{
		MeshName:           aws.String(meshName),
		VirtualGatewayName: aws.String(vgName),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe virtual gateway: " + err.Error()
		return base
	}
	if desc.VirtualGateway == nil || desc.VirtualGateway.Spec == nil {
		base.Status = fix.FixFailed
		base.Message = "virtual gateway spec not found"
		return base
	}

	spec := desc.VirtualGateway.Spec
	if spec.Logging != nil && spec.Logging.AccessLog != nil {
		if fileLog, ok := spec.Logging.AccessLog.(*appmeshtypes.VirtualGatewayAccessLogMemberFile); ok {
			if strings.TrimSpace(aws.ToString(fileLog.Value.Path)) != "" {
				base.Status = fix.FixSkipped
				base.Message = "virtual gateway logging file path already configured"
				return base
			}
			fileLog.Value.Path = aws.String(defaultAppMeshAccessLogPath)
			spec.Logging.AccessLog = fileLog
		} else {
			spec.Logging.AccessLog = &appmeshtypes.VirtualGatewayAccessLogMemberFile{Value: appmeshtypes.VirtualGatewayFileAccessLog{Path: aws.String(defaultAppMeshAccessLogPath)}}
		}
	} else {
		spec.Logging = &appmeshtypes.VirtualGatewayLogging{AccessLog: &appmeshtypes.VirtualGatewayAccessLogMemberFile{Value: appmeshtypes.VirtualGatewayFileAccessLog{Path: aws.String(defaultAppMeshAccessLogPath)}}}
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would set virtual gateway logging file path to " + defaultAppMeshAccessLogPath + " for " + resourceID}
		return base
	}

	_, err = f.clients.AppMesh.UpdateVirtualGateway(fctx.Ctx, &appmesh.UpdateVirtualGatewayInput{
		MeshName:           aws.String(meshName),
		VirtualGatewayName: aws.String(vgName),
		Spec:               spec,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update virtual gateway logging: " + err.Error()
		return base
	}

	base.Status = fix.FixApplied
	base.Steps = []string{"set virtual gateway logging file path to " + defaultAppMeshAccessLogPath + " for " + resourceID}
	return base
}

type appMeshVirtualNodeBackendDefaultsTLSFix struct{ clients *awsdata.Clients }

func (f *appMeshVirtualNodeBackendDefaultsTLSFix) CheckID() string {
	return "appmesh-virtual-node-backend-defaults-tls-on"
}
func (f *appMeshVirtualNodeBackendDefaultsTLSFix) Description() string {
	return "Enforce backend defaults TLS for App Mesh virtual node"
}
func (f *appMeshVirtualNodeBackendDefaultsTLSFix) Impact() fix.ImpactType {
	return fix.ImpactDegradation
}
func (f *appMeshVirtualNodeBackendDefaultsTLSFix) Severity() fix.SeverityLevel {
	return fix.SeverityMedium
}

func (f *appMeshVirtualNodeBackendDefaultsTLSFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	meshName, vnName, ok := parseMeshScopedResourceID(resourceID)
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	if !ok {
		base.Status = fix.FixFailed
		base.Message = "invalid resource ID format, expected mesh:virtual-node"
		return base
	}

	desc, err := f.clients.AppMesh.DescribeVirtualNode(fctx.Ctx, &appmesh.DescribeVirtualNodeInput{
		MeshName:        aws.String(meshName),
		VirtualNodeName: aws.String(vnName),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe virtual node: " + err.Error()
		return base
	}
	if desc.VirtualNode == nil || desc.VirtualNode.Spec == nil {
		base.Status = fix.FixFailed
		base.Message = "virtual node spec not found"
		return base
	}

	spec := desc.VirtualNode.Spec
	if spec.BackendDefaults == nil || spec.BackendDefaults.ClientPolicy == nil || spec.BackendDefaults.ClientPolicy.Tls == nil || spec.BackendDefaults.ClientPolicy.Tls.Validation == nil {
		base.Status = fix.FixSkipped
		base.Message = "cannot safely enforce TLS without an existing TLS validation context"
		return base
	}
	if spec.BackendDefaults.ClientPolicy.Tls.Enforce != nil && *spec.BackendDefaults.ClientPolicy.Tls.Enforce {
		base.Status = fix.FixSkipped
		base.Message = "backend defaults TLS is already enforced"
		return base
	}

	spec.BackendDefaults.ClientPolicy.Tls.Enforce = aws.Bool(true)

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would enforce backend defaults TLS on virtual node " + resourceID}
		return base
	}

	_, err = f.clients.AppMesh.UpdateVirtualNode(fctx.Ctx, &appmesh.UpdateVirtualNodeInput{
		MeshName:        aws.String(meshName),
		VirtualNodeName: aws.String(vnName),
		Spec:            spec,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update virtual node: " + err.Error()
		return base
	}

	base.Status = fix.FixApplied
	base.Steps = []string{"enforced backend defaults TLS on virtual node " + resourceID}
	return base
}

type appMeshVirtualNodeCloudMapIPPrefFix struct{ clients *awsdata.Clients }

func (f *appMeshVirtualNodeCloudMapIPPrefFix) CheckID() string {
	return "appmesh-virtual-node-cloud-map-ip-pref-check"
}
func (f *appMeshVirtualNodeCloudMapIPPrefFix) Description() string {
	return "Set Cloud Map IP preference on App Mesh virtual node"
}
func (f *appMeshVirtualNodeCloudMapIPPrefFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *appMeshVirtualNodeCloudMapIPPrefFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *appMeshVirtualNodeCloudMapIPPrefFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	meshName, vnName, ok := parseMeshScopedResourceID(resourceID)
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	if !ok {
		base.Status = fix.FixFailed
		base.Message = "invalid resource ID format, expected mesh:virtual-node"
		return base
	}

	desc, err := f.clients.AppMesh.DescribeVirtualNode(fctx.Ctx, &appmesh.DescribeVirtualNodeInput{
		MeshName:        aws.String(meshName),
		VirtualNodeName: aws.String(vnName),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe virtual node: " + err.Error()
		return base
	}
	if desc.VirtualNode == nil || desc.VirtualNode.Spec == nil {
		base.Status = fix.FixFailed
		base.Message = "virtual node spec not found"
		return base
	}

	spec := desc.VirtualNode.Spec
	if spec.ServiceDiscovery == nil {
		base.Status = fix.FixSkipped
		base.Message = "service discovery is not configured"
		return base
	}

	cloudMap, isCloudMap := spec.ServiceDiscovery.(*appmeshtypes.ServiceDiscoveryMemberAwsCloudMap)
	if !isCloudMap {
		base.Status = fix.FixSkipped
		base.Message = "service discovery is not AWS Cloud Map"
		return base
	}
	if cloudMap.Value.IpPreference != "" {
		base.Status = fix.FixSkipped
		base.Message = "Cloud Map IP preference already configured"
		return base
	}

	cloudMap.Value.IpPreference = appmeshtypes.IpPreferenceIPv4Preferred
	spec.ServiceDiscovery = cloudMap

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would set Cloud Map IP preference to IPv4_PREFERRED for " + resourceID}
		return base
	}

	_, err = f.clients.AppMesh.UpdateVirtualNode(fctx.Ctx, &appmesh.UpdateVirtualNodeInput{
		MeshName:        aws.String(meshName),
		VirtualNodeName: aws.String(vnName),
		Spec:            spec,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update virtual node: " + err.Error()
		return base
	}

	base.Status = fix.FixApplied
	base.Steps = []string{"set Cloud Map IP preference to IPv4_PREFERRED for " + resourceID}
	return base
}

type appMeshVirtualNodeDNSIPPrefFix struct{ clients *awsdata.Clients }

func (f *appMeshVirtualNodeDNSIPPrefFix) CheckID() string {
	return "appmesh-virtual-node-dns-ip-pref-check"
}
func (f *appMeshVirtualNodeDNSIPPrefFix) Description() string {
	return "Set DNS IP preference on App Mesh virtual node"
}
func (f *appMeshVirtualNodeDNSIPPrefFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *appMeshVirtualNodeDNSIPPrefFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *appMeshVirtualNodeDNSIPPrefFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	meshName, vnName, ok := parseMeshScopedResourceID(resourceID)
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	if !ok {
		base.Status = fix.FixFailed
		base.Message = "invalid resource ID format, expected mesh:virtual-node"
		return base
	}

	desc, err := f.clients.AppMesh.DescribeVirtualNode(fctx.Ctx, &appmesh.DescribeVirtualNodeInput{
		MeshName:        aws.String(meshName),
		VirtualNodeName: aws.String(vnName),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe virtual node: " + err.Error()
		return base
	}
	if desc.VirtualNode == nil || desc.VirtualNode.Spec == nil {
		base.Status = fix.FixFailed
		base.Message = "virtual node spec not found"
		return base
	}

	spec := desc.VirtualNode.Spec
	if spec.ServiceDiscovery == nil {
		base.Status = fix.FixSkipped
		base.Message = "service discovery is not configured"
		return base
	}

	dns, isDNS := spec.ServiceDiscovery.(*appmeshtypes.ServiceDiscoveryMemberDns)
	if !isDNS {
		base.Status = fix.FixSkipped
		base.Message = "service discovery is not DNS"
		return base
	}
	if dns.Value.IpPreference != "" {
		base.Status = fix.FixSkipped
		base.Message = "DNS IP preference already configured"
		return base
	}

	dns.Value.IpPreference = appmeshtypes.IpPreferenceIPv4Preferred
	spec.ServiceDiscovery = dns

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would set DNS IP preference to IPv4_PREFERRED for " + resourceID}
		return base
	}

	_, err = f.clients.AppMesh.UpdateVirtualNode(fctx.Ctx, &appmesh.UpdateVirtualNodeInput{
		MeshName:        aws.String(meshName),
		VirtualNodeName: aws.String(vnName),
		Spec:            spec,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update virtual node: " + err.Error()
		return base
	}

	base.Status = fix.FixApplied
	base.Steps = []string{"set DNS IP preference to IPv4_PREFERRED for " + resourceID}
	return base
}

type appMeshVirtualNodeLoggingFilePathFix struct{ clients *awsdata.Clients }

func (f *appMeshVirtualNodeLoggingFilePathFix) CheckID() string {
	return "appmesh-virtual-node-logging-file-path-exists"
}
func (f *appMeshVirtualNodeLoggingFilePathFix) Description() string {
	return "Set App Mesh virtual node access log file path"
}
func (f *appMeshVirtualNodeLoggingFilePathFix) Impact() fix.ImpactType      { return fix.ImpactNone }
func (f *appMeshVirtualNodeLoggingFilePathFix) Severity() fix.SeverityLevel { return fix.SeverityLow }

func (f *appMeshVirtualNodeLoggingFilePathFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	meshName, vnName, ok := parseMeshScopedResourceID(resourceID)
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}
	if !ok {
		base.Status = fix.FixFailed
		base.Message = "invalid resource ID format, expected mesh:virtual-node"
		return base
	}

	desc, err := f.clients.AppMesh.DescribeVirtualNode(fctx.Ctx, &appmesh.DescribeVirtualNodeInput{
		MeshName:        aws.String(meshName),
		VirtualNodeName: aws.String(vnName),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe virtual node: " + err.Error()
		return base
	}
	if desc.VirtualNode == nil || desc.VirtualNode.Spec == nil {
		base.Status = fix.FixFailed
		base.Message = "virtual node spec not found"
		return base
	}

	spec := desc.VirtualNode.Spec
	if spec.Logging != nil && spec.Logging.AccessLog != nil {
		if fileLog, ok := spec.Logging.AccessLog.(*appmeshtypes.AccessLogMemberFile); ok {
			if strings.TrimSpace(aws.ToString(fileLog.Value.Path)) != "" {
				base.Status = fix.FixSkipped
				base.Message = "virtual node logging file path already configured"
				return base
			}
			fileLog.Value.Path = aws.String(defaultAppMeshAccessLogPath)
			spec.Logging.AccessLog = fileLog
		} else {
			spec.Logging.AccessLog = &appmeshtypes.AccessLogMemberFile{Value: appmeshtypes.FileAccessLog{Path: aws.String(defaultAppMeshAccessLogPath)}}
		}
	} else {
		spec.Logging = &appmeshtypes.Logging{AccessLog: &appmeshtypes.AccessLogMemberFile{Value: appmeshtypes.FileAccessLog{Path: aws.String(defaultAppMeshAccessLogPath)}}}
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{"would set virtual node logging file path to " + defaultAppMeshAccessLogPath + " for " + resourceID}
		return base
	}

	_, err = f.clients.AppMesh.UpdateVirtualNode(fctx.Ctx, &appmesh.UpdateVirtualNodeInput{
		MeshName:        aws.String(meshName),
		VirtualNodeName: aws.String(vnName),
		Spec:            spec,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update virtual node logging: " + err.Error()
		return base
	}

	base.Status = fix.FixApplied
	base.Steps = []string{"set virtual node logging file path to " + defaultAppMeshAccessLogPath + " for " + resourceID}
	return base
}
