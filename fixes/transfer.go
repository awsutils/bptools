package fixes

import (
	"fmt"

	"bptools/awsdata"
	"bptools/fix"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/transfer"
	transfertypes "github.com/aws/aws-sdk-go-v2/service/transfer/types"
)

// ── transfer-family-server-no-ftp ─────────────────────────────────────────────

type transferNoFTPFix struct{ clients *awsdata.Clients }

func (f *transferNoFTPFix) CheckID() string { return "transfer-family-server-no-ftp" }
func (f *transferNoFTPFix) Description() string {
	return "Remove FTP (unencrypted) protocol from AWS Transfer Family server"
}
func (f *transferNoFTPFix) Impact() fix.ImpactType      { return fix.ImpactDegradation }
func (f *transferNoFTPFix) Severity() fix.SeverityLevel { return fix.SeverityMedium }

func (f *transferNoFTPFix) Apply(fctx fix.FixContext, resourceID string) fix.FixResult {
	base := fix.FixResult{CheckID: f.CheckID(), ResourceID: resourceID, Impact: f.Impact(), Severity: f.Severity()}

	svrOut, err := f.clients.Transfer.DescribeServer(fctx.Ctx, &transfer.DescribeServerInput{
		ServerId: aws.String(resourceID),
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "describe server: " + err.Error()
		return base
	}
	if svrOut.Server == nil {
		base.Status = fix.FixFailed
		base.Message = "server not found"
		return base
	}

	hasFTP := false
	var nonFTPProtocols []transfertypes.Protocol
	for _, p := range svrOut.Server.Protocols {
		if p == transfertypes.ProtocolFtp {
			hasFTP = true
		} else {
			nonFTPProtocols = append(nonFTPProtocols, p)
		}
	}
	if !hasFTP {
		base.Status = fix.FixSkipped
		base.Message = "FTP protocol not enabled on this server"
		return base
	}
	if len(nonFTPProtocols) == 0 {
		base.Status = fix.FixFailed
		base.Message = "cannot remove FTP: it is the only protocol enabled (server would have no protocols)"
		return base
	}

	if fctx.DryRun {
		base.Status = fix.FixDryRun
		base.Steps = []string{fmt.Sprintf("would remove FTP protocol from Transfer Family server %s", resourceID)}
		return base
	}

	_, err = f.clients.Transfer.UpdateServer(fctx.Ctx, &transfer.UpdateServerInput{
		ServerId:  aws.String(resourceID),
		Protocols: nonFTPProtocols,
	})
	if err != nil {
		base.Status = fix.FixFailed
		base.Message = "update server: " + err.Error()
		return base
	}
	base.Steps = []string{fmt.Sprintf("removed FTP protocol from Transfer Family server %s", resourceID)}
	base.Status = fix.FixApplied
	return base
}
