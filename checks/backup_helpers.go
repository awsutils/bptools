package checks

import (
	"fmt"
	"time"

	"bptools/awsdata"

	"github.com/aws/aws-sdk-go-v2/service/backup"
	backuptypes "github.com/aws/aws-sdk-go-v2/service/backup/types"
)

const (
	backupRecoveryPointRecencyWindow = 24 * time.Hour
	backupRestoreTimeTargetWindow    = 24 * time.Hour
	backupAirGappedRecencyWindow     = 24 * time.Hour
)

func latestRecoveryPointCreation(points []backuptypes.RecoveryPointByResource) (*time.Time, bool) {
	var latest *time.Time
	for _, rp := range points {
		if rp.CreationDate == nil {
			continue
		}
		if latest == nil || rp.CreationDate.After(*latest) {
			latest = rp.CreationDate
		}
	}
	return latest, latest != nil
}

func latestAirGappedRecoveryPointCreation(points []backuptypes.RecoveryPointByResource) (*time.Time, bool) {
	var latest *time.Time
	for _, rp := range points {
		if rp.CreationDate == nil {
			continue
		}
		if string(rp.VaultType) != "LOGICALLY_AIR_GAPPED" {
			continue
		}
		if latest == nil || rp.CreationDate.After(*latest) {
			latest = rp.CreationDate
		}
	}
	return latest, latest != nil
}

func backupRecencyResult(points []backuptypes.RecoveryPointByResource, window time.Duration) (bool, string) {
	latest, ok := latestRecoveryPointCreation(points)
	if !ok {
		return false, "No recovery point found"
	}
	age := time.Since(*latest)
	passing := age <= window
	return passing, fmt.Sprintf("Latest recovery point age: %s", age.Round(time.Minute))
}

func airGappedRecencyResult(points []backuptypes.RecoveryPointByResource, window time.Duration) (bool, string) {
	latest, ok := latestAirGappedRecoveryPointCreation(points)
	if !ok {
		return false, "No logically air-gapped recovery point found"
	}
	age := time.Since(*latest)
	passing := age <= window
	return passing, fmt.Sprintf("Latest air-gapped recovery point age: %s", age.Round(time.Minute))
}

func restoreTimeTargetResult(d *awsdata.Data, resourceARN string, target time.Duration) (bool, string, error) {
	if resourceARN == "" {
		return false, "Missing resource ARN", nil
	}

	var (
		nextToken *string
		latest    *backuptypes.RestoreJobsListMember
	)
	for {
		out, err := d.Clients.Backup.ListRestoreJobsByProtectedResource(d.Ctx, &backup.ListRestoreJobsByProtectedResourceInput{
			ResourceArn: &resourceARN,
			NextToken:   nextToken,
		})
		if err != nil {
			return false, "", err
		}
		for _, job := range out.RestoreJobs {
			if job.Status != backuptypes.RestoreJobStatusCompleted {
				continue
			}
			if job.CompletionDate == nil || job.CreationDate == nil {
				continue
			}
			if latest == nil || job.CompletionDate.After(*latest.CompletionDate) {
				jobCopy := job
				latest = &jobCopy
			}
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}

	if latest == nil {
		return false, "No completed restore job found", nil
	}

	duration := latest.CompletionDate.Sub(*latest.CreationDate)
	passing := duration <= target
	return passing, fmt.Sprintf("Latest restore execution time: %s", duration.Round(time.Minute)), nil
}
