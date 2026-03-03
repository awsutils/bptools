package pool

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"
	tagtypes "github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// S3BucketSpec describes the desired shared S3 bucket.
type S3BucketSpec struct {
	// Purpose is a semantic key used for tag-based reuse (e.g. "alb-access-logs").
	Purpose string
	// Region scopes the bucket to a specific AWS region.
	Region string
	// BucketPrefix is prepended to the generated bucket name on creation.
	BucketPrefix string
	// AdditionalTags are merged with the standard bptools tags on creation.
	AdditionalTags map[string]string
	// BucketPolicyFn, if non-nil, is called once after the bucket is created.
	BucketPolicyFn func(ctx context.Context, s3Client *s3.Client, bucketName string) error
}

// S3BucketPool manages shared S3 buckets, finding existing ones by tag before
// creating new ones. Safe for concurrent use; bucket creation is serialised per
// purpose/region pair via the in-process cache + mutex.
type S3BucketPool struct {
	mu      sync.Mutex
	cache   map[string]string // "purpose/region" → bucketName
	s3      *s3.Client
	tagging *resourcegroupstaggingapi.Client
}

// NewS3BucketPool creates a pool backed by the provided AWS clients.
func NewS3BucketPool(s3Client *s3.Client, tagging *resourcegroupstaggingapi.Client) *S3BucketPool {
	return &S3BucketPool{
		cache:   make(map[string]string),
		s3:      s3Client,
		tagging: tagging,
	}
}

// Ensure returns the name of a bucket matching spec, creating one if needed.
// In dry-run mode the create step is skipped and a placeholder name is returned.
// Order of resolution: in-process cache → AWS tag search → create.
func (p *S3BucketPool) Ensure(ctx context.Context, spec S3BucketSpec, dryRun bool) (string, []string, error) {
	cacheKey := spec.Purpose + "/" + spec.Region

	p.mu.Lock()
	if name, ok := p.cache[cacheKey]; ok {
		p.mu.Unlock()
		return name, nil, nil
	}
	p.mu.Unlock()

	// Search AWS for an existing bptools-managed bucket with matching tags.
	name, steps, err := p.searchByTag(ctx, spec)
	if err != nil {
		return "", steps, err
	}
	if name != "" {
		p.mu.Lock()
		p.cache[cacheKey] = name
		p.mu.Unlock()
		return name, steps, nil
	}

	if dryRun {
		placeholder := spec.BucketPrefix + spec.Region + "-<dry-run>"
		s := fmt.Sprintf("[dry-run] would create S3 bucket %s (purpose=%s, region=%s)", placeholder, spec.Purpose, spec.Region)
		return placeholder, []string{s}, nil
	}

	// Create a new bucket and cache it.
	name, steps, err = p.create(ctx, spec)
	if err != nil {
		return "", steps, err
	}
	p.mu.Lock()
	p.cache[cacheKey] = name
	p.mu.Unlock()
	return name, steps, nil
}

func (p *S3BucketPool) searchByTag(ctx context.Context, spec S3BucketSpec) (string, []string, error) {
	input := &resourcegroupstaggingapi.GetResourcesInput{
		ResourceTypeFilters: []string{"s3"},
		TagFilters: []tagtypes.TagFilter{
			{Key: aws.String("bptools:purpose"), Values: []string{spec.Purpose}},
			{Key: aws.String("bptools:region"), Values: []string{spec.Region}},
		},
	}
	out, err := p.tagging.GetResources(ctx, input)
	if err != nil {
		return "", nil, fmt.Errorf("tag search for S3 bucket (purpose=%s region=%s): %w", spec.Purpose, spec.Region, err)
	}
	for _, r := range out.ResourceTagMappingList {
		if r.ResourceARN == nil {
			continue
		}
		// ARN format: arn:aws:s3:::bucket-name
		parts := strings.SplitN(*r.ResourceARN, ":::", 2)
		if len(parts) == 2 && parts[1] != "" {
			return parts[1], []string{"found existing bucket " + parts[1] + " via tag search"}, nil
		}
	}
	return "", nil, nil
}

func (p *S3BucketPool) create(ctx context.Context, spec S3BucketSpec) (string, []string, error) {
	name := spec.BucketPrefix + spec.Region + "-" + shortID()
	var steps []string

	input := &s3.CreateBucketInput{Bucket: aws.String(name)}
	if spec.Region != "us-east-1" {
		input.CreateBucketConfiguration = &s3types.CreateBucketConfiguration{
			LocationConstraint: s3types.BucketLocationConstraint(spec.Region),
		}
	}
	_, err := p.s3.CreateBucket(ctx, input)
	if err != nil {
		var baoby *s3types.BucketAlreadyOwnedByYou
		if !errors.As(err, &baoby) {
			return "", nil, fmt.Errorf("create S3 bucket %s: %w", name, err)
		}
		steps = append(steps, "bucket "+name+" already owned by this account")
	} else {
		steps = append(steps, "created S3 bucket "+name)
	}

	if spec.BucketPolicyFn != nil {
		if err := spec.BucketPolicyFn(ctx, p.s3, name); err != nil {
			return name, steps, fmt.Errorf("apply bucket policy to %s: %w", name, err)
		}
		steps = append(steps, "applied bucket policy to "+name)
	}

	tags := map[string]string{
		"bptools:managed-by": "bptools",
		"bptools:purpose":    spec.Purpose,
		"bptools:region":     spec.Region,
	}
	for k, v := range spec.AdditionalTags {
		tags[k] = v
	}
	tagSet := make([]s3types.Tag, 0, len(tags))
	for k, v := range tags {
		tagSet = append(tagSet, s3types.Tag{Key: aws.String(k), Value: aws.String(v)})
	}
	_, err = p.s3.PutBucketTagging(ctx, &s3.PutBucketTaggingInput{
		Bucket:  aws.String(name),
		Tagging: &s3types.Tagging{TagSet: tagSet},
	})
	if err != nil {
		return name, steps, fmt.Errorf("tag S3 bucket %s: %w", name, err)
	}
	steps = append(steps, "tagged "+name+" with bptools metadata")

	return name, steps, nil
}

func shortID() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		// Unreachable in practice; crypto/rand always works on supported platforms.
		return "00000000"
	}
	return hex.EncodeToString(b)
}
