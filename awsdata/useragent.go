package awsdata

import (
	"context"

	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

const userAgent = "aws-cli/2.33.23 md/awscrt#0.31.1 ua/2.1 os/linux#6.1.161-183.298.amzn2023.x86_64 md/arch#x86_64 lang/python#3.13.11 md/pyimpl#CPython exec-env/CloudShell m/Z,E,b,C,z cfg/retry-mode#standard md/installer#exe md/distrib#amzn.2023 md/prompt#off md/command#ec2.describe-instances"

type userAgentOverride struct{}

func (userAgentOverride) ID() string { return "UserAgentOverride" }

func (userAgentOverride) HandleFinalize(ctx context.Context, in middleware.FinalizeInput, next middleware.FinalizeHandler) (
	middleware.FinalizeOutput, middleware.Metadata, error,
) {
	if req, ok := in.Request.(*smithyhttp.Request); ok {
		req.Header.Set("User-Agent", userAgent)
	}
	return next.HandleFinalize(ctx, in)
}

func addUserAgentOverride(stack *middleware.Stack) error {
	return stack.Finalize.Add(userAgentOverride{}, middleware.Before)
}
