package awsdata

import (
	"context"

	"github.com/aws/smithy-go/middleware"
)

type opLogger struct{}

func (o opLogger) ID() string { return "OperationLogger" }

func (o opLogger) HandleFinalize(ctx context.Context, in middleware.FinalizeInput, next middleware.FinalizeHandler) (
	out middleware.FinalizeOutput, metadata middleware.Metadata, err error,
) {
	return next.HandleFinalize(ctx, in)
}

func addOpLogger(stack *middleware.Stack) error {
	return stack.Finalize.Add(opLogger{}, middleware.After)
}
