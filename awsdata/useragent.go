package awsdata

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

var userAgent = buildUserAgent()

func buildUserAgent() string {
	osName := runtime.GOOS
	arch := normalizeArch(runtime.GOARCH)
	kernel := kernelVersion()
	distrib := detectDistrib()
	execEnv := strings.TrimSpace(os.Getenv("AWS_EXECUTION_ENV"))

	parts := []string{
		"aws-cli/2.33.23",
		"md/awscrt#0.31.1",
		"ua/2.1",
		fmt.Sprintf("os/%s#%s", osName, kernel),
		fmt.Sprintf("md/arch#%s", arch),
		"lang/python#3.13.11",
		"md/pyimpl#CPython",
	}
	if execEnv != "" {
		parts = append(parts, "exec-env/"+execEnv)
	}
	parts = append(parts, "m/Z,E,b,C,z", "cfg/retry-mode#standard", "md/installer#exe")
	if distrib != "" {
		parts = append(parts, "md/distrib#"+distrib)
	}
	parts = append(parts, "md/prompt#off", "md/command#ec2.describe-instances")

	return strings.Join(parts, " ")
}

// normalizeArch converts Go arch names to the convention used in the CLI UA.
func normalizeArch(goarch string) string {
	switch goarch {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	case "386":
		return "i386"
	default:
		return goarch
	}
}

// kernelVersion reads the kernel release string.
// On Linux this comes from /proc/sys/kernel/osrelease; elsewhere it falls back
// to the Go OS name.
func kernelVersion() string {
	if data, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		return strings.TrimSpace(string(data))
	}
	return runtime.GOOS
}

// detectDistrib parses /etc/os-release for ID and VERSION_ID and returns a
// string like "amzn.2023" or "ubuntu.22.04". Returns "" if undetectable.
func detectDistrib() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}
	vals := parseKeyValues(data)
	id := strings.Trim(vals["ID"], `"'`)
	ver := strings.Trim(vals["VERSION_ID"], `"'`)
	if id == "" {
		return ""
	}
	if ver == "" {
		return id
	}
	return id + "." + ver
}

func parseKeyValues(data []byte) map[string]string {
	out := make(map[string]string)
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out
}

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
