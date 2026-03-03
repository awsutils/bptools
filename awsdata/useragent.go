package awsdata

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"unicode"

	awsmw "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// userAgentPrefix is the static portion built once at startup.
// The per-request md/command#... token is appended in HandleFinalize.
var userAgentPrefix = buildUserAgentPrefix()

func buildUserAgentPrefix() string {
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
	parts = append(parts, "md/prompt#off")
	return strings.Join(parts, " ")
}

// formatCommand converts SDK service ID + operation name to CLI notation.
// e.g. "Amazon EC2" + "DescribeInstances" → "ec2.describe-instances"
func formatCommand(serviceID, opName string) string {
	svc := strings.ToLower(strings.ReplaceAll(serviceID, " ", ""))
	// Strip common "amazon" / "aws" prefixes that the CLI omits
	svc = strings.TrimPrefix(svc, "amazon")
	svc = strings.TrimPrefix(svc, "aws")
	op := pascalToKebab(opName)
	if svc == "" || op == "" {
		return "unknown"
	}
	return svc + "." + op
}

// pascalToKebab converts PascalCase to kebab-case.
// e.g. "DescribeInstances" → "describe-instances"
func pascalToKebab(s string) string {
	runes := []rune(s)
	var b strings.Builder
	for i, r := range runes {
		if i > 0 && unicode.IsUpper(r) {
			prev := runes[i-1]
			next := rune(0)
			if i+1 < len(runes) {
				next = runes[i+1]
			}
			// Insert dash before an uppercase that follows a lowercase,
			// or before the last uppercase in a run (e.g. "XMLParser" → "xml-parser").
			if unicode.IsLower(prev) || (unicode.IsUpper(prev) && next != 0 && unicode.IsLower(next)) {
				b.WriteRune('-')
			}
		}
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
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

// kernelVersion reads the kernel release string from /proc on Linux,
// falling back to the Go OS name on other platforms.
func kernelVersion() string {
	if data, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		return strings.TrimSpace(string(data))
	}
	return runtime.GOOS
}

// detectDistrib parses /etc/os-release for ID and VERSION_ID.
// Returns e.g. "amzn.2023" or "" if undetectable.
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
		cmd := formatCommand(awsmw.GetServiceID(ctx), awsmw.GetOperationName(ctx))
		req.Header.Set("User-Agent", userAgentPrefix+" md/command#"+cmd)
	}
	return next.HandleFinalize(ctx, in)
}

func addUserAgentOverride(stack *middleware.Stack) error {
	return stack.Finalize.Add(userAgentOverride{}, middleware.Before)
}
