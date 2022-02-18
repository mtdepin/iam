package internal

import (
	"path"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	SlashSeparator        = "/"
	dynamicTimeoutLogSize = 16
	DEFAULT_USER_QUOTA    = 20
)

func IamPolicyClaimNameSA() string {
	return "sa-policy"
}
func IamPolicyClaimNameOpenID() string {
	return globalOpenIDConfig.ClaimPrefix + globalOpenIDConfig.ClaimName
}

// pathJoin - like path.Join() but retains trailing SlashSeparator of the last element
func pathJoin(elem ...string) string {
	trailingSlash := ""
	if len(elem) > 0 {
		if HasSuffix(elem[len(elem)-1], SlashSeparator) {
			trailingSlash = SlashSeparator
		}
	}
	return path.Join(elem...) + trailingSlash
}
func iamPolicyClaimNameSA() string {
	return "sa-policy"
}

// HasSuffix - Suffix matcher string matches suffix in a platform specific way.
// For example on windows since its case insensitive we are supposed
// to do case insensitive checks.
func HasSuffix(s string, suffix string) bool {
	if runtime.GOOS == globalWindowsOSName {
		return strings.HasSuffix(strings.ToLower(s), strings.ToLower(suffix))
	}
	return strings.HasSuffix(s, suffix)
}

// timeouts that are dynamically adapted based on actual usage results
type dynamicTimeout struct {
	timeout int64
	minimum int64
	entries int64
	log     [dynamicTimeoutLogSize]time.Duration
	mutex   sync.Mutex
}

// newDynamicTimeout returns a new dynamic timeout initialized with timeout value
func newDynamicTimeout(timeout, minimum time.Duration) *dynamicTimeout {
	if timeout <= 0 || minimum <= 0 {
		panic("newDynamicTimeout: negative or zero timeout")
	}
	if minimum > timeout {
		minimum = timeout
	}
	return &dynamicTimeout{timeout: int64(timeout), minimum: int64(minimum)}
}

func parseOpenIDParentUser(parentUser string) (userID string, err error) {
	if strings.HasPrefix(parentUser, "openid:") {
		tokens := strings.SplitN(strings.TrimPrefix(parentUser, "openid:"), ":", 2)
		if len(tokens) == 2 {
			return tokens[0], nil
		}
	}
	return "", errSkipFile
}
func iamPolicyClaimNameOpenID() string {
	return globalOpenIDConfig.ClaimPrefix + globalOpenIDConfig.ClaimName
}
