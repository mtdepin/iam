package internal

import (
	xldap "mt-iam/conf/ldap"
	"mt-iam/conf/openid"
	"mt-iam/conf/policy/opa"
	"mt-iam/internal/auth"
	"time"
)

var (
	// OPA policy system.
	globalPolicyOPA    *opa.Opa
	globalOpenIDConfig openid.Config
	globalActiveCred   auth.Credentials
	GlobalIAMSys       *IAMSys
	globalLDAPConfig   xldap.Config

	globalIsDistErasure = false
)

const (
	globalWindowsOSName = "windows"
	// Refresh interval to update in-memory iam config cache.
	globalRefreshIAMInterval = 5 * time.Minute
)

func Start() {
	GlobalIAMSys = NewIAMSys()
}
