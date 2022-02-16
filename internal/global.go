package internal

import (
	"mt-iam/conf/openid"
	"mt-iam/conf/policy/opa"

	"mt-iam/internal/auth"
)

var (
	// OPA policy system.
	globalPolicyOPA    *opa.Opa
	globalOpenIDConfig openid.Config
	globalActiveCred   auth.Credentials
)
