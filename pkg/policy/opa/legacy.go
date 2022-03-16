

package opa

import (
	config2 "mt-iam/pkg/iam-config"
)

// Legacy OPA envs
const (
	EnvIamOpaURL       = "MINIO_IAM_OPA_URL"
	EnvIamOpaAuthToken = "MINIO_IAM_OPA_AUTHTOKEN"
)

// SetPolicyOPAConfig - One time migration code needed, for migrating from older config to new for PolicyOPAConfig.
func SetPolicyOPAConfig(s config2.Config, opaArgs Args) {
	if opaArgs.URL == nil || opaArgs.URL.String() == "" {
		// Do not enable if opaArgs was empty.
		return
	}
	s[config2.PolicyOPASubSys][config2.Default] = config2.KVS{
		config2.KV{
			Key:   URL,
			Value: opaArgs.URL.String(),
		},
		config2.KV{
			Key:   AuthToken,
			Value: opaArgs.AuthToken,
		},
	}
}
