

package openid

import (
	config2 "mt-iam/pkg/iam-config"
)

// Legacy envs
const (
	EnvIamJwksURL = "MINIO_IAM_JWKS_URL"
)

// SetIdentityOpenID - One time migration code needed, for migrating from older config to new for OpenIDConfig.
func SetIdentityOpenID(s config2.Config, cfg Config) {
	if cfg.JWKS.URL == nil || cfg.JWKS.URL.String() == "" {
		// No need to save not-enabled settings in new config.
		return
	}
	s[config2.IdentityOpenIDSubSys][config2.Default] = config2.KVS{
		config2.KV{
			Key:   JwksURL,
			Value: cfg.JWKS.URL.String(),
		},
		config2.KV{
			Key:   ConfigURL,
			Value: "",
		},
		config2.KV{
			Key:   ClaimPrefix,
			Value: "",
		},
	}
}
