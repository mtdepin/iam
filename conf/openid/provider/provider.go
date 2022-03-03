

package provider

import "errors"

// DiscoveryDoc - parses the output from openid-configuration
// for example https://accounts.google.com/.well-known/openid-configuration
type DiscoveryDoc struct {
	Issuer                           string   `json:"issuer,omitempty"`
	AuthEndpoint                     string   `json:"authorization_endpoint,omitempty"`
	TokenEndpoint                    string   `json:"token_endpoint,omitempty"`
	UserInfoEndpoint                 string   `json:"userinfo_endpoint,omitempty"`
	RevocationEndpoint               string   `json:"revocation_endpoint,omitempty"`
	JwksURI                          string   `json:"jwks_uri,omitempty"`
	ResponseTypesSupported           []string `json:"response_types_supported,omitempty"`
	SubjectTypesSupported            []string `json:"subject_types_supported,omitempty"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported,omitempty"`
	ScopesSupported                  []string `json:"scopes_supported,omitempty"`
	TokenEndpointAuthMethods         []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	ClaimsSupported                  []string `json:"claims_supported,omitempty"`
	CodeChallengeMethodsSupported    []string `json:"code_challenge_methods_supported,omitempty"`
}

// User represents information about user.
type User struct {
	Name    string `json:"username"`
	ID      string `json:"id"`
	Enabled bool   `json:"enabled"`
}

// Standard errors.
var (
	ErrNotImplemented     = errors.New("function not implemented")
	ErrAccessTokenExpired = errors.New("access_token expired or unauthorized")
)

// Provider implements indentity provider specific admin operations, such as
// looking up users, fetching additional attributes etc.
type Provider interface {
	LoginWithUser(username, password string) error
	LoginWithClientID(clientID, clientSecret string) error
	LookupUser(userid string) (User, error)
}
