package internal

const (
	// STS API version.
	stsAPIVersion       = "2011-06-15"
	stsVersion          = "Version"
	stsAction           = "Action"
	stsPolicy           = "Policy"
	stsToken            = "Token"
	stsWebIdentityToken = "WebIdentityToken"
	stsDurationSeconds  = "DurationSeconds"
	stsLDAPUsername     = "LDAPUsername"
	stsLDAPPassword     = "LDAPPassword"

	// add tenant
	stsTenantName = "TenantName"
	stsAccessKey  = "AccessKey"
	stsSecretKey  = "SecretKey"
	stsSign       = "Sign"
	stsUserQuota  = "UserQuota"

	// STS API action constants
	clientGrants = "AssumeRoleWithClientGrants"
	webIdentity  = "AssumeRoleWithWebIdentity"
	ldapIdentity = "AssumeRoleWithLDAPIdentity"
	assumeRole   = "AssumeRole"

	stsRequestBodyLimit = 10 * (1 << 20) // 10 MiB

	// JWT claim keys
	expClaim = "exp"
	subClaim = "sub"
	issClaim = "iss"

	// JWT claim to check the parent user
	parentClaim = "parent"

	// LDAP claim keys
	ldapUser  = "ldapUser"
	ldapUserN = "ldapUsername"
)
