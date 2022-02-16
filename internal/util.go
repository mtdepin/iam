package internal

func IamPolicyClaimNameSA() string {
	return "sa-policy"
}
func IamPolicyClaimNameOpenID() string {
	return globalOpenIDConfig.ClaimPrefix + globalOpenIDConfig.ClaimName
}
