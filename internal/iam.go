package internal

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/minio/minio-go/v7/pkg/set"
	iampolicy "github.com/minio/pkg/iam/policy"
	"mt-iam/datastore"
	"mt-iam/internal/auth"
	"mt-iam/logger"
	"strings"
	"sync"
)

const (
	statusEnabled  = "enabled"
	statusDisabled = "disabled"
)

//IAMSys - config system.
type IAMSys struct {
	sync.Mutex

	usersSysType UsersSysType

	// map of policy names to policy definitions
	iamPolicyDocsMap map[string]iampolicy.Policy
	// map of usernames to credentials
	iamUsersMap map[string]auth.Credentials
	// map of group names to group info
	iamGroupsMap map[string]GroupInfo
	// map of user names to groups they are a member of
	iamUserGroupMemberships map[string]set.StringSet
	// map of usernames/temporary access keys to policy names
	iamUserPolicyMap map[string]MappedPolicy
	// map of group names to policy names
	iamGroupPolicyMap map[string]MappedPolicy

	// Persistence layer for IAM subsystem
	store IAMStorageAPI

	// configLoaded will be closed and remain so after first load.
	configLoaded chan struct{}
}

// IAMUserType represents a user type inside MinIO server
type IAMUserType int

const (
	// tenant
	tenant IAMUserType = iota + 1
	regUser
	svcUser
	stsUser
)

type option struct {
	ttl int64
}
type IAMStorageAPI interface {
	rlock()
	runlock()
}
type UsersSysType string

// Types of users configured in the server.
const (
	// This mode uses the internal users system in MinIO.
	MinIOUsersSysType UsersSysType = "MinIOUsersSys"

	// LDAPUsersSysType This mode uses users and groups from a configured LDAP
	// server.
	LDAPUsersSysType UsersSysType = "LDAPUsersSys"
)

// GroupInfo contains info about a group
type GroupInfo struct {
	Version int      `json:"version"`
	Status  string   `json:"status"`
	Members []string `json:"members"`
}

// MappedPolicy represents a policy name mapped to a user or group
type MappedPolicy struct {
	Version  int    `json:"version"`
	Policies string `json:"policy"`
}

func (sys *IAMSys) IsAllowed(args iampolicy.Args) bool {
	// If opa is configured, use OPA always.
	if globalPolicyOPA != nil {
		ok, err := globalPolicyOPA.IsAllowed(args)
		if err != nil {
			//logger.LogIf(GlobalContext, err)
			fmt.Println("err")
		}
		return ok
	}

	// Policies don't apply to the owner.
	if args.IsOwner {
		return true
	}

	// If the credential is temporary, perform STS related checks.
	ok, parentUser, err := sys.IsTempUser(args.AccountName)
	if err != nil && err != errNoSuchUser {
		return false
	}
	if ok {
		return sys.IsAllowedSTS(args, parentUser)
	}

	// If the credential is for a service account, perform related check
	ok, parentUser, err = sys.IsServiceAccount(args.AccountName)
	if err != nil {
		return false
	}
	if ok {
		return sys.IsAllowedServiceAccount(args, parentUser)
	}

	// Continue with the assumption of a regular user
	policies, err := sys.PolicyDBGet(args.AccountName, false, args.Groups...)
	if err != nil {
		return false
	}

	if len(policies) == 0 {
		// No policy found.
		return false
	}

	// Policies were found, evaluate all of them.
	return sys.GetCombinedPolicy(policies...).IsAllowed(args)
}

// GetCombinedPolicy returns a combined policy combining all policies
func (sys *IAMSys) GetCombinedPolicy(policies ...string) iampolicy.Policy {
	// Policies were found, evaluate all of them.
	sys.store.rlock()
	defer sys.store.runlock()

	var availablePolicies []iampolicy.Policy
	for _, pname := range policies {
		p, found := sys.iamPolicyDocsMap[pname]
		if found {
			availablePolicies = append(availablePolicies, p)
		}
	}

	if len(availablePolicies) == 0 {
		return iampolicy.Policy{}
	}

	combinedPolicy := availablePolicies[0]
	for i := 1; i < len(availablePolicies); i++ {
		combinedPolicy.Statements = append(combinedPolicy.Statements,
			availablePolicies[i].Statements...)
	}

	return combinedPolicy
}

// PolicyDBGet - gets policy set on a user or group. If a list of groups is
// given, policies associated with them are included as well.
func (sys *IAMSys) PolicyDBGet(name string, isGroup bool, groups ...string) ([]string, error) {
	if !sys.Initialized() {
		return nil, errServerNotInitialized
	}

	if name == "" {
		return nil, errInvalidArgument
	}

	sys.store.rlock()
	defer sys.store.runlock()

	policies, err := sys.policyDBGet(name, isGroup)
	if err != nil {
		return nil, err
	}

	if !isGroup {
		for _, group := range groups {
			ps, err := sys.policyDBGet(group, true)
			if err != nil {
				return nil, err
			}
			policies = append(policies, ps...)
		}
	}

	return policies, nil
}

// This call assumes that caller has the sys.RLock().
//
// If a group is passed, it returns policies associated with the group.
//
// If a user is passed, it returns policies of the user along with any groups
// that the server knows the user is a member of.
//
// In LDAP users mode, the server does not store any group membership
// information in IAM (i.e sys.iam*Map) - this info is stored only in the STS
// generated credentials. Thus we skip looking up group memberships, user map,
// and group map and check the appropriate policy maps directly.
func (sys *IAMSys) policyDBGet(name string, isGroup bool) (policies []string, err error) {
	if isGroup {
		if sys.usersSysType == MinIOUsersSysType {
			g, ok := sys.iamGroupsMap[name]
			if !ok {
				return nil, errNoSuchGroup
			}

			// Group is disabled, so we return no policy - this
			// ensures the request is denied.
			if g.Status == statusDisabled {
				return nil, nil
			}
		}

		return sys.iamGroupPolicyMap[name].toSlice(), nil
	}

	if name == globalActiveCred.AccessKey {
		return []string{"consoleAdmin"}, nil
	}

	// When looking for a user's policies, we also check if the user
	// and the groups they are member of are enabled.
	var parentName string
	u, ok := sys.iamUsersMap[name]
	if ok {
		if !u.IsValid() {
			return nil, nil
		}
		parentName = u.ParentUser
	}

	mp, ok := sys.iamUserPolicyMap[name]
	if !ok {
		if parentName != "" {
			mp = sys.iamUserPolicyMap[parentName]
		}
	}

	// returned policy could be empty
	policies = append(policies, mp.toSlice()...)

	for _, group := range sys.iamUserGroupMemberships[name].ToSlice() {
		// Skip missing or disabled groups
		gi, ok := sys.iamGroupsMap[group]
		if !ok || gi.Status == statusDisabled {
			continue
		}

		policies = append(policies, sys.iamGroupPolicyMap[group].toSlice()...)
	}

	return policies, nil
}

// IsAllowedServiceAccount - checks if the given service account is allowed to perform
// actions. The permission of the parent user is checked first
func (sys *IAMSys) IsAllowedServiceAccount(args iampolicy.Args, parentUser string) bool {
	// Now check if we have a subject claim
	p, ok := args.Claims[parentClaim]
	if ok {
		parentInClaim, ok := p.(string)
		if !ok {
			// Reject malformed/malicious requests.
			return false
		}
		// The parent claim in the session token should be equal
		// to the parent detected in the backend
		if parentInClaim != parentUser {
			return false
		}
	} else {
		// This is needed so a malicious user cannot
		// use a leaked session key of another user
		// to widen its privileges.
		return false
	}

	// Check policy for this service account.
	svcPolicies, err := sys.PolicyDBGet(parentUser, false, args.Groups...)
	if err != nil {
		logger.Info("", err)
		return false
	}

	if len(svcPolicies) == 0 {
		return false
	}

	var availablePolicies []iampolicy.Policy

	// Policies were found, evaluate all of them.
	sys.store.rlock()
	for _, pname := range svcPolicies {
		p, found := sys.iamPolicyDocsMap[pname]
		if found {
			availablePolicies = append(availablePolicies, p)
		}
	}
	sys.store.runlock()

	if len(availablePolicies) == 0 {
		return false
	}

	combinedPolicy := availablePolicies[0]
	for i := 1; i < len(availablePolicies); i++ {
		combinedPolicy.Statements = append(combinedPolicy.Statements,
			availablePolicies[i].Statements...)
	}

	parentArgs := args
	parentArgs.AccountName = parentUser
	// These are dynamic values set them appropriately.
	parentArgs.ConditionValues["username"] = []string{parentUser}
	parentArgs.ConditionValues["userid"] = []string{parentUser}

	saPolicyClaim, ok := args.Claims[IamPolicyClaimNameSA()]
	if !ok {
		return false
	}

	saPolicyClaimStr, ok := saPolicyClaim.(string)
	if !ok {
		// Sub policy if set, should be a string reject
		// malformed/malicious requests.
		return false
	}

	if saPolicyClaimStr == "inherited-policy" {
		return combinedPolicy.IsAllowed(parentArgs)
	}

	// Now check if we have a sessionPolicy.
	spolicy, ok := args.Claims[iampolicy.SessionPolicyName]
	if !ok {
		return false
	}

	spolicyStr, ok := spolicy.(string)
	if !ok {
		// Sub policy if set, should be a string reject
		// malformed/malicious requests.
		return false
	}

	// Check if policy is parseable.
	subPolicy, err := iampolicy.ParseConfig(bytes.NewReader([]byte(spolicyStr)))
	if err != nil {
		// Log any error in input session policy config.
		logger.Info("", err)
		return false
	}

	// This can only happen if policy was set but with an empty JSON.
	if subPolicy.Version == "" && len(subPolicy.Statements) == 0 {
		return combinedPolicy.IsAllowed(parentArgs)
	}

	if subPolicy.Version == "" {
		return false
	}

	return combinedPolicy.IsAllowed(parentArgs) && subPolicy.IsAllowed(parentArgs)
}

// IsServiceAccount - returns if given key is a service account
func (sys *IAMSys) IsServiceAccount(name string) (bool, string, error) {
	if !sys.Initialized() {
		return false, "", errServerNotInitialized
	}

	sys.store.rlock()
	defer sys.store.runlock()

	// get user
	user := datastore.GetMtAccount(name)
	if user == nil {
		return false, "", errors.New("database err: get mt_account failed")
	}
	if user.Username == "" || user.Username != name {
		return false, "", errNoSuchUser
	}
	// get cred
	dbCred := datastore.GetCredential(name)
	if dbCred == nil {
		return false, "", errors.New("database err: get credential failed")
	}
	if dbCred.AccessKey == "" || dbCred.AccessKey != name {
		return false, "", errNoSuchUser
	}

	// get parent user
	parent := datastore.GetAccountByUid(dbCred.ParentUser)
	if parent == nil {
		return false, "", errors.New("database err: get mt_account failed")
	}
	cred := auth.Credentials{
		AccessKey:    dbCred.AccessKey,
		SecretKey:    dbCred.SecretKey,
		Expiration:   dbCred.Expiration,
		SessionToken: dbCred.SessionToken,
		Status: func() string {
			if dbCred.Status {
				return auth.AccountOn
			} else {
				return auth.AccountOff
			}
		}(),
		ParentUser: parent.Username,
	}

	if user.Ctype == int(svcUser) {
		return true, cred.ParentUser, nil
	}

	return false, "", nil
}

// IsAllowedSTS is meant for STS based temporary credentials,
// which implements claims validation and verification other than
// applying policies.
func (sys *IAMSys) IsAllowedSTS(args iampolicy.Args, parentUser string) bool {
	// If it is an LDAP request, check that user and group
	// policies allow the request.
	if sys.usersSysType == LDAPUsersSysType {
		return sys.IsAllowedLDAPSTS(args, parentUser)
	}

	policies, ok := args.GetPolicies(IamPolicyClaimNameOpenID())
	if !ok {
		// When claims are set, it should have a policy claim field.
		return false
	}

	// When claims are set, it should have policies as claim.
	if policies.IsEmpty() {
		// No policy, no access!
		return false
	}

	sys.store.rlock()
	defer sys.store.runlock()

	// If policy is available for given user, check the policy.
	mp, ok := sys.iamUserPolicyMap[args.AccountName]
	if !ok {
		// No policy set for the user that we can find, no access!
		return false
	}

	if !policies.Equals(mp.policySet()) {
		// When claims has a policy, it should match the
		// policy of args.AccountName which server remembers.
		// if not reject such requests.
		return false
	}

	var availablePolicies []iampolicy.Policy
	for pname := range policies {
		p, found := sys.iamPolicyDocsMap[pname]
		if !found {
			// find the policy exists in db
			dbPolicy, err := loadPolicyFromDB(pname)
			if err != nil {
				// all policies presented in the claim should exist
				logger.Info("", fmt.Errorf("expected policy (%s) missing from the JWT claim %s, rejecting the request", pname, IamPolicyClaimNameOpenID()))
				return false
			}
			availablePolicies = append(availablePolicies, dbPolicy)
		} else {
			availablePolicies = append(availablePolicies, p)
		}
	}

	combinedPolicy := availablePolicies[0]
	for i := 1; i < len(availablePolicies); i++ {
		combinedPolicy.Statements = append(combinedPolicy.Statements,
			availablePolicies[i].Statements...)
	}

	// These are dynamic values set them appropriately.
	args.ConditionValues["username"] = []string{parentUser}
	args.ConditionValues["userid"] = []string{parentUser}

	// Now check if we have a sessionPolicy.
	hasSessionPolicy, isAllowedSP := isAllowedBySessionPolicy(args)
	if hasSessionPolicy {
		return isAllowedSP && combinedPolicy.IsAllowed(args)
	}

	// Sub policy not set, this is most common since subPolicy
	// is optional, use the inherited policies.
	return combinedPolicy.IsAllowed(args)
}
func (sys *IAMSys) IsAllowedLDAPSTS(args iampolicy.Args, parentUser string) bool {
	// parentUser value must match the ldap user in the claim.
	if parentInClaimIface, ok := args.Claims[ldapUser]; !ok {
		// no ldapUser claim present reject it.
		return false
	} else if parentInClaim, ok := parentInClaimIface.(string); !ok {
		// not the right type, reject it.
		return false
	} else if parentInClaim != parentUser {
		// ldap claim has been modified maliciously reject it.
		return false
	}

	// Check policy for this LDAP user.
	ldapPolicies, err := sys.PolicyDBGet(parentUser, false, args.Groups...)
	if err != nil {
		return false
	}

	if len(ldapPolicies) == 0 {
		return false
	}

	var availablePolicies []iampolicy.Policy

	// Policies were found, evaluate all of them.
	sys.store.rlock()
	for _, pname := range ldapPolicies {
		p, found := sys.iamPolicyDocsMap[pname]
		if found {
			availablePolicies = append(availablePolicies, p)
		}
	}
	sys.store.runlock()

	if len(availablePolicies) == 0 {
		return false
	}

	combinedPolicy := availablePolicies[0]
	for i := 1; i < len(availablePolicies); i++ {
		combinedPolicy.Statements =
			append(combinedPolicy.Statements,
				availablePolicies[i].Statements...)
	}

	hasSessionPolicy, isAllowedSP := isAllowedBySessionPolicy(args)
	if hasSessionPolicy {
		return isAllowedSP && combinedPolicy.IsAllowed(args)
	}

	return combinedPolicy.IsAllowed(args)
}
func isAllowedBySessionPolicy(args iampolicy.Args) (hasSessionPolicy bool, isAllowed bool) {
	hasSessionPolicy = false
	isAllowed = false

	// Now check if we have a sessionPolicy.
	spolicy, ok := args.Claims[iampolicy.SessionPolicyName]
	if !ok {
		return
	}

	hasSessionPolicy = true

	spolicyStr, ok := spolicy.(string)
	if !ok {
		// Sub policy if set, should be a string reject
		// malformed/malicious requests.
		return
	}

	// Check if policy is parseable.
	subPolicy, err := iampolicy.ParseConfig(bytes.NewReader([]byte(spolicyStr)))
	if err != nil {
		// Log any error in input session policy config.
		logger.Info("", err)
		return
	}

	// Policy without Version string value reject it.
	if subPolicy.Version == "" {
		return
	}

	// Sub policy is set and valid.
	return hasSessionPolicy, subPolicy.IsAllowed(args)
}

// Initialized check if IAM is initialized
func (sys *IAMSys) Initialized() bool {
	if sys == nil {
		return false
	}
	sys.Lock()
	defer sys.Unlock()
	return sys.store != nil
}

// IsTempUser - returns if given key is a temporary user.
func (sys *IAMSys) IsTempUser(name string) (bool, string, error) {
	if !sys.Initialized() {
		return false, "", errServerNotInitialized
	}

	sys.store.rlock()
	defer sys.store.runlock()

	cred, found := sys.iamUsersMap[name]
	if !found {
		return false, "", errNoSuchUser
	}

	if cred.IsTemp() {
		return true, cred.ParentUser, nil
	}

	return false, "", nil
}
func (mp MappedPolicy) policySet() set.StringSet {
	var policies []string
	for _, policy := range strings.Split(mp.Policies, ",") {
		policy = strings.TrimSpace(policy)
		if policy == "" {
			continue
		}
		policies = append(policies, policy)
	}
	return set.CreateStringSet(policies...)
}

// converts a mapped policy into a slice of distinct policies
func (mp MappedPolicy) toSlice() []string {
	var policies []string
	for _, policy := range strings.Split(mp.Policies, ",") {
		policy = strings.TrimSpace(policy)
		if policy == "" {
			continue
		}
		policies = append(policies, policy)
	}
	return policies
}
