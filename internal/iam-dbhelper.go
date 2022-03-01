// Copyright (c) 2015-2021 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package internal

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/minio/pkg/bucket/policy"
	"github.com/minio/pkg/bucket/policy/condition"
	db "mt-iam/datastore"
	"mt-iam/internal/auth"
	"mt-iam/logger"
	"regexp"
	"strings"
	"sync"
	"time"

	humanize "github.com/dustin/go-humanize"
	"github.com/minio/madmin-go"
	"github.com/minio/minio-go/v7/pkg/set"
	iampolicy "github.com/minio/pkg/iam/policy"
)

// UsersSysType - defines the type of users and groups system that is
// active on the server.
type UsersSysType string

// Types of users configured in the server.
const (
	// This mode uses the internal users system in MinIO.
	MinIOUsersSysType UsersSysType = "MinIOUsersSys"

	// This mode uses users and groups from a configured LDAP
	// server.
	LDAPUsersSysType UsersSysType = "LDAPUsersSys"
)

const (
	minioConfigPrefix = "config"
	// IAM configuration directory.
	iamConfigPrefix = minioConfigPrefix + "/iam"

	// IAM users directory.
	iamConfigUsersPrefix = iamConfigPrefix + "/users/"

	// IAM service accounts directory.
	iamConfigServiceAccountsPrefix = iamConfigPrefix + "/service-accounts/"

	// IAM groups directory.
	iamConfigGroupsPrefix = iamConfigPrefix + "/groups/"

	// IAM policies directory.
	iamConfigPoliciesPrefix = iamConfigPrefix + "/policies/"

	// IAM sts directory.
	iamConfigSTSPrefix = iamConfigPrefix + "/sts/"

	// IAM Policy DB prefixes.
	iamConfigPolicyDBPrefix                = iamConfigPrefix + "/policydb/"
	iamConfigPolicyDBUsersPrefix           = iamConfigPolicyDBPrefix + "users/"
	iamConfigPolicyDBSTSUsersPrefix        = iamConfigPolicyDBPrefix + "sts-users/"
	iamConfigPolicyDBServiceAccountsPrefix = iamConfigPolicyDBPrefix + "service-accounts/"
	iamConfigPolicyDBGroupsPrefix          = iamConfigPolicyDBPrefix + "groups/"

	// IAM identity file which captures identity credentials.
	iamIdentityFile = "identity.json"

	// IAM policy file which provides policies for each users.
	iamPolicyFile = "policy.json"

	// IAM group members file
	iamGroupMembersFile = "members.json"

	// IAM format file
	iamFormatFile = "format.json"

	iamFormatVersion1 = 1
)

const (
	statusEnabled  = "enabled"
	statusDisabled = "disabled"
)

// 用户名、群组名格式
const (
	accesskeyFormat  = "^[a-zA-Z0-9_.-]{3,64}$"
	policynameFormat = "^[a-zA-Z0-9-]{1,128}$"
	secretkeyMinLen  = 8
	secretkeyMaxLen  = 64
)

type iamFormat struct {
	Version int `json:"version"`
}

func newIAMFormatVersion1() iamFormat {
	return iamFormat{Version: iamFormatVersion1}
}

func getIAMFormatFilePath() string {
	return iamConfigPrefix + SlashSeparator + iamFormatFile
}

func getUserIdentityPath(user string, userType IAMUserType) string {
	var basePath string
	switch userType {
	case svcUser:
		basePath = iamConfigServiceAccountsPrefix
	case stsUser:
		basePath = iamConfigSTSPrefix
	default:
		basePath = iamConfigUsersPrefix
	}
	return pathJoin(basePath, user, iamIdentityFile)
}

func getGroupInfoPath(group string) string {
	return pathJoin(iamConfigGroupsPrefix, group, iamGroupMembersFile)
}

func getPolicyDocPath(name string) string {
	return pathJoin(iamConfigPoliciesPrefix, name, iamPolicyFile)
}

func getMappedPolicyPath(name string, userType IAMUserType, isGroup bool) string {
	if isGroup {
		return pathJoin(iamConfigPolicyDBGroupsPrefix, name+".json")
	}
	switch userType {
	case svcUser:
		return pathJoin(iamConfigPolicyDBServiceAccountsPrefix, name+".json")
	case stsUser:
		return pathJoin(iamConfigPolicyDBSTSUsersPrefix, name+".json")
	default:
		return pathJoin(iamConfigPolicyDBUsersPrefix, name+".json")
	}
}

// UserIdentity represents a user's secret key and their status
type UserIdentity struct {
	Version     int              `json:"version"`
	Credentials auth.Credentials `json:"credentials"`
}

func newUserIdentity(cred auth.Credentials) UserIdentity {
	return UserIdentity{Version: 1, Credentials: cred}
}

// GroupInfo contains info about a group
type GroupInfo struct {
	Version int      `json:"version"`
	Status  string   `json:"status"`
	Members []string `json:"members"`
}

func newGroupInfo(members []string) GroupInfo {
	return GroupInfo{Version: 1, Status: statusEnabled, Members: members}
}

// MappedPolicy represents a policy name mapped to a user or group
type MappedPolicy struct {
	Version  int    `json:"version"`
	Policies string `json:"policy"`
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

func newMappedPolicy(policy string) MappedPolicy {
	return MappedPolicy{Version: 1, Policies: policy}
}

// 用户名和群组名格式满足：
// 长度为3~64字符，包含英文字母、数字、.、_或-
func isNameValid(name string) bool {
	r := regexp.MustCompile(accesskeyFormat)
	return r.MatchString(name)
}

// 策略名格式满足：
// 长度为1~128字符，包含英文字母、数字和-
func isPolicyNameValid(name string) bool {
	r := regexp.MustCompile(policynameFormat)
	return r.MatchString(name)
}

// 私钥格式：
// 长度满足8~64字符
func isSecretKeyValid(secret string) bool {
	return len(secret) >= secretkeyMinLen && len(secret) <= secretkeyMaxLen
}

// IAMSys - config system.
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

// key options
type options struct {
	ttl int64 //expiry in seconds
}

// IAMStorageAPI defines an interface for the IAM persistence layer
type IAMStorageAPI interface {
	lock()
	unlock()

	rlock()
	runlock()

	migrateBackendFormat(context.Context) error

	loadPolicyDoc(ctx context.Context, policy string, m map[string]iampolicy.Policy) error
	loadPolicyDocs(ctx context.Context, m map[string]iampolicy.Policy) error

	loadUser(ctx context.Context, user string, userType IAMUserType, m map[string]auth.Credentials) error
	loadUsers(ctx context.Context, userType IAMUserType, m map[string]auth.Credentials) error

	loadGroup(ctx context.Context, group string, m map[string]GroupInfo) error
	loadGroups(ctx context.Context, m map[string]GroupInfo) error

	loadMappedPolicy(ctx context.Context, name string, userType IAMUserType, isGroup bool, m map[string]MappedPolicy) error
	loadMappedPolicies(ctx context.Context, userType IAMUserType, isGroup bool, m map[string]MappedPolicy) error

	loadAll(context.Context, *IAMSys) error

	saveIAMConfig(ctx context.Context, item interface{}, path string, opts ...options) error
	loadIAMConfig(ctx context.Context, item interface{}, path string) error
	deleteIAMConfig(ctx context.Context, path string) error

	savePolicyDoc(ctx context.Context, policyName string, p iampolicy.Policy) error
	saveMappedPolicy(ctx context.Context, name string, userType IAMUserType, isGroup bool, mp MappedPolicy, opts ...options) error
	saveUserIdentity(ctx context.Context, name string, userType IAMUserType, u UserIdentity, opts ...options) error
	saveGroupInfo(ctx context.Context, group string, gi GroupInfo) error

	deletePolicyDoc(ctx context.Context, policyName string) error
	deleteMappedPolicy(ctx context.Context, name string, userType IAMUserType, isGroup bool) error
	deleteUserIdentity(ctx context.Context, name string, userType IAMUserType) error
	deleteGroupInfo(ctx context.Context, name string) error

	watch(context.Context, *IAMSys)
}

// LoadGroup - loads a specific group from storage, and updates the
// memberships cache. If the specified group does not exist in
// storage, it is removed from in-memory maps as well - this
// simplifies the implementation for group removal. This is called
// only via IAM notifications.
func (sys *IAMSys) LoadGroup(objAPI ObjectLayer, group string) error {
	if !sys.Initialized() {
		return errServerNotInitialized
	}

	sys.store.lock()
	defer sys.store.unlock()

	err := sys.store.loadGroup(context.Background(), group, sys.iamGroupsMap)
	if err != nil && err != errNoSuchGroup {
		return err
	}

	if err == errNoSuchGroup {
		// group does not exist - so remove from memory.
		sys.removeGroupFromMembershipsMap(group)
		delete(sys.iamGroupsMap, group)
		delete(sys.iamGroupPolicyMap, group)
		return nil
	}

	gi := sys.iamGroupsMap[group]

	// Updating the group memberships cache happens in two steps:
	//
	// 1. Remove the group from each user's list of memberships.
	// 2. Add the group to each member's list of memberships.
	//
	// This ensures that regardless of members being added or
	// removed, the cache stays current.
	sys.removeGroupFromMembershipsMap(group)
	sys.updateGroupMembershipsMap(group, &gi)
	return nil
}

// LoadPolicy - reloads a specific canned policy from backend disks or etcd.
func (sys *IAMSys) LoadPolicy(objAPI ObjectLayer, policyName string) error {
	if !sys.Initialized() {
		return errServerNotInitialized
	}

	sys.store.lock()
	defer sys.store.unlock()

	// When etcd is set, we use watch APIs so this code is not needed.
	return nil
}

// LoadPolicyMapping - loads the mapped policy for a user or group
// from storage into server memory.
func (sys *IAMSys) LoadPolicyMapping(objAPI ObjectLayer, userOrGroup string, isGroup bool) error {
	if !sys.Initialized() {
		return errServerNotInitialized
	}

	sys.store.lock()
	defer sys.store.unlock()

	var err error
	userType := regUser
	if sys.usersSysType == LDAPUsersSysType {
		userType = stsUser
	}

	if isGroup {
		err = sys.store.loadMappedPolicy(context.Background(), userOrGroup, userType, isGroup, sys.iamGroupPolicyMap)
	} else {
		err = sys.store.loadMappedPolicy(context.Background(), userOrGroup, userType, isGroup, sys.iamUserPolicyMap)
	}

	if err == errNoSuchPolicy {
		if isGroup {
			delete(sys.iamGroupPolicyMap, userOrGroup)
		} else {
			delete(sys.iamUserPolicyMap, userOrGroup)
		}
	}
	// Ignore policy not mapped error
	if err != nil && err != errNoSuchPolicy {
		return err
	}

	// When etcd is set, we use watch APIs so this code is not needed.
	return nil
}

// LoadUser - reloads a specific user from backend disks or etcd.
func (sys *IAMSys) LoadUser(objAPI ObjectLayer, accessKey string, userType IAMUserType) error {
	if !sys.Initialized() {
		return errServerNotInitialized
	}

	sys.store.lock()
	defer sys.store.unlock()

	err := sys.store.loadUser(context.Background(), accessKey, userType, sys.iamUsersMap)
	if err != nil {
		return err
	}
	err = sys.store.loadMappedPolicy(context.Background(), accessKey, userType, false, sys.iamUserPolicyMap)
	// Ignore policy not mapped error
	if err != nil && err != errNoSuchPolicy {
		return err
	}
	// We are on purpose not persisting the policy map for parent
	// user, although this is a hack, it is a good enough hack
	// at this point in time - we need to overhaul our OIDC
	// usage with service accounts with a more cleaner implementation
	//
	// This mapping is necessary to ensure that valid credentials
	// have necessary ParentUser present - this is mainly for only
	// webIdentity based STS tokens.
	cred, ok := sys.iamUsersMap[accessKey]
	if ok {
		if cred.IsTemp() && cred.ParentUser != "" && cred.ParentUser != globalActiveCred.AccessKey {
			if _, ok := sys.iamUserPolicyMap[cred.ParentUser]; !ok {
				sys.iamUserPolicyMap[cred.ParentUser] = sys.iamUserPolicyMap[accessKey]
			}
		}
	}

	// When etcd is set, we use watch APIs so this code is not needed.
	return nil
}

// LoadServiceAccount - reloads a specific service account from backend disks or etcd.
func (sys *IAMSys) LoadServiceAccount(accessKey string) error {
	if !sys.Initialized() {
		return errServerNotInitialized
	}

	sys.store.lock()
	defer sys.store.unlock()
	// When etcd is set, we use watch APIs so this code is not needed.
	return nil
}

// Perform IAM configuration migration.
func (sys *IAMSys) doIAMConfigMigration(ctx context.Context) error {
	return sys.store.migrateBackendFormat(ctx)
}

// InitStore initializes IAM stores
func (sys *IAMSys) InitStore(objAPI ObjectLayer) {
	sys.Lock()
	defer sys.Unlock()

	sys.store = &IAMDBStore{}

	if globalLDAPConfig.Enabled {
		sys.EnableLDAPSys()
	}
}

// Initialized check if IAM is initialized
func (sys *IAMSys) Initialized() bool {
	if sys == nil {
		return false
	}
	sys.Lock()
	defer sys.Unlock()
	return sys.store != nil
	//return true
}

// Load - loads all credentials
func (sys *IAMSys) Load(ctx context.Context, store IAMStorageAPI) error {
	iamUsersMap := make(map[string]auth.Credentials)
	iamGroupsMap := make(map[string]GroupInfo)
	iamUserPolicyMap := make(map[string]MappedPolicy)
	iamGroupPolicyMap := make(map[string]MappedPolicy)
	iamPolicyDocsMap := make(map[string]iampolicy.Policy)

	store.rlock()
	isMinIOUsersSys := sys.usersSysType == MinIOUsersSysType
	store.runlock()

	if err := store.loadPolicyDocs(ctx, iamPolicyDocsMap); err != nil {
		return err
	}

	// Sets default canned policies, if none are set.
	setDefaultCannedPolicies(iamPolicyDocsMap)

	if isMinIOUsersSys {
		if err := store.loadUsers(ctx, regUser, iamUsersMap); err != nil {
			return err
		}
		if err := store.loadGroups(ctx, iamGroupsMap); err != nil {
			return err
		}
	}

	// load polices mapped to users
	if err := store.loadMappedPolicies(ctx, regUser, false, iamUserPolicyMap); err != nil {
		return err
	}

	// load policies mapped to groups
	if err := store.loadMappedPolicies(ctx, regUser, true, iamGroupPolicyMap); err != nil {
		return err
	}

	if err := store.loadUsers(ctx, svcUser, iamUsersMap); err != nil {
		return err
	}

	// load STS temp users
	if err := store.loadUsers(ctx, stsUser, iamUsersMap); err != nil {
		return err
	}

	// load STS policy mappings
	if err := store.loadMappedPolicies(ctx, stsUser, false, iamUserPolicyMap); err != nil {
		return err
	}

	store.lock()
	defer store.unlock()

	for k, v := range iamPolicyDocsMap {
		sys.iamPolicyDocsMap[k] = v
	}

	// Merge the new reloaded entries into global map.
	// See issue https://github.com/minio/minio/issues/9651
	// where the present list of entries on disk are not yet
	// latest, there is a small window where this can make
	// valid users invalid.
	for k, v := range iamUsersMap {
		sys.iamUsersMap[k] = v
	}

	for k, v := range iamUserPolicyMap {
		sys.iamUserPolicyMap[k] = v
	}

	// purge any expired entries which became expired now.
	for k, v := range sys.iamUsersMap {
		if v.IsExpired() {
			delete(sys.iamUsersMap, k)
			delete(sys.iamUserPolicyMap, k)
			// deleting will be done in the next cycle.
		}
	}

	for k, v := range iamGroupPolicyMap {
		sys.iamGroupPolicyMap[k] = v
	}

	for k, v := range iamGroupsMap {
		sys.iamGroupsMap[k] = v
	}

	sys.buildUserGroupMemberships()
	select {
	case <-sys.configLoaded:
	default:
		close(sys.configLoaded)
	}
	return nil
}

// Init - initializes config system by reading entries from config/iam
func (sys *IAMSys) Init(ctx context.Context, objAPI ObjectLayer) {
	// Initialize IAM store
	sys.InitStore(objAPI)

	retryCtx, cancel := context.WithCancel(ctx)

	// Indicate to our routine to exit cleanly upon return.
	defer cancel()

	for {
		if err := sys.store.loadAll(retryCtx, sys); err != nil {
			//if configRetriableErrors(err) {
			//	logger.Info("Waiting for all MinIO IAM sub-system to be initialized.. possible cause (%v)", err)
			//	time.Sleep(time.Duration(r.Float64() * float64(5*time.Second)))
			//	continue
			//}
			if err != nil {
				logger.Info("", fmt.Errorf("Unable to initialize IAM sub-system, some users may not be available %w", err))
			}
		}
		break
	}

	// Set up polling for expired accounts and credentials purging.
	switch {
	case globalOpenIDConfig.ProviderEnabled():
		go func() {
			for {
				time.Sleep(globalRefreshIAMInterval)
				sys.purgeExpiredCredentialsForExternalSSO(ctx)
			}
		}()
	case globalLDAPConfig.EnabledWithLookupBind():
		go func() {

			for {
				time.Sleep(globalRefreshIAMInterval)
				sys.purgeExpiredCredentialsForLDAP(ctx)
				sys.updateGroupMembershipsForLDAP(ctx)
			}
		}()
	}

	go sys.store.watch(ctx, sys)
}

func (sys *IAMSys) purgeExpiredCredentials(ctx context.Context) {
	_, cancel := context.WithCancel(ctx)

	// Indicate to our routine to exit cleanly upon return.
	defer cancel()

	// delete expired credentials
	go func() {
		for {
			time.Sleep(globalRefreshIAMInterval)
			sys.store.lock()
			for _, cred := range sys.iamUsersMap {
				if cred.IsExpired() {
					delete(sys.iamUsersMap, cred.AccessKey)
					delete(sys.iamUserPolicyMap, cred.AccessKey)
				}
			}
			sys.store.unlock()
		}
	}()
}

// DeletePolicy - deletes a canned policy from backend or etcd.
func (sys *IAMSys) DeletePolicy(policyName string) error {
	if !sys.Initialized() {
		return errServerNotInitialized
	}

	if !isPolicyNameValid(policyName) {
		return errInvalidArgument
	}

	if isDefaultPolicy(policyName) {
		return errors.New("cannot delete default policy")
	}

	sys.store.lock()
	defer sys.store.unlock()

	// delete policies
	return deletePolicy(policyName)
}

// InfoPolicy - expands the canned policy into its JSON structure.
func (sys *IAMSys) InfoPolicy(policyName string) (iampolicy.Policy, error) {
	if !sys.Initialized() {
		return iampolicy.Policy{}, errServerNotInitialized
	}

	sys.store.rlock()
	defer sys.store.runlock()

	var combinedPolicy iampolicy.Policy
	for _, name := range strings.Split(policyName, ",") {
		if name == "" {
			continue
		}
		// load default policies
		v, ok := sys.iamPolicyDocsMap[name]
		if ok {
			combinedPolicy = combinedPolicy.Merge(v)
		} else {
			// get policy from db
			p, err := loadPolicyFromDB(name)
			if err != nil {
				return iampolicy.Policy{}, err
			}
			combinedPolicy = combinedPolicy.Merge(p)
		}
	}
	return combinedPolicy, nil
}

// ListPolicies - lists all canned policies.
func (sys *IAMSys) ListPolicies(tenantName, bucketName string) (map[string]iampolicy.Policy, error) {
	if !sys.Initialized() {
		return nil, errServerNotInitialized
	}

	sys.store.rlock()
	defer sys.store.runlock()

	policyDocsMap := make(map[string]iampolicy.Policy, len(sys.iamPolicyDocsMap))
	for k, v := range sys.iamPolicyDocsMap {
		if bucketName != "" && v.MatchResource(bucketName) {
			policyDocsMap[k] = v
		} else {
			policyDocsMap[k] = v
		}
	}

	// list policies from db
	// get tenant
	tenantUser := db.GetMtAccount(tenantName)
	if tenantUser == nil {
		return nil, errors.New("database err: get mt_account failed")
	}
	// if tenant user does not exists, only lists default policies.
	if tenantUser.Username == "" || tenantUser.Username != tenantName {
		return policyDocsMap, nil
	}

	// get policies
	policies := tenantUser.GetPoliciesByTenant()
	if policies == nil {
		return nil, errors.New("database err: get policies failed")
	}
	// if policies does not exists, only lists default policies.
	if len(policies) == 0 {
		return policyDocsMap, nil
	}
	policyName := make(map[string]struct{})
	for i := 0; i < len(policies); i++ {
		if _, ok := policyName[policies[i].Name]; !ok && !isDefaultPolicy(policies[i].Name) {
			policyName[policies[i].Name] = struct{}{}
		}
	}
	for name, _ := range policyName {
		// get policy
		policies = db.GetPolicy(name)
		if policies == nil {
			return nil, errors.New("database err: get policies failed")
		}
		if len(policies) == 0 {
			return nil, errNoSuchPolicy
		}
		var states []iampolicy.Statement
		for _, p := range policies {
			// get statements
			s := p.GetStatementByPolicy()
			if s == nil {
				return nil, errors.New("database err: get statements failed")
			}
			if s.ID != 0 {
				// get conditions
				con, err := base64.StdEncoding.DecodeString(s.Condition)
				if err != nil {
					return nil, err
				}
				var confunc condition.Functions
				if bytes.Equal(con, []byte{'{', '}'}) {
					confunc = make(condition.Functions, 0)
				} else {
					err = confunc.UnmarshalJSON(con)
					if err != nil {
						return nil, err
					}
				}
				// get resources
				res, err := base64.StdEncoding.DecodeString(s.Resource)
				if err != nil {
					return nil, err
				}
				var resset iampolicy.ResourceSet
				if len(res) != 0 {
					err = resset.UnmarshalJSON(res)
					if err != nil {
						return nil, err
					}
				}
				// get actions
				var actionset iampolicy.ActionSet
				at := s.GetActionsByStatement()
				if at == nil {
					return nil, errors.New("database err: get actions failed")
				}
				if at.ID != 0 {
					action, err := base64.StdEncoding.DecodeString(at.Actions)
					if err != nil {
						return nil, err
					}
					err = actionset.UnmarshalJSON(action)
					if err != nil {
						return nil, err
					}
				}
				state := iampolicy.Statement{
					Effect: func() policy.Effect {
						if s.Effect {
							return policy.Allow
						} else {
							return policy.Deny
						}
					}(),
					Actions:    actionset,
					Resources:  resset,
					Conditions: confunc,
				}
				states = append(states, state)
			}
		}
		policyDocsMap[name] = iampolicy.Policy{
			Version:    policies[0].Version,
			Statements: states,
		}
	}
	return policyDocsMap, nil
}

// SetPolicy - sets a new name policy.
func (sys *IAMSys) SetPolicy(tenantName, policyName string, p iampolicy.Policy) error {
	if !sys.Initialized() {
		return errServerNotInitialized
	}

	if p.IsEmpty() || policyName == "" {
		return errInvalidArgument
	}

	if !isPolicyNameValid(policyName) {
		return errInvalidArgument
	}

	if isDefaultPolicy(policyName) {
		return nil
	}

	sys.store.lock()
	defer sys.store.unlock()
	// save policy
	return savePolicy(tenantName, policyName, p)
}

// DeleteUser - delete user (only for long-term users not STS users).
func (sys *IAMSys) DeleteUser(accessKey string) error {
	if !sys.Initialized() {
		return errServerNotInitialized
	}

	if sys.usersSysType != MinIOUsersSysType {
		return errIAMActionNotAllowed
	}

	// Next we can remove the user from memory and IAM store
	sys.store.lock()
	defer sys.store.unlock()

	for _, u := range sys.iamUsersMap {
		// Delete any associated STS users.
		if u.IsTemp() {
			if u.ParentUser == accessKey {
				delete(sys.iamUsersMap, u.AccessKey)
			}
		}
	}

	// delete user from db
	return deleteUserFromDB(accessKey)
}

// delete user
func deleteUserFromDB(accessKey string) error {
	// find user from db
	user := db.GetMtAccount(accessKey)
	if user == nil {
		return errors.New("database err: get mt_account failed")
	}
	if user.Username == "" || user.Username != accessKey {
		return nil
	}

	return user.DeleteUserInfo()
}
func savePolicy(tenantName, policyName string, p iampolicy.Policy) error {
	dbPolicies := db.GetPolicy(policyName)
	if dbPolicies == nil {
		return errors.New("database err: get policies failed")
	}
	if len(dbPolicies) == 0 {
		err := saveNewPolicy(tenantName, policyName, p)
		if err != nil {
			return err
		}
	} else {
		return updatePolicy(dbPolicies, p)
	}
	return nil
}

// CurrentPolicies - returns comma separated policy string, from
// an input policy after validating if there are any current
// policies which exist on MinIO corresponding to the input.
func (sys *IAMSys) CurrentPolicies(policyName string) string {
	if !sys.Initialized() {
		return ""
	}

	sys.store.rlock()
	defer sys.store.runlock()

	var policies []string
	mp := newMappedPolicy(policyName)
	for _, policy := range mp.toSlice() {
		_, found := sys.iamPolicyDocsMap[policy]
		if found {
			policies = append(policies, policy)
		}
	}
	return strings.Join(policies, ",")
}

// SetTempUser - set temporary user credentials, these credentials have an expiry.
func (sys *IAMSys) SetTempUser(accessKey string, cred auth.Credentials, policyName string) error {
	if !sys.Initialized() {
		return errServerNotInitialized
	}

	// If OPA is not set we honor any policy claims for this
	// temporary user which match with pre-configured canned
	// policies for this server.
	if globalPolicyOPA == nil && policyName != "" {
		mp := newMappedPolicy(policyName)
		combinedPolicy := sys.GetCombinedPolicy(mp.toSlice()...)

		if combinedPolicy.IsEmpty() {
			return fmt.Errorf("specified policy %s, not found %w", policyName, errNoSuchPolicy)
		}

		sys.store.lock()
		defer sys.store.unlock()

		sys.iamUserPolicyMap[accessKey] = mp

		// We are on purpose not persisting the policy map for parent
		// user, although this is a hack, it is a good enough hack
		// at this point in time - we need to overhaul our OIDC
		// usage with service accounts with a more cleaner implementation
		//
		// This mapping is necessary to ensure that valid credentials
		// have necessary ParentUser present - this is mainly for only
		// webIdentity based STS tokens.
		//if cred.IsTemp() && cred.ParentUser != "" && cred.ParentUser != globalActiveCred.AccessKey {
		//if cred.IsTemp() && cred.ParentUser != "" {
		//	if _, ok := sys.iamUserPolicyMap[cred.ParentUser]; !ok {
		//		sys.iamUserPolicyMap[cred.ParentUser] = mp
		//	}
		//}
	} else {
		sys.store.lock()
		defer sys.store.unlock()
	}

	sys.iamUsersMap[accessKey] = cred
	return nil
}

// ListBucketUsers - list all users who can access this 'bucket'
func (sys *IAMSys) ListBucketUsers(bucket string) (map[string]madmin.UserInfo, error) {
	if bucket == "" {
		return nil, errInvalidArgument
	}

	sys.store.rlock()
	defer sys.store.runlock()

	var users = make(map[string]madmin.UserInfo)

	for k, v := range sys.iamUsersMap {
		if v.IsTemp() || v.IsServiceAccount() {
			continue
		}
		var policies []string
		mp, ok := sys.iamUserPolicyMap[k]
		if ok {
			policies = append(policies, mp.toSlice()...)
			for _, group := range sys.iamUserGroupMemberships[k].ToSlice() {
				if nmp, ok := sys.iamGroupPolicyMap[group]; ok {
					policies = append(policies, nmp.toSlice()...)
				}
			}
		}
		var matchesPolices []string
		for _, p := range policies {
			if sys.iamPolicyDocsMap[p].MatchResource(bucket) {
				matchesPolices = append(matchesPolices, p)
			}
		}
		if len(matchesPolices) > 0 {
			users[k] = madmin.UserInfo{
				PolicyName: strings.Join(matchesPolices, ","),
				Status: func() madmin.AccountStatus {
					if v.IsValid() {
						return madmin.AccountEnabled
					}
					return madmin.AccountDisabled
				}(),
				MemberOf: sys.iamUserGroupMemberships[k].ToSlice(),
			}
		}
	}

	return users, nil
}

// ListUsers - list all users from database.
func (sys *IAMSys) ListUsers(username string) (map[string]madmin.UserInfo, error) {
	sys.store.lock()
	defer sys.store.unlock()

	var users = make(map[string]madmin.UserInfo)

	// tenant
	tenantUser := db.GetMtAccount(username)
	if tenantUser == nil {
		return nil, errors.New("database err: get mt_account failed")
	}
	if tenantUser.Username == "" || tenantUser.Username != username {
		return nil, errNoSuchUser
	}
	// find users
	accounts := tenantUser.GetAccountsByTenant()
	if accounts == nil {
		return nil, errors.New("database err: get accounts failed")
	}
	for _, account := range accounts {
		dbCred := account.GetCredentialByAccount()
		if dbCred == nil {
			return nil, errors.New("database err: get credential failed")
		}
		if dbCred.AccessKey == "" || dbCred.AccessKey != account.Username {
			continue
		}
		// get policies
		apolicy := account.GetPoliciesByAccount()
		if apolicy == nil {
			return nil, errors.New("database err: get policies failed")
		}
		var policies []string
		m := make(map[string]struct{})
		for _, p := range apolicy {
			if _, ok := m[p.Name]; !ok {
				policies = append(policies, p.Name)
				m[p.Name] = struct{}{}
			}
		}
		policyName := strings.Join(policies, ",")
		// get group
		groups := account.GetGroupsByAccount()
		if groups == nil {
			return nil, errors.New("database err: get group failed")
		}
		groupName := make([]string, 0)
		for _, g := range groups {
			if g.Name != "" {
				groupName = append(groupName, g.Name)
			}
		}

		if account.Ctype == int(regUser) {
			users[account.Username] = madmin.UserInfo{
				PolicyName: policyName,
				Status: func() madmin.AccountStatus {
					if dbCred.Status {
						return madmin.AccountEnabled
					}
					return madmin.AccountDisabled
				}(),
				MemberOf: groupName,
			}
		}
	}
	return users, nil
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

// IsServiceAccount - returns if given key is a service account
func (sys *IAMSys) IsServiceAccount(name string) (bool, string, error) {
	if !sys.Initialized() {
		return false, "", errServerNotInitialized
	}

	sys.store.rlock()
	defer sys.store.runlock()

	// get user
	user := db.GetMtAccount(name)
	if user == nil {
		return false, "", errors.New("database err: get mt_account failed")
	}
	if user.Username == "" || user.Username != name {
		return false, "", errNoSuchUser
	}
	// get cred
	dbCred := db.GetCredential(name)
	if dbCred == nil {
		return false, "", errors.New("database err: get credential failed")
	}
	if dbCred.AccessKey == "" || dbCred.AccessKey != name {
		return false, "", errNoSuchUser
	}

	// get parent user
	parent := db.GetAccountByUid(dbCred.ParentUser)
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

// GetUserInfo - get info on a user.
func (sys *IAMSys) GetUserInfo(name string) (u madmin.UserInfo, err error) {
	if !sys.Initialized() {
		return u, errServerNotInitialized
	}

	if sys.usersSysType != MinIOUsersSysType {
		return madmin.UserInfo{}, errors.New("only support minio user type")
	}

	sys.store.rlock()
	defer sys.store.runlock()

	// find user
	user := db.GetMtAccount(name)
	if user == nil {
		return madmin.UserInfo{}, errors.New("database err: get mt_account failed")
	}
	if user.Ctype != int(tenant) && user.Ctype != int(regUser) {
		return madmin.UserInfo{}, errors.New("only support tenant or regular users")
	}
	// find cred
	cred := user.GetCredentialByAccount()
	if cred == nil {
		return madmin.UserInfo{}, errors.New("database err: get credential failed")
	}
	if cred.AccessKey == "" || cred.AccessKey != name {
		return madmin.UserInfo{}, errNoSuchUser
	}
	// find group
	groups := user.GetGroupsByAccount()
	if groups == nil {
		return madmin.UserInfo{}, errors.New("database err: get group failed")
	}
	groupName := make([]string, 0)
	for _, g := range groups {
		if g.Name != "" {
			groupName = append(groupName, g.Name)
		}
	}

	// find policy
	var policyName string
	policies := user.GetPoliciesByAccount()
	if policies == nil {
		return madmin.UserInfo{}, errors.New("database err: get policies failed")
	}
	var policy []string
	m := make(map[string]struct{})
	for _, p := range policies {
		if _, ok := m[p.Name]; !ok {
			policy = append(policy, p.Name)
			m[p.Name] = struct{}{}
		}
	}
	policyName = strings.Join(policy, ",")

	return madmin.UserInfo{
		PolicyName: policyName,
		Status: func() madmin.AccountStatus {
			if cred.Status {
				return madmin.AccountEnabled
			}
			return madmin.AccountDisabled
		}(),
		MemberOf: groupName,
	}, nil
}

// SetUserStatus - sets current user status, supports disabled or enabled.
func (sys *IAMSys) SetUserStatus(tenantName, accessKey string, status madmin.AccountStatus) error {
	if !sys.Initialized() {
		return errServerNotInitialized
	}

	if sys.usersSysType != MinIOUsersSysType {
		return errIAMActionNotAllowed
	}

	if status != madmin.AccountEnabled && status != madmin.AccountDisabled {
		return errInvalidArgument
	}

	sys.store.lock()
	defer sys.store.unlock()

	cred, _ := sys.iamUsersMap[accessKey]
	if cred.IsTemp() || cred.IsServiceAccount() {
		return errIAMActionNotAllowed
	}

	cred = auth.Credentials{
		AccessKey: accessKey,
		Status: func() string {
			if status == madmin.AccountEnabled {
				return auth.AccountOn
			} else {
				return auth.AccountOff
			}
		}(),
	}

	uinfo := UserIdentity{
		Credentials: cred,
	}

	if err := saveUserIdentity(tenantName, accessKey, regUser, uinfo); err != nil {
		return err
	}
	return nil
}

type newServiceAccountOpts struct {
	sessionPolicy *iampolicy.Policy
	accessKey     string
	secretKey     string

	// LDAP username
	ldapUsername string
}

// NewServiceAccount - create a new service account
func (sys *IAMSys) NewServiceAccount(ctx context.Context, parentUser string, groups []string, opts newServiceAccountOpts) (auth.Credentials, error) {
	if !sys.Initialized() {
		return auth.Credentials{}, errServerNotInitialized
	}

	var policyBuf []byte
	if opts.sessionPolicy != nil {
		err := opts.sessionPolicy.Validate()
		if err != nil {
			return auth.Credentials{}, err
		}
		policyBuf, err = json.Marshal(opts.sessionPolicy)
		if err != nil {
			return auth.Credentials{}, err
		}
		if len(policyBuf) > 16*humanize.KiByte {
			return auth.Credentials{}, fmt.Errorf("Session policy should not exceed 16 KiB characters")
		}
	}

	sys.store.lock()
	defer sys.store.unlock()

	// find parent user
	parent := db.GetMtAccount(parentUser)
	if parent == nil {
		return auth.Credentials{}, errors.New("database err: get mt_account failed")
	}
	// Disallow service accounts to further create more service accounts.
	if parent.Ctype == int(svcUser) {
		return auth.Credentials{}, errIAMActionNotAllowed
	}

	policies, err := sys.policyDBGet(parentUser, false)
	if err != nil {
		return auth.Credentials{}, err
	}
	for _, group := range groups {
		gpolicies, err := sys.policyDBGet(group, true)
		if err != nil && err != errNoSuchGroup {
			return auth.Credentials{}, err
		}
		policies = append(policies, gpolicies...)
	}
	if len(policies) == 0 {
		return auth.Credentials{}, errNoSuchPolicy
	}

	m := make(map[string]interface{})
	m[parentClaim] = parentUser

	//add by lyc begin
	mtAccount := db.GetMtAccount(parentUser)
	if mtAccount == nil {
		return auth.Credentials{}, errors.New("database err: get mt_account failed")
	} else if mtAccount.TenantId > 0 {
		tenantUser := db.GetAccountByUid(mtAccount.TenantId)
		if tenantUser == nil {
			return auth.Credentials{}, errors.New("database err: get mt_account failed")
		}
		m["TenantId"] = tenantUser.Uid
		m["ParentUserId"] = mtAccount.ParentUser
	} else {
		m["TenantId"] = mtAccount.Uid
		m["ParentUserId"] = mtAccount.Uid
	}
	//add by lyc end

	if len(policyBuf) > 0 {
		m[iampolicy.SessionPolicyName] = base64.StdEncoding.EncodeToString(policyBuf)
		m[iamPolicyClaimNameSA()] = "embedded-policy"
	} else {
		m[iamPolicyClaimNameSA()] = "inherited-policy"
	}

	// For LDAP service account, save the ldap username in the metadata.
	if opts.ldapUsername != "" {
		m[ldapUserN] = opts.ldapUsername
	}

	var (
		cred auth.Credentials
	)

	secret := parent.Password
	if len(opts.accessKey) > 0 {
		cred, err = auth.CreateNewCredentialsWithMetadata(opts.accessKey, opts.secretKey, m, secret)
	} else {
		cred, err = auth.GetNewCredentialsWithMetadata(m, secret)
	}
	if err != nil {
		return auth.Credentials{}, err
	}
	cred.ParentUser = parentUser
	cred.Groups = groups
	cred.Status = auth.AccountOn

	u := newUserIdentity(cred)

	// save user identity
	// find tenant
	tenantUser := &db.MtAccount{}
	if parent.Ctype == int(tenant) {
		tenantUser = db.GetAccountByUid(parent.Uid)
		if tenantUser == nil {
			return auth.Credentials{}, errors.New("database err: get mt_account failed")
		}
	} else {
		tenantUser = db.GetAccountByUid(parent.TenantId)
		if tenantUser == nil {
			return auth.Credentials{}, errors.New("database err: get mt_account failed")
		}
	}
	if tenantUser.Username == "" {
		return auth.Credentials{}, errNoSuchUser
	}

	if err = saveUserIdentity(tenantUser.Username, u.Credentials.AccessKey, svcUser, u); err != nil {
		return auth.Credentials{}, err
	}

	return cred, nil
}

type updateServiceAccountOpts struct {
	sessionPolicy *iampolicy.Policy
	secretKey     string
	status        string
}

// UpdateServiceAccount - edit a service account
func (sys *IAMSys) UpdateServiceAccount(ctx context.Context, tenantName, accessKey string, opts updateServiceAccountOpts) error {
	if !sys.Initialized() {
		return errServerNotInitialized
	}

	sys.store.lock()
	defer sys.store.unlock()

	// find user
	user := db.GetMtAccount(accessKey)
	if user == nil {
		return errors.New("database err: get mt_account failed")
	}
	if user.Username == "" || user.Username != accessKey || user.Ctype != int(svcUser) {
		return errNoSuchServiceAccount
	}
	// find cred
	dbCred := user.GetCredentialByAccount()
	if dbCred == nil {
		return errors.New("database err: get credential failed")
	}
	if dbCred.AccessKey == "" || dbCred.AccessKey != accessKey {
		return errNoSuchServiceAccount
	}
	// find parent
	parent := db.GetAccountByUid(user.ParentUser)
	if parent == nil {
		return errors.New("database err: get mt_account failed")
	}
	if parent.Username == "" {
		return errNoSuchUser
	}
	// find group
	groups := user.GetGroupsByAccount()
	if groups == nil {
		return errors.New("database err: get group failed")
	}
	groupName := make([]string, 0)
	for _, g := range groups {
		if g.Name != "" {
			groupName = append(groupName, g.Name)
		}
	}

	cred := auth.Credentials{
		AccessKey:    accessKey,
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
		Groups:     groupName,
	}

	if opts.secretKey != "" {
		if !auth.IsSecretKeyValid(opts.secretKey) {
			return auth.ErrInvalidSecretKeyLength
		}
		cred.SecretKey = opts.secretKey
	}

	switch opts.status {
	// The caller did not ask to update status account, do nothing
	case "":
	// Update account status
	case auth.AccountOn, auth.AccountOff:
		cred.Status = opts.status
	default:
		return errors.New("unknown account status value")
	}

	if opts.sessionPolicy != nil {
		m := make(map[string]interface{})
		err := opts.sessionPolicy.Validate()
		if err != nil {
			return err
		}
		policyBuf, err := json.Marshal(opts.sessionPolicy)
		if err != nil {
			return err
		}
		if len(policyBuf) > 16*humanize.KiByte {
			return fmt.Errorf("Session policy should not exceed 16 KiB characters")
		}

		m[iampolicy.SessionPolicyName] = base64.StdEncoding.EncodeToString(policyBuf)
		m[iamPolicyClaimNameSA()] = "embedded-policy"
		m[parentClaim] = cred.ParentUser
		//cred.SessionToken, err = auth.JWTSignWithAccessKey(accessKey, m, globalActiveCred.SecretKey)
		cred.SessionToken, err = auth.JWTSignWithAccessKey(accessKey, m, parent.Password)
		if err != nil {
			return err
		}
	}

	u := newUserIdentity(cred)
	if err := saveUserIdentity(tenantName, u.Credentials.AccessKey, svcUser, u); err != nil {
		return err
	}

	return nil
}

// ListServiceAccounts - lists all services accounts associated to a specific user
func (sys *IAMSys) ListServiceAccounts(ctx context.Context, accessKey string) ([]auth.Credentials, error) {
	if !sys.Initialized() {
		return nil, errServerNotInitialized
	}

	sys.store.rlock()
	defer sys.store.runlock()

	// find user
	user := db.GetMtAccount(accessKey)
	if user == nil {
		return nil, errors.New("database err: get mt_account failed")
	}
	if user.Username == "" || user.Username != accessKey {
		return nil, nil
	}
	// find service account
	var serviceAccounts []auth.Credentials
	svcs := user.GetServiceAccounts()
	if svcs == nil {
		return nil, errors.New("database err: get service accounts failed")
	}
	for _, svc := range svcs {
		// find cred
		dbCred := svc.GetCredentialByAccount()
		if dbCred == nil {
			return nil, errors.New("database err: get credential failed")
		}
		if dbCred.AccessKey == "" {
			continue
		}
		// find parent
		parent := db.GetAccountByUid(dbCred.ParentUser)
		if parent == nil {
			return nil, errors.New("database err: get mt_account failed")
		}
		if parent.Username == "" {
			continue
		}
		// find group
		//group := svc.GetGroupByAccount()
		//if group == nil {
		//	return nil, errors.New("database err: get group failed")
		//}
		//var groups []string
		//if group.Name != "" {
		//	groups = append(groups, group.Name)
		//}
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
			//Groups:     groups,
		}

		if svc.Ctype == int(svcUser) {
			serviceAccounts = append(serviceAccounts, cred)
		}
	}

	return serviceAccounts, nil
}

// GetServiceAccount - gets information about a service account
func (sys *IAMSys) GetServiceAccount(ctx context.Context, accessKey string) (auth.Credentials, *iampolicy.Policy, error) {
	if !sys.Initialized() {
		return auth.Credentials{}, nil, errServerNotInitialized
	}

	sys.store.rlock()
	defer sys.store.runlock()

	// find user
	user := db.GetMtAccount(accessKey)
	if user == nil {
		return auth.Credentials{}, nil, errors.New("database err: get mt_account failed")
	}
	if user.Username == "" || user.Username != accessKey || user.Ctype != int(svcUser) {
		return auth.Credentials{}, nil, errNoSuchServiceAccount
	}
	// find cred
	dbCred := user.GetCredentialByAccount()
	if dbCred == nil {
		return auth.Credentials{}, nil, errors.New("database err: get credential failed")
	}
	if dbCred.AccessKey == "" || dbCred.AccessKey != accessKey {
		return auth.Credentials{}, nil, errNoSuchServiceAccount
	}
	// find parent
	parent := db.GetAccountByUid(user.ParentUser)
	if parent == nil {
		return auth.Credentials{}, nil, errors.New("database err: get mt_account failed")
	}
	if parent.Username == "" {
		return auth.Credentials{}, nil, errNoSuchUser
	}
	// find group
	groups := user.GetGroupsByAccount()
	if groups == nil {
		return auth.Credentials{}, nil, errors.New("database err: get group failed")
	}
	groupName := make([]string, 0)
	for _, g := range groups {
		if g.Name != "" {
			groupName = append(groupName, g.Name)
		}
	}

	cred := auth.Credentials{
		AccessKey:    accessKey,
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
		Groups:     groupName,
	}

	var embeddedPolicy *iampolicy.Policy

	//jwtClaims, err := auth.ExtractClaims(cred.SessionToken, globalActiveCred.SecretKey)
	jwtClaims, err := auth.ExtractClaims(cred.SessionToken, parent.Password)
	if err == nil {
		pt, ptok := jwtClaims.Lookup(iamPolicyClaimNameSA())
		sp, spok := jwtClaims.Lookup(iampolicy.SessionPolicyName)
		if ptok && spok && pt == "embedded-policy" {
			policyBytes, err := base64.StdEncoding.DecodeString(sp)
			if err == nil {
				p, err := iampolicy.ParseConfig(bytes.NewReader(policyBytes))
				if err == nil {
					policy := iampolicy.Policy{}.Merge(*p)
					embeddedPolicy = &policy
				}
			}
		}
	}
	return cred, embeddedPolicy, nil
}

// DeleteServiceAccount - delete a service account
func (sys *IAMSys) DeleteServiceAccount(ctx context.Context, accessKey string) error {
	if !sys.Initialized() {
		return errServerNotInitialized
	}

	sys.store.lock()
	defer sys.store.unlock()

	// find user
	user := db.GetMtAccount(accessKey)
	if user == nil {
		return errors.New("database err: get mt_account failed")
	}
	if user.Username == "" || user.Username != accessKey || user.Ctype != int(svcUser) {
		return errNoSuchServiceAccount
	}

	// It is ok to ignore deletion error on the mapped policy
	err := deleteUserIdentity(accessKey, svcUser)
	if err != nil && err != errNoSuchUser {
		return err
	}

	return nil
}

// CreateUser - create new user credentials and policy, if user already exists
// they shall be rewritten with new inputs.
func (sys *IAMSys) CreateUser(tenantUser, accessKey string, uinfo madmin.UserInfo) error {
	if !sys.Initialized() {
		return errServerNotInitialized
	}

	if sys.usersSysType != MinIOUsersSysType {
		return errIAMActionNotAllowed
	}

	// determine if user belongs to other tenant
	user := db.GetMtAccount(accessKey)
	if user.Username != "" {
		// find tenant
		t := db.GetAccountByUid(user.TenantId)
		if t.Username != "" && tenantUser != t.Username {
			return errors.New("cannot create an existing user")
		}
	}

	//if !auth.IsAccessKeyValid(accessKey) {
	//	return auth.ErrInvalidAccessKeyLength
	//}

	if !isNameValid(accessKey) || !isSecretKeyValid(uinfo.SecretKey) {
		return errInvalidArgument
	}

	//if !auth.IsSecretKeyValid(uinfo.SecretKey) || len(uinfo.SecretKey) > secretkeyMaxLen {
	//	return auth.ErrInvalidSecretKeyLength
	//}

	sys.store.lock()
	defer sys.store.unlock()

	cr, ok := sys.iamUsersMap[accessKey]
	if cr.IsTemp() && ok {
		return errIAMActionNotAllowed
	}

	u := newUserIdentity(auth.Credentials{
		AccessKey: accessKey,
		SecretKey: uinfo.SecretKey,
		Status: func() string {
			if uinfo.Status == madmin.AccountEnabled {
				return auth.AccountOn
			}
			return auth.AccountOff
		}(),
	})

	if err := saveUserIdentity(tenantUser, accessKey, regUser, u); err != nil {
		return err
	}

	// Set policy if specified.
	if uinfo.PolicyName != "" {
		return sys.policyDBSet(accessKey, uinfo.PolicyName, regUser, false)
	}
	return nil
}

// CreateTenant - create new tenant credentials and policy, if tenant already exists
// they shall be rewritten with new inputs.
func (sys *IAMSys) CreateTenant(cred *auth.Credentials, quota int, svcGenFunc func(map[string]interface{}) (auth.Credentials, error)) (auth.Credentials, error) {
	if !sys.Initialized() {
		return auth.Credentials{}, errServerNotInitialized
	}

	if !isNameValid(cred.AccessKey) || !isSecretKeyValid(cred.SecretKey) {
		return auth.Credentials{}, errInvalidArgument
	}

	sys.store.lock()
	defer sys.store.unlock()

	u := newUserIdentity(*cred)

	return saveTenantIdentity(u, quota, svcGenFunc)
}

// SetUserSecretKey - sets user secret key
func (sys *IAMSys) SetUserSecretKey(tenantName, accessKey string, secretKey string) error {
	if !sys.Initialized() {
		return errServerNotInitialized
	}

	if sys.usersSysType != MinIOUsersSysType {
		return errIAMActionNotAllowed
	}

	//if !auth.IsAccessKeyValid(accessKey) {
	//	return auth.ErrInvalidAccessKeyLength
	//}
	//
	//if !auth.IsSecretKeyValid(secretKey) {
	//	return auth.ErrInvalidSecretKeyLength
	//}
	if !isNameValid(accessKey) || !isSecretKeyValid(secretKey) {
		return errInvalidArgument
	}

	sys.store.lock()
	defer sys.store.unlock()

	// find user
	user := db.GetMtAccount(accessKey)
	if user == nil {
		return errors.New("database err: get mt_account failed")
	}
	if user.Username == "" || user.Username != accessKey {
		return errNoSuchUser
	}
	dbCred := db.GetCredential(accessKey)
	if dbCred == nil {
		return errors.New("database err: get credential failed")
	}
	if dbCred.AccessKey == "" || dbCred.AccessKey != accessKey {
		return errNoSuchUser
	}

	// find parent
	parent := db.GetAccountByUid(dbCred.ParentUser)
	if parent == nil {
		return errors.New("database err: get mt_account failed")
	}
	// find group
	groups := user.GetGroupsByAccount()
	if groups == nil {
		return errors.New("database err: get group failed")
	}
	groupName := make([]string, 0)
	for _, g := range groups {
		if g.Name != "" {
			groupName = append(groupName, g.Name)
		}
	}

	cred := auth.Credentials{
		AccessKey:    accessKey,
		SecretKey:    secretKey,
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
		Groups:     groupName,
	}

	cred.SecretKey = secretKey
	u := newUserIdentity(cred)
	if err := saveUserIdentity(tenantName, accessKey, regUser, u); err != nil {
		return err
	}

	return nil
}

func (sys *IAMSys) loadUserFromStore(accessKey string) {
	sys.store.lock()
	// If user is already found proceed.
	if _, found := sys.iamUsersMap[accessKey]; !found {
		sys.store.loadUser(context.Background(), accessKey, regUser, sys.iamUsersMap)
		if _, found = sys.iamUsersMap[accessKey]; found {
			// found user, load its mapped policies
			sys.store.loadMappedPolicy(context.Background(), accessKey, regUser, false, sys.iamUserPolicyMap)
		} else {
			sys.store.loadUser(context.Background(), accessKey, svcUser, sys.iamUsersMap)
			if svc, found := sys.iamUsersMap[accessKey]; found {
				// Found service account, load its parent user and its mapped policies.
				if sys.usersSysType == MinIOUsersSysType {
					sys.store.loadUser(context.Background(), svc.ParentUser, regUser, sys.iamUsersMap)
				}
				sys.store.loadMappedPolicy(context.Background(), svc.ParentUser, regUser, false, sys.iamUserPolicyMap)
			} else {
				// None found fall back to STS users.
				sys.store.loadUser(context.Background(), accessKey, stsUser, sys.iamUsersMap)
				if _, found = sys.iamUsersMap[accessKey]; found {
					// STS user found, load its mapped policy.
					sys.store.loadMappedPolicy(context.Background(), accessKey, stsUser, false, sys.iamUserPolicyMap)
				}
			}
		}
	}

	// Load associated policies if any.
	for _, policy := range sys.iamUserPolicyMap[accessKey].toSlice() {
		if _, found := sys.iamPolicyDocsMap[policy]; !found {
			sys.store.loadPolicyDoc(context.Background(), policy, sys.iamPolicyDocsMap)
		}
	}

	sys.buildUserGroupMemberships()
	sys.store.unlock()
}

// purgeExpiredCredentialsForExternalSSO - validates if local credentials are still valid
// by checking remote IDP if the relevant users are still active and present.
func (sys *IAMSys) purgeExpiredCredentialsForExternalSSO(ctx context.Context) {
	sys.store.lock()
	parentUsersMap := make(map[string][]auth.Credentials, len(sys.iamUsersMap))
	for _, cred := range sys.iamUsersMap {
		if cred.IsServiceAccount() || cred.IsTemp() {
			userid, err := parseOpenIDParentUser(cred.ParentUser)
			if err == errSkipFile {
				continue
			}
			parentUsersMap[userid] = append(parentUsersMap[userid], cred)
		}
	}
	sys.store.unlock()

	expiredUsers := make([]auth.Credentials, 0, len(parentUsersMap))
	for userid, creds := range parentUsersMap {
		u, err := globalOpenIDConfig.LookupUser(userid)
		if err != nil {
			logger.Info("", err)
			continue
		}
		// Disabled parentUser purge the entries locally
		if !u.Enabled {
			expiredUsers = append(expiredUsers, creds...)
		}
	}

	for _, cred := range expiredUsers {
		userType := regUser
		if cred.IsServiceAccount() {
			userType = svcUser
		} else if cred.IsTemp() {
			userType = stsUser
		}
		sys.store.deleteIAMConfig(ctx, getUserIdentityPath(cred.AccessKey, userType))
		sys.store.deleteIAMConfig(ctx, getMappedPolicyPath(cred.AccessKey, userType, false))
	}

	sys.store.lock()
	for _, cred := range expiredUsers {
		delete(sys.iamUsersMap, cred.AccessKey)
		delete(sys.iamUserPolicyMap, cred.AccessKey)
	}
	sys.store.unlock()
}

// purgeExpiredCredentialsForLDAP - validates if local credentials are still
// valid by checking LDAP server if the relevant users are still present.
func (sys *IAMSys) purgeExpiredCredentialsForLDAP(ctx context.Context) {
	sys.store.lock()
	parentUsersMap := make(map[string][]auth.Credentials, len(sys.iamUsersMap))
	parentUsers := make([]string, 0, len(sys.iamUsersMap))
	for _, cred := range sys.iamUsersMap {
		if cred.IsServiceAccount() || cred.IsTemp() {
			if globalLDAPConfig.IsLDAPUserDN(cred.ParentUser) {
				if _, ok := parentUsersMap[cred.ParentUser]; !ok {
					parentUsers = append(parentUsers, cred.ParentUser)
				}
				parentUsersMap[cred.ParentUser] = append(parentUsersMap[cred.ParentUser], cred)
			}
		}
	}
	sys.store.unlock()

	expiredUsers, err := globalLDAPConfig.GetNonExistentUserDistNames(parentUsers)
	if err != nil {
		// Log and return on error - perhaps it'll work the next time.
		logger.Info("", err)
		return
	}

	for _, expiredUser := range expiredUsers {
		for _, cred := range parentUsersMap[expiredUser] {
			userType := regUser
			if cred.IsServiceAccount() {
				userType = svcUser
			} else if cred.IsTemp() {
				userType = stsUser
			}
			sys.store.deleteIAMConfig(ctx, getUserIdentityPath(cred.AccessKey, userType))
			sys.store.deleteIAMConfig(ctx, getMappedPolicyPath(cred.AccessKey, userType, false))
		}
	}

	sys.store.lock()
	for _, user := range expiredUsers {
		for _, cred := range parentUsersMap[user] {
			delete(sys.iamUsersMap, cred.AccessKey)
			delete(sys.iamUserPolicyMap, cred.AccessKey)
		}
	}
	sys.store.unlock()
}

// updateGroupMembershipsForLDAP - updates the list of groups associated with the credential.
func (sys *IAMSys) updateGroupMembershipsForLDAP(ctx context.Context) {
	// 1. Collect all LDAP users with active creds.
	sys.store.lock()
	// List of unique LDAP (parent) user DNs that have active creds
	parentUsers := make([]string, 0, len(sys.iamUsersMap))
	// Map of LDAP user to list of active credential objects
	parentUserToCredsMap := make(map[string][]auth.Credentials, len(sys.iamUsersMap))
	// DN to ldap username mapping for each LDAP user
	parentUserToLDAPUsernameMap := make(map[string]string, len(sys.iamUsersMap))
	for _, cred := range sys.iamUsersMap {
		if cred.IsServiceAccount() || cred.IsTemp() {
			if globalLDAPConfig.IsLDAPUserDN(cred.ParentUser) {
				// Check if this is the first time we are
				// encountering this LDAP user.
				if _, ok := parentUserToCredsMap[cred.ParentUser]; !ok {
					// Try to find the ldapUsername for this
					// parentUser by extracting JWT claims
					jwtClaims, err := auth.ExtractClaims(cred.SessionToken, globalActiveCred.SecretKey)
					if err != nil {
						// skip this cred - session token seems
						// invalid
						continue
					}
					ldapUsername, ok := jwtClaims.Lookup(ldapUserN)
					if !ok {
						// skip this cred - we dont have the
						// username info needed
						continue
					}

					// Collect each new cred.ParentUser into parentUsers
					parentUsers = append(parentUsers, cred.ParentUser)

					// Update the ldapUsernameMap
					parentUserToLDAPUsernameMap[cred.ParentUser] = ldapUsername
				}
				parentUserToCredsMap[cred.ParentUser] = append(parentUserToCredsMap[cred.ParentUser], cred)
			}
		}
	}
	sys.store.unlock()

	// 2. Query LDAP server for groups of the LDAP users collected.
	updatedGroups, err := globalLDAPConfig.LookupGroupMemberships(parentUsers, parentUserToLDAPUsernameMap)
	if err != nil {
		// Log and return on error - perhaps it'll work the next time.
		logger.Info("", err)
		return
	}

	// 3. Update creds for those users whose groups are changed
	sys.store.lock()
	defer sys.store.unlock()
	for _, parentUser := range parentUsers {
		currGroupsSet := updatedGroups[parentUser]
		currGroups := currGroupsSet.ToSlice()
		for _, cred := range parentUserToCredsMap[parentUser] {
			gSet := set.CreateStringSet(cred.Groups...)
			if gSet.Equals(currGroupsSet) {
				// No change to groups memberships for this
				// credential.
				continue
			}

			cred.Groups = currGroups
			userType := regUser
			if cred.IsServiceAccount() {
				userType = svcUser
			} else if cred.IsTemp() {
				userType = stsUser
			}
			// Overwrite the user identity here. As store should be
			// atomic, it shouldn't cause any corruption.
			if err := sys.store.saveUserIdentity(ctx, cred.AccessKey, userType, newUserIdentity(cred)); err != nil {
				// Log and continue error - perhaps it'll work the next time.
				logger.Info("", err)
				continue
			}
			// If we wrote the updated creds to IAM storage, we can
			// update the in memory map.
			sys.iamUsersMap[cred.AccessKey] = cred
		}
	}
}

// GetUser - get user credentials
func (sys *IAMSys) GetUser(accessKey string) (cred auth.Credentials, ok bool) {
	if !sys.Initialized() {
		return cred, false
	}

	if !sys.Initialized() {
		return cred, false
	}
	sys.store.lock()
	defer sys.store.unlock()
	cred, ok = sys.iamUsersMap[accessKey]
	if ok && cred.IsValid() {
		return cred, ok
	} else {
		// find tenant or user
		user := db.GetMtAccount(accessKey)
		if user == nil {
			logger.Error("database err: get mt_account failed")
			return auth.Credentials{}, false
		}
		if user.Username == "" || user.Username != accessKey {
			return auth.Credentials{}, false
		}
		// find credential
		dbCred := user.GetCredentialByAccount()
		if dbCred == nil {
			logger.Error("database err: get credential failed")
			return auth.Credentials{}, false
		}
		if dbCred.AccessKey == "" || dbCred.AccessKey != accessKey {
			return auth.Credentials{}, false
		}
		cred = auth.Credentials{
			AccessKey:    dbCred.AccessKey,
			SecretKey:    dbCred.SecretKey,
			Expiration:   dbCred.Expiration,
			SessionToken: dbCred.SessionToken,
			Status: func() string {
				if dbCred.Status {
					return auth.AccountOn
				}
				return auth.AccountOff
			}(),
		}

		if user.Ctype == int(svcUser) {
			// find parent user
			parent := db.GetAccountByUid(dbCred.ParentUser)
			if parent == nil {
				logger.Error("database err: get mt_account failed")
				return auth.Credentials{}, false
			}
			cred.ParentUser = parent.Username
		}
		return cred, true
	}
}

// AddUsersToGroup - adds users to a group, creating the group if
// needed. No error if user(s) already are in the group.
func (sys *IAMSys) AddUsersToGroup(tenantName, group string, members []string) error {
	if !sys.Initialized() {
		return errServerNotInitialized
	}

	if group == "" || !isNameValid(group) {
		return errInvalidArgument
	}

	if sys.usersSysType != MinIOUsersSysType {
		return errIAMActionNotAllowed
	}

	sys.store.lock()
	defer sys.store.unlock()

	// Validate that all members exist.
	for _, member := range members {
		account := db.GetMtAccount(member)
		if account == nil {
			return errors.New("database err: get mt_account failed")
		}
		if account.Username == "" || account.Username != member {
			return errNoSuchUser
		}

		cr, ok := sys.iamUsersMap[member]
		if ok && cr.IsTemp() {
			return errIAMActionNotAllowed
		}
	}

	// find if group exits
	g := db.GetGroup(group)
	if g == nil {
		return errors.New("database err: get group failed")
	}
	var gi GroupInfo
	if g.Name == "" || g.Name != group {
		// Set group as enabled by default when it doesn't
		// exist.
		gi = newGroupInfo(members)
	} else {
		// find tenant
		tenantUser := db.GetMtAccount(tenantName)
		if tenantUser == nil {
			return errors.New("database err: get mt_account failed")
		}
		// if tenant is not the correct, return err.
		if g.TenantId != tenantUser.Uid && tenantUser.Uid != 0 {
			return errors.New("group has been created by other tenant")
		}
		mergedMembers := append(gi.Members, members...)
		uniqMembers := set.CreateStringSet(mergedMembers...).ToSlice()
		gi.Members = uniqMembers
		gi.Status = statusEnabled
	}

	if err := saveGroupInfo(tenantName, group, gi); err != nil {
		return err
	}
	return nil
}

// RemoveUsersFromGroup - remove users from group. If no users are
// given, and the group is empty, deletes the group as well.
func (sys *IAMSys) RemoveUsersFromGroup(tenantName, group string, members []string) error {
	if !sys.Initialized() {
		return errServerNotInitialized
	}

	if sys.usersSysType != MinIOUsersSysType {
		return errIAMActionNotAllowed
	}

	if group == "" || !isNameValid(group) {
		return errInvalidArgument
	}

	sys.store.lock()
	defer sys.store.unlock()

	// Validate that all members exist.
	for _, member := range members {
		// find user
		user := db.GetMtAccount(member)
		if user == nil {
			return errors.New("database err: get mt_account failed")
		}
		if user.Username == "" || user.Username != member {
			return errNoSuchUser
		}
		cr, ok := sys.iamUsersMap[member]
		if ok && cr.IsTemp() {
			return errIAMActionNotAllowed
		}
	}

	// find group
	g := db.GetGroup(group)
	if g == nil {
		return errors.New("database err: get group failed")
	}
	if g.Name == "" || g.Name != group {
		return errNoSuchGroup
	}

	// find users in the group
	var users []string
	accounts := g.GetAccountsByGroup()
	if accounts == nil {
		return errors.New("database err: get accounts failed")
	}
	for _, account := range accounts {
		users = append(users, account.Username)
	}

	// Check if attempting to delete a non-empty group.
	if len(members) == 0 && len(users) != 0 {
		return errGroupNotEmpty
	}

	if len(members) == 0 {
		if err := deleteGroupInfo(group); err != nil {
			return err
		}
		return nil
	}
	// Only removing members.
	s := set.CreateStringSet(users...)
	d := set.CreateStringSet(members...)
	users = s.Difference(d).ToSlice()

	gi := GroupInfo{
		Version: g.Version,
		Status: func() string {
			if g.Status {
				return statusEnabled
			} else {
				return statusDisabled
			}
		}(),
		Members: users,
	}
	// update group id for removed users
	var removed []*db.MtAccount
	for _, account := range accounts {
		if _, ok := d[account.Username]; ok {
			removed = append(removed, account)
		}
	}

	// save group info
	return removeUsersAndSaveGroupInfo(tenantName, group, gi, removed)
}

// SetGroupStatus - enable/disabled a group
func (sys *IAMSys) SetGroupStatus(tenantName, group string, enabled bool) error {
	if !sys.Initialized() {
		return errServerNotInitialized
	}

	if sys.usersSysType != MinIOUsersSysType {
		return errIAMActionNotAllowed
	}

	sys.store.lock()
	defer sys.store.unlock()

	if group == "" {
		return errInvalidArgument
	}

	gi := GroupInfo{
		Status: func() string {
			if enabled {
				return statusEnabled
			} else {
				return statusDisabled
			}
		}(),
	}
	if err := saveGroupInfo(tenantName, group, gi); err != nil {
		return err
	}

	return nil
}

// GetGroupDescription - builds up group description
func (sys *IAMSys) GetGroupDescription(group string) (gd madmin.GroupDesc, err error) {
	if !sys.Initialized() {
		return gd, errServerNotInitialized
	}

	ps, err := sys.PolicyDBGet(group, true)
	if err != nil {
		return gd, err
	}

	policy := strings.Join(ps, ",")

	if sys.usersSysType != MinIOUsersSysType {
		return madmin.GroupDesc{
			Name:   group,
			Policy: policy,
		}, nil
	}

	sys.store.rlock()
	defer sys.store.runlock()

	// get group
	g := db.GetGroup(group)
	if g == nil {
		return gd, errors.New("database err: get group failed")
	}
	if g.Name == "" || g.Name != group {
		return gd, errNoSuchGroup
	}

	var members []string
	users := g.GetAccountsByGroup()
	if users == nil {
		return gd, errors.New("database err: get accounts failed")
	}
	for _, v := range users {
		members = append(members, v.Username)
	}

	return madmin.GroupDesc{
		Name: group,
		Status: func() string {
			if g.Status {
				return statusEnabled
			} else {
				return statusDisabled
			}
		}(),
		Members: members,
		Policy:  policy,
	}, nil
}

// ListGroups - lists groups.
func (sys *IAMSys) ListGroups(name string) (r []string, err error) {
	if !sys.Initialized() {
		return r, errServerNotInitialized
	}

	sys.store.rlock()
	defer sys.store.runlock()
	// get tenant user
	tenantUser := db.GetMtAccount(name)
	if tenantUser == nil {
		return nil, errors.New("database err: get mt_account failed")
	}
	if tenantUser.Username == "" || tenantUser.Username != name {
		return nil, errNoSuchUser
	}
	// get groups
	groups := tenantUser.GetGroupsByTenant()
	if groups == nil {
		return nil, errors.New("database err: get groups failed")
	}
	for _, v := range groups {
		r = append(r, v.Name)
	}
	// TODO
	if sys.usersSysType == LDAPUsersSysType {
		return nil, errors.New("not support LDAP users yet")
	}

	return r, nil
}

// PolicyDBSet - sets a policy for a user or group in the PolicyDB.
func (sys *IAMSys) PolicyDBSet(name, policy string, isGroup bool) error {
	if !sys.Initialized() {
		return errServerNotInitialized
	}

	sys.store.lock()
	defer sys.store.unlock()

	// TODO
	if sys.usersSysType == LDAPUsersSysType {
		return errors.New("not support LDAP user yet")
	}

	return sys.policyDBSet(name, policy, regUser, isGroup)
}

// policyDBSet - sets a policy for user in the policy db. Assumes that caller
// has sys.Lock(). If policy == "", then policy mapping is removed.
func (sys *IAMSys) policyDBSet(name, policyName string, userType IAMUserType, isGroup bool) error {
	if name == "" {
		return errInvalidArgument
	}

	if sys.usersSysType == MinIOUsersSysType {
		if !isGroup {
			if userType == stsUser {
				if _, ok := sys.iamUsersMap[name]; !ok {
					return errNoSuchUser
				}
			}
		}
	}

	// Handle policy mapping removal
	if policyName == "" {
		return deleteMappedPolicy(name, regUser, isGroup)
	}

	// remove policies and set new policies
	return deleteAndSaveMappedPolicies(name, policyName, regUser, isGroup)
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

	pset := set.CreateStringSet(policies...)

	if !isGroup {
		for _, group := range groups {
			ps, err := sys.policyDBGet(group, true)
			if err != nil {
				return nil, err
			}

			for _, p := range ps {
				if _, ok := pset[p]; !ok {
					policies = append(policies, p)
					pset.Add(p)
				}
			}
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
			g := db.GetGroup(name)
			if g == nil {
				return nil, errors.New("database err: get group failed")
			}
			if !g.Status {
				return nil, nil
			}
			gpolicy := g.GetPoliciesByGroup()
			if gpolicy == nil {
				return nil, errors.New("database err: get policies failed")
			}
			m := make(map[string]struct{})
			for _, p := range gpolicy {
				if _, ok := m[p.Name]; !ok {
					policies = append(policies, p.Name)
					m[p.Name] = struct{}{}
				}
			}
		}
		return policies, nil
	}

	// When looking for a user's policies, we also check if the user
	// and the groups they are member of are enabled.
	var parentName string
	u, ok := sys.iamUsersMap[name]
	if ok {
		// sts user
		if !u.IsValid() {
			return nil, nil
		}
		parentName = u.ParentUser
		mp, ok := sys.iamUserPolicyMap[name]
		if !ok {
			if parentName != "" {
				mp = sys.iamUserPolicyMap[parentName]
			}
		}
		// returned policy could be empty
		policies = append(policies, mp.toSlice()...)
		m := set.CreateStringSet(policies...)
		// find sts parentuser
		user := db.GetMtAccount(parentName)
		if user == nil {
			return nil, errors.New("database err: get mt_account failed")
		}
		if user.Username == "" || user.Username != parentName {
			return policies, nil
		}
		// find groups
		groups := user.GetGroupsByAccount()
		if groups == nil {
			return nil, errors.New("database err: get group failed")
		}
		for _, g := range groups {
			if g.Name == "" || !g.Status {
				continue
			}
			// find groups' policies
			gpolicy := g.GetPoliciesByGroup()
			if gpolicy == nil {
				return nil, errors.New("database err: get policies failed")
			}
			for _, p := range gpolicy {
				if _, ok := m[p.Name]; !ok {
					policies = append(policies, p.Name)
					m.Add(p.Name)
				}
			}
		}
	} else {
		// find user
		user := db.GetMtAccount(name)
		if user == nil {
			return nil, errors.New("database err: get mt_account failed")
		}
		if user.Username == "" {
			return policies, nil
		}
		// find user's polices
		upolicy := user.GetPoliciesByAccount()
		if upolicy == nil {
			return nil, errors.New("database err: get policies failed")
		}
		m := make(map[string]struct{})
		for _, p := range upolicy {
			if _, ok := m[p.Name]; !ok {
				policies = append(policies, p.Name)
				m[p.Name] = struct{}{}
			}
		}

		// find groups
		groups := user.GetGroupsByAccount()
		if groups == nil {
			return nil, errors.New("database err: get group failed")
		}
		for _, g := range groups {
			if g.Name == "" || !g.Status {
				continue
			}
			// find groups' policies
			gpolicy := g.GetPoliciesByGroup()
			if gpolicy == nil {
				return nil, errors.New("database err: get policies failed")
			}
			for _, p := range gpolicy {
				if _, ok := m[p.Name]; !ok {
					policies = append(policies, p.Name)
					m[p.Name] = struct{}{}
				}
			}
		}
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
		} else if !found && pname == "consoleAdmin" {
			availablePolicies = append(availablePolicies, iampolicy.DefaultPolicies[3].Definition)
		} else if !found && pname == "diagnostics" {
			availablePolicies = append(availablePolicies, iampolicy.DefaultPolicies[2].Definition)
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

	saPolicyClaim, ok := args.Claims[iamPolicyClaimNameSA()]
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

// IsAllowedLDAPSTS - checks for LDAP specific claims and values
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

// IsAllowedSTS is meant for STS based temporary credentials,
// which implements claims validation and verification other than
// applying policies.
func (sys *IAMSys) IsAllowedSTS(args iampolicy.Args, parentUser string) bool {
	// If it is an LDAP request, check that user and group
	// policies allow the request.
	if sys.usersSysType == LDAPUsersSysType {
		return sys.IsAllowedLDAPSTS(args, parentUser)
	}

	policies, ok := args.GetPolicies(iamPolicyClaimNameOpenID())
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
				logger.Info("", fmt.Errorf("expected policy (%s) missing from the JWT claim %s, rejecting the request", pname, iamPolicyClaimNameOpenID()))
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
		logger.Info("GlobalContext", err)
		return
	}

	// Policy without Version string value reject it.
	if subPolicy.Version == "" {
		return
	}

	// Sub policy is set and valid.
	return hasSessionPolicy, subPolicy.IsAllowed(args)
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
		} else {
			dbPolicy, err := loadPolicyFromDB(pname)
			if err != nil && err != errNoSuchPolicy {
				logger.FatalIf("load policy from db failed", err)
			}
			availablePolicies = append(availablePolicies, dbPolicy)
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

// IsAllowed - checks given policy args is allowed to continue the Rest API.
func (sys *IAMSys) IsAllowed(args iampolicy.Args) bool {
	// If opa is configured, use OPA always.
	if globalPolicyOPA != nil {
		ok, err := globalPolicyOPA.IsAllowed(args)
		if err != nil {
			logger.Info("GlobalContext", err)
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

// 为用户分配默认策略时，最好单独设置，不要组合多个默认策略，否则，策略之间可能会冲突:
// 例如设置只写和读写的策略时，读策略并不会生效，原因是只写策略禁用了读策略，在策略判断时禁用读(Deny)先生效导致读写策略中的读无法生效；
// 如果有除默认策略外的需求，应根据实际情况设置新策略。
// Set default canned policies only if not already overridden by users.
func setDefaultCannedPolicies(policies map[string]iampolicy.Policy) {
	// ReadWrite - provides full access to all buckets and all objects
	var ReadWrite = iampolicy.Policy{
		Version: iampolicy.DefaultVersion,
		Statements: []iampolicy.Statement{
			{
				SID:       policy.ID(""),
				Effect:    policy.Allow,
				Actions:   iampolicy.NewActionSet(iampolicy.AllActions),
				Resources: iampolicy.NewResourceSet(iampolicy.NewResource("*", "")),
			},
		},
	}

	// ReadOnly - read only.
	var ReadOnly = iampolicy.Policy{
		Version: iampolicy.DefaultVersion,
		Statements: []iampolicy.Statement{
			{
				SID:       policy.ID(""),
				Effect:    policy.Allow,
				Actions:   iampolicy.NewActionSet(iampolicy.GetBucketLocationAction, iampolicy.GetObjectAction, iampolicy.ListBucketAction),
				Resources: iampolicy.NewResourceSet(iampolicy.NewResource("*", "")),
			},
		},
	}

	// WriteOnly - provides write access.
	var WriteOnly = iampolicy.Policy{
		Version: iampolicy.DefaultVersion,
		Statements: []iampolicy.Statement{
			{
				SID:       policy.ID(""),
				Effect:    policy.Allow,
				Actions:   iampolicy.NewActionSet(iampolicy.AllActions),
				Resources: iampolicy.NewResourceSet(iampolicy.NewResource("*", "")),
			},
			{
				SID:       policy.ID(""),
				Effect:    policy.Deny,
				Actions:   iampolicy.NewActionSet(iampolicy.GetObjectAction),
				Resources: iampolicy.NewResourceSet(iampolicy.NewResource("*", "")),
			},
		},
	}

	// AdminDiagnostics - provides admin diagnostics access.
	var AdminDiagnostics = iampolicy.Policy{
		Version: iampolicy.DefaultVersion,
		Statements: []iampolicy.Statement{
			{
				SID:    policy.ID(""),
				Effect: policy.Allow,
				Actions: iampolicy.NewActionSet(iampolicy.ProfilingAdminAction,
					iampolicy.TraceAdminAction, iampolicy.ConsoleLogAdminAction,
					iampolicy.ServerInfoAdminAction, iampolicy.TopLocksAdminAction,
					iampolicy.HealthInfoAdminAction, iampolicy.BandwidthMonitorAction,
					iampolicy.PrometheusAdminAction,
				),
				Resources: iampolicy.NewResourceSet(iampolicy.NewResource("*", "")),
			},
		},
	}

	// Admin - provides admin all-access canned policy
	var Admin = iampolicy.Policy{
		Version: iampolicy.DefaultVersion,
		Statements: []iampolicy.Statement{
			{
				SID:        policy.ID(""),
				Effect:     policy.Allow,
				Actions:    iampolicy.NewActionSet(iampolicy.AllAdminActions),
				Resources:  iampolicy.NewResourceSet(),
				Conditions: condition.NewFunctions(),
			},
			{
				SID:        policy.ID(""),
				Effect:     policy.Allow,
				Actions:    iampolicy.NewActionSet(iampolicy.AllActions),
				Resources:  iampolicy.NewResourceSet(iampolicy.NewResource("*", "")),
				Conditions: condition.NewFunctions(),
			},
		},
	}

	_, ok := policies["writeonly"]
	if !ok {
		policies["writeonly"] = WriteOnly
	}
	_, ok = policies["readonly"]
	if !ok {
		policies["readonly"] = ReadOnly
	}
	_, ok = policies["readwrite"]
	if !ok {
		policies["readwrite"] = ReadWrite
	}
	//_, ok = policies["diagnostics"]
	//if !ok {
	//	policies["diagnostics"] = AdminDiagnostics
	//}
	//_, ok = policies["consoleAdmin"]
	//if !ok {
	//	policies["consoleAdmin"] = Admin
	//}

	// store default policies in db
	// writeonly policy
	wo := db.GetPolicy("writeonly")
	if wo == nil {
		logger.Error("database err: get policies failed")
		return
	}
	if len(wo) == 0 {
		err := saveDefaultPolicies("writeonly", WriteOnly)
		if err != nil {
			logger.FatalIf("Unable to store writeonly policy", err)
		}
	}
	// readonly policy
	ro := db.GetPolicy("readonly")
	if ro == nil {
		logger.Error("database err: get policies failed")
		return
	}
	if len(ro) == 0 {
		err := saveDefaultPolicies("readonly", ReadOnly)
		if err != nil {
			logger.FatalIf("Unable to store readonly policy", err)
		}
	}
	// readwrite policy
	rw := db.GetPolicy("readwrite")
	if rw == nil {
		logger.Error("database err: get policies failed")
		return
	}
	if len(rw) == 0 {
		err := saveDefaultPolicies("readwrite", ReadWrite)
		if err != nil {
			logger.FatalIf("Unable to store readwrite policy", err)
		}
	}
	// diagnostics policy
	diag := db.GetPolicy("diagnostics")
	if diag == nil {
		logger.Error("database err: get policies failed")
		return
	}
	if len(diag) == 0 {
		err := saveDefaultPolicies("diagnostics", AdminDiagnostics)
		if err != nil {
			logger.FatalIf("Unable to store diagnostics policy", err)
		}
	}
	// consoleAdmin policy
	admin := db.GetPolicy("consoleAdmin")
	if admin == nil {
		logger.Error("database err: get policies failed")
		return
	}
	if len(admin) == 0 {
		err := saveDefaultPolicies("consoleAdmin", Admin)
		if err != nil {
			logger.FatalIf("Unable to store consoleAdmin policy", err)
		}
	}
}

// buildUserGroupMemberships - builds the memberships map. IMPORTANT:
// Assumes that sys.Lock is held by caller.
func (sys *IAMSys) buildUserGroupMemberships() {
	for group, gi := range sys.iamGroupsMap {
		sys.updateGroupMembershipsMap(group, &gi)
	}
}

// updateGroupMembershipsMap - updates the memberships map for a
// group. IMPORTANT: Assumes sys.Lock() is held by caller.
func (sys *IAMSys) updateGroupMembershipsMap(group string, gi *GroupInfo) {
	if gi == nil {
		return
	}
	for _, member := range gi.Members {
		v := sys.iamUserGroupMemberships[member]
		if v == nil {
			v = set.CreateStringSet(group)
		} else {
			v.Add(group)
		}
		sys.iamUserGroupMemberships[member] = v
	}
}

// removeGroupFromMembershipsMap - removes the group from every member
// in the cache. IMPORTANT: Assumes sys.Lock() is held by caller.
func (sys *IAMSys) removeGroupFromMembershipsMap(group string) {
	for member, groups := range sys.iamUserGroupMemberships {
		if !groups.Contains(group) {
			continue
		}
		groups.Remove(group)
		sys.iamUserGroupMemberships[member] = groups
	}
}

// EnableLDAPSys - enable ldap system users type.
func (sys *IAMSys) EnableLDAPSys() {
	sys.usersSysType = LDAPUsersSysType
}

// NewIAMSys - creates new config system object.
func NewIAMSys() *IAMSys {
	return &IAMSys{
		usersSysType:            MinIOUsersSysType,
		iamUsersMap:             make(map[string]auth.Credentials),
		iamPolicyDocsMap:        make(map[string]iampolicy.Policy),
		iamUserPolicyMap:        make(map[string]MappedPolicy),
		iamGroupPolicyMap:       make(map[string]MappedPolicy),
		iamGroupsMap:            make(map[string]GroupInfo),
		iamUserGroupMemberships: make(map[string]set.StringSet),
		configLoaded:            make(chan struct{}),
	}
}
