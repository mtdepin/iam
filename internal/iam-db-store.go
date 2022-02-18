package internal

import (
	"bytes"
	"encoding/base64"
	"errors"
	"github.com/minio/pkg/bucket/policy"
	"github.com/minio/pkg/bucket/policy/condition"
	iampolicy "github.com/minio/pkg/iam/policy"
	db "mt-iam/datastore"
	"mt-iam/internal/auth"
	"strconv"
	"strings"
	"time"
)

func loadPolicyFromDB(policyName string) (iampolicy.Policy, error) {
	policies := db.GetPolicy(policyName)
	if policies == nil {
		return iampolicy.Policy{}, errors.New("database err: get policies failed")
	}
	if len(policies) == 0 {
		return iampolicy.Policy{}, errNoSuchPolicy
	}
	var states []iampolicy.Statement
	for _, p := range policies {
		// get statements
		s := p.GetStatementByPolicy()
		if s == nil {
			return iampolicy.Policy{}, errors.New("database err: get statements failed")
		}
		if s.ID != 0 {
			// get conditions
			con, err := base64.StdEncoding.DecodeString(s.Condition)
			if err != nil {
				return iampolicy.Policy{}, err
			}
			var confunc condition.Functions
			// 0 condition functions?
			if bytes.Equal(con, []byte{'{', '}'}) {
				confunc = make(condition.Functions, 0)
			} else {
				err = confunc.UnmarshalJSON(con)
				if err != nil {
					return iampolicy.Policy{}, err
				}
			}
			// get resources
			res, err := base64.StdEncoding.DecodeString(s.Resource)
			if err != nil {
				return iampolicy.Policy{}, err
			}
			var resset iampolicy.ResourceSet
			if len(res) != 0 {
				err = resset.UnmarshalJSON(res)
				if err != nil {
					return iampolicy.Policy{}, err
				}
			}

			// get actions
			var actionset iampolicy.ActionSet
			at := s.GetActionsByStatement()
			if at == nil {
				return iampolicy.Policy{}, errors.New("database err: get actions failed")
			}
			if at.ID != 0 {
				action, err := base64.StdEncoding.DecodeString(at.Actions)
				if err != nil {
					return iampolicy.Policy{}, err
				}
				err = actionset.UnmarshalJSON(action)
				if err != nil {
					return iampolicy.Policy{}, err
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
	return iampolicy.Policy{
		Version:    policies[0].Version,
		Statements: states,
	}, nil
}
func saveDefaultPolicies(policyName string, p iampolicy.Policy) error {
	return saveNewPolicy("", policyName, p)
}
func isDefaultPolicy(policyName string) bool {
	return policyName == "writeonly" || policyName == "readonly" || policyName == "readwrite" || policyName == "diagnostics" || policyName == "consoleAdmin"
}
func updatePolicy(dbPolicy []*db.Policy, p iampolicy.Policy) error {
	if len(dbPolicy) == 0 {
		return errors.New("invalid policy")
	}
	// support multi-statements
	if len(p.Statements) == 0 {
		return nil
	}

	policyName := dbPolicy[0].Name
	tenantID := dbPolicy[0].TenantId

	var oldStates []*db.Statement
	var oldActions []*db.Action
	for i := 0; i < len(dbPolicy); i++ {
		states := dbPolicy[i].GetStatementByPolicy()
		if states == nil {
			return errors.New("database err: get statement failed")
		}
		oldStates = append(oldStates, states)

		actions := dbPolicy[i].GetActionsByPolicy()
		if actions == nil {
			return errors.New("database err: get actions failed")
		}
		oldActions = append(oldActions, actions)
	}

	var newStates []*db.Statement
	var newActions []*db.Action
	var newPolicies []*db.Policy
	for i := 0; i < len(p.Statements); i++ {
		actbuf, err := p.Statements[i].Actions.MarshalJSON()
		if err != nil {
			return err
		}
		actionStr := base64.StdEncoding.EncodeToString(actbuf)

		dbAction := &db.Action{
			Name:    policyName + "_" + strconv.Itoa(i),
			Actions: actionStr,
		}
		newActions = append(newActions, dbAction)

		// marshal statement
		resources, err := p.Statements[i].Resources.MarshalJSON()
		if err != nil {
			return err
		}
		resstr := base64.StdEncoding.EncodeToString(resources)
		// marshal conditions
		conditions, err := p.Statements[i].Conditions.MarshalJSON()
		if err != nil {
			return err
		}
		constr := base64.StdEncoding.EncodeToString(conditions)
		dbState := &db.Statement{
			Name: policyName + "_" + strconv.Itoa(i),
			Effect: func() bool {
				if p.Statements[i].Effect == policy.Allow {
					return true
				} else {
					return false
				}
			}(),
			Resource:  resstr,
			Condition: constr,
		}
		newStates = append(newStates, dbState)

		// store policy
		policy := &db.Policy{
			Name:    policyName,
			Version: p.Version,
			//StatementId: dbState.ID,
			TenantId: tenantID,
		}
		newPolicies = append(newPolicies, policy)
	}

	if len(dbPolicy) >= len(p.Statements) {
		return db.UpdateAndDeletePolicy(dbPolicy, newPolicies, oldStates, newStates, oldActions, newActions)
	} else {
		return db.UpdateAndStorePolicy(dbPolicy, newPolicies, oldStates, newStates, oldActions, newActions)
	}
}
func saveTenantIdentity(u UserIdentity, quota int, svcGenFunc func(map[string]interface{}) (auth.Credentials, error)) (auth.Credentials, error) {
	status := func() bool {
		if u.Credentials.Status == auth.AccountOn {
			return true
		} else {
			return false
		}
	}()

	dbcred := &db.Credential{
		Version:      u.Version,
		AccessKey:    u.Credentials.AccessKey,
		SecretKey:    u.Credentials.SecretKey,
		Expiration:   time.Unix(0, 0).UTC(),
		SessionToken: u.Credentials.SessionToken,
		Status:       status,
	}

	return dbcred.StoreTenantInfo(quota, svcGenFunc)
}
func deletePolicy(policyName string) error {
	// find policies
	policies := db.GetPolicy(policyName)
	if policies == nil {
		return errors.New("database err: get policies failed")
	}
	// if policy does not exists, return nil.
	if len(policies) == 0 {
		return nil
	}
	var states []*db.Statement
	var actions []*db.Action
	for _, p := range policies {
		// delete policies
		// find statement
		dbState := p.GetStatementByPolicy()
		if dbState == nil {
			return errors.New("database err: get statements failed")
		}
		if dbState.ID != 0 {
			states = append(states, dbState)
			// find actions
			dbActions := dbState.GetActionsByStatement()
			if dbActions == nil {
				return errors.New("database err: get actions failed")
			}
			if dbActions.ID != 0 {
				actions = append(actions, dbActions)
			}
		}
	}
	return db.DeletePolicy(policies, states, actions)
}
func saveUserIdentity(tenantName, name string, userType IAMUserType, u UserIdentity) error {
	user := db.GetMtAccount(name)
	if user == nil {
		return errors.New("database err: get mt_account failed")
	}
	if user.Username == "" || user.Username != name {
		// create user
		return saveUserInfo(tenantName, userType, u)
	} else {
		// update user
		return updateUserInfo(name, userType, u)
	}
}

// support changing password and status for reg, tenant and svc users.
func updateUserInfo(name string, userType IAMUserType, u UserIdentity) error {
	if userType == regUser || userType == tenant {
		// get user
		user := db.GetMtAccount(name)
		if user == nil {
			return errors.New("database err: get mt_account failed")
		}
		if user.Username == "" || user.Username != name {
			return errNoSuchUser
		}
		// get cred
		cred := user.GetCredentialByAccount()
		if cred == nil {
			return errors.New("database err: get credential failed")
		}
		if cred.AccessKey == "" || cred.AccessKey != name {
			return errNoSuchUser
		}
		// new user
		newUser := db.MtAccount{
			Username: name,
			Password: u.Credentials.SecretKey,
		}
		// new cred
		newCred := db.Credential{
			SecretKey: u.Credentials.SecretKey,
			Status: func() bool {
				if u.Credentials.Status == auth.AccountOn {
					return true
				} else {
					return false
				}
			}(),
		}
		return db.UpdateUserInfo(user, &newUser, cred, &newCred)
	} else {
		return errors.New("sts and svc users are not supported")
	}
}
func saveUserInfo(tenantName string, userType IAMUserType, u UserIdentity) error {
	switch userType {
	case tenant:
		var status bool
		if u.Credentials.Status == auth.AccountOn {
			status = true
		} else {
			status = false
		}
		// create cred
		cred := &db.Credential{
			Version:      u.Version,
			AccessKey:    u.Credentials.AccessKey,
			SecretKey:    u.Credentials.SecretKey,
			Expiration:   time.Unix(0, 0).UTC(),
			SessionToken: u.Credentials.SessionToken,
			Status:       status,
		}
		//var svc *db.Credential
		_, err := cred.StoreTenantInfo(DEFAULT_USER_QUOTA, nil)
		return err
	case regUser:
		// get tenant id
		tenantUser := db.GetMtAccount(tenantName)
		if tenantUser == nil {
			return errors.New("database err: get mt_account failed")
		}
		if tenantUser.Username == "" || tenantUser.Username != tenantName {
			return errNoSuchUser
		}
		var status bool
		if u.Credentials.Status == auth.AccountOn {
			status = true
		} else {
			status = false
		}

		cred := db.Credential{
			Version:      u.Version,
			AccessKey:    u.Credentials.AccessKey,
			SecretKey:    u.Credentials.SecretKey,
			Expiration:   time.Unix(0, 0).UTC(),
			SessionToken: u.Credentials.SessionToken,
			Status:       status,
			ParentUser:   tenantUser.Uid,
		}
		// find groups
		var groups []*db.Group
		for _, name := range u.Credentials.Groups {
			g := db.GetGroup(name)
			if g == nil {
				return errors.New("database err: get group failed")
			}
			groups = append(groups, g)
		}
		return cred.StoreRegUserInfo(tenantUser.Uid, groups)
	case svcUser:
		// get tenant id
		tenantUser := db.GetMtAccount(tenantName)
		if tenantUser == nil {
			return errors.New("database err: get mt_account failed")
		}
		if tenantUser.Username == "" || tenantUser.Username != tenantName {
			return errNoSuchUser
		}
		var status bool
		if u.Credentials.Status == auth.AccountOn {
			status = true
		} else {
			status = false
		}

		// find parent user
		parent := db.GetMtAccount(u.Credentials.ParentUser)
		if parent == nil {
			return errors.New("database err: get mt_account failed")
		}
		if parent.Username == "" || parent.Username != u.Credentials.ParentUser {
			return errNoSuchUser
		}

		cred := db.Credential{
			Version:      u.Version,
			AccessKey:    u.Credentials.AccessKey,
			SecretKey:    u.Credentials.SecretKey,
			Expiration:   time.Unix(0, 0).UTC(),
			SessionToken: u.Credentials.SessionToken,
			Status:       status,
			ParentUser:   parent.Uid,
		}
		return cred.StoreSvcUserInfo(parent.Uid, tenantUser.Uid)
	case stsUser:
		return errors.New("sts user is not allowed")
	}
	return nil
}
func deleteUserIdentity(name string, userType IAMUserType) error {
	switch userType {
	case stsUser:
		return errors.New("sts user is not allowed")
	default:
		// find user
		user := db.GetMtAccount(name)
		if user == nil {
			return errors.New("database err: get mt_account failed")
		}
		if user.Username == "" || user.Username != name {
			return errNoSuchUser
		}
		return user.DeleteUserIdentity()
	}
}
func saveGroupInfo(tenantName, group string, gi GroupInfo) error {
	// get tenant
	tenantUser := db.GetMtAccount(tenantName)
	if tenantUser == nil {
		return errors.New("database err: get mt_account failed")
	}
	if tenantUser.Username == "" || tenantUser.Username != tenantName {
		return errNoSuchUser
	}
	// get group
	g := db.GetGroup(group)
	if g == nil {
		return errors.New("database err: get group failed")
	}
	// if there is no such group, creating a new group.
	if g.Name == "" || g.Name != group {
		dbGroup := &db.Group{
			Name:    group,
			Version: gi.Version,
			Status: func() bool {
				if gi.Status == statusEnabled {
					return true
				} else {
					return false
				}
			}(),
			TenantId: tenantUser.Uid,
		}
		return dbGroup.StoreGroupInfo(gi.Members)
	} else {
		// update group
		newGroup := &db.Group{
			Name:    group,
			Version: gi.Version,
			Status: func() bool {
				if gi.Status == statusEnabled {
					return true
				} else {
					return false
				}
			}(),
			TenantId: tenantUser.Uid,
		}
		return db.UpdateGroupInfo(g, newGroup, gi.Members)
	}
}
func removeUsersAndSaveGroupInfo(tenantName, group string, gi GroupInfo, removed []*db.MtAccount) error {
	// get tenant
	tenantUser := db.GetMtAccount(tenantName)
	if tenantUser == nil {
		return errors.New("database err: get mt_account failed")
	}
	if tenantUser.Username == "" || tenantUser.Username != tenantName {
		return errNoSuchUser
	}
	// get group
	g := db.GetGroup(group)
	if g == nil {
		return errors.New("database err: get group failed")
	}
	if g.Name == "" || g.Name != group {
		return errNoSuchGroup
	} else {
		// update group
		newGroup := &db.Group{
			Name:    group,
			Version: gi.Version,
			Status: func() bool {
				if gi.Status == statusEnabled {
					return true
				} else {
					return false
				}
			}(),
			TenantId: tenantUser.Uid,
		}
		return db.RemoveUsersAndUpdateGroupInfo(g, newGroup, removed, gi.Members)
	}
}
func deleteMappedPolicy(name string, userType IAMUserType, isGroup bool) error {
	if isGroup {
		// find group
		group := db.GetGroup(name)
		if group == nil {
			return errors.New("database err: get group failed")
		}
		if group.Name == "" || group.Name != name {
			return errNoSuchGroup
		}
		return group.DeleteGroupPolicy()
	} else {
		switch userType {
		case stsUser:
			return errors.New("sts user is not allowed")
		default:
			// find user
			user := db.GetMtAccount(name)
			if user == nil {
				return errors.New("database err: get mt_account failed")
			}
			if user.Username == "" || user.Username != name {
				return errNoSuchUser
			}
			return user.DeleteUserPolicy()
		}
	}
}
func deleteAndSaveMappedPolicies(name, policyName string, userType IAMUserType, isGroup bool) error {
	polices := strings.Split(policyName, ",")
	if isGroup {
		// find group
		group := db.GetGroup(name)
		if group == nil {
			return errors.New("database err: get group failed")
		}
		if group.Name == "" || group.Name != name {
			return errNoSuchGroup
		}
		return group.DeleteAndSaveGroupMappedPolicy(polices)
	} else {
		switch userType {
		case stsUser:
			return errors.New("sts user is not allowed")
		default:
			// find user
			user := db.GetMtAccount(name)
			if user == nil {
				return errors.New("database err: get mt_account failed")
			}
			if user.Username == "" || user.Username != name {
				return errNoSuchUser
			}
			if user.Ctype != int(tenant) {
				for _, p := range polices {
					if p == "consoleAdmin" || p == "diagnostics" {
						return errors.New("cannot assign admin policy for regular user")
					}
				}
			}
			return user.DeleteAndSaveUserMappedPolicy(polices)
		}
	}
}

func deleteGroupInfo(name string) error {
	// find group
	group := db.GetGroup(name)
	if group == nil {
		return errors.New("database err: get group failed")
	}
	if group.Name == "" || group.Name != name {
		return errNoSuchGroup
	}

	return group.DeleteGroupInfo()
}
func saveNewPolicy(tenantName, policyName string, p iampolicy.Policy) error {
	// support multi-statements
	if len(p.Statements) == 0 {
		return errors.New("no statements")
	}

	var dbStatements []*db.Statement
	var dbActions []*db.Action
	var dbPolicies []*db.Policy
	for i := 0; i < len(p.Statements); i++ {
		actbuf, err := p.Statements[i].Actions.MarshalJSON()
		if err != nil {
			return err
		}
		actionStr := base64.StdEncoding.EncodeToString(actbuf)

		dbAction := &db.Action{
			Name:    policyName + "_" + strconv.Itoa(i),
			Actions: actionStr,
		}
		dbActions = append(dbActions, dbAction)
		// store statement
		// marshal statement
		resources := make([]byte, 0)
		if len(p.Statements[i].Resources) != 0 {
			resources, err = p.Statements[i].Resources.MarshalJSON()
			if err != nil {
				return err
			}
		}
		resstr := base64.StdEncoding.EncodeToString(resources)
		// marshal conditions
		conditions, err := p.Statements[i].Conditions.MarshalJSON()
		if err != nil {
			return err
		}
		constr := base64.StdEncoding.EncodeToString(conditions)
		dbState := &db.Statement{
			Name: policyName + "_" + strconv.Itoa(i),
			Effect: func() bool {
				if p.Statements[i].Effect == policy.Allow {
					return true
				} else {
					return false
				}
			}(),
			Resource:  resstr,
			Condition: constr,
		}
		dbStatements = append(dbStatements, dbState)

		// store policy
		tenantUser := db.GetMtAccount(tenantName)
		if tenantUser == nil {
			return errors.New("database err: get mt_account failed")
		}
		//if tenantUser.Username == "" || tenantUser.Username != tenantName {
		//	return errNoSuchUser
		//}
		dbPolicy := &db.Policy{
			Name:    policyName,
			Version: p.Version,
			//StatementId: dbState.ID,
			TenantId: tenantUser.Uid,
		}
		dbPolicies = append(dbPolicies, dbPolicy)
	}
	return db.StoreNewPolicy(dbPolicies, dbStatements, dbActions)
}
