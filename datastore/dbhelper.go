package datastore

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"mt-iam/internal/auth"
	"mt-iam/internal/crypto"
	"mt-iam/logger"

	iampolicy "github.com/minio/pkg/iam/policy"
	"gorm.io/gorm"
	"time"
)

type MtAccount struct {
	Uid        int         `json:"uid"`
	Username   string      `json:"username" gorm:"type:varchar(64)"`
	Password   string      `json:"password" gorm:"type:varchar(64)"`
	CredId     int         `json:"cred_id"`
	Version    int         `json:"version"`
	Ctype      int         `json:"ctype" gorm:"type:tinyint"`
	ParentUser int         `json:"parent_user"`
	TenantId   int         `json:"tenant_id"`
	CreatedAt  time.Time   `json:"created_at"`
	UpdatedAt  time.Time   `json:"updated_at"`
	Credential *Credential `gorm:"-"`
	Group      []*Group    `gorm:"-"`
	Tenant     *TenantInfo `gorm:"-"`
	Policies   []*Policy   `gorm:"-"`
}

type Credential struct {
	ID           int       `json:"id" gorm:"primary_key"`
	Version      int       `json:"version"`
	AccessKey    string    `json:"access_key" gorm:"type:varchar(64)"`
	SecretKey    string    `json:"secret_key" gorm:"type:varchar(64)"`
	Expiration   time.Time `json:"expiration"`
	SessionToken string    `json:"session_token" gorm:"type:varchar(1024)"`
	Status       bool      `json:"status"`
	ParentUser   int       `json:"parent_user"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type TenantInfo struct {
	ID        int       `json:"id" gorm:"primary_key"`
	Creator   string    `json:"creator" gorm:"type:varchar(64)"`
	Desc      string    `json:"desc"`
	Quota     int       `json:"quota"  gorm:"type:int(5)"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Group struct {
	ID        int       `json:"id" gorm:"primary_key"`
	Name      string    `json:"name" gorm:"type:varchar(64)"`
	Version   int       `json:"version"`
	Status    bool      `json:"status"`
	TenantId  int       `json:"tenant_id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Policies  []*Policy `gorm:"-"`
}

type GroupAccount struct {
	GroupID   int       `json:"group_id,omitempty"`
	Uid       int       `json:"uid,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Policy struct {
	ID          int        `json:"id" gorm:"primary_key"`
	Name        string     `json:"name" gorm:"type:varchar(64)"`
	Version     string     `json:"version" gorm:"type:varchar(64)"`
	StatementId int        `json:"statement_id"`
	TenantId    int        `json:"tenant_id"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	Statements  *Statement `gorm:"-"`
	Actions     *Action    `gorm:"-"`
}

type Statement struct {
	ID        int       `json:"id" gorm:"primary_key"`
	Name      string    `json:"name" gorm:"type:varchar(64)"`
	Effect    bool      `json:"effect"`
	Resource  string    `json:"resource"`
	Condition string    `json:"condition"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Action struct {
	ID        int       `json:"id" gorm:"primary_key"`
	Name      string    `json:"name,omitempty" gorm:"type:varchar(64)"`
	Actions   string    `json:"actions,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type StatementAction struct {
	ActionId    int       `json:"action_id,omitempty"`
	StatementId int       `json:"statement_id,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type PolicyGroup struct {
	PolicyId  int       `json:"policy_id,omitempty"`
	GroupId   int       `json:"group_id,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type PolicyAccount struct {
	PolicyId  int       `json:"policy_id,omitempty"`
	Uid       int       `json:"uid,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

var (
	InsertNullValuesErr = errors.New("cannot insert null values")
	DeleteNullValuesErr = errors.New("cannot delete null values")
	UpdateNullValuesErr = errors.New("cannot update null values")
)

// database query options

func GetMtAccount(username string) *MtAccount {
	var user MtAccount
	if err := GlobalDB.DB.Raw("SELECT * FROM t_mt_account WHERE username = ?", username).Find(&user).Error; err != nil {
		return nil
	}
	user.Password = crypto.PasswordDecrypt(user.Password)
	return &user
}

func GetAccountByUid(uid int) *MtAccount {
	var user MtAccount
	if err := GlobalDB.DB.Raw("SELECT * FROM t_mt_account WHERE uid = ?", uid).Find(&user).Error; err != nil {
		return nil
	}
	user.Password = crypto.PasswordDecrypt(user.Password)
	return &user
}

func GetCredential(accesskey string) *Credential {
	var cred Credential
	if err := GlobalDB.DB.Raw("SELECT * FROM t_credential WHERE access_key = ?", accesskey).Find(&cred).Error; err != nil {
		return nil
	}
	cred.SecretKey = crypto.PasswordDecrypt(cred.SecretKey)
	return &cred
}

func GetGroup(groupname string) *Group {
	var group Group
	if err := GlobalDB.DB.Raw("SELECT * FROM t_group WHERE name = ?", groupname).Find(&group).Error; err != nil {
		return nil
	}
	return &group
}

func GetPolicy(policyname string) []*Policy {
	var p []*Policy
	if err := GlobalDB.DB.Raw("SELECT * FROM t_policy WHERE name = ?", policyname).Find(&p).Error; err != nil {
		return nil
	}
	return p
}

func (a *MtAccount) GetAccount() *MtAccount {
	if a == nil {
		return nil
	}
	var user MtAccount
	if err := GlobalDB.DB.Raw("SELECT * FROM t_mt_account WHERE uid = ?", a.Uid).Find(&user).Error; err != nil {
		return nil
	}
	user.Password = crypto.PasswordDecrypt(user.Password)
	return &user
}

// for finding svc users.
func (a *MtAccount) GetServiceAccounts() []*MtAccount {
	if a == nil {
		return nil
	}
	var users []*MtAccount
	//todo 判断 ParentUser 是原因？
	//if a.Ctype != svcUser && a.ParentUser != 0 {
	if a.Ctype != svcUser {
		if err := GlobalDB.DB.Raw("SELECT * FROM t_mt_account WHERE ctype = ? AND parent_user = ?", svcUser, a.Uid).Find(&users).Error; err != nil {
			return nil
		}
	}
	return users
}

func (a *MtAccount) GetCredentialByAccount() *Credential {
	if a == nil {
		return nil
	}
	if a.Credential == nil {
		var cred Credential
		if err := GlobalDB.DB.Raw("SELECT * FROM t_credential WHERE id = ?", a.CredId).Find(&cred).Error; err != nil {
			return nil
		}
		cred.SecretKey = crypto.PasswordDecrypt(cred.SecretKey)
		a.Credential = &cred
	}
	return a.Credential
}

func (a *MtAccount) GetGroupsByAccount() []*Group {
	if a == nil {
		return nil
	}
	if a.Group == nil {
		var g []*Group
		if err := GlobalDB.DB.Raw("SELECT t_group.* FROM t_group, t_group_account WHERE t_group.id = t_group_account.group_id AND t_group_account.uid = ?", a.Uid).Find(&g).Error; err != nil {
			return nil
		}
		a.Group = g
	}
	return a.Group
}

const (
	// tenant
	tenant int = iota + 1
	regUser
	svcUser
	stsUser
)

func (a *MtAccount) GetAccountsByTenant() []*MtAccount {
	if a == nil || a.Ctype != tenant {
		return nil
	}
	var users []*MtAccount
	if err := GlobalDB.DB.Raw("SELECT * FROM t_mt_account WHERE tenant_id = ? AND ctype = ?", a.Uid, regUser).Find(&users).Error; err != nil {
		return nil
	}
	return users
}

func (a *MtAccount) GetGroupsByTenant() []*Group {
	if a == nil || a.Ctype != tenant {
		return nil
	}
	var groups []*Group
	if err := GlobalDB.DB.Raw("SELECT * FROM t_group WHERE tenant_id = ?", a.Uid).Find(&groups).Error; err != nil {
		return nil
	}
	return groups
}

func (a *MtAccount) GetCredentialsByTenant() []*Credential {
	if a == nil || a.Ctype != tenant {
		return nil
	}
	var creds []*Credential
	if err := GlobalDB.DB.Raw("SELECT t_credential.* FROM t_mt_account, t_credential WHERE t_credential.id = t_mt_account.cred_id AND t_mt_account.tenant_id = ?", a.TenantId).Find(&creds).Error; err != nil {
		return nil
	}
	return creds
}

func (a *MtAccount) GetTenantByAccount() *TenantInfo {
	if a == nil {
		return nil
	}
	if a.Tenant == nil {
		var t TenantInfo
		if err := GlobalDB.DB.Raw("SELECT * FROM t_tenant_info WHERE id = ?", a.TenantId).Find(&t).Error; err != nil {
			return nil
		}
		a.Tenant = &t
	}
	return a.Tenant
}

func (a *MtAccount) GetPoliciesByAccount() []*Policy {
	if a == nil {
		return nil
	}
	if a.Policies == nil {
		var policies []*Policy
		if err := GlobalDB.DB.Raw("SELECT t_policy.* FROM t_policy_account, t_policy WHERE t_policy_account.policy_id = t_policy.id AND t_policy_account.uid = ?", a.Uid).Find(&policies).Error; err != nil {
			return nil
		}
		a.Policies = policies
	}
	return a.Policies
}

func (a *MtAccount) GetPoliciesByTenant() []*Policy {
	if a == nil {
		return nil
	}
	var policies []*Policy
	if err := GlobalDB.DB.Raw("SELECT * FROM t_policy WHERE tenant_id = ?", a.Uid).Find(&policies).Error; err != nil {
		return nil
	}
	return policies
}

func (g *Group) GetAccountsByGroup() []*MtAccount {
	if g == nil {
		return nil
	}
	var users []*MtAccount
	if err := GlobalDB.DB.Raw("SELECT t_mt_account.* FROM t_mt_account, t_group_account WHERE t_mt_account.uid = t_group_account.uid AND t_group_account.group_id = ?", g.ID).Find(&users).Error; err != nil {
		return nil
	}
	return users
}

func (g *Group) GetPoliciesByGroup() []*Policy {
	if g == nil {
		return nil
	}
	if g.Policies == nil {
		var policies []*Policy
		if err := GlobalDB.DB.Raw("SELECT t_policy.* FROM t_policy_group, t_policy WHERE t_policy_group.policy_id = t_policy.id AND t_policy_group.group_id = ?", g.ID).Find(&policies).Error; err != nil {
			return nil
		}
		g.Policies = policies
	}
	return g.Policies
}

func (g *Group) GetTenantByGroup() *TenantInfo {
	if g == nil {
		return nil
	}
	var tenantInfo TenantInfo
	if err := GlobalDB.DB.Raw("SELECT * FROM t_tenant_info WHERE id = ?", g.TenantId).Find(&tenantInfo).Error; err != nil {
		return nil
	}
	return &tenantInfo
}

func (p *Policy) GetAccountsByPolicy() []*MtAccount {
	if p == nil {
		return nil
	}
	var users []*MtAccount
	if err := GlobalDB.DB.Raw("SELECT t_mt_account.* FROM t_policy_account, t_mt_account WHERE t_policy_account.uid = t_mt_account.uid AND t_policy_account.policy_id = ?", p.ID).Find(&users).Error; err != nil {
		return nil
	}
	return users
}

func (p *Policy) GetGroupsByPolicy() []*Group {
	if p == nil {
		return nil
	}
	var groups []*Group
	if err := GlobalDB.DB.Raw("SELECT t_group.* FROM t_policy_group,t_group WHERE t_policy_group.group_id = t_group.id AND t_policy_group.policy_id = ?", p.ID).Find(&groups).Error; err != nil {
		return nil
	}
	return groups
}

func (p *Policy) GetStatementByPolicy() *Statement {
	if p == nil {
		return nil
	}
	if p.Statements == nil {
		var statement Statement
		if err := GlobalDB.DB.Raw("SELECT * FROM t_statement WHERE id = ?", p.StatementId).Find(&statement).Error; err != nil {
			return nil
		}
		p.Statements = &statement
	}
	return p.Statements
}

func (p *Policy) GetActionsByPolicy() *Action {
	if p == nil {
		return nil
	}
	var actions *Action
	if p.Actions == nil {
		if p.Statements == nil {
			statements := p.GetStatementByPolicy()
			if statements == nil {
				return nil
			}
			actions = statements.GetActionsByStatement()
			if actions == nil {
				return nil
			}
		} else {
			actions = p.Statements.GetActionsByStatement()
			if actions == nil {
				return nil
			}
		}
		p.Actions = actions
	}
	return p.Actions
}

func (s *Statement) GetActionsByStatement() *Action {
	if s == nil {
		return nil
	}
	var actions *Action
	if err := GlobalDB.DB.Raw("SELECT t_action.* FROM t_statement_action,t_action WHERE t_statement_action.action_id = t_action.id AND t_statement_action.statement_id = ? LIMIT 1", s.ID).Find(&actions).Error; err != nil {
		return nil
	}
	return actions
}

func (p *Policy) GetPolicy() *Policy {
	if p == nil {
		return nil
	}
	var policy Policy
	if p.Name != "" {
		if err := GlobalDB.DB.Raw("SELECT * FROM t_policy WHERE name = ?", p.Name).Find(&policy).Error; err != nil {
			return nil
		}
	} else {
		if err := GlobalDB.DB.Raw("SELECT * FROM t_policy WHERE id = ?", p.ID).Find(&policy).Error; err != nil {
			return nil
		}
	}
	return &policy
}

func (s *Statement) GetStatement() *Statement {
	if s == nil {
		return nil
	}
	var state Statement
	if s.Name != "" {
		if err := GlobalDB.DB.Raw("SELECT * FROM t_statement WHERE name = ?", s.Name).Find(&state).Error; err != nil {
			return nil
		}
	} else {
		if err := GlobalDB.DB.Raw("SELECT * FROM t_statement WHERE id = ?", s.ID).Find(&state).Error; err != nil {
			return nil
		}
	}
	return &state
}

func (at *Action) GetAction() *Action {
	if at == nil {
		return nil
	}
	var dbAction Action
	if at.Name != "" {
		if err := GlobalDB.DB.Raw("SELECT * FROM t_action WHERE name = ?", at.Name).Find(&dbAction).Error; err != nil {
			return nil
		}
	} else {
		if err := GlobalDB.DB.Raw("SELECT * FROM t_action WHERE id = ?", at.ID).Find(&dbAction).Error; err != nil {
			return nil
		}
	}
	return &dbAction
}

// database creation options

// store account
func (a *MtAccount) StoreMtAccount() error {
	if a == nil {
		return InsertNullValuesErr
	}
	// 密码加密
	a.Password = crypto.PasswordEncrypt(a.Password)
	err := GlobalDB.DB.Exec("INSERT INTO t_mt_account (username, password, cred_id, version, ctype, parent_user, tenant_id) VALUES (?,?,?,?,?,?,?)",
		a.Username, a.Password, a.CredId, a.Version, a.Ctype, a.ParentUser, a.TenantId).Error
	return err
}

// store credential
func (c *Credential) StoreCredential() error {
	if c == nil {
		return InsertNullValuesErr
	}
	c.SecretKey = crypto.PasswordEncrypt(c.SecretKey)
	err := GlobalDB.DB.Exec("INSERT INTO t_credential (version, access_key, secret_key, session_token, status, parent_user) VALUES (?,?,?,?,?,?)",
		c.Version, c.AccessKey, c.SecretKey, c.SessionToken, c.Status, c.ParentUser).Error
	return err
}

// store tenant info
func (t *TenantInfo) StoreTenantInfo() error {
	if t == nil {
		return InsertNullValuesErr
	}
	err := GlobalDB.DB.Exec("INSERT INTO t_tenant_info (creator, desc) VALUES (?,?)", t.Creator, t.Desc).Error
	return err
}

// store group
func (g *Group) StoreGroup() error {
	if g == nil {
		return InsertNullValuesErr
	}
	err := GlobalDB.DB.Exec("INSERT INTO t_group (name, version, status, tenant_id) VALUES (?,?,?,?)", g.Name, g.Version, g.Status, g.TenantId).Error
	return err
}

// store policy
func (p *Policy) StorePolicy() error {
	if p == nil {
		return InsertNullValuesErr
	}
	err := GlobalDB.DB.Exec("INSERT INTO t_policy (name, version, statement_id, tenant_id) VALUES (?,?,?,?)", p.Name, p.Version, p.StatementId, p.TenantId).Error
	return err
}

// store statements
func (s *Statement) StoreStatement() error {
	if s == nil {
		return InsertNullValuesErr
	}
	err := GlobalDB.DB.Exec("INSERT INTO `t_statement` (`name`, `effect`, `resource`, `condition`) VALUES (?,?,?,?)", s.Name, s.Effect, s.Resource, s.Condition).Error
	return err
}

// store actions
func (at *Action) StoreAction() error {
	if at == nil {
		return InsertNullValuesErr
	}
	err := GlobalDB.DB.Exec("INSERT INTO t_action (name, actions) VALUES (?,?)", at.Name, at.Actions).Error
	return err
}

// store statement-action
func (sa *StatementAction) StoreStatementAction() error {
	if sa == nil {
		return InsertNullValuesErr
	}
	err := GlobalDB.DB.Exec("INSERT INTO t_statement_action (action_id, statement_id) VALUES (?,?)", sa.ActionId, sa.StatementId).Error
	return err
}

// store policy-account
func (pa *PolicyAccount) StorePolicyAccount() error {
	if pa == nil {
		return InsertNullValuesErr
	}
	err := GlobalDB.DB.Exec("INSERT INTO t_policy_account (policy_id, uid) VALUES (?,?)", pa.PolicyId, pa.Uid).Error
	return err
}

// store policy-group
func (pg *PolicyGroup) StorePolicyGroup() error {
	if pg == nil {
		return InsertNullValuesErr
	}
	err := GlobalDB.DB.Exec("INSERT INTO t_policy_group (policy_id, group_id) VALUES (?,?)", pg.PolicyId, pg.GroupId).Error
	return err
}

// transaction for database store options

// StoreTenantInfo store mt_account and credential
func (c *Credential) StoreTenantInfo(quota int, svcGenFunc func(map[string]interface{}) (auth.Credentials, error)) (svcCred auth.Credentials, err error) {
	if c == nil {
		return svcCred, InsertNullValuesErr
	}
	// 密码加密
	c.SecretKey = crypto.PasswordEncrypt(c.SecretKey)
	//todo 事务问题
	err = GlobalDB.DB.Transaction(func(tx *gorm.DB) error {
		// create cred
		if err := tx.Exec("INSERT INTO t_credential (version, access_key, secret_key, session_token, status, parent_user) VALUES (?,?,?,?,?,?)",
			c.Version, c.AccessKey, c.SecretKey, c.SessionToken, c.Status, c.ParentUser).Error; err != nil {
			return err
		}

		// find cred id
		var dbCred Credential
		if err := tx.Raw("SELECT * FROM t_credential WHERE access_key = ?", c.AccessKey).Find(&dbCred).Error; err != nil {
			return nil
		}
		if dbCred.AccessKey == "" || dbCred.AccessKey != c.AccessKey {
			return errors.New("specified user does not exist")
		}
		tenantUser := MtAccount{
			Username: c.AccessKey,
			Password: dbCred.SecretKey,
			CredId:   dbCred.ID,
			Version:  dbCred.Version,
			Ctype:    tenant,
		}
		// create tenant
		if err := tx.Exec("INSERT INTO t_mt_account (username, password, cred_id, version, ctype, parent_user, tenant_id) VALUES (?,?,?,?,?,?,?)",
			tenantUser.Username, tenantUser.Password, tenantUser.CredId, tenantUser.Version, tenantUser.Ctype, tenantUser.ParentUser, tenantUser.TenantId).Error; err != nil {
			return err
		}

		// find tenant id
		var t MtAccount
		if err := tx.Raw("SELECT * FROM t_mt_account WHERE username = ?", tenantUser.Username).Find(&t).Error; err != nil {
			return nil
		}
		if t.Uid == 0 {
			return errors.New("specified user does not exist")
		}
		tenantInfo := TenantInfo{
			ID:    t.Uid,
			Quota: quota,
		}
		// create tenant info
		if err := tx.Exec("INSERT INTO t_tenant_info (id, `creator`, `desc`, `quota`) VALUES (?,?,?,?)", tenantInfo.ID, tenantInfo.Creator, tenantInfo.Desc, tenantInfo.Quota).Error; err != nil {
			return err
		}

		// get admin policy id
		var policies []*Policy
		if err := tx.Raw("SELECT * FROM t_policy WHERE name = ?", "consoleAdmin").Find(&policies).Error; err != nil {
			return err
		}
		if len(policies) == 0 {
			return errors.New("admin policy does not exists")
		}
		// create admin policy-account
		for _, p := range policies {
			pa := PolicyAccount{
				PolicyId: p.ID,
				Uid:      t.Uid,
			}
			var aPolicy PolicyAccount
			if err := tx.Raw("SELECT * FROM t_policy_account WHERE uid = ? AND policy_id = ?", pa.Uid, pa.PolicyId).Find(&aPolicy).Error; err != nil {
				return err
			}
			// if not found, create new policy-account. otherwise, the policy-account already exists.
			if aPolicy.Uid == 0 && aPolicy.PolicyId == 0 {
				if err := tx.Exec("INSERT INTO t_policy_account (policy_id, uid) VALUES (?,?)", pa.PolicyId, pa.Uid).Error; err != nil {
					return err
				}
			}
		}
		return nil
	})

	if svcGenFunc != nil {
		err = GlobalDB.DB.Transaction(func(tx *gorm.DB) error {
			m := make(map[string]interface{})
			m["parent"] = c.AccessKey
			//adminpolicy := iampolicy.DefaultPolicies[3] //Admin
			adminpolicy := iampolicy.Admin

			policyBuf, err := json.Marshal(adminpolicy)
			if err != nil {
				logger.Error("json marshal failed")
				return err
			}
			if len(policyBuf) > 0 {
				m[iampolicy.SessionPolicyName] = base64.StdEncoding.EncodeToString(policyBuf)
				m["sa-policy"] = "embedded-policy"
			} else {
				m["sa-policy"] = "inherited-policy"
			}

			//add by lyc begin
			mtAccount := GetMtAccount(c.AccessKey)
			if mtAccount == nil {
				logger.Error("database err: get mt_account failed")
				return errors.New("database err: get mt_account failed")
			} else if mtAccount.TenantId > 0 {
				tenantUser := GetAccountByUid(mtAccount.TenantId)
				if tenantUser == nil {
					logger.Error("database err: get mt_account failed")
					return errors.New("database err: get mt_account failed")
				} else {
					m["TenantId"] = tenantUser.Uid
					m["ParentUserId"] = mtAccount.ParentUser
					m["UserQuota"] = 20
				}
			} else {
				m["TenantId"] = mtAccount.Uid
				m["ParentUserId"] = mtAccount.Uid
				m["UserQuota"] = 20
			}
			svcCred, err = svcGenFunc(m)
			//svc cred
			svcCred.SecretKey = crypto.PasswordEncrypt(svcCred.SecretKey)
			svc := &Credential{
				Version:      c.Version,
				AccessKey:    svcCred.AccessKey,
				SecretKey:    svcCred.SecretKey,
				Expiration:   time.Unix(0, 0).UTC(),
				SessionToken: svcCred.SessionToken,
				Status:       c.Status,
			}

			// create svc cred
			svc.ParentUser = mtAccount.Uid
			if err := tx.Exec("INSERT INTO t_credential (version, access_key, secret_key, session_token, status, parent_user) VALUES (?,?,?,?,?,?)",
				svc.Version, svc.AccessKey, svc.SecretKey, svc.SessionToken, svc.Status, svc.ParentUser).Error; err != nil {
				return err
			}

			// find cred id
			var newSvcCred Credential
			if err := tx.Raw("SELECT * FROM t_credential WHERE access_key = ?", svc.AccessKey).Find(&newSvcCred).Error; err != nil {
				return nil
			}
			if newSvcCred.AccessKey == "" || newSvcCred.AccessKey != svc.AccessKey {
				return errors.New("specified user does not exist")
			}

			user := MtAccount{
				Username:   newSvcCred.AccessKey,
				Password:   newSvcCred.SecretKey,
				CredId:     newSvcCred.ID,
				Version:    newSvcCred.Version,
				Ctype:      svcUser,
				ParentUser: mtAccount.Uid,
				TenantId:   mtAccount.Uid,
			}
			// create svc account
			err = tx.Exec("INSERT INTO t_mt_account (username, password, cred_id, version, ctype, parent_user, tenant_id) VALUES (?,?,?,?,?,?,?)",
				user.Username, user.Password, user.CredId, user.Version, user.Ctype, user.ParentUser, user.TenantId).Error
			if err != nil {
				return err
			}
			return nil
		})
	}

	return svcCred, err
}

func (c *Credential) StoreRegUserInfo(tenantID int, groups []*Group) error {
	if c == nil {
		return InsertNullValuesErr
	}
	c.SecretKey = crypto.PasswordEncrypt(c.SecretKey)
	return GlobalDB.DB.Transaction(func(tx *gorm.DB) error {
		// create cred
		if err := tx.Exec("INSERT INTO t_credential (version, access_key, secret_key, session_token, status, parent_user) VALUES (?,?,?,?,?,?)",
			c.Version, c.AccessKey, c.SecretKey, c.SessionToken, c.Status, c.ParentUser).Error; err != nil {
			return err
		}

		// find cred id
		var dbCred Credential
		if err := tx.Raw("SELECT * FROM t_credential WHERE access_key = ?", c.AccessKey).Find(&dbCred).Error; err != nil {
			return nil
		}
		if dbCred.AccessKey == "" || dbCred.AccessKey != c.AccessKey {
			return errors.New("specified user does not exist")
		}

		user := MtAccount{
			Username:   c.AccessKey,
			Password:   dbCred.SecretKey,
			CredId:     dbCred.ID,
			Version:    dbCred.Version,
			Ctype:      regUser,
			ParentUser: tenantID,
			TenantId:   tenantID,
		}
		// create user
		if err := tx.Exec("INSERT INTO t_mt_account (username, password, cred_id, version, ctype, parent_user, tenant_id) VALUES (?,?,?,?,?,?,?)",
			user.Username, user.Password, user.CredId, user.Version, user.Ctype, user.ParentUser, user.TenantId).Error; err != nil {
			return err
		}
		// find user id
		var dbAccount MtAccount
		if err := tx.Raw("SELECT * FROM t_mt_account WHERE username = ?", c.AccessKey).Find(&dbAccount).Error; err != nil {
			return err
		}
		// store group-account
		for _, g := range groups {
			ga := GroupAccount{
				GroupID: g.ID,
				Uid:     user.Uid,
			}
			if err := tx.Exec("INSERT INTO t_group_account (group_id, uid) VALUES (?,?)", ga.GroupID, ga.Uid).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func (c *Credential) StoreSvcUserInfo(parentID, tenantID int) error {
	if c == nil {
		return InsertNullValuesErr
	}
	c.SecretKey = crypto.PasswordEncrypt(c.SecretKey)
	return GlobalDB.DB.Transaction(func(tx *gorm.DB) error {
		// create cred
		if err := tx.Exec("INSERT INTO t_credential (version, access_key, secret_key, session_token, status, parent_user) VALUES (?,?,?,?,?,?)",
			c.Version, c.AccessKey, c.SecretKey, c.SessionToken, c.Status, c.ParentUser).Error; err != nil {
			return err
		}

		// find cred id
		var dbCred Credential
		if err := tx.Raw("SELECT * FROM t_credential WHERE access_key = ?", c.AccessKey).Find(&dbCred).Error; err != nil {
			return nil
		}
		if dbCred.AccessKey == "" || dbCred.AccessKey != c.AccessKey {
			return errors.New("specified user does not exist")
		}

		user := MtAccount{
			Username:   c.AccessKey,
			Password:   dbCred.SecretKey,
			CredId:     dbCred.ID,
			Version:    dbCred.Version,
			Ctype:      svcUser,
			ParentUser: parentID,
			TenantId:   tenantID,
		}
		// create user
		err := tx.Exec("INSERT INTO t_mt_account (username, password, cred_id, version, ctype, parent_user, tenant_id) VALUES (?,?,?,?,?,?,?)",
			user.Username, user.Password, user.CredId, user.Version, user.Ctype, user.ParentUser, user.TenantId).Error
		if err != nil {
			return err
		}
		return nil
	})
}

// store group info
func (g *Group) StoreGroupInfo(members []string) error {
	if g == nil {
		return InsertNullValuesErr
	}

	return GlobalDB.DB.Transaction(func(tx *gorm.DB) error {
		// create group
		if err := tx.Exec("INSERT INTO t_group (name, version, status, tenant_id) VALUES (?,?,?,?)", g.Name, g.Version, g.Status, g.TenantId).Error; err != nil {
			return err
		}
		var group Group
		if err := tx.Raw("SELECT * FROM t_group WHERE name = ?", g.Name).Find(&group).Error; err != nil {
			return err
		}
		// create group-account
		for _, member := range members {
			// get user
			var user MtAccount
			if err := tx.Raw("SELECT * FROM t_mt_account WHERE username = ?", member).Find(&user).Error; err != nil {
				return err
			}
			if user.Username == "" || user.Username != member {
				return errors.New("specified user does not exist")
			}
			// create group-account
			ga := GroupAccount{
				GroupID: group.ID,
				Uid:     user.Uid,
			}
			if err := tx.Exec("INSERT INTO t_group_account (group_id, uid) VALUES(?,?)", ga.GroupID, ga.Uid).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func StoreNewPolicy(policies []*Policy, states []*Statement, actions []*Action) error {
	if len(policies) != len(states) || len(states) != len(actions) || len(policies) == 0 {
		return errors.New("invalid policy")
	}

	return GlobalDB.DB.Transaction(func(tx *gorm.DB) error {
		for i := 0; i < len(policies); i++ {
			// store actions
			if err := tx.Exec("INSERT INTO t_action (name, actions) VALUES (?,?)", actions[i].Name, actions[i].Actions).Error; err != nil {
				return err
			}
			// get action id
			var action Action
			if actions[i].Name != "" {
				if err := tx.Raw("SELECT * FROM t_action WHERE name = ?", actions[i].Name).Find(&action).Error; err != nil {
					return nil
				}
			} else {
				if err := tx.Raw("SELECT * FROM t_action WHERE id = ?", actions[i].ID).Find(&action).Error; err != nil {
					return nil
				}
			}
			// store statement
			if err := tx.Exec("INSERT INTO `t_statement` (`name`, `effect`, `resource`, `condition`) VALUES (?,?,?,?)", states[i].Name, states[i].Effect, states[i].Resource, states[i].Condition).Error; err != nil {
				return err
			}
			// get statement id
			var state Statement
			if states[i].Name != "" {
				if err := tx.Raw("SELECT * FROM t_statement WHERE name = ?", states[i].Name).Find(&state).Error; err != nil {
					return nil
				}
			} else {
				if err := tx.Raw("SELECT * FROM t_statement WHERE id = ?", states[i].ID).Find(&state).Error; err != nil {
					return nil
				}
			}
			// store statement-action
			sa := &StatementAction{
				ActionId:    action.ID,
				StatementId: state.ID,
			}
			if err := tx.Exec("INSERT INTO t_statement_action (action_id, statement_id) VALUES (?,?)", sa.ActionId, sa.StatementId).Error; err != nil {
				return err
			}
			// store policy
			policies[i].StatementId = state.ID
			if err := tx.Exec("INSERT INTO t_policy (name, version, statement_id, tenant_id) VALUES (?,?,?,?)", policies[i].Name, policies[i].Version, policies[i].StatementId, policies[i].TenantId).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// store mapped policies for user
func (a *MtAccount) StoreUserMappedPolicies(policies []*Policy) error {
	if a == nil {
		return InsertNullValuesErr
	}
	return GlobalDB.DB.Transaction(func(tx *gorm.DB) error {
		for _, p := range policies {
			// store policy-account
			pa := PolicyAccount{
				PolicyId: p.ID,
				Uid:      a.Uid,
			}
			var aPolicy PolicyAccount
			if err := tx.Raw("SELECT * FROM t_policy_account WHERE uid = ? AND policy_id = ?", pa.Uid, pa.PolicyId).Find(&aPolicy).Error; err != nil {
				return err
			}
			// if not found, create new policy-account. otherwise, the policy-account already exists.
			if aPolicy.Uid == 0 && aPolicy.PolicyId == 0 {
				if err := tx.Exec("INSERT INTO t_policy_account (policy_id, uid) VALUES (?,?)", pa.PolicyId, pa.Uid).Error; err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// store mapped policies for group
func (g *Group) StoreGroupMappedPolicies(policies []*Policy) error {
	if g == nil {
		return InsertNullValuesErr
	}
	return GlobalDB.DB.Transaction(func(tx *gorm.DB) error {
		for _, p := range policies {
			// store policy-group
			pg := PolicyGroup{
				PolicyId: p.ID,
				GroupId:  g.ID,
			}
			var gPolicy PolicyGroup
			if err := tx.Raw("SELECT * FROM t_policy_group WHERE group_id = ? AND policy_id = ?", pg.GroupId, pg.PolicyId).Find(&gPolicy).Error; err != nil {
				return err
			}
			// if not found, create new policy-group. otherwise, the policy-group already exists.
			if gPolicy.GroupId == 0 && gPolicy.PolicyId == 0 {
				if err := tx.Exec("INSERT INTO t_policy_group (policy_id, group_id) VALUES (?,?)", pg.PolicyId, pg.GroupId).Error; err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// database delete options

// delete account
func (a *MtAccount) DeleteMtAccount() error {
	if a == nil {
		return DeleteNullValuesErr
	}
	if a.Username != "" {
		if err := GlobalDB.DB.Exec("DELETE FROM t_mt_account WHERE username = ?", a.Username).Error; err != nil {
			return err
		}
	} else {
		if err := GlobalDB.DB.Exec("DELETE FROM t_mt_account WHERE uid = ?", a.Uid).Error; err != nil {
			return err
		}
	}
	return nil
}

// delete credential
func (c *Credential) DeleteCredential() error {
	if c == nil {
		return DeleteNullValuesErr
	}
	if c.AccessKey != "" {
		if err := GlobalDB.DB.Exec("DELETE FROM t_credential WHERE access_key = ?", c.AccessKey).Error; err != nil {
			return err
		}
	} else {
		if err := GlobalDB.DB.Exec("DELETE FROM t_credential WHERE id = ?", c.ID).Error; err != nil {
			return err
		}
	}
	return nil
}

// delete tenant info
func (t *TenantInfo) DeleteTenantInfo() error {
	if t == nil {
		return DeleteNullValuesErr
	}
	err := GlobalDB.DB.Exec("DELETE FROM t_tenant_info WHERE id = ?", t.ID).Error
	return err
}

// delete group
func (g *Group) DeleteGroup() error {
	if g == nil {
		return DeleteNullValuesErr
	}
	if g.Name != "" {
		if err := GlobalDB.DB.Exec("DELETE FROM t_group WHERE name = ?", g.Name).Error; err != nil {
			return err
		}
	} else {
		if err := GlobalDB.DB.Exec("DELETE FROM t_group WHERE id = ?", g.ID).Error; err != nil {
			return err
		}
	}
	return nil
}

// delete policy
func (p *Policy) DeletePolicy() error {
	if p == nil {
		return DeleteNullValuesErr
	}
	err := GlobalDB.DB.Exec("DELETE FROM t_policy WHERE id = ?", p.ID).Error
	return err
}

// delete statements
func (s *Statement) DeleteStatement() error {
	if s == nil {
		return DeleteNullValuesErr
	}
	if s.Name != "" {
		if err := GlobalDB.DB.Exec("DELETE FROM t_statement WHERE name = ?", s.Name).Error; err != nil {
			return err
		}
	} else {
		if err := GlobalDB.DB.Exec("DELETE FROM t_statement WHERE id = ?", s.ID).Error; err != nil {
			return err
		}
	}
	return nil
}

// delete actions
func (at *Action) DeleteAction() error {
	if at == nil {
		return DeleteNullValuesErr
	}
	if at.Name != "" {
		if err := GlobalDB.DB.Exec("DELETE FROM t_action WHERE name = ?", at.Name).Error; err != nil {
			return err
		}
	} else {
		if err := GlobalDB.DB.Exec("DELETE FROM t_action WHERE id = ?", at.ID).Error; err != nil {
			return err
		}
	}
	return nil
}

// delete statement-action
func (sa *StatementAction) DeleteStatementAction() error {
	if sa == nil {
		return DeleteNullValuesErr
	}
	err := GlobalDB.DB.Exec("DELETE FROM t_statement_action WHERE statement_id = ? AND action_id = ?", sa.StatementId, sa.ActionId).Error
	return err
}

// delete policy-account
func (pa *PolicyAccount) DeletePolicyAccount() error {
	if pa == nil {
		return DeleteNullValuesErr
	}
	err := GlobalDB.DB.Exec("DELETE FROM t_policy_account WHERE policy_id = ? AND uid = ?", pa.PolicyId, pa.Uid).Error
	return err
}

// delete policy-group
func (pg *PolicyGroup) DeletePolicyGroup() error {
	if pg == nil {
		return DeleteNullValuesErr
	}
	err := GlobalDB.DB.Exec("DELETE FROM t_policy_group WHERE policy_id = ? AND group_id = ?", pg.PolicyId, pg.GroupId).Error
	return err
}

// delete users' or groups' policy
func DeleteUserOrGroupPolicy(name string) error {
	return nil
}

// transaction for database delete options

// delete user identity
func (a *MtAccount) DeleteUserIdentity() error {
	if a == nil {
		return DeleteNullValuesErr
	}

	return GlobalDB.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("DELETE FROM t_credential WHERE id = ?", a.CredId).Error; err != nil {
			return err
		}
		if err := tx.Exec("DELETE FROM t_mt_account WHERE uid = ?", a.Uid).Error; err != nil {
			return err
		}
		return nil
	})
}

func (a *MtAccount) DeleteUserInfo() error {
	if a == nil {
		return DeleteNullValuesErr
	}

	return GlobalDB.DB.Transaction(func(tx *gorm.DB) error {
		// Delete any service accounts if any first.
		if err := tx.Exec("DELETE FROM t_credential WHERE parent_user = ?", a.Uid).Error; err != nil {
			return err
		}
		if err := tx.Exec("DELETE FROM t_mt_account WHERE ctype = ? AND parent_user = ?", svcUser, a.Uid).Error; err != nil {
			return err
		}
		// delete mapped policies
		if err := tx.Exec("DELETE FROM t_policy_account WHERE uid = ?", a.Uid).Error; err != nil {
			return err
		}
		// delete group-account
		if err := tx.Exec("DELETE FROM t_group_account WHERE uid = ?", a.Uid).Error; err != nil {
			return err
		}
		// delete user identity
		if err := tx.Exec("DELETE FROM t_credential WHERE id = ?", a.CredId).Error; err != nil {
			return err
		}
		if err := tx.Exec("DELETE FROM t_mt_account WHERE uid = ?", a.Uid).Error; err != nil {
			return err
		}
		return nil
	})
}

// delete group info
func (g *Group) DeleteGroupInfo() error {
	if g == nil {
		return DeleteNullValuesErr
	}

	return GlobalDB.DB.Transaction(func(tx *gorm.DB) error {
		// delete policy from db
		if err := tx.Exec("DELETE FROM t_policy_group WHERE group_id = ?", g.ID).Error; err != nil {
			return err
		}
		//// delete group-account
		//if err := tx.Exec("DELETE FROM t_mt_account WHERE group_id = ?", g.ID).Error; err != nil {
		//	return err
		//}
		// delete group
		if err := tx.Exec("DELETE FROM t_group WHERE id = ?", g.ID).Error; err != nil {
			return err
		}
		return nil
	})
}

// delete policy-account
func (a *MtAccount) DeleteUserPolicy() error {
	if a == nil {
		return DeleteNullValuesErr
	}

	if err := GlobalDB.DB.Exec("DELETE FROM t_policy_account WHERE uid = ?", a.Uid).Error; err != nil {
		return err
	}
	return nil
}

// delete policy-group
func (g *Group) DeleteGroupPolicy() error {
	if g == nil {
		return DeleteNullValuesErr
	}

	if err := GlobalDB.DB.Exec("DELETE FROM t_policy_group WHERE group_id = ?", g.ID).Error; err != nil {
		return err
	}
	return nil
}

func (a *MtAccount) DeleteAndSaveUserMappedPolicy(saved []string) error {
	if a == nil {
		return DeleteNullValuesErr
	}

	return GlobalDB.DB.Transaction(func(tx *gorm.DB) error {
		// delete policy from db
		if err := tx.Exec("DELETE FROM t_policy_account WHERE uid = ?", a.Uid).Error; err != nil {
			return err
		}

		// save mapped policies
		for _, policyName := range saved {
			var policies []*Policy
			if err := tx.Raw("SELECT * FROM t_policy WHERE name = ?", policyName).Find(&policies).Error; err != nil {
				return nil
			}
			for _, p := range policies {
				// store policy-account
				pa := PolicyAccount{
					PolicyId: p.ID,
					Uid:      a.Uid,
				}
				var aPolicy PolicyAccount
				if err := tx.Raw("SELECT * FROM t_policy_account WHERE uid = ? AND policy_id = ?", pa.Uid, pa.PolicyId).Find(&aPolicy).Error; err != nil {
					return err
				}
				// if not found, create new policy-account. otherwise, the policy-account already exists.
				if aPolicy.Uid == 0 && aPolicy.PolicyId == 0 {
					if err := tx.Exec("INSERT INTO t_policy_account (policy_id, uid) VALUES (?,?)", pa.PolicyId, pa.Uid).Error; err != nil {
						return err
					}
				}
			}
		}
		return nil
	})
}

func (g *Group) DeleteAndSaveGroupMappedPolicy(saved []string) error {
	if g == nil {
		return DeleteNullValuesErr
	}

	return GlobalDB.DB.Transaction(func(tx *gorm.DB) error {
		// delete policy from db
		if err := tx.Exec("DELETE FROM t_policy_group WHERE group_id = ?", g.ID).Error; err != nil {
			return err
		}

		// save mapped policies
		for _, policyName := range saved {
			var policies []*Policy
			if err := tx.Raw("SELECT * FROM t_policy WHERE name = ?", policyName).Find(&policies).Error; err != nil {
				return nil
			}
			for _, p := range policies {
				// store policy-group
				pg := PolicyGroup{
					PolicyId: p.ID,
					GroupId:  g.ID,
				}
				var gPolicy PolicyGroup
				if err := tx.Raw("SELECT * FROM t_policy_group WHERE group_id = ? AND policy_id = ?", pg.GroupId, pg.PolicyId).Find(&gPolicy).Error; err != nil {
					return err
				}
				// if not found, create new policy-group. otherwise, the policy-group already exists.
				if gPolicy.GroupId == 0 && gPolicy.PolicyId == 0 {
					if err := tx.Exec("INSERT INTO t_policy_group (policy_id, group_id) VALUES (?,?)", pg.PolicyId, pg.GroupId).Error; err != nil {
						return err
					}
				}
			}
		}
		return nil
	})
}

//
func DeletePolicy(policies []*Policy, statements []*Statement, actions []*Action) error {
	if len(policies) != len(statements) || len(policies) != len(actions) {
		return errors.New("invalid policy")
	}
	if len(policies) == 0 {
		return nil
	}

	return GlobalDB.DB.Transaction(func(tx *gorm.DB) error {
		// delete policies
		for i := 0; i < len(policies); i++ {
			// delete users' policies
			if err := tx.Exec("DELETE FROM t_policy_account WHERE policy_id = ?", policies[i].ID).Error; err != nil {
				return err
			}
			// delete groups' policies
			if err := tx.Exec("DELETE FROM t_policy_group WHERE policy_id = ?", policies[i].ID).Error; err != nil {
				return err
			}
			// delete statement-action
			sa := StatementAction{
				ActionId:    actions[i].ID,
				StatementId: statements[i].ID,
			}
			if err := tx.Exec("DELETE FROM t_statement_action WHERE statement_id = ? AND action_id = ?", sa.StatementId, sa.ActionId).Error; err != nil {
				return err
			}
			// delete statements
			if statements[i].Name != "" {
				if err := tx.Exec("DELETE FROM t_statement WHERE name = ?", statements[i].Name).Error; err != nil {
					return err
				}
			} else {
				if err := tx.Exec("DELETE FROM t_statement WHERE id = ?", statements[i].ID).Error; err != nil {
					return err
				}
			}
			// delete actions
			if actions[i].Name != "" {
				if err := tx.Exec("DELETE FROM t_action WHERE name = ?", actions[i].Name).Error; err != nil {
					return err
				}
			} else {
				if err := tx.Exec("DELETE FROM t_action WHERE id = ?", actions[i].ID).Error; err != nil {
					return err
				}
			}
			// delete policies
			if err := tx.Exec("DELETE FROM t_policy WHERE id = ?", policies[i].ID).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// datebase update options

// update account
func (a *MtAccount) UpdateMtAccount(values *MtAccount) error {
	if a == nil {
		return UpdateNullValuesErr
	}
	// 密码加密
	values.Password = crypto.PasswordEncrypt(values.Password)
	if a.Username != "" {
		if err := GlobalDB.DB.Table("t_mt_account").Where("username = ?", a.Username).Updates(values).Error; err != nil {
			return err
		}
	} else {
		if err := GlobalDB.DB.Table("t_mt_account").Where("uid = ?", a.Uid).Updates(values).Error; err != nil {
			return err
		}
	}
	return nil
}

// update group id when removing users from group
func (a *MtAccount) UpdateUserGroupID(id int) error {
	if a == nil {
		return UpdateNullValuesErr
	}
	err := GlobalDB.DB.Table("t_mt_account").Where("uid = ?", a.Uid).Update("group_id", id).Error
	return err
}

// update credential
func (c *Credential) UpdateCredential(values *Credential) error {
	if c == nil {
		return UpdateNullValuesErr
	}
	if c.AccessKey != "" {
		if err := GlobalDB.DB.Table("t_credential").Where("access_key = ?", c.AccessKey).Updates(values).Error; err != nil {
			return err
		}
	} else {
		if err := GlobalDB.DB.Table("t_credential").Where("id = ?", c.ID).Updates(values).Error; err != nil {
			return err
		}
	}
	return nil
}

// update credential status
func (c *Credential) UpdateCredentialStatus(status bool) error {
	if c == nil {
		return UpdateNullValuesErr
	}
	// update zero value "off" for status
	if !status {
		if err := GlobalDB.DB.Table("t_credential").Where("id = ?", c.ID).Update("status", status).Error; err != nil {
			return err
		}
	}
	return nil
}

// update group id when removing users from group
func (c *Credential) UpdateCredentialGroupID(id int) error {
	if c == nil {
		return UpdateNullValuesErr
	}
	err := GlobalDB.DB.Table("t_credential").Where("id = ?", c.ID).Update("group_id", id).Error
	return err
}

// update tenant info
func (t *TenantInfo) UpdateTenantInfo(values *TenantInfo) error {
	if t == nil {
		return UpdateNullValuesErr
	}
	err := GlobalDB.DB.Table("t_tenant_info").Where("id = ?", t.ID).Updates(values).Error
	return err
}

// update group
func (g *Group) UpdateGroup(values *Group) error {
	if g == nil {
		return UpdateNullValuesErr
	}
	if g.Name != "" {
		if err := GlobalDB.DB.Table("t_group").Where("name = ?", g.Name).Updates(values).Error; err != nil {
			return err
		}
	} else {
		if err := GlobalDB.DB.Table("t_group").Where("id = ?", g.ID).Updates(values).Error; err != nil {
			return err
		}
	}
	return nil
}

// update group status
func (g *Group) UpdateGroupStatus(status bool) error {
	if g == nil {
		return UpdateNullValuesErr
	}
	// update zero value "disabled" for status
	if !status {
		if err := GlobalDB.DB.Table("t_group").Where("id = ?", g.ID).Update("status", status).Error; err != nil {
			return err
		}
	}
	return nil
}

// update policy
func (p *Policy) UpdatePolicy(values *Policy) error {
	if p == nil {
		return UpdateNullValuesErr
	}
	if p.Name != "" {
		if err := GlobalDB.DB.Table("t_policy").Where("name = ?", p.Name).Updates(values).Error; err != nil {
			return err
		}
	} else {
		if err := GlobalDB.DB.Table("t_policy").Where("id = ?", p.ID).Updates(values).Error; err != nil {
			return err
		}
	}
	return nil
}

// update statements
func (s *Statement) UpdateStatement(values *Statement) error {
	if s == nil {
		return UpdateNullValuesErr
	}
	if s.Name != "" {
		if err := GlobalDB.DB.Table("t_statement").Where("name = ?", s.Name).Updates(values).Error; err != nil {
			return err
		}
	} else {
		if err := GlobalDB.DB.Table("t_statement").Where("id = ?", s.ID).Updates(values).Error; err != nil {
			return err
		}
	}
	return nil
}

// update statements effect
func (s *Statement) UpdateStatementEffect(effect bool) error {
	if s == nil {
		return UpdateNullValuesErr
	}
	// update zero value "Deny" for status
	if !effect {
		if err := GlobalDB.DB.Table("t_statement").Where("id = ?", s.ID).Update("effect", effect).Error; err != nil {
			return err
		}
	}
	return nil
}

// update actions
func (at *Action) UpdateAction(values *Action) error {
	if at == nil {
		return UpdateNullValuesErr
	}
	if at.Name != "" {
		if err := GlobalDB.DB.Table("t_action").Where("name = ?", at.Name).Updates(values).Error; err != nil {
			return err
		}
	} else {
		if err := GlobalDB.DB.Table("t_action").Where("id = ?", at.ID).Updates(values).Error; err != nil {
			return err
		}
	}
	return nil
}

// update statement-action
func (sa *StatementAction) UpdateStatementAction(values *StatementAction) error {
	if sa == nil {
		return UpdateNullValuesErr
	}
	err := GlobalDB.DB.Table("t_statement_action").Where("statement_id = ? AND action_id = ?", sa.StatementId, sa.ActionId).Updates(values).Error
	return err
}

// update policy-account
func (pa *PolicyAccount) UpdatePolicyAccount(values *PolicyAccount) error {
	if pa == nil {
		return UpdateNullValuesErr
	}
	err := GlobalDB.DB.Table("t_policy_account").Where("policy_id = ? AND uid = ?", pa.PolicyId, pa.Uid).Updates(values).Error
	return err
}

// update policy-group
func (pg *PolicyGroup) UpdatePolicyGroup(values *PolicyGroup) error {
	if pg == nil {
		return UpdateNullValuesErr
	}
	err := GlobalDB.DB.Table("t_policy_group").Where("policy_id = ? AND group_id = ?", pg.PolicyId, pg.GroupId).Updates(values).Error
	return err
}

// transaction for database update options

// update account and cred
func UpdateUserInfo(oldUser, newUser *MtAccount, oldCred, newCred *Credential) error {
	if oldUser == nil || oldCred == nil {
		return UpdateNullValuesErr
	}
	newUser.Password = crypto.PasswordEncrypt(newUser.Password)
	return GlobalDB.DB.Transaction(func(tx *gorm.DB) error {
		// update user info
		if oldUser.Username != "" {
			if err := tx.Table("t_mt_account").Where("username = ?", oldUser.Username).Updates(newUser).Error; err != nil {
				return err
			}
		} else {
			if err := tx.Table("t_mt_account").Where("uid = ?", oldUser.Uid).Updates(newUser).Error; err != nil {
				return err
			}
		}
		// update cred
		if oldCred.AccessKey != "" {
			if err := tx.Table("t_credential").Where("access_key = ?", oldCred.AccessKey).Updates(newCred).Error; err != nil {
				return err
			}
			if !newCred.Status {
				if err := tx.Table("t_credential").Where("access_key = ?", oldCred.AccessKey).Update("status", newCred.Status).Error; err != nil {
					return err
				}
			}
		} else {
			if err := tx.Table("t_credential").Where("id = ?", oldCred.ID).Updates(newCred).Error; err != nil {
				return err
			}
			if !newCred.Status {
				if err := tx.Table("t_credential").Where("id = ?", oldCred.ID).Update("status", newCred.Status).Error; err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// update group info
func UpdateGroupInfo(oldGroup, newGroup *Group, members []string) error {
	if oldGroup == nil || oldGroup.ID == 0 {
		return UpdateNullValuesErr
	}

	return GlobalDB.DB.Transaction(func(tx *gorm.DB) error {
		// update group
		if err := tx.Table("t_group").Where("id = ?", oldGroup.ID).Updates(newGroup).Error; err != nil {
			return err
		}
		if !newGroup.Status {
			if err := tx.Table("t_group").Where("id = ?", oldGroup.ID).Update("status", newGroup.Status).Error; err != nil {
				return err
			}
		}

		// create group-account
		for _, member := range members {
			// get user
			var user MtAccount
			if err := tx.Raw("SELECT * FROM t_mt_account WHERE username = ?", member).Find(&user).Error; err != nil {
				return err
			}
			if user.Username == "" || user.Username != member {
				return errors.New("specified user does not exist")
			}

			// create group-account
			ga := GroupAccount{
				GroupID: oldGroup.ID,
				Uid:     user.Uid,
			}
			var gAccount GroupAccount
			if err := tx.Raw("SELECT * FROM t_group_account WHERE group_id = ? AND uid = ?", ga.GroupID, ga.Uid).Find(&gAccount).Error; err != nil {
				return err
			}
			// if not found, create new group-account. otherwise, the group-account already exists.
			if gAccount.GroupID == 0 && gAccount.Uid == 0 {
				if err := tx.Exec("INSERT INTO t_group_account (group_id, uid) VALUES(?,?)", ga.GroupID, ga.Uid).Error; err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func UpdateAndDeletePolicy(oldPolicy, newPolicy []*Policy, oldStates, newStates []*Statement, oldActions, newActions []*Action) error {
	if len(oldPolicy) != len(oldStates) || len(oldPolicy) != len(oldActions) || len(newPolicy) != len(newStates) || len(newPolicy) != len(newActions) || len(oldPolicy) < len(newPolicy) {
		return errors.New("invalid policy")
	}

	return GlobalDB.DB.Transaction(func(tx *gorm.DB) error {
		// update policies
		for i := 0; i < len(newPolicy); i++ {
			// update actions
			if oldActions[i].Name != "" {
				if err := tx.Table("t_action").Where("name = ?", oldActions[i].Name).Updates(newActions[i]).Error; err != nil {
					return err
				}
			} else {
				if err := tx.Table("t_action").Where("id = ?", oldActions[i].ID).Updates(newActions[i]).Error; err != nil {
					return err
				}
			}
			// update statements
			if oldStates[i].Name != "" {
				if err := tx.Table("t_statement").Where("name = ?", oldStates[i].Name).Updates(newStates[i]).Error; err != nil {
					return err
				}
			} else {
				if err := tx.Table("t_statement").Where("id = ?", oldStates[i].ID).Updates(newStates[i]).Error; err != nil {
					return err
				}
			}
		}

		// delete policies
		for i := len(newPolicy); i < len(oldPolicy); i++ {
			// delete policy
			// delete statement-action
			sa := StatementAction{
				ActionId:    oldActions[i].ID,
				StatementId: oldStates[i].ID,
			}
			if err := tx.Exec("DELETE FROM t_statement_action WHERE statement_id = ? AND action_id = ?", sa.StatementId, sa.ActionId).Error; err != nil {
				return err
			}
			// delete actions
			if oldActions[i].Name != "" {
				if err := tx.Exec("DELETE FROM t_action WHERE name = ?", oldActions[i].Name).Error; err != nil {
					return err
				}
			} else {
				if err := tx.Exec("DELETE FROM t_action WHERE id = ?", oldActions[i].ID).Error; err != nil {
					return err
				}
			}
			// delete statement
			if oldStates[i].Name != "" {
				if err := tx.Exec("DELETE FROM t_statement WHERE name = ?", oldStates[i].Name).Error; err != nil {
					return err
				}
			} else {
				if err := tx.Exec("DELETE FROM t_statement WHERE id = ?", oldStates[i].ID).Error; err != nil {
					return err
				}
			}
			// delete policy
			if err := tx.Exec("DELETE FROM t_policy WHERE id = ?", oldPolicy[i].ID).Error; err != nil {
				return err
			}
			// update mapped policy
			// delete policy-account
			if err := tx.Exec("DELETE FROM t_policy_account WHERE policy_id = ?", oldPolicy[i].ID).Error; err != nil {
				return err
			}
			// delete policy-group
			if err := tx.Exec("DELETE FROM t_policy_group WHERE policy_id = ?", oldPolicy[i].ID).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func UpdateAndStorePolicy(oldPolicy, newPolicy []*Policy, oldStates, newStates []*Statement, oldActions, newActions []*Action) error {
	if len(oldPolicy) != len(oldStates) || len(oldPolicy) != len(oldActions) || len(newPolicy) != len(newStates) || len(newPolicy) != len(newActions) || len(oldPolicy) > len(newPolicy) {
		return errors.New("invalid policy")
	}

	// find users
	var users []*MtAccount
	if err := GlobalDB.DB.Raw("SELECT t_mt_account.* FROM t_policy_account,t_mt_account WHERE t_policy_account.uid = t_mt_account.uid AND t_policy_account.policy_id = ?", oldPolicy[0].ID).Find(&users).Error; err != nil {
		return nil
	}

	// find groups
	var groups []*Group
	if err := GlobalDB.DB.Raw("SELECT t_group.* FROM t_policy_group,t_group WHERE t_policy_group.group_id = t_group.id AND t_policy_group.policy_id = ?", oldPolicy[0].ID).Find(&groups).Error; err != nil {
		return nil
	}

	return GlobalDB.DB.Transaction(func(tx *gorm.DB) error {
		// update policies
		for i := 0; i < len(oldPolicy); i++ {
			// update actions
			if oldActions[i].Name != "" {
				if err := tx.Table("t_action").Where("name = ?", oldActions[i].Name).Updates(newActions[i]).Error; err != nil {
					return err
				}
			} else {
				if err := tx.Table("t_action").Where("id = ?", oldActions[i].ID).Updates(newActions[i]).Error; err != nil {
					return err
				}
			}
			// update statements
			if oldStates[i].Name != "" {
				if err := tx.Table("t_statement").Where("name = ?", oldStates[i].Name).Updates(newStates[i]).Error; err != nil {
					return err
				}
			} else {
				if err := tx.Table("t_statement").Where("id = ?", oldStates[i].ID).Updates(newStates[i]).Error; err != nil {
					return err
				}
			}
		}
		// store policies
		for i := len(oldPolicy); i < len(newPolicy); i++ {
			// store actions
			if err := tx.Exec("INSERT INTO t_action (name, actions) VALUES (?,?)", newActions[i].Name, newActions[i].Actions).Error; err != nil {
				return err
			}
			// get action id
			var action Action
			if newActions[i].Name != "" {
				if err := tx.Raw("SELECT * FROM t_action WHERE name = ?", newActions[i].Name).Find(&action).Error; err != nil {
					return nil
				}
			} else {
				if err := tx.Raw("SELECT * FROM t_action WHERE id = ?", newActions[i].ID).Find(&action).Error; err != nil {
					return nil
				}
			}
			// store statement
			if err := tx.Exec("INSERT INTO `t_statement` (`name`, `effect`, `resource`, `condition`) VALUES (?,?,?,?)", newStates[i].Name, newStates[i].Effect, newStates[i].Resource, newStates[i].Condition).Error; err != nil {
				return err
			}
			// get statement id
			var state Statement
			if newStates[i].Name != "" {
				if err := tx.Raw("SELECT * FROM t_statement WHERE name = ?", newStates[i].Name).Find(&state).Error; err != nil {
					return nil
				}
			} else {
				if err := tx.Raw("SELECT * FROM t_statement WHERE id = ?", newStates[i].ID).Find(&state).Error; err != nil {
					return nil
				}
			}
			// store statement-action
			sa := &StatementAction{
				ActionId:    action.ID,
				StatementId: state.ID,
			}
			if err := tx.Exec("INSERT INTO t_statement_action (action_id, statement_id) VALUES (?,?)", sa.ActionId, sa.StatementId).Error; err != nil {
				return err
			}
			// store policy
			newPolicy[i].StatementId = state.ID
			if err := tx.Exec("INSERT INTO t_policy (name, version, statement_id, tenant_id) VALUES (?,?,?,?)", newPolicy[i].Name, newPolicy[i].Version, newPolicy[i].StatementId, newPolicy[i].TenantId).Error; err != nil {
				return err
			}
			// update mapped policy
			// store policy-account
			for _, user := range users {
				pa := PolicyAccount{
					PolicyId: newPolicy[i].ID,
					Uid:      user.Uid,
				}
				if err := tx.Exec("INSERT INTO t_policy_account (policy_id, uid) VALUES (?,?)", pa.PolicyId, pa.Uid).Error; err != nil {
					return err
				}
			}
			// store policy-group
			for _, group := range groups {
				pg := PolicyGroup{
					PolicyId: newPolicy[i].ID,
					GroupId:  group.ID,
				}
				if err := tx.Exec("INSERT INTO t_policy_group (policy_id, group_id) VALUES (?,?)", pg.PolicyId, pg.GroupId).Error; err != nil {
					return err
				}
			}
		}

		return nil
	})
}

// remove users and update group info
func RemoveUsersAndUpdateGroupInfo(oldGroup, newGroup *Group, removed []*MtAccount, members []string) error {
	if oldGroup == nil || oldGroup.ID == 0 {
		return UpdateNullValuesErr
	}

	return GlobalDB.DB.Transaction(func(tx *gorm.DB) error {
		// remove group-account
		for _, account := range removed {
			ga := GroupAccount{
				GroupID: oldGroup.ID,
				Uid:     account.Uid,
			}
			if err := tx.Exec("DELETE FROM t_group_account WHERE group_id = ? AND uid = ?", ga.GroupID, ga.Uid).Error; err != nil {
				return err
			}
		}
		// update group
		if err := tx.Table("t_group").Where("id = ?", oldGroup.ID).Updates(newGroup).Error; err != nil {
			return err
		}
		if !newGroup.Status {
			if err := tx.Table("t_group").Where("id = ?", oldGroup.ID).Update("status", newGroup.Status).Error; err != nil {
				return err
			}
		}
		// create group-account
		for _, member := range members {
			// get user
			var user MtAccount
			if err := tx.Raw("SELECT * FROM t_mt_account WHERE username = ?", member).Find(&user).Error; err != nil {
				return err
			}
			if user.Username == "" || user.Username != member {
				return errors.New("specified user does not exist")
			}
			ga := GroupAccount{
				GroupID: oldGroup.ID,
				Uid:     user.Uid,
			}
			var gAccount GroupAccount
			if err := tx.Raw("SELECT * FROM t_group_account WHERE group_id = ? AND uid = ?", ga.GroupID, ga.Uid).Find(&gAccount).Error; err != nil {
				return err
			}
			// if not found, create new group-account. otherwise, the group-account already exists.
			if gAccount.GroupID == 0 && gAccount.Uid == 0 {
				if err := tx.Exec("INSERT INTO t_group_account (group_id, uid) VALUES(?,?)", ga.GroupID, ga.Uid).Error; err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// update user's group id
func UpdateGroupID(account *MtAccount, id int) error {
	if account == nil {
		return UpdateNullValuesErr
	}

	return GlobalDB.DB.Transaction(func(tx *gorm.DB) error {
		// update account
		if err := tx.Table("t_mt_account").Where("uid = ?", account.Uid).Update("group_id", id).Error; err != nil {
			return err
		}
		// update cred
		if err := tx.Table("t_credential").Where("id = ?", account.CredId).Update("group_id", id).Error; err != nil {
			return err
		}
		return nil
	})
}

func GetTenantInfo(uid int) *TenantInfo {
	var ti TenantInfo
	if err := GlobalDB.DB.Raw("SELECT * FROM t_tenant_info WHERE id = ?", uid).Find(&ti).Error; err != nil {
		return nil
	}
	return &ti
}
