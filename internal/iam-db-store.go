package internal

import (
	"bytes"
	"encoding/base64"
	"errors"
	"github.com/minio/pkg/bucket/policy"
	"github.com/minio/pkg/bucket/policy/condition"
	iampolicy "github.com/minio/pkg/iam/policy"
	"mt-iam/datastore"
)

func loadPolicyFromDB(policyName string) (iampolicy.Policy, error) {
	policies := datastore.GetPolicy(policyName)
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
