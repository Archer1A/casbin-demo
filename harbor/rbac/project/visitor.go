package project

import "github.com/Archer1A/casbin-demo/harbor/rbac"

type VisitorRole struct {
	roleId int
}


var policy  = map[string][]*rbac.Policy{
	"admin":{
		&rbac.Policy{Resource: rbac.ResourceRepository,Action:rbac.ActionPull}, // pull 权限
		&rbac.Policy{Resource: rbac.ResourceRepository,Action:rbac.ActionPush}, // push
		&rbac.Policy{Resource: rbac.ResourceRepository,Action:rbac.ActionList}, // list
		&rbac.Policy{Resource: rbac.ResourceRepository,Action:rbac.ActionDelete}, // delete
		&rbac.Policy{Resource: rbac.ResourceConfiguration,Action:rbac.ActionList}, // list configuration
		&rbac.Policy{Resource: rbac.ResourceConfiguration,Action:rbac.ActionUpdate}, // update Configuration
	},
	"master":{
		&rbac.Policy{Resource: rbac.ResourceRepository,Action:rbac.ActionList},
		&rbac.Policy{Resource: rbac.ResourceRepository,Action:rbac.ActionPull},
		&rbac.Policy{Resource: rbac.ResourceRepository,Action:rbac.ActionList},
		&rbac.Policy{Resource: rbac.ResourceRepository,Action:rbac.ActionDelete},
	},
	"dev":{
		&rbac.Policy{Resource: rbac.ResourceRepository,Action:rbac.ActionList},
		&rbac.Policy{Resource: rbac.ResourceRepository,Action:rbac.ActionPull},
	},
}

type Visitor struct {
	UserName string
	Role int
}

var publicPolicy = []*rbac.Policy{
	&rbac.Policy{Resource: rbac.ResourceRepository,Action:rbac.ActionPull},
	&rbac.Policy{Resource: rbac.ResourceRepository,Action:rbac.ActionPush},
	&rbac.Policy{Resource: rbac.ResourceRepository,Action:rbac.ActionList},
	&rbac.Policy{Resource: rbac.ResourceRepository,Action:rbac.ActionDelete},
}

var privatePolicy = []*rbac.Policy{
	&rbac.Policy{Resource: rbac.ResourceRepository,Action:rbac.ActionPull},
	&rbac.Policy{Resource: rbac.ResourceRepository,Action:rbac.ActionList},
}

func (role *VisitorRole)GetRoleName() string  {
	switch role.roleId {
	case 1:
		return "admin"
	case 2:
		return "master"
	case 3:
		return "dev"
	case 4:
		return "guest"
	default:
		return ""
	}
}

func (role *VisitorRole)GetPolicies() []*rbac.Policy {
	roleName := role.GetRoleName()
	return policy[roleName]
}


func (vi *Visitor)GetUserName() string{
	return vi.UserName
}
func (vi *Visitor)GetPolicies() []*rbac.Policy{
	if vi.GetUserName() == "alice" {
		return publicPolicy
	}else {
		return privatePolicy
	}
}
func (vi *Visitor)GetRoles() []rbac.Role{
	return []rbac.Role{&VisitorRole{roleId:vi.Role}}
}


