package rbac

import (
	"fmt"
	"github.com/casbin/casbin"
	"github.com/casbin/casbin/model"
	"github.com/casbin/casbin/persist"
	"github.com/pkg/errors"
)

type userAdapter struct {
	User
}

const casbinModel = `
# Request definition
# 要去请求的资源sub(subject) 请求的实体
[request_definition]
r = sub, obj, act

# Policy definition 
# 表示拥有的权限
# 例如: p, vic, /project/1/member, list, allow  表示vic用户拥有获取project id=1的项目 的下成员的列表权限
[policy_definition]
p = sub, obj, act, eft

# Role definition
# 代表着role 的所属关系
# 例如: g, vic, admin  表示vic 拥有admin 权限
[role_definition]
g = _, _

# Policy effect
# policy 生效的范围  其中p.eft 表示策略规则的决策结果，可以为allow 或者deny，当不指定规则的决策结果时,取默认值allow 。
#通常情况下，policy的p.eft默认为allow
#该Effect原语表示当至少存在一个决策结果为allow的匹配规则，且不存在决策结果为deny的匹配规则时，则最终决策结果为allow。
#这时allow授权和deny授权同时存在，但是deny优先。
[policy_effect]
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))

# Matchers
# 匹配器用于上面 请求和策略的匹配
[matchers]
m = g(r.sub, p.sub) && (r.act == p.act || p.act == '*')
`

// 获取role的所有策略
func (u *userAdapter)getRoleAllPoliciesLine(role Role) []string  {
	lines := []string{}
	name := role.GetRoleName()
	if name == "" {
		return lines
	}
	for _ ,policy := range role.GetPolicies() {
		line := fmt.Sprintf("p, %s, %s, %s, %s",name,policy.Resource,policy.Action,policy.GetEffect())
		lines = append(lines,line)
	}
	return lines
}
// 获取绑定在user 上的权限(不包括role)
func (u *userAdapter)getUserPoliciesLine() []string {
	lines := []string{}
	userName := u.GetUserName()
	if userName == "" {
		return lines
	}
	for _,policy := range u.GetPolicies(){
		line := fmt.Sprintf("p, %s, %s, %s, %s",userName,policy.Resource,policy.Action,policy.GetEffect())
		lines = append(lines, line)
	}
	return lines
}
// 获取该用户的所有权限(包括role)
func (u *userAdapter)getUserAllPoliciesLine() []string {
	lines := []string{}
	userName := u.GetUserName()
	if userName == "" {
		return lines
	}
	lines = append(lines, u.getUserPoliciesLine()...)
	for _,role := range u.GetRoles() {
		lines = append(lines, u.getRoleAllPoliciesLine(role)...)
		lines = append(lines, fmt.Sprintf("g, %s, %s",userName,role.GetRoleName()))

	}
	return lines
}

type unImplementError  error

func (u *userAdapter)LoadPolicy(model model.Model) error  {
	lines := u.getUserAllPoliciesLine()
	for _,line := range lines{
		persist.LoadPolicyLine(line,model)
	}
	return nil

}


func (u *userAdapter)SavePolicy(model model.Model)error  {
	return unImplementError(errors.New(""))

}
func (u *userAdapter)AddPolicy(sec string, ptype string, rule []string) error  {
	return unImplementError(errors.New(""))

}
func (u *userAdapter)RemovePolicy(sec string, ptype string, rule []string) error  {
	return unImplementError(errors.New(""))

}

func (u *userAdapter)RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error  {
	return unImplementError(errors.New(""))

}

func enforceForUser(user User) *casbin.Enforcer {
	m := model.Model{}
	m.LoadModelFromText(casbinModel)
	//csv := "C:\\Users\\Vic\\go\\src\\github.com\\Archer1A\\casbin-demo\\model.csv"
	//a := fileadapter.NewAdapter(csv)
	e,_ := casbin.NewEnforcer(m,&userAdapter{User:user})
	return e
}