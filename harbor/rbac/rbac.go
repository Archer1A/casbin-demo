package rbac

type Action string
type Resource string
type Effect string

const (
	// allow effect
	EffectAllow = Effect("allow")
	// deny effect
	EffectDeny = Effect("deny")
)



type Policy struct {
	Action
	Resource
	Effect
}

type Role interface {
	GetRoleName() string
	GetPolicies() []*Policy
}

type User interface {
	GetUserName() string
	GetPolicies() []*Policy
	GetRoles() []Role
}

func (eff Effect)String() string  {
	return string(eff)
}

func (resource Resource)String()string  {
	return string(resource)
}

func (action Action)String()string  {
	return string(action)

}

func (p *Policy)GetEffect()string  {
	eft := p.Effect
	if eft.String() == "" {
		return EffectAllow.String()
	}
	return eft.String()

}
