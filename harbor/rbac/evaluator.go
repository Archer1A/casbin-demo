package rbac

import (
	"fmt"
	"github.com/casbin/casbin"
	"sync"
)

type evaluator struct {
	user User
	enforcer *casbin.Enforcer
	once sync.Once
}

func (e *evaluator)HasPermission(resource Resource,action Action) bool  {
	e.once.Do(func() {
		e.enforcer = enforceForUser(e.user)
	})
	b, err := e.enforcer.Enforce(e.user.GetUserName(), resource.String(), action.String())
	if err != nil {
		fmt.Println(err.Error())
	}

	return b
}

func NewEvaluator(user User) *evaluator {
	return &evaluator{
		user: user,
	}
}