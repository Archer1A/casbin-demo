package main

import (
	"fmt"
	"github.com/Archer1A/casbin-demo/harbor/rbac"
	"github.com/Archer1A/casbin-demo/harbor/rbac/project"
	"sync"
)

var once sync.Once
func main()  {
	admin := &project.Visitor{
		UserName: "Archer",
		Role: 1,
	}
	evaluate(admin,rbac.ResourceRepository,rbac.ActionList)
	evaluate(admin,rbac.ResourceRepository,rbac.ActionRead)
	evaluate(admin,rbac.ResourceRepository,rbac.ActionPush)
	evaluate(admin,rbac.ResourceRepository,rbac.ActionPull)
	evaluate(admin,rbac.ResourceRepository,rbac.ActionCreate)
	evaluate(admin,rbac.ResourceRepository,rbac.ActionDelete)

	saber := &project.Visitor{
		UserName: "Saber",
		Role:     2,
	}
	evaluate(saber,rbac.ResourceRepository,rbac.ActionList)
	evaluate(saber,rbac.ResourceRepository,rbac.ActionRead)
	evaluate(saber,rbac.ResourceRepository,rbac.ActionPush)
	evaluate(saber,rbac.ResourceRepository,rbac.ActionPull)
	evaluate(saber,rbac.ResourceRepository,rbac.ActionCreate)
	evaluate(saber,rbac.ResourceRepository,rbac.ActionDelete)
	
	alice := &project.Visitor{
		UserName: "alice",
		Role:     0,
	}

	evaluate(alice,rbac.ResourceRepository,rbac.ActionList)
	evaluate(alice,rbac.ResourceRepository,rbac.ActionRead)
	evaluate(alice,rbac.ResourceRepository,rbac.ActionPush)
	evaluate(alice,rbac.ResourceRepository,rbac.ActionPull)
	evaluate(alice,rbac.ResourceRepository,rbac.ActionCreate)
	evaluate(alice,rbac.ResourceRepository,rbac.ActionDelete)

}

func evaluate(visit *project.Visitor,resource rbac.Resource,action rbac.Action)  {

	adminEvaluator := rbac.NewEvaluator(visit)
	if  (adminEvaluator.HasPermission(resource,action)){
		fmt.Printf("%s role %d have %s %s permission \n", visit.UserName,visit.Role,resource.String(),action)
	}else {
		fmt.Printf("%s role %d  don't have %s %s permission \n", visit.UserName,visit.Role,resource.String(),action)
	}
}