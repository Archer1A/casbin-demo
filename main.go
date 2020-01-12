package main

import (

	"fmt"
	"github.com/casbin/casbin"
)

var (
	conf = "C:\\Users\\Vic\\go\\src\\github.com\\Archer1A\\casbin-demo\\model.conf"
	csv = "C:\\Users\\Vic\\go\\src\\github.com\\Archer1A\\casbin-demo\\model.csv"

)
func main()  {
	e,_ :=casbin.NewEnforcer(conf,csv)
	if res,_ := e.Enforce("Archer","configuration","list");res{ // archer 是否有list configuration 权限
		fmt.Println("Archer can list configuration")
	}else {
		fmt.Println("Archer can't list configuration")
	}
	if res,_ := e.Enforce("Archer","configuration","operate");res{ // archer 是否有list configuration 权限
		fmt.Println("Archer can operate configuration")
	}else {
		fmt.Println("Archer can't operate configuration")
	}
}