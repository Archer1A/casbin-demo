package rbac

const (
	ActionAll = Action("*") // action match any other actions

	ActionPull = Action("pull") // pull repository tag
	ActionPush = Action("push") // push repository tag

	// create, read, update, delete, list actions compatible with restful api methods
	ActionCreate = Action("create")
	ActionRead   = Action("read")
	ActionUpdate = Action("update")
	ActionDelete = Action("delete")
	ActionList   = Action("list")

	ActionOperate = Action("operate")
)

const (
	ResourceAll = Resource("*")
	ResourceConfiguration = Resource("configuration")
	ResourceRepository = Resource("repository")
)