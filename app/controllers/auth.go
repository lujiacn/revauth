package controllers

import (
	"strings"

	"github.com/lujiacn/revauth"
	"github.com/lujiacn/revauth/app/models"
	"github.com/revel/revel"
	"github.com/revel/revel/cache"

	"github.com/lujiacn/mongodo"
)

type Auth struct {
	*revel.Controller
}

//Authenticate for LDAP authenticate
func (c *Auth) Authenticate(account, password string) revel.Result {
	//get nextUrl
	nextUrl := c.Params.Get("nextUrl")
	if nextUrl == "" {
		nextUrl = "/"
	}

	if account == "" || password == "" {
		c.Flash.Error("Please fill in account and password")
		return c.Redirect(c.Request.Referer())
	}

	authUser := revauth.Authenticate(account, password)
	if !authUser.IsAuthenticated {
		//Save LoginLog
		loginLog := new(models.LoginLog)
		loginLog.Account = account
		loginLog.Status = "FAILURE"
		loginLog.IPAddress = c.Request.RemoteAddr
		mongodo.New(loginLog).Create()

		c.Flash.Error("Authenticate failed: %v", authUser.Error)
		return c.Redirect(c.Request.Referer())
	}

	// save login log
	loginLog := new(models.LoginLog)
	loginLog.Account = account
	loginLog.Status = "SUCCESS"
	loginLog.IPAddress = c.Request.RemoteAddr
	mongodo.New(loginLog).Create()

	c.Session["Identity"] = strings.ToLower(account)

	//save current user information
	currentUser := new(models.User)
	currentUser.Identity = strings.ToLower(account)
	currentUser.Mail = authUser.Email
	currentUser.Avatar = authUser.Avatar
	currentUser.Name = authUser.Name
	currentUser.Depart = authUser.Depart
	currentUser.First = authUser.First
	currentUser.Last = authUser.Last

	// cache user info
	go cache.Set(c.Session.ID(), currentUser, cache.DefaultExpiryTime)

	go func(user *models.User) {
		// save to local user
		err := user.SaveUser()
		if err != nil {
			revel.AppLog.Errorf("Save user error: %v", err)
		}

	}(currentUser)

	c.Flash.Success("Welcome, %v", currentUser.Name)
	return c.Redirect(nextUrl)
}

//Logout
func (c *Auth) Logout() revel.Result {
	//delete cache which is logged in user info
	cache.Delete(c.Session.ID())

	c.Session = make(map[string]interface{})
	c.Flash.Success("You have logged out.")
	return c.Redirect("/")
}
