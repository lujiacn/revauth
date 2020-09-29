package controllers

import (
	"strings"

	"github.com/lujiacn/revauth"
	"github.com/lujiacn/revauth/app/models"
	"github.com/revel/revel"
)

type AuthUser struct {
	*revel.Controller
}

func (c *AuthUser) NewUser() revel.Result {
	if revauth.AuthMethod != "local" {
		return c.RenderText("Cannot Add User in current auth method")
	}
	return c.Render()
}

// CreateUser
func (c *AuthUser) CreateUser(record *models.User) revel.Result {
	nextUrl := c.Params.Get("nextUrl")
	if nextUrl == "" {
		nextUrl = c.Request.Referer()
	}
	if record.Identity == "" || record.RawPassword == "" {
		c.Flash.Error("Please fill in account and password")
		return c.Redirect(nextUrl)
	}

	//save current user information
	record.Identity = strings.ToLower(record.Identity) //identity is email
	record.Add()
	c.Flash.Success("User added")
	return c.Redirect("/login")
}
