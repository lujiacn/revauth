package controllers

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	revel "github.com/revel/revel"
)

// BasicAuth for html basic auth

func getCredentials(data string) (username, password string, err error) {
	decodedData, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", "", err
	}
	strData := strings.Split(string(decodedData), ":")
	username = strData[0]
	password = strData[1]
	return
}

func basicAuth(c *revel.Controller) revel.Result {
	correctUsername := revel.Config.StringDefault("revauth.user", "user321")
	correctPassword := revel.Config.StringDefault("revauth.pass", "pass654")

	if auth := c.Request.Header.Get("Authorization"); auth != "" {
		// Split up the string to get just the data, then get the credentials
		username, password, err := getCredentials(strings.Split(auth, " ")[1])
		if err != nil {
			return c.RenderError(err)
		}
		if username != correctUsername || password != correctPassword {
			c.Response.Status = http.StatusUnauthorized
			c.Response.Out.Header().Set("WWW-Authenticate", `Basic realm="revel"`)
			return c.RenderError(errors.New("401: Not authorized"))
		}
		return nil
	} else {
		c.Response.Status = http.StatusUnauthorized
		c.Response.Out.Header().Set("WWW-Authenticate", `Basic realm="revel"`)
		return c.RenderError(errors.New("401: Not authorized"))
	}
}

func init() {
	revel.InterceptFunc(basicAuth, revel.BEFORE, &AuthUser{})
}
