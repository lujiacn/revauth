package revauth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/lujiacn/revauth/app/models"
	gAuth "github.com/lujiacn/revauth/auth"
	"google.golang.org/grpc"

	"github.com/revel/revel"
)

var (
	grpcDial   string
	AuthMethod string // default grpc
)

//Init reading LDAP configuration
func Init() {
	grpcAuthServer, ok := revel.Config.String("grpcauth.server")
	if !ok {
		panic("Authenticate server not defined")

	}
	grpcAuthPort := revel.Config.StringDefault("grpcauth.port", "50051")
	grpcDial = grpcAuthServer + ":" + grpcAuthPort
	AuthMethod = revel.Config.StringDefault("grpcauth.method", "grpc")
	revel.AppLog.Infof("AuthMethod is %s", AuthMethod)
}

//Authenticate do auth and return Auth object including user information and lognin success or not
func Authenticate(account, password string) *gAuth.AuthReply {
	switch AuthMethod {
	case "local":
		// check local or grpc
		user, err := models.CheckUser(account, password)
		if err != nil {
			return &gAuth.AuthReply{IsAuthenticated: false, Error: fmt.Sprintf("%v", err)}
		}
		return &gAuth.AuthReply{IsAuthenticated: true, Account: user.Identity, Email: user.Mail, Avatar: user.Avatar, Name: user.Name, First: user.First, Last: user.Last}

	default:
		conn, err := grpc.Dial(grpcDial, grpc.WithInsecure())
		if err != nil {
			return &gAuth.AuthReply{Error: fmt.Sprintf("Connect auth server failed, %v", err)}
		}
		defer conn.Close()
		c := gAuth.NewAuthClient(conn)
		r, err := c.Authenticate(context.Background(), &gAuth.AuthRequest{Account: account, Password: password})
		if err != nil {
			return &gAuth.AuthReply{Error: fmt.Sprintf("Authenticate failed due to %v ", err)}
		}
		return r
	}
}

func Query(account string) (*gAuth.QueryReply, error) {
	if AuthMethod == "local" {
		// TODO, search local user list
		return nil, errors.New("Not implemented")
	}
	conn, err := grpc.Dial(grpcDial, grpc.WithInsecure())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	c := gAuth.NewAuthClient(conn)
	r, err := c.Query(context.Background(), &gAuth.QueryRequest{Account: account})
	if err != nil {
		r.NotExist = true
	}
	return r, nil

}

func QueryMail(email string) (*gAuth.QueryReply, error) {
	if AuthMethod == "local" {
		// TODO, search local user list
		return nil, errors.New("Not implemented")
	}

	conn, err := grpc.Dial(grpcDial, grpc.WithInsecure())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	c := gAuth.NewAuthClient(conn)
	r, err := c.Query(context.Background(), &gAuth.QueryRequest{Email: email})
	if err != nil {
		r.NotExist = true
	}
	return r, nil
}

func QueryMailAndSave(email string) (*models.User, error) {
	authUser, err := QueryMail(email)
	if err != nil {
		return nil, err
	}

	if authUser.Error != "" && authUser.Error != "<nil>" {
		fmt.Println("Errors", authUser.Error)
		return nil, fmt.Errorf(authUser.Error)
	}
	if authUser.NotExist {
		fmt.Println("Not exist", authUser.Error)
		return nil, fmt.Errorf("User not exist")
	}

	user := new(models.User)
	user.Identity = strings.ToLower(authUser.Account)
	user.Mail = authUser.Email
	user.Avatar = authUser.Avatar
	user.Name = authUser.Name
	user.Depart = authUser.Depart
	user.SaveUser()
	return user, nil
}

func QueryAndSave(account string) (*models.User, error) {
	authUser, err := Query(account)
	if err != nil {
		return nil, err
	}

	if authUser.Error != "" && authUser.Error != "<nil>" {
		fmt.Println("Errors", authUser.Error)
		return nil, fmt.Errorf(authUser.Error)
	}
	if authUser.NotExist {
		fmt.Println("Not exist", authUser.Error)
		return nil, fmt.Errorf("User not exist")
	}

	user := new(models.User)
	user.Identity = strings.ToLower(account)
	user.Mail = authUser.Email
	user.Avatar = authUser.Avatar
	user.Name = authUser.Name
	user.Depart = authUser.Depart
	user.SaveUser()
	return user, nil
}
