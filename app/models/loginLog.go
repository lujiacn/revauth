package models

import (
	"github.com/lujiacn/mongodo"
	"go.mongodb.org/mongo-driver/bson"
)

type LoginLog struct {
	mongodo.BaseModel `bson:",inline"`
	Account           string `bson:"Account,omitempty"`
	Status            string `bson:"Status,omitempty"`
	IPAddress         string `bson:"IPAddress,omitempty"`
	User              *User  `bson:"-"`
}

func (m *LoginLog) GenUser() {
	user := new(User)
	do := mongodo.New(user)
	do.Query = bson.M{"Identity": m.Account}
	do.GetByQ()
	m.User = user
}
