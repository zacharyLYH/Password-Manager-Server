package server

import (
	"crypto/rsa"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type ServerCreds struct {
	ServerPub  *rsa.PublicKey
	ServerPriv *rsa.PrivateKey
	Salt       []byte
}

type Input struct {
	AccountUsername string
	AccountPassword []byte
	Description     string
	DesktopPub      *rsa.PublicKey
	Hash            []byte
	SecretMsg       []byte
	SymKey          []byte
	SiteUsername    []byte
	SitePassword    []byte
	DocID           string
}

type Output struct {
	SecretSym    []byte
	Msg          []byte
	Status       string
	SiteUsername []byte
	SitePassword []byte
}

type UserData struct {
	ID              primitive.ObjectID `bson:"_id"`
	AccountUsername string             `bson:"AccountUsername"`
	AccountPassword string             `bson:"AccountPassword"`
	SymKey          string             `bson:"SymKey"`
	SiteUsername    string             `bson:"SiteUsername"`
	SitePassword    string             `bson:"SitePassword"`
	DocID           string             `bson:"DocID"`
	Description     string             `bson:"Description"`
}

type AllPasswords struct {
	DocID       string `bson:"DocID"`
	Description string `bson:"Description"`
}

var C ServerCreds
var TestSymKey []byte

func InitializeStructs() {
	C = ServerCreds{
		ExtractPubKey(Pwd() + "/server/serverPublic.pem"),
		ExtractPrivKey(Pwd() + "/server/serverPrivate.pem"),
		[]byte{105, 86, 89, 70, 118, 101, 121, 90, 48, 76, 57, 69, 48, 116, 102, 52, 69, 75, 110, 106, 97, 65, 98, 110, 83, 105, 89, 84, 71, 84, 48, 97},
	}
	TestSymKey = GenerateSymKey(32)
}
