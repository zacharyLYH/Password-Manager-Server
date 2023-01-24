package main

import (
	"crypto/rsa"
	"fmt"
	"log"
	"net/http"

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

func main() {
	C = ServerCreds{
		extractPubKey(pwd() + "/serverPublic.pem"),
		extractPrivKey(pwd() + "/serverPrivate.pem"),
		[]byte{105, 86, 89, 70, 118, 101, 121, 90, 48, 76, 57, 69, 48, 116, 102, 52, 69, 75, 110, 106, 97, 65, 98, 110, 83, 105, 89, 84, 71, 84, 48, 97},
	}
	connect()
	TestSymKey = generateSymKey(32)
	//add listeners
	mux := http.NewServeMux()
	mux.HandleFunc("/askForSym", askForSym)
	mux.HandleFunc("/checkAESConnection", checkAESConnection)
	mux.HandleFunc("/testRSAConnection", testRSAConnection)
	mux.HandleFunc("/signup", signup)
	mux.HandleFunc("/checkIfUsernameAvailable", checkIfUsernameAvailable)
	mux.HandleFunc("/login", login)
	mux.HandleFunc("/clearSymMap", clearSymMap)
	mux.HandleFunc("/createPasswordEntry", createPasswordEntry)
	mux.HandleFunc("/getAllPasswords", getAllPasswords)
	mux.HandleFunc("/getOnePassword", getOnePassword)
	mux.HandleFunc("/updatePassword", updatePassword)
	mux.HandleFunc("/deletePassword", deletePassword)
	fmt.Printf("Starting server at port 8000\n")
	if err := http.ListenAndServe(":8000", mux); err != nil {
		log.Fatal(err)
	}
}
