package server

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

func TestRSAConnection(w http.ResponseWriter, r *http.Request) { //refactor this
	input := AcceptUserInput(r)
	rawMsg := string(DecryptRSA(input.SecretMsg, C.ServerPriv))
	helloWorld := rawMsg + " world!"
	type Send struct {
		SecretMsg []byte
	}
	secret := EncryptRSA(input.DesktopPub, []byte(helloWorld))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(Send{secret})
}

func AcceptUserInput(r *http.Request) Input {
	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Printf("server: could not read request body: %s\n", err)
	}
	var input Input
	json.Unmarshal(reqBody, &input)
	return input
}

func AskForSym(w http.ResponseWriter, r *http.Request) {
	input := AcceptUserInput(r)
	var output Output
	output.SecretSym = EncryptRSA(input.DesktopPub, C.Salt)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(output)
}

func CheckAESConnection(w http.ResponseWriter, r *http.Request) {
	input := AcceptUserInput(r)
	decryptedMsg := DecryptAES(C.Salt, input.Hash)
	ret := decryptedMsg + " Success"
	var output Output
	output.Msg = EncryptAES([]byte(ret), C.Salt)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(output)
}

func Signup(w http.ResponseWriter, r *http.Request) {
	input := AcceptUserInput(r)
	userdataCollection := Db.Collection("userdata")
	rawPass := DecryptRSA(input.AccountPassword, C.ServerPriv)
	storePass := EncryptAES([]byte(rawPass), C.Salt)
	InsertOne(userdataCollection, []string{"AccountUsername", "AccountPassword", "DocID"}, []string{input.AccountUsername, string(storePass), "0"})
	w.Header().Set("Content-Type", "application/json")
	var output Output
	output.Msg = []byte("Successly signed up " + input.AccountUsername + "\n")
	json.NewEncoder(w).Encode(output)
}

func CheckIfUsernameAvailable(w http.ResponseWriter, r *http.Request) {
	input := AcceptUserInput(r)
	userdataCollection := Db.Collection("userdata")
	var output Output
	if IsAvailableUsername(userdataCollection, input.AccountUsername) {
		output.Msg = []byte(input.AccountUsername + " available")
		output.Status = "success"
	} else {
		output.Msg = []byte(input.AccountUsername + " not available")
		output.Status = "failed"
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(output)
}

func Login(w http.ResponseWriter, r *http.Request) {
	input := AcceptUserInput(r)
	userObj := QueryByField(Db.Collection("userdata"), []string{"AccountUsername"}, []string{input.AccountUsername})
	givenPass := DecryptRSA(input.AccountPassword, C.ServerPriv)
	serverPass := DecryptAES(C.Salt, []byte(userObj.AccountPassword))
	var output Output
	if string(givenPass) == serverPass {
		output.Status = "Authenticated"
		key := GenerateSymKey(32)
		output.SecretSym = EncryptRSA(input.DesktopPub, key)
		InsertOne(Db.Collection("symmap"), []string{"AccountUsername", "SymKey"}, []string{input.AccountUsername, string(key)})
	} else {
		output.Status = "Failed"
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(output)
}

func ClearSymMap(w http.ResponseWriter, r *http.Request) {
	input := AcceptUserInput(r)
	del := DeleteDocument(Db.Collection("symmap"), []string{"AccountUsername"}, []string{input.AccountUsername}) //susceptible to DOS attacks if attacker spams clearSym
	var output Output
	if del.DeletedCount == 1 {
		output.Status = "Success"
	} else {
		output.Status = "Fail"
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(output)
}

func CreatePasswordEntry(w http.ResponseWriter, r *http.Request) {
	input := AcceptUserInput(r)
	sym := QueryByField(Db.Collection("symmap"), []string{"AccountUsername"}, []string{input.AccountUsername})
	userdata := QueryByField(Db.Collection("userdata"), []string{"AccountUsername"}, []string{input.AccountUsername})
	add1, _ := strconv.Atoi(userdata.DocID)
	userdata.DocID = strconv.Itoa(add1 + 1)
	input.SitePassword = []byte(DecryptAES([]byte(sym.SymKey), input.SitePassword))
	origPassword := string(input.SitePassword)
	input.SitePassword = EncryptAES(input.SitePassword, C.Salt)
	input.SiteUsername = []byte(DecryptAES([]byte(sym.SymKey), input.SiteUsername))
	origUsername := string(input.SiteUsername)
	input.SiteUsername = EncryptAES(input.SiteUsername, C.Salt)
	res := InsertOne(Db.Collection("password"), []string{"SiteUsername", "SitePassword", "Description", "AccountUsername", "DocID"}, []string{string(input.SiteUsername), string(input.SitePassword), input.Description, input.AccountUsername, userdata.DocID})
	userObj := QueryByID(Db.Collection("password"), res.InsertedID.(primitive.ObjectID))
	var output Output
	if DecryptAES(C.Salt, []byte(userObj.SiteUsername)) == origUsername && DecryptAES(C.Salt, []byte(userObj.SitePassword)) == origPassword {
		UpdateDocument(Db.Collection("userdata"), "DocID", userdata.DocID, userdata.ID)
		output.Status = "Success"
	} else {
		output.Status = "Fail"
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(output)
}

func GetAllPasswords(w http.ResponseWriter, r *http.Request) {
	input := AcceptUserInput(r)
	ret := RetrieveAllPass(Db.Collection("password"), input.AccountUsername)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ret)
}

func GetOnePassword(w http.ResponseWriter, r *http.Request) {
	input := AcceptUserInput(r)
	sym := QueryByField(Db.Collection("symmap"), []string{"AccountUsername"}, []string{input.AccountUsername})
	ret := QueryByField(Db.Collection("password"), []string{"DocID", "AccountUsername"}, []string{input.DocID, input.AccountUsername})
	var output Output
	decodedUsername := DecryptAES(C.Salt, []byte(ret.SiteUsername))
	decodedPassword := DecryptAES(C.Salt, []byte(ret.SitePassword))
	output.SiteUsername = EncryptAES([]byte(decodedUsername), []byte(sym.SymKey))
	output.SitePassword = EncryptAES([]byte(decodedPassword), []byte(sym.SymKey))
	output.Msg = []byte(ret.Description)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(output)
}

func UpdatePassword(w http.ResponseWriter, r *http.Request) {
	input := AcceptUserInput(r)
	sym := QueryByField(Db.Collection("symmap"), []string{"AccountUsername"}, []string{input.AccountUsername})
	ret := QueryByField(Db.Collection("password"), []string{"DocID", "AccountUsername"}, []string{input.DocID, input.AccountUsername})
	var output Output
	w.Header().Set("Content-Type", "application/json")
	if input.SiteUsername != nil {
		decodedUsername := []byte(DecryptAES([]byte(sym.SymKey), input.SiteUsername))
		encryptUsername := EncryptAES(decodedUsername, C.Salt)
		res := UpdateDocument(Db.Collection("password"), "SiteUsername", string(encryptUsername), ret.ID)
		if res.ModifiedCount != 1 {
			output.Msg = []byte("Failed to update username")
			json.NewEncoder(w).Encode(output)
		}
	}
	if input.SitePassword != nil {
		decodedPassword := []byte(DecryptAES([]byte(sym.SymKey), input.SitePassword))
		encryptPass := EncryptAES(decodedPassword, C.Salt)
		res := UpdateDocument(Db.Collection("password"), "SitePassword", string(encryptPass), ret.ID)
		if res.ModifiedCount != 1 {
			if output.Msg != nil {
				output.Msg = append(output.Msg, []byte("Failed to update password")...)
			} else {
				output.Msg = []byte("Failed to update password")
			}
			json.NewEncoder(w).Encode(output)
		}
	}
	output.Msg = []byte("Successfully updated username and or password!")
	json.NewEncoder(w).Encode(output)
}

func DeletePassword(w http.ResponseWriter, r *http.Request) {
	input := AcceptUserInput(r)
	DeleteDocument(Db.Collection("password"), []string{"DocID", "AccountUsername"}, []string{input.DocID, input.AccountUsername})
	userdata := QueryByField(Db.Collection("userdata"), []string{"AccountUsername"}, []string{input.AccountUsername})
	if userdata.DocID != input.DocID {
		replacement := QueryByField(Db.Collection("password"), []string{"DocID", "AccountUsername"}, []string{userdata.DocID, input.AccountUsername})
		UpdateDocument(Db.Collection("password"), "DocID", input.DocID, replacement.ID)
	}
	minus1, _ := strconv.Atoi(userdata.DocID)
	UpdateDocument(Db.Collection("userdata"), "DocID", strconv.Itoa(minus1-1), userdata.ID)
	var output Output
	w.Header().Set("Content-Type", "application/json")
	output.Msg = []byte("Success")
	json.NewEncoder(w).Encode(output)
}
