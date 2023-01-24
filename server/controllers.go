package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

func testRSAConnection(w http.ResponseWriter, r *http.Request) { //refactor this
	input := acceptUserInput(r)
	rawMsg := string(decryptRSA(input.SecretMsg, C.ServerPriv))
	helloWorld := rawMsg + " world!"
	type Send struct {
		SecretMsg []byte
	}
	secret := encryptRSA(input.DesktopPub, []byte(helloWorld))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(Send{secret})
}

func acceptUserInput(r *http.Request) Input {
	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Printf("server: could not read request body: %s\n", err)
	}
	var input Input
	json.Unmarshal(reqBody, &input)
	return input
}

func askForSym(w http.ResponseWriter, r *http.Request) {
	input := acceptUserInput(r)
	var output Output
	output.SecretSym = encryptRSA(input.DesktopPub, C.Salt)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(output)
}

func checkAESConnection(w http.ResponseWriter, r *http.Request) {
	input := acceptUserInput(r)
	decryptedMsg := decryptAES(C.Salt, input.Hash)
	ret := decryptedMsg + " Success"
	var output Output
	output.Msg = encryptAES([]byte(ret), C.Salt)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(output)
}

func signup(w http.ResponseWriter, r *http.Request) {
	input := acceptUserInput(r)
	userdataCollection := db.Collection("userdata")
	rawPass := decryptRSA(input.AccountPassword, C.ServerPriv)
	storePass := encryptAES([]byte(rawPass), C.Salt)
	insertOne(userdataCollection, []string{"AccountUsername", "AccountPassword", "DocID"}, []string{input.AccountUsername, string(storePass), "0"})
	w.Header().Set("Content-Type", "application/json")
	var output Output
	output.Msg = []byte("Successly signed up " + input.AccountUsername + "\n")
	json.NewEncoder(w).Encode(output)
}

func checkIfUsernameAvailable(w http.ResponseWriter, r *http.Request) {
	input := acceptUserInput(r)
	userdataCollection := db.Collection("userdata")
	var output Output
	if isAvailableUsername(userdataCollection, input.AccountUsername) {
		output.Msg = []byte(input.AccountUsername + " available")
		output.Status = "success"
	} else {
		output.Msg = []byte(input.AccountUsername + " not available")
		output.Status = "failed"
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(output)
}

func login(w http.ResponseWriter, r *http.Request) {
	input := acceptUserInput(r)
	userObj := queryByField(db.Collection("userdata"), []string{"AccountUsername"}, []string{input.AccountUsername})
	givenPass := decryptRSA(input.AccountPassword, C.ServerPriv)
	serverPass := decryptAES(C.Salt, []byte(userObj.AccountPassword))
	var output Output
	if string(givenPass) == serverPass {
		output.Status = "Authenticated"
		key := generateSymKey(32)
		output.SecretSym = encryptRSA(input.DesktopPub, key)
		insertOne(db.Collection("symmap"), []string{"AccountUsername", "SymKey"}, []string{input.AccountUsername, string(key)})
	} else {
		output.Status = "Failed"
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(output)
}

func clearSymMap(w http.ResponseWriter, r *http.Request) {
	input := acceptUserInput(r)
	del := deleteDocument(db.Collection("symmap"), []string{"AccountUsername"}, []string{input.AccountUsername}) //susceptible to DOS attacks if attacker spams clearSym
	var output Output
	if del.DeletedCount == 1 {
		output.Status = "Success"
	} else {
		output.Status = "Fail"
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(output)
}

func createPasswordEntry(w http.ResponseWriter, r *http.Request) {
	input := acceptUserInput(r)
	sym := queryByField(db.Collection("symmap"), []string{"AccountUsername"}, []string{input.AccountUsername})
	userdata := queryByField(db.Collection("userdata"), []string{"AccountUsername"}, []string{input.AccountUsername})
	add1, _ := strconv.Atoi(userdata.DocID)
	userdata.DocID = strconv.Itoa(add1 + 1)
	input.SitePassword = []byte(decryptAES([]byte(sym.SymKey), input.SitePassword))
	origPassword := string(input.SitePassword)
	input.SitePassword = encryptAES(input.SitePassword, C.Salt)
	input.SiteUsername = []byte(decryptAES([]byte(sym.SymKey), input.SiteUsername))
	origUsername := string(input.SiteUsername)
	input.SiteUsername = encryptAES(input.SiteUsername, C.Salt)
	res := insertOne(db.Collection("password"), []string{"SiteUsername", "SitePassword", "Description", "AccountUsername", "DocID"}, []string{string(input.SiteUsername), string(input.SitePassword), input.Description, input.AccountUsername, userdata.DocID})
	userObj := queryByID(db.Collection("password"), res.InsertedID.(primitive.ObjectID))
	var output Output
	if decryptAES(C.Salt, []byte(userObj.SiteUsername)) == origUsername && decryptAES(C.Salt, []byte(userObj.SitePassword)) == origPassword {
		updateDocument(db.Collection("userdata"), "DocID", userdata.DocID, userdata.ID)
		output.Status = "Success"
	} else {
		output.Status = "Fail"
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(output)
}

func getAllPasswords(w http.ResponseWriter, r *http.Request) {
	input := acceptUserInput(r)
	ret := retrieveAllPass(db.Collection("password"), input.AccountUsername)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ret)
}

func getOnePassword(w http.ResponseWriter, r *http.Request) {
	input := acceptUserInput(r)
	sym := queryByField(db.Collection("symmap"), []string{"AccountUsername"}, []string{input.AccountUsername})
	ret := queryByField(db.Collection("password"), []string{"DocID", "AccountUsername"}, []string{input.DocID, input.AccountUsername})
	var output Output
	decodedUsername := decryptAES(C.Salt, []byte(ret.SiteUsername))
	decodedPassword := decryptAES(C.Salt, []byte(ret.SitePassword))
	output.SiteUsername = encryptAES([]byte(decodedUsername), []byte(sym.SymKey))
	output.SitePassword = encryptAES([]byte(decodedPassword), []byte(sym.SymKey))
	output.Msg = []byte(ret.Description)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(output)
}

func updatePassword(w http.ResponseWriter, r *http.Request) {
	input := acceptUserInput(r)
	sym := queryByField(db.Collection("symmap"), []string{"AccountUsername"}, []string{input.AccountUsername})
	ret := queryByField(db.Collection("password"), []string{"DocID", "AccountUsername"}, []string{input.DocID, input.AccountUsername})
	var output Output
	w.Header().Set("Content-Type", "application/json")
	if input.SiteUsername != nil {
		decodedUsername := []byte(decryptAES([]byte(sym.SymKey), input.SiteUsername))
		encryptUsername := encryptAES(decodedUsername, C.Salt)
		res := updateDocument(db.Collection("password"), "SiteUsername", string(encryptUsername), ret.ID)
		if res.ModifiedCount != 1 {
			output.Msg = []byte("Failed to update username")
			json.NewEncoder(w).Encode(output)
		}
	}
	if input.SitePassword != nil {
		decodedPassword := []byte(decryptAES([]byte(sym.SymKey), input.SitePassword))
		encryptPass := encryptAES(decodedPassword, C.Salt)
		res := updateDocument(db.Collection("password"), "SitePassword", string(encryptPass), ret.ID)
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

func deletePassword(w http.ResponseWriter, r *http.Request) {
	input := acceptUserInput(r)
	deleteDocument(db.Collection("password"), []string{"DocID", "AccountUsername"}, []string{input.DocID, input.AccountUsername})
	userdata := queryByField(db.Collection("userdata"), []string{"AccountUsername"}, []string{input.AccountUsername})
	if userdata.DocID != input.DocID {
		replacement := queryByField(db.Collection("password"), []string{"DocID", "AccountUsername"}, []string{userdata.DocID, input.AccountUsername})
		updateDocument(db.Collection("password"), "DocID", input.DocID, replacement.ID)
	}
	minus1, _ := strconv.Atoi(userdata.DocID)
	updateDocument(db.Collection("userdata"), "DocID", strconv.Itoa(minus1-1), userdata.ID)
	var output Output
	w.Header().Set("Content-Type", "application/json")
	output.Msg = []byte("Success")
	json.NewEncoder(w).Encode(output)
}
