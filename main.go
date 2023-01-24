package main

import (
	"fmt"
	"log"
	"net/http"
	w "pm/server"

	"github.com/spf13/viper"
)

var URI string

func main() {
	viper.SetConfigFile("ENV")
	viper.ReadInConfig()
	w.Connect(fmt.Sprintf("%v", viper.Get("MONGO_URI")))
	w.InitializeStructs()
	//add listeners
	mux := http.NewServeMux()
	mux.HandleFunc("/askForSym", w.AskForSym)
	mux.HandleFunc("/checkAESConnection", w.CheckAESConnection)
	mux.HandleFunc("/testRSAConnection", w.TestRSAConnection)
	mux.HandleFunc("/signup", w.Signup)
	mux.HandleFunc("/checkIfUsernameAvailable", w.CheckIfUsernameAvailable)
	mux.HandleFunc("/login", w.Login)
	mux.HandleFunc("/clearSymMap", w.ClearSymMap)
	mux.HandleFunc("/createPasswordEntry", w.CreatePasswordEntry)
	mux.HandleFunc("/getAllPasswords", w.GetAllPasswords)
	mux.HandleFunc("/getOnePassword", w.GetOnePassword)
	mux.HandleFunc("/updatePassword", w.UpdatePassword)
	mux.HandleFunc("/deletePassword", w.DeletePassword)
	fmt.Printf("Starting server at port 8000\n")
	if err := http.ListenAndServe(":8000", mux); err != nil {
		log.Fatal(err)
	}
}
