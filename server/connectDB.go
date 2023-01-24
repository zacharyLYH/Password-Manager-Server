package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/spf13/viper"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var db *mongo.Database

func connect() {
	viper.SetConfigFile("../.env")
	viper.ReadInConfig()
	client, err := mongo.NewClient(options.Client().ApplyURI(fmt.Sprintf("%v", viper.Get("MONGO_URI"))))
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = client.Connect(ctx)
	if err != nil {
		log.Fatal(err)
	}
	db = client.Database("learning-mongo-go")
}
