package main

import (
	"context"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

func insertOne(collection *mongo.Collection, parameters, values []string) *mongo.InsertOneResult {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	data := make(bson.M)
	for i := 0; i < len(parameters); i++ {
		data[parameters[i]] = values[i]
	}
	result, err := collection.InsertOne(ctx, data)
	if err != nil {
		log.Fatal(err)
	}
	return result
}

func isAvailableUsername(collection *mongo.Collection, try string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := collection.FindOne(ctx, bson.M{"AccountUsername": try}).Err(); err == mongo.ErrNoDocuments {
		return true
	}
	return false
}

func queryByField(collection *mongo.Collection, parameters, values []string) UserData {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	data := make(bson.M)
	for i := 0; i < len(parameters); i++ {
		data[parameters[i]] = values[i]
	}
	var ret UserData
	if err := collection.FindOne(ctx, data).Decode(&ret); err != nil {
		log.Fatal(err)
	}
	return ret
}

func queryByID(collection *mongo.Collection, objID primitive.ObjectID) UserData {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var ret UserData
	if err := collection.FindOne(ctx, bson.M{"_id": objID}).Decode(&ret); err != nil {
		log.Fatal(err)
	}
	return ret
}

func deleteDocument(collection *mongo.Collection, parameters, values []string) *mongo.DeleteResult {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	data := make(bson.M)
	for i := 0; i < len(parameters); i++ {
		data[parameters[i]] = values[i]
	}
	result, err := collection.DeleteOne(ctx, data)
	if err != nil {
		log.Fatal(err)
	}
	return result
}

func updateDocument(collection *mongo.Collection, change, changeTo string, objID primitive.ObjectID) *mongo.UpdateResult {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := collection.UpdateOne(
		ctx,
		bson.M{"_id": objID},
		bson.D{
			{Key: "$set", Value: bson.D{{Key: change, Value: changeTo}}},
		},
	)
	if err != nil {
		log.Fatal(err)
	}
	return result
}

func retrieveAllPass(collection *mongo.Collection, username string) []AllPasswords {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var ret []AllPasswords
	cursor, err := collection.Find(ctx, bson.M{"AccountUsername": username})
	if err != nil {
		log.Fatal(err)
	}
	if err = cursor.All(ctx, &ret); err != nil {
		log.Fatal(err)
	}
	return ret
}
