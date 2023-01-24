package server

import (
	"context"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

func InsertOne(collection *mongo.Collection, parameters, values []string) *mongo.InsertOneResult {
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

func IsAvailableUsername(collection *mongo.Collection, try string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := collection.FindOne(ctx, bson.M{"AccountUsername": try}).Err(); err == mongo.ErrNoDocuments {
		return true
	}
	return false
}

func QueryByField(collection *mongo.Collection, parameters, values []string) UserData {
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

func QueryByID(collection *mongo.Collection, objID primitive.ObjectID) UserData {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var ret UserData
	if err := collection.FindOne(ctx, bson.M{"_id": objID}).Decode(&ret); err != nil {
		log.Fatal(err)
	}
	return ret
}

func DeleteDocument(collection *mongo.Collection, parameters, values []string) *mongo.DeleteResult {
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

func UpdateDocument(collection *mongo.Collection, change, changeTo string, objID primitive.ObjectID) *mongo.UpdateResult {
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

func RetrieveAllPass(collection *mongo.Collection, username string) []AllPasswords {
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
