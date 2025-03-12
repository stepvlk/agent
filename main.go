package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var client *mongo.Client
var collection *mongo.Collection
var apiKey string
var cache = make(map[string]Connection)
var cacheMutex sync.RWMutex

type Connection struct {
	ID         string `json:"id"`
	LocalIP    string `json:"local_ip"`
	LocalPort  string `json:"local_port"`
	LocalName  string `json:"local_name"`
	RemoteIP   string `json:"remote_ip"`
	RemotePort string `json:"remote_port"`
	DstName    string `json:"dst_name"`
	Process    string `json:"process"`
	Direction  string `json:"direction"`
	Timestamp  int64  `json:"timestamp"`
}

func connectDB() error {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
		return err
	}

	apiKey = os.Getenv("API_KEY")
	clientOptions := options.Client().ApplyURI(os.Getenv("MONGO_URI"))
	client, err = mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		log.Fatal("Error connecting to MongoDB:", err)
		return err
	}

	err = client.Ping(context.TODO(), nil)
	if err != nil {
		log.Fatal("Failed to connect to MongoDB:", err)
		return err
	}

	collection = client.Database(os.Getenv("MONGO_DB")).Collection("connections")
	log.Println("Connected to MongoDB")
	return nil
}

func closeDB() {
	if err := client.Disconnect(context.TODO()); err != nil {
		log.Fatal("Error closing MongoDB connection:", err)
	}
	log.Println("MongoDB connection closed")
}

func upsertConnectionInDB(conn Connection) error {
	filter := bson.M{"id": conn.ID}
	update := bson.M{
		"$set": bson.M{
			"id":          conn.ID,
			"local_ip":    conn.LocalIP,
			"local_port":  conn.LocalPort,
			"local_name":  conn.LocalName,
			"remote_ip":   conn.RemoteIP,
			"remote_port": conn.RemotePort,
			"dst_name":    conn.DstName,
			"process":     conn.Process,
			"direction":   conn.Direction,
			"timestamp":   conn.Timestamp,
		},
	}

	_, err := collection.UpdateOne(context.TODO(), filter, update, options.Update().SetUpsert(true))
	return err
}

func receiveConnections(w http.ResponseWriter, r *http.Request) {
	clientApiKey := r.Header.Get("X-API-KEY")
	if clientApiKey != apiKey {
		http.Error(w, "Invalid API key", http.StatusForbidden)
		return
	}

	var report struct {
		Hostname    string       `json:"hostname"`
		Timestamp   string       `json:"timestamp"`
		Connections []Connection `json:"connections"`
	}

	err := json.NewDecoder(r.Body).Decode(&report)
	if err != nil {
		log.Printf("❌ Error decoding data: %v", err)
		http.Error(w, "Error decoding data", http.StatusBadRequest)
		return
	}

	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	for _, conn := range report.Connections {
		cache[conn.ID] = conn
		err := upsertConnectionInDB(conn)
		if err != nil {
			log.Printf("Error writing to MongoDB: %v", err)
			http.Error(w, fmt.Sprintf("Error writing to MongoDB: %v", err), http.StatusInternalServerError)
			return
		}
		log.Printf("Connection %s updated/added to the database", conn.ID)
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Data successfully saved"))
}

func periodicCacheFlush() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		cacheMutex.Lock()
		for _, conn := range cache {
			err := upsertConnectionInDB(conn)
			if err != nil {
				log.Printf("Error updating data in MongoDB: %v", err)
			} else {
				log.Printf("Connection %s sent to the database", conn.ID)
			}
		}
		cacheMutex.Unlock()
	}
}

func main() {
	router := mux.NewRouter()

	err := connectDB()
	if err != nil {
		log.Fatal("Failed to connect to MongoDB")
		return
	}
	defer closeDB()

	router.HandleFunc("/api/netstat", receiveConnections).Methods("POST")

	go periodicCacheFlush()

	port := os.Getenv("SERVER_PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server started on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, router))
}
