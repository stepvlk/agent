package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var client *mongo.Client
var collection *mongo.Collection

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
		log.Fatal("Download error .env file")
		return err
	}

	clientOptions := options.Client().ApplyURI(os.Getenv("MONGO_URI"))
	client, err = mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		log.Fatal("Error connecting to MongoDB:", err)
		return err
	}

	// Проверка подключения
	err = client.Ping(context.TODO(), nil)
	if err != nil {
		log.Fatal("Couldn't connect to MongoDB:", err)
		return err
	}

	collection = client.Database(os.Getenv("MONGO_DB")).Collection("connections")
	log.Println("Connection to MongoDB is established")
	return nil
}

func closeDB() {
	if err := client.Disconnect(context.TODO()); err != nil {
		log.Fatal("Error closing connection to MongoDB:", err)
	}
	log.Println("Подключение к MongoDB закрыто")
}

func receiveConnections(w http.ResponseWriter, r *http.Request) {
	var report struct {
		Hostname    string       `json:"hostname"`
		Timestamp   string       `json:"timestamp"`
		Connections []Connection `json:"connections"`
	}

	err := json.NewDecoder(r.Body).Decode(&report)
	if err != nil {
		log.Printf("Data decoding error: %v", err)
		http.Error(w, "Data decoding error", http.StatusBadRequest)
		return
	}

	for _, conn := range report.Connections {
		_, err := collection.InsertOne(context.TODO(), conn)
		if err != nil {
			log.Printf("Data decoding error MongoDB write error: %v", err)
			http.Error(w, fmt.Sprintf("Error writing to MongoDB: %v", err), http.StatusInternalServerError)
			return
		}
		log.Printf("The %s connection is recorded in the database", conn.ID)
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Data saved successfully"))
}

func main() {
	router := mux.NewRouter()

	err := connectDB()
	if err != nil {
		log.Fatal("Couldn't connect to MongoDB")
		return
	}
	defer closeDB()

	router.HandleFunc("/api/netstat", receiveConnections).Methods("POST")

	port := os.Getenv("SERVER_PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Сервер запущен на порту %s", port)
	log.Fatal(http.ListenAndServe(":"+port, router))
}
