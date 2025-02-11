package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

type Config struct {
	ServerURL   string `json:"server_url"`
	LogFile     string `json:"log_file"`
	Interval    int    `json:"interval"`
	HTTPTimeout int    `json:"timeout"`
}

var (
	config     Config
	cache      = make(map[string]Connection)
	cacheMutex sync.RWMutex
	localIP    string
)

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

func loadConfig(filename string) error {
	file, err := os.ReadFile(filename)
	if err != nil {
		log.Println("The configuration file was not found, we use the default settings.")
		return err
	}
	return json.Unmarshal(file, &config)
}

func initLogger(logFile string) {
	logFileHandle, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatal("Error creating the log file:", err)
	}
	log.SetOutput(logFileHandle)
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
}

func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Println("Local IP detection error:", err)
		return "127.0.0.1"
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
			return ipNet.IP.String()
		}
	}
	return "127.0.0.1"
}

func generateConnectionID(localIP, localPort, remoteIP, remotePort string) string {
	data := fmt.Sprintf("%s:%s-%s:%s", localIP, localPort, remoteIP, remotePort)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func getProcessName(pid string) string {
	if runtime.GOOS != "linux" {
		return "process_permit"
	}

	cmd := exec.Command("ps", "-p", pid, "-o", "comm=")
	output, err := cmd.Output()
	if err != nil {
		return "process_permit"
	}
	return strings.TrimSpace(string(output))
}

func getEstablishedConnections() ([]Connection, error) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("netstat", "-ano")
	} else {
		cmd = exec.Command("netstat", "-tunap")
	}

	output, err := cmd.Output()
	if err != nil {
		log.Println("Netstat execution error:", err)
		return nil, err
	}

	lines := strings.Split(string(output), "\n")
	var connections []Connection

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		stateIndex := 5
		if runtime.GOOS == "windows" {
			stateIndex = 3
		}

		if len(fields) <= stateIndex || fields[stateIndex] != "ESTABLISHED" {
			continue
		}

		localIP, localPort := parseAddress(fields[1])
		remoteIP, remotePort := parseAddress(fields[2])

		var direction string
		if localIP == localIP {
			direction = "incoming"
		} else {
			direction = "outgoing"
		}

		conn := Connection{
			ID:         generateConnectionID(localIP, localPort, remoteIP, remotePort),
			LocalIP:    localIP,
			LocalPort:  localPort,
			LocalName:  resolveHostname(localIP),
			RemoteIP:   remoteIP,
			RemotePort: remotePort,
			DstName:    resolveHostname(remoteIP),
			Direction:  direction,
			Timestamp:  time.Now().Unix(),
			Process:    "process_permit",
		}

		if len(fields) > stateIndex+1 {
			conn.Process = getProcessName(fields[stateIndex+1])
		}

		connections = append(connections, conn)
	}

	log.Printf("Found %d ESTABLISHED connections\n", len(connections))
	return connections, nil
}

func parseAddress(address string) (string, string) {
	parts := strings.Split(address, ":")
	if len(parts) < 2 {
		return address, ""
	}
	return parts[0], parts[1]
}

func resolveHostname(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ip
	}
	return names[0]
}

func updateCache(connections []Connection) {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	currentIDs := make(map[string]bool)
	newConnections := []Connection{}

	for _, conn := range connections {
		currentIDs[conn.ID] = true

		if _, exists := cache[conn.ID]; !exists {
			newConnections = append(newConnections, conn)
		}
		cache[conn.ID] = conn
	}

	for id := range cache {
		if !currentIDs[id] {
			delete(cache, id)
			log.Printf("Connection %s deleted from cache (inactive)", id)
		}
	}

	if len(newConnections) > 0 {
		sendReport(newConnections)
	} else {
		log.Println("There are no new connections to send")
	}
}

func sendReport(connections []Connection) {
	hostname, _ := os.Hostname()

	report := struct {
		Hostname    string       `json:"hostname"`
		Timestamp   time.Time    `json:"timestamp"`
		Connections []Connection `json:"connections"`
	}{
		Hostname:    hostname,
		Timestamp:   time.Now(),
		Connections: connections,
	}

	jsonData, err := json.Marshal(report)
	if err != nil {
		log.Println("❌ Ошибка сериализации JSON:", err)
		return
	}

	client := &http.Client{Timeout: time.Duration(config.HTTPTimeout) * time.Second}
	resp, err := client.Post(config.ServerURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Println("Error sending data:", err)
		return
	}
	defer resp.Body.Close()

	log.Printf("Data sent (%d connections), status: %s", len(connections), resp.Status)
}

func main() {
	var configFile string
	flag.StringVar(&configFile, "config", "config.json", "Configuration file")
	flag.StringVar(&config.ServerURL, "server", "", "Server URL")
	flag.StringVar(&config.LogFile, "logfile", "", "The logs file")
	flag.IntVar(&config.Interval, "interval", 10, "Collection interval (seconds)")
	flag.IntVar(&config.HTTPTimeout, "timeout", 5, "HTTP timeout (seconds)")
	flag.Parse()

	loadConfig(configFile)
	initLogger(config.LogFile)

	localIP = getLocalIP()
	log.Println("The local IP is defined:", localIP)

	log.Println("The agent is running. Collecting ESTABLISHED connections every", config.Interval, "seconds")

	connections, err := getEstablishedConnections()
	if err == nil && len(connections) > 0 {
		sendReport(connections)

		cacheMutex.Lock()
		for _, conn := range connections {
			cache[conn.ID] = conn
		}
		cacheMutex.Unlock()
	}

	ticker := time.NewTicker(time.Duration(config.Interval) * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		connections, err := getEstablishedConnections()
		if err != nil {
			log.Println("Connection receipt error:", err)
			continue
		}

		updateCache(connections)
	}
}
