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
  "strconv"
  "strings"
  "sync"
  "time"

  "gopkg.in/natefinch/lumberjack.v2"
)

type Config struct {
  ServerURL   string `json:"server_url"`
  LogFile     string `json:"log_file"`
  Interval    int    `json:"interval"`
  HTTPTimeout int    `json:"timeout"`
  APIKey      string `json:"APIKey"`
}

var (
  config     Config
  cache      = make(map[string]Connection)
  cacheMutex sync.RWMutex
  localIP    string
  Version    = "dev"
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

func isLocalIP(ip string) bool {
  ipAddr := net.ParseIP(ip)
  if ipAddr == nil {
    return false
  }
  localIPs := []string{
    "127.0.0.1",
    "::1",
        "localhost"     
  }

  for _, localIP := range localIPs {
    if ipAddr.String() == localIP {
      return true
    }
  }

  _, localNet1, _ := net.ParseCIDR("192.168.0.0/16")
  _, localNet2, _ := net.ParseCIDR("10.0.0.0/8")
  _, localNet3, _ := net.ParseCIDR("172.16.0.0/12")

  if localNet1.Contains(ipAddr) || localNet2.Contains(ipAddr) || localNet3.Contains(ipAddr) {
    return true
  }

  return false
}

func isLocalConnection(localIP, remoteIP string) bool {
    return isLocalIP(localIP) && isLocalIP(remoteIP)
}

func isDockerIP(ip string) bool {
  ipAddr := net.ParseIP(ip)
  if ipAddr == nil {
    return false
  }

  // Docker подсети
  _, dockerNet1, _ := net.ParseCIDR("172.17.0.0/16")
  _, dockerNet2, _ := net.ParseCIDR("172.18.0.0/16")
  _, dockerNet3, _ := net.ParseCIDR("172.19.0.0/16")

  if dockerNet1.Contains(ipAddr) || dockerNet2.Contains(ipAddr) || dockerNet3.Contains(ipAddr) {
    return true
  }

  return false
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

func parseAddress(address string) (string, string) {
  address = strings.TrimSpace(address)
  lastColonIndex := strings.LastIndex(address, ":")
  if lastColonIndex == -1 {
    return address, ""
  }

  ip := address[:lastColonIndex]
  port := address[lastColonIndex+1:]

  ip = strings.Trim(ip, "[]")
  return ip, port
}

func isDynamicPort(port string) bool {
  portNum, err := strconv.Atoi(port)
  if err != nil {
    log.Printf("Invalid port number: %s", port)
    return false
  }

  return portNum >= 49152 && portNum <= 65535
}

func determineDirection(localIP, remoteIP string) string {
    hostIP := getLocalIP()
  
    if localIP == hostIP {
      return "outgoing"
    }
  
    if remoteIP == hostIP {
      return "incoming"
    }
  
    return "incoming"
  }
  
  func getEstablishedConnections() ([]Connection, error) {
      var cmd *exec.Cmd
      switch runtime.GOOS {
      case "darwin":
          cmd = exec.Command("netstat", "-an")
      case "windows":
          cmd = exec.Command("netstat", "-ano")
      default:
          cmd = exec.Command("netstat", "-tunap")
      }
  
      output, err := cmd.Output()
      if err != nil {
          log.Println("Netstat execution error:", err)
          return nil, err
      }
      log.Printf("Netstat output:\n%s", string(output))
  
      lines := strings.Split(string(output), "\n")
      var connections []Connection
  
      for _, line := range lines {
          log.Printf("Processing line: %s", line)
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
  
          localAddr := fields[3]
          remoteAddr := fields[4]
  
          localIP, localPort := parseAddress(localAddr)
          remoteIP, remotePort := parseAddress(remoteAddr)
  
          log.Printf("Parsed connection: LocalIP=%s, LocalPort=%s, RemoteIP=%s, RemotePort=%s", localIP, localPort, remoteIP, remotePort) // Логируем распарсенные данные
  
          if localIP == "" || localPort == "" || remoteIP == "" || remotePort == "" {
              log.Printf("Skipping connection due to empty fields")
              continue
          }
  
          // Пропускаем только локальные соединения (например, 127.0.0.1 -> 127.0.0.1)
          if isLocalConnection(localIP, remoteIP) {
              log.Printf("Skipping local connection: %s:%s -> %s:%s", localIP, localPort, remoteIP, remotePort)
              continue
          }
  
          // Проверяем, являются ли порты динамическими (диапазон 49152-65535)
          if isDynamicPort(localPort) || isDynamicPort(remotePort) {
              log.Printf("Skipping connection due to dynamic port")
              continue
          }
  
          // Определяем направление соединения
          direction := determineDirection(localIP, remoteIP)
  
          // Создаем объект Connection
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
  
          // Если доступен PID, получаем имя процесса
          if len(fields) > stateIndex+1 {
              conn.Process = getProcessName(fields[stateIndex+1])
          }
  
          log.Printf("Connection: %+v", conn) 
          connections = append(connections, conn)
      }
  
      log.Printf("Found %d ESTABLISHED connections (excluding dynamic ports and local connections)\n", len(connections))
      return connections, nil
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
      log.Println("Ошибка сериализации JSON:", err)
      return
    }
  
    log.Printf("Sending report: %s", string(jsonData)) 
  
    client := &http.Client{Timeout: time.Duration(config.HTTPTimeout) * time.Second}
  
    serverURL := config.ServerURL
    if !strings.HasPrefix(serverURL, "http://") && !strings.HasPrefix(serverURL, "https://") {
      serverURL = "http://" + serverURL
    }
  
    if serverURL == "" {
      log.Println("Server URL is empty")
      return
    }
  
    req, err := http.NewRequest("POST", serverURL, bytes.NewBuffer(jsonData))
    if err != nil {
      log.Println("Error creating request:", err)
      return
    }
  
    req.Header.Set("X-API-KEY", config.APIKey)
    req.Header.Set("Content-Type", "application/json")
  
    resp, err := client.Do(req)
    if err != nil {
      log.Println("Error sending data:", err)
      return
    }
    defer resp.Body.Close()
  
    log.Printf("Data sent (%d connections), status: %s", len(connections), resp.Status)
  }
  
  func main() {
    var configFile string
    flag.StringVar(&configFile, "config.file", "config.json", "Configuration file")
    flag.StringVar(&config.ServerURL, "server", "", "Server URL")
    flag.StringVar(&config.LogFile, "log.file", "", "The logs file")
    flag.IntVar(&config.Interval, "interval", 10, "Collection interval (seconds)")
    flag.IntVar(&config.HTTPTimeout, "timeout", 5, "HTTP timeout (seconds)")
  
    logMaxSize := flag.Int("log.max-size", 1, "log max size")
    logMaxBackups := flag.Int("log.max-backups", 3, "log max backups")
    logMaxAge := flag.Int("log.max-age", 10, "log max age")
    logCompress := flag.Bool("log.compress", true, "log compress")
    version := flag.Bool("version", false, "show cdagent version")
  
    flag.Parse()
  
    if *version {
      fmt.Printf("%v\n", Version)
      return
    }
  
    if config.LogFile != "" {
      log.SetOutput(&lumberjack.Logger{
        Filename:   config.LogFile,
        MaxSize:    *logMaxSize,    
        MaxBackups: *logMaxBackups, 
        MaxAge:     *logMaxAge,     
        Compress:   *logCompress,  
      })
    }
  
    loadConfig(configFile)
    log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
  
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