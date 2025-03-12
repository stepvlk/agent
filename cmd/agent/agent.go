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
        // Выводим каждый проверяемый адрес в лог
        log.Printf("Checking address: %s", addr.String())

        // Проверяем, что это IPv4-адрес и не loopback
        if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
            // Пропускаем интерфейсы, связанные с Docker, WSL, Citrix и т.д.
            if isExcludedInterface(addr.String(), ipNet.IP.String()) {
                log.Printf("Excluded interface: %s", addr.String())
                continue
            }

            // Возвращаем первый найденный реальный IP-адрес
            log.Printf("Real local IP found: %s", ipNet.IP.String())
            return ipNet.IP.String()
        }
    }

    // Если не найдено, возвращаем стандартный loopback адрес
    log.Println("No valid local IP found, returning 127.0.0.1")
    return "127.0.0.1"
}

// Проверка, является ли интерфейс исключением (например, Docker, WSL, Citrix, IPv6 и т.д.)
func isExcludedInterface(interfaceInfo, ip string) bool {
    // Исключаем интерфейсы по именам и IP-диапазонам
    excludedInterfaces := []string{
        "docker", // Docker
        "veth",   // Виртуальные интерфейсы Docker
        "br-",    // Бриджи Docker
        "wsl",    // WSL интерфейсы
        "tun",    // TUN/TAP интерфейсы (часто используется в VPN и WSL)
        "citrix", // Citrix интерфейсы
        "vmnet",  // Виртуальные интерфейсы VMware
    }

    // Проверяем, содержит ли строка какую-либо из исключенных подсетей
    for _, exclusion := range excludedInterfaces {
        if strings.Contains(interfaceInfo, exclusion) {
            return true
        }
    }

    // Проверяем, если IP в диапазоне Docker или других виртуальных подсетей
    if isDockerRange(ip) {
        return true
    }

    // Исключаем WSL интерфейсы по диапазону IP-адресов (например, 192.168.80.0/20)
    if isWSLRange(ip) {
        return true
    }

    // Исключаем IPv6 link-local адреса (например, fe80::)
    if strings.HasPrefix(ip, "fe80::") {
        return true
    }

    return false
}

// Проверка, находится ли IP-адрес в диапазоне WSL (например, 192.168.80.0/20)
func isWSLRange(ip string) bool {
    // Диапазон IP-адресов WSL
    ipAddr := net.ParseIP(ip)
    if ipAddr == nil {
        log.Printf("Invalid IP address: %s", ip)
        return false
    }

    // Диапазоны IP-адресов WSL (например, 192.168.80.0/20)
    wslRanges := []string{
        "192.168.80.0/20", // Диапазон для WSL
    }

    for _, cidr := range wslRanges {
        _, network, err := net.ParseCIDR(cidr)
        if err != nil {
            log.Printf("Invalid CIDR block: %s", cidr)
            continue
        }

        if network.Contains(ipAddr) {
            return true
        }
    }

    return false
}

// Проверка, находится ли IP-адрес в диапазоне Docker
func isDockerRange(ip string) bool {
    // Проверяем диапазоны IP-адресов Docker (например, 172.17.0.0/16, 172.23.0.0/16 и т. д.)
    ipAddr := net.ParseIP(ip)
    if ipAddr == nil {
        log.Printf("Invalid IP address: %s", ip)
        return false
    }

    // Диапазоны IP-адресов Docker
    dockerRanges := []string{
        "172.17.0.0/16", // Docker стандартный диапазон
        "172.18.0.0/16", // Дополнительные диапазоны
        "172.19.0.0/16",
        "172.20.0.0/16",
        "172.21.0.0/16",
        "172.22.0.0/16",
        "172.23.0.0/16",
    }

    for _, cidr := range dockerRanges {
        _, network, err := net.ParseCIDR(cidr)
        if err != nil {
            log.Printf("Invalid CIDR block: %s", cidr)
            continue
        }

        if network.Contains(ipAddr) {
            return true
        }
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

func getEstablishedConnections() ([]Connection, error) {
    var cmd *exec.Cmd
    switch os := runtime.GOOS; os {
	case "darwin":
		cmd = exec.Command("netstat")
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

        // Проверяем, являются ли порты динамическими (диапазон 49152-65535)
        if isDynamicPort(localPort) || isDynamicPort(remotePort) {
            continue
        }

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

    log.Printf("Found %d ESTABLISHED connections (excluding dynamic ports)\n", len(connections))
    return connections, nil
}

func isDynamicPort(port string) bool {
    portNum, err := strconv.Atoi(port)
    if err != nil {
        log.Printf("Invalid port number: %s", port)
        return false
    }

    return portNum >= 49152 && portNum <= 65535
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
        log.Println("Ошибка сериализации JSON:", err)
        return
    }

    client := &http.Client{Timeout: time.Duration(config.HTTPTimeout) * time.Second}

    // Убедитесь, что URL содержит схему (http:// или https://)
    serverURL := config.ServerURL
    if !strings.HasPrefix(serverURL, "http://") && !strings.HasPrefix(serverURL, "https://") {
        serverURL = "http://" + serverURL
    }

    // Создаем HTTP запрос
    req, err := http.NewRequest("POST", serverURL, bytes.NewBuffer(jsonData))
    if err != nil {
        log.Println("Error creating request:", err)
        return
    }

    // Указываем заголовок с API-ключом
    req.Header.Set("X-API-KEY", config.APIKey)
    req.Header.Set("Content-Type", "application/json")

    // Отправка запроса
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

	// Show version
    if *version {
        fmt.Printf("%v\n", Version)
        return
    }

	// Logging settings
	if config.LogFile != "" {
		log.SetOutput(&lumberjack.Logger{
			Filename:   config.LogFile,
			MaxSize:    *logMaxSize,    // megabytes after which new file is created
			MaxBackups: *logMaxBackups, // number of backups
			MaxAge:     *logMaxAge,     // days
			Compress:   *logCompress,   // using gzip
		})
	}

    loadConfig(configFile)
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
    //initLogger(config.LogFile)

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
