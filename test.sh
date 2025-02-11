curl -X POST -H "Content-Type: application/json" -d '{
  "hostname": "server1",
  "timestamp": "2025-02-11T12:34:56Z",
  "connections": [
    {
      "id": "unique_id_123",
      "local_ip": "192.168.1.1",
      "local_port": "8080",
      "local_name": "localhost",
      "remote_ip": "192.168.1.2",
      "remote_port": "8081",
      "dst_name": "remotehost",
      "process": "process_name",
      "direction": "incoming",
      "timestamp": 1617625576
    }
  ]
}' http://localhost:8080/api/connections