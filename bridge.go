package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/tarm/serial"
	"gopkg.in/yaml.v2"
)

const (
	ServerType = "tcp"
	// Initial state. Input is ignored until start byte is detected.
	STATE_IGNORING int = 0
	// Start byte (hex "DB") has been detected.
	STATE_STARTED = 1
	// Length of system title has been read.
	STATE_HAS_SYSTEM_TITLE_LENGTH = 2
	// System title has been read.
	STATE_HAS_SYSTEM_TITLE = 3
	// Additional byte after the system title has been read.
	STATE_HAS_SYSTEM_TITLE_SUFFIX = 4
	// Length of remaining data has been read.
	STATE_HAS_DATA_LENGTH = 5
	// Additional byte after the remaining data length has been read.
	STATE_HAS_SEPARATOR = 6
	// Frame counter has been read.
	STATE_HAS_FRAME_COUNTER = 7
	// Payload has been read.
	STATE_HAS_PAYLOAD = 8
	// GCM tag has been read.
	STATE_HAS_GCM_TAG = 9
	// All input has been read. After this, we switch back to STATE_IGNORING and wait for a new start byte.
	STATE_DONE = 10
	// GCM TAG LENGTH in bytes (96 bits)
	GCM_TAG_LENGTH = 12
)

var defaultPaths = []string{"/etc/smartmeter-bridge/config.yml", "config.yml"}

type ServerConfig struct {
	Host string `yaml:"host"`
	Port int64  `yaml:"port"`
}

func (c ServerConfig) validate() {
	if c.Port < 0 {
		log.Fatal("Server port number must be positive or 0 for automatic port selection")
	}
}

type WebConfig struct {
	Enabled bool   `yaml:"enabled"`
	Host    string `yaml:"host"`
	Port    int    `yaml:"port"`
}

type Config struct {
	SerialPort  string       `yaml:"serial_port"`
	DSMRVersion string       `yaml:"dsmr_version"`
	Server      ServerConfig `yaml:"server"`
	Web         WebConfig    `yaml:"web"`
	Verbose     bool         `yaml:"verbose"`
	AESKey      string       `yaml:"aes_key"`
	AAD         string       `yaml:"aad"`
}

var config = Config{
	DSMRVersion: "4",
	Server: ServerConfig{
		Host: "",
		Port: 9988,
	},
	Web: WebConfig{
		Enabled: true,
		Host:    "",
		Port:    8080,
	},
	Verbose: false,
}

func (c Config) validate() {
	if c.SerialPort == "" {
		log.Fatal("Serial port is not configured")
	}
	c.Server.validate()
	if c.DSMRVersion == "5L" && (c.AESKey == "" || c.AAD == "") {
		log.Fatal("For DSMR 5L, aes_key and aad must be set")
	}
}

func getSerialConfig(port, dsmrVersion string) serial.Config {
	confs := map[string]serial.Config{
		"2": {
			Baud:     9600,
			Size:     7,
			Parity:   serial.ParityEven,
			StopBits: 1,
		},
		"4": {
			Baud:     115200,
			Size:     8,
			Parity:   serial.ParityNone,
			StopBits: 0,
		},
	}

	confs["2.2"] = confs["2"]
	confs["3"] = confs["2"]
	conf5 := confs["4"]
	conf5.StopBits = 1
	confs["5"] = conf5
	confs["5B"] = confs["5"]
	confs["5L"] = confs["5"]
	confs["5S"] = confs["5"]
	confs["Q3D"] = confs["3"]

	conf, ok := confs[dsmrVersion]
	if !ok {
		log.Fatal("Unknown dsmr_version. Use 2, 2.2, 3, 4, 5, 5B, 5L, 5S or Q3D")
	}
	conf.Name = port

	return conf
}

func main() {
	configPath := flag.String("config", "", "Path to YAML configuration file")
	flag.Parse()

	// Environment variable overrides
	if envPort := os.Getenv("SMB_SERIAL_PORT"); envPort != "" {
		config.SerialPort = envPort
	}
	if envHost := os.Getenv("SMB_SERVER_HOST"); envHost != "" {
		config.Server.Host = envHost
	}
	if envServerPort := os.Getenv("SMB_SERVER_PORT"); envServerPort != "" {
		config.Server.Port, _ = strconv.ParseInt(envServerPort, 10, 64)
	}

	if *configPath != "" {
		b, err := os.ReadFile(*configPath)
		if err != nil {
			log.Fatalf("Failed to read specified config file %s: %v", *configPath, err)
		}
		if err := yaml.Unmarshal(b, &config); err != nil {
			log.Fatalf("Failed to parse config file %s: %v", *configPath, err)
		}
	} else {
		loaded := false
		for _, path := range defaultPaths {
			b, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			if err := yaml.Unmarshal(b, &config); err != nil {
				log.Fatalf("Failed to parse config file %s: %v", path, err)
			}
			loaded = true
			log.Printf("Loaded config from %s\n", path)
			break
		}
		if !loaded {
			log.Println("No config file found in default locations (/etc/smartmeter-bridge/config.yml, config.yml), using defaults and env")
		}
	}

	config.validate()

	if config.Web.Port == 0 {
		config.Web.Port = 8080
	}

	var webServer *WebServer
	if config.Web.Enabled {
		webServer = NewWebServer()
		webServer.Start(config.Web.Host, config.Web.Port)
	}

	rawTelegrams := make(chan string, 10)
	go ReadRawTelegrams(getSerialConfig(config.SerialPort, config.DSMRVersion), rawTelegrams)

	newConnections := make(chan net.Conn)
	go startServer(newConnections)
	sendTelegrams(newConnections, rawTelegrams, webServer)
}

func startServer(clients chan net.Conn) {
	listenAddr := fmt.Sprintf("%s:%d", config.Server.Host, config.Server.Port)
	log.Printf("Starting TCP server on %s...\n", listenAddr)
	server, err := net.Listen(ServerType, listenAddr)
	if err != nil {
		log.Fatalf("Could not start TCP server on %s: %v", listenAddr, err)
	}
	defer server.Close()

	log.Printf("Listening for TCP clients on %s\n", server.Addr().String())
	for {
		c, err := server.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v\n", err)
			continue
		}
		clients <- c
		log.Printf("%s connected to TCP bridge\n", c.RemoteAddr())
	}
}

func sendTelegrams(connections chan net.Conn, telegrams chan string, webServer *WebServer) {
	var clients []net.Conn
	var mu sync.Mutex

	go func() {
		for connection := range connections {
			mu.Lock()
			clients = append(clients, connection)
			mu.Unlock()
		}
	}()

	for telegram := range telegrams {
		if webServer != nil {
			webServer.Broadcast(telegram)
		}

		if config.Verbose {
			log.Print(telegram)
		}

		mu.Lock()
		var activeClients []net.Conn
		for _, c := range clients {
			_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
			_, err := c.Write([]byte(telegram))
			if err != nil {
				_ = c.Close()
				log.Printf("%s disconnected\n", c.RemoteAddr())
			} else {
				activeClients = append(activeClients, c)
			}
		}
		clients = activeClients
		mu.Unlock()
	}
}

func ReadRawTelegrams(serialConfig serial.Config, rawTelegrams chan string) {
	lineChan := make(chan string, 10)
	if config.DSMRVersion == "5L" {
		go readBuffer(serialConfig, lineChan)
		go collectEncryptedTelegrams(lineChan, rawTelegrams)
	} else {
		go readLines(serialConfig, lineChan)
		go collectTelegrams(lineChan, rawTelegrams)
	}
}

func readBuffer(serialConfig serial.Config, rChan chan string) {
	log.Printf("Opening serial port %s (DSMR 5L: 115200 8N1)...\n", serialConfig.Name)
	s, err := serial.OpenPort(&serialConfig)
	if err != nil {
		log.Fatalf("Failed to open serial port %s: %v", serialConfig.Name, err)
	}
	defer s.Close()

	buf := make([]byte, 1024)
	reader := bufio.NewReader(s)
	for {
		n, err := reader.Read(buf)
		if err != nil {
			if config.Verbose {
				log.Printf("Serial read error: %v\n", err)
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}

		if n > 0 {
			rChan <- string(buf[:n])
		}
	}
}

func collectEncryptedTelegrams(rChan chan string, tChan chan string) {
	var systemTitleLength int
	var systemTitle []byte
	var dataLengthBytes []byte
	var dataLength int
	var frameCounter []byte
	var frame []byte
	var data []byte
	var state int = STATE_IGNORING
	var iv []byte

	for line := range rChan {
		for _, hexInput := range []byte(line) {
			// keep the original frame for debugging
			if state != STATE_IGNORING {
				frame = append(frame, hexInput)
			}
			switch state {
			case STATE_IGNORING:
				if hexInput == 0xDB {
					state = STATE_STARTED
					systemTitleLength = 0
					systemTitle = []byte("")
					dataLengthBytes = []byte("")
					frameCounter = []byte("")
					frame = []byte("")
					data = []byte("")
					frame = append(frame, hexInput)
				} else {
					if config.Verbose {
						log.Printf("DEBUG: expected 0xDB start byte, got 0x%02X\n", hexInput)
					}
				}
			case STATE_STARTED:
				systemTitleLength = int(hexInput)
				state = STATE_HAS_SYSTEM_TITLE_LENGTH
				systemTitle = make([]byte, 0, systemTitleLength)
			case STATE_HAS_SYSTEM_TITLE_LENGTH:
				systemTitle = append(systemTitle, hexInput)
				if len(systemTitle) == systemTitleLength {
					state = STATE_HAS_SYSTEM_TITLE
				}
			case STATE_HAS_SYSTEM_TITLE:
				if hexInput == 0x82 {
					state = STATE_HAS_SYSTEM_TITLE_SUFFIX
				} else {
					log.Println("ERROR: expected 0x82 separator byte not found, dropping frame")
					state = STATE_IGNORING
				}
			case STATE_HAS_SYSTEM_TITLE_SUFFIX:
				dataLengthBytes = append(dataLengthBytes, hexInput)
				if len(dataLengthBytes) == 2 {
					dataLength = int(binary.BigEndian.Uint16(dataLengthBytes)) - 17 + GCM_TAG_LENGTH
					state = STATE_HAS_DATA_LENGTH
					data = make([]byte, 0, dataLength)
				}
			case STATE_HAS_DATA_LENGTH:
				if hexInput == 0x30 {
					state = STATE_HAS_SEPARATOR
				} else {
					log.Println("ERROR: expected 0x30 separator byte not found, dropping frame")
					state = STATE_IGNORING
				}
			case STATE_HAS_SEPARATOR:
				frameCounter = append(frameCounter, hexInput)
				if len(frameCounter) == 4 {
					state = STATE_HAS_FRAME_COUNTER
				}
			case STATE_HAS_FRAME_COUNTER:
				data = append(data, hexInput)
				if len(data) == dataLength {
					state = STATE_DONE
				}
			} // end switch

			if state == STATE_DONE {
				// Decrypt data
				AESKey, err := hex.DecodeString(config.AESKey)
				if err != nil {
					log.Printf("Invalid AES key: %v\n", err)
					state = STATE_IGNORING
					continue
				}
				AAD, err := hex.DecodeString(config.AAD)
				if err != nil {
					log.Printf("Invalid AAD: %v\n", err)
					state = STATE_IGNORING
					continue
				}
				iv = append(systemTitle, frameCounter...)
				block, err := aes.NewCipher(AESKey)
				if err != nil {
					log.Printf("AES cipher creation error: %v\n", err)
					state = STATE_IGNORING
					continue
				}
				gcm, err := cipher.NewGCMWithTagSize(block, 12)
				if err != nil {
					log.Printf("GCM error: %v\n", err)
					state = STATE_IGNORING
					continue
				}
				plaintext, err := gcm.Open(nil, iv, data, AAD)
				if err != nil {
					log.Printf("Decryption failed: %v\n", err)
					state = STATE_IGNORING
					continue
				}

				if config.Verbose {
					log.Printf("Decrypted telegram (%d bytes):\n%s\n", len(plaintext), string(plaintext))
				}
				tChan <- string(plaintext)
				state = STATE_IGNORING
			}
		}
	}
}

func readLines(serialConfig serial.Config, rChan chan string) {
	s, err := serial.OpenPort(&serialConfig)
	if err != nil {
		log.Fatal(err)
	}
	defer s.Close()

	reader := bufio.NewReader(s)
	for {
		reply, err := reader.ReadString('\n')
		if err != nil && config.Verbose {
			log.Println(err)
		}

		if len(reply) > 0 {
			rChan <- reply
		}
	}
}

func collectTelegrams(rChan chan string, tChan chan string) {
	telegram := ""
	foundStart := false

	for line := range rChan {
		if len(line) > 0 && line[0] == '/' {
			foundStart = true
			telegram = ""
		}

		if !foundStart {
			continue
		}

		telegram += line

		if len(line) > 0 && line[0] == '!' {
			tChan <- telegram
		}
	}
}
