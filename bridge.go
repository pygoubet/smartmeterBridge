package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"log"
	"net"
	"os"
	"strconv"

	"github.com/go-yaml/yaml"
	"github.com/tarm/serial"
	"encoding/binary"
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

var Paths = []string{"/etc/smartmeter-bridge/config.yml", "config.yml"}

type ServerConfig struct {
	Host string `yaml:"host"`
	Port int64  `yaml:"port"`
}

func (c ServerConfig) validate() {
	if c.Port < 0 {
		log.Fatal("Server port number must be positive or 0 for automatic port selection")
	}
}

type Config struct {
	SerialPort  string       `yaml:"serial_port"`
	DSMRVersion string       `yaml:"dsmr_version"`
	Server      ServerConfig `yaml:"server"`
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
	config.SerialPort = os.Getenv("SMB_SERIAL_PORT")
	config.Server.Host = os.Getenv("SMB_SERVER_HOST")
	config.Server.Port, _ = strconv.ParseInt(os.Getenv("SMB_SERVER_PORT"), 10, 64)
	for _, path := range Paths {
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		err = yaml.Unmarshal(b, &config)
		if err != nil {
			log.Fatal(err)
		}
	}

	config.validate()

	rawTelegrams := make(chan string)

	go ReadRawTelegrams(getSerialConfig(config.SerialPort, config.DSMRVersion), rawTelegrams)

	newConnections := make(chan net.Conn)
	go startServer(newConnections)
	sendTelegrams(newConnections, rawTelegrams)
}

func startServer(clients chan net.Conn) {
	log.Println("Starting server...")
	server, err := net.Listen(ServerType, config.Server.Host+":"+strconv.FormatInt(config.Server.Port, 10))
	if err != nil {
		log.Println("Could not start server:", err.Error())
		os.Exit(1)
	}
	defer func(server net.Listener) {
		_ = server.Close()
	}(server)

	log.Println("Listening on", server.Addr().String())
	for {
		c, err := server.Accept()
		if err != nil {
			log.Println("Error accepting", c.RemoteAddr(), err.Error())
			_ = c.Close()
			continue
		}
		clients <- c
		log.Println(c.RemoteAddr(), "connected")
	}
}

func sendTelegrams(connections chan net.Conn, telegrams chan string) {
	clients := make([]net.Conn, 0)
	for {
		select {
		case connection := <-connections:
			clients = append(clients, connection)
		case telegram := <-telegrams:
			for i, c := range clients {
				_, err := c.Write([]byte(telegram))
				if err != nil {
					_ = c.Close()
					clients = append(clients[:i], clients[i+1:]...)
					log.Println(c.RemoteAddr(), "disconnected")
					continue
				}

				if config.Verbose {
					log.Println(telegram)
				}
			}
		}
	}
}

func ReadRawTelegrams(serialConfig serial.Config, rawTelegrams chan string) {
	lineChan := make(chan string)
	if config.DSMRVersion == "5L" {
		go readBuffer(serialConfig, lineChan)
		go collectEncryptedTelegrams(lineChan, rawTelegrams)
	} else {
		go readLines(serialConfig, lineChan)
		go collectTelegrams(lineChan, rawTelegrams)
	}
}

func readBuffer(serialConfig serial.Config, rChan chan string) {
	s, err := serial.OpenPort(&serialConfig)
	if err != nil {
		log.Fatal(err)
	}

	buf := make([]byte, 1024)
	reader := bufio.NewReader(s)
	for {
		n, err := reader.Read(buf)
		if err != nil && config.Verbose {
			log.Println(err)
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
					log.Println("ERROR, expected 0xDB separator byte not found but:", hexInput)
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
					log.Println("ERROR, expected 0x82 separator byte not found, dropping frame")
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
						log.Println("ERROR, expected 0x30 separator byte not found, dropping frame")
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
				AESKey, _ := hex.DecodeString(config.AESKey)
				AAD, _ := hex.DecodeString(config.AAD)
				iv = append(systemTitle, frameCounter...)
				block, err := aes.NewCipher(AESKey)
				if err != nil {
					log.Fatalf("AES error: %v", err)
				}
				gcm, err := cipher.NewGCMWithTagSize(block, 12)
				if err != nil {
					log.Fatalf("GCM error: %v", err)
				}
				plaintext, err := gcm.Open(nil, iv, data, AAD)
				if err != nil {
					log.Fatalf("Decryption failed: %v", err)
				}
				log.Printf("%s\n", plaintext)
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
		if line[0] == '/' {
			foundStart = true
			telegram = ""
		}

		// We usually start halfway through a telegram.
		// Which means that the first telegram would be corrupt.
		// We therefore ignore everything until the first telegram start.
		if !foundStart {
			continue
		}

		telegram += line

		// The last line of a telegram starts with an exclamation mark.
		if line[0] == '!' {
			tChan <- telegram
		}
	}
}
