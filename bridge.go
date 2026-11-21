package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"

	"github.com/jacobsa/go-serial/serial"
	"gopkg.in/yaml.v2"
)

type Config struct {
	SerialPort  string `yaml:"serial_port"`
	DsmrVersion string `yaml:"dsmr_version"`
	AesKey      string `yaml:"aes_key"`
	Aad         string `yaml:"aad"`
	Server      struct {
		Host string `yaml:"host"`
		Port int    `yaml:"port"`
	} `yaml:"server"`
	Web struct {
		Enabled bool   `yaml:"enabled"`
		Host    string `yaml:"host"`
		Port    int    `yaml:"port"`
	} `yaml:"web"`
}

func (c *Config) readConfig(path string) {
	yamlFile, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatalf("Error reading config file %s: %v", path, err)
	}
	err = yaml.Unmarshal(yamlFile, c)
	if err != nil {
		log.Fatalf("Unmarshal error in %s: %v", path, err)
	}
}

func openSerialPort(port string, dsmrVersion string) (io.ReadWriteCloser, error) {
	var baudRate uint = 115200
	var dataBits uint = 8
	var stopBits uint = 1
	var parityMode serial.ParityMode = serial.PARITY_NONE

	if dsmrVersion == "22" {
		baudRate = 9600
		dataBits = 7
		parityMode = serial.PARITY_EVEN
	} else if dsmrVersion == "4" {
		dataBits = 7
		parityMode = serial.PARITY_EVEN
	}

	options := serial.OpenOptions{
		PortName:        port,
		BaudRate:        baudRate,
		DataBits:        dataBits,
		StopBits:        stopBits,
		MinimumReadSize: 4,
		ParityMode:      parityMode,
	}

	serialPort, err := serial.Open(options)
	if err != nil {
		return nil, err
	}

	return serialPort, nil
}

func startServer(host string, port int) (net.Listener, error) {
	server, err := net.Listen("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return nil, err
	}
	return server, nil
}

func readBuffer(serialPort io.ReadWriteCloser) {
	buf := make([]byte, 1024)
	for {
		n, err := serialPort.Read(buf)
		if err != nil {
			log.Printf("Error reading buffer: %v", err)
			break
		}
		if n == 0 {
			break
		}
	}
}

func collectEncryptedTelegrams(serialPort io.ReadWriteCloser, telegrams chan string, aesKeyHex string, aadHex string) {
	reader := bufio.NewReader(serialPort)

	for {
		for {
			b, err := reader.ReadByte()
			if err != nil {
				log.Printf("Error finding start byte: %v", err)
				continue
			}
			if b == 0xDB {
				break
			}
		}

		systemTitleLength, err := reader.ReadByte()
		if err != nil {
			log.Printf("Error reading system title length: %v", err)
			continue
		}

		systemTitle := make([]byte, systemTitleLength)
		_, err = io.ReadFull(reader, systemTitle)
		if err != nil {
			log.Printf("Error reading system title: %v", err)
			continue
		}

		separator, err := reader.ReadByte()
		if err != nil || separator != 0x82 {
			log.Printf("Error or invalid byte after system title: %v", err)
			continue
		}

		lengthBytes := make([]byte, 2)
		_, err = io.ReadFull(reader, lengthBytes)
		if err != nil {
			log.Printf("Error reading length bytes: %v", err)
			continue
		}
		dataLength := int(lengthBytes[0])<<8 | int(lengthBytes[1])
		dataLength -= 17

		separator, err = reader.ReadByte()
		if err != nil || separator != 0x30 {
			log.Printf("Error or invalid byte after data length: %v", err)
			continue
		}

		frameCounter := make([]byte, 4)
		_, err = io.ReadFull(reader, frameCounter)
		if err != nil {
			log.Printf("Error reading frame counter: %v", err)
			continue
		}

		payload := make([]byte, dataLength)
		_, err = io.ReadFull(reader, payload)
		if err != nil {
			log.Printf("Error reading payload: %v", err)
			continue
		}

		tag := make([]byte, 12)
		_, err = io.ReadFull(reader, tag)
		if err != nil {
			log.Printf("Error reading GCM tag: %v", err)
			continue
		}

		ciphertext := append(payload, tag...)

		iv := append(systemTitle, frameCounter...)

		aesKey, err := hex.DecodeString(aesKeyHex)
		if err != nil {
			log.Fatalf("Invalid AES key: %v", err)
		}

		aad, err := hex.DecodeString(aadHex)
		if err != nil {
			log.Fatalf("Invalid AAD: %v", err)
		}

		block, err := aes.NewCipher(aesKey)
		if err != nil {
			log.Fatalf("Error creating cipher: %v", err)
		}

		aesGCM, err := cipher.NewGCMWithTagSize(block, 12)
		if err != nil {
			log.Fatalf("Error creating GCM: %v", err)
		}

		plaintext, err := aesGCM.Open(nil, iv, ciphertext, aad)
		if err != nil {
			log.Printf("Decryption failed: %v", err)
			continue
		}

		telegrams <- string(plaintext)
	}
}

func collectTelegrams(serialPort io.ReadWriteCloser, telegrams chan string) {
	scanner := bufio.NewScanner(serialPort)
	telegram := ""
	for scanner.Scan() {
		line := scanner.Text()
		telegram += line + "\n"
		if line[0] == '!' {
			telegrams <- telegram
			telegram = ""
		}
	}
	if err := scanner.Err(); err != nil {
		log.Printf("Failed to read from serial port: %v", err)
	}
}

func handleServerConnections(server net.Listener, telegrams chan string, webServer *WebServer) {
	var clients []net.Conn

	go func() {
		for {
			telegram := <-telegrams

			if webServer != nil {
				webServer.Broadcast(telegram)
			}

			if server != nil {
				for i, client := range clients {
					_, err := client.Write([]byte(telegram))
					if err != nil {
						client.Close()
						clients = append(clients[:i], clients[i+1:]...)
					}
				}
			}
		}
	}()

	if server != nil {
		for {
			conn, err := server.Accept()
			if err != nil {
				log.Printf("Failed to accept connection: %v", err)
				continue
			}
			clients = append(clients, conn)
		}
	} else {
		// Keep the main goroutine alive if no TCP server was configured
		select {}
	}
}

func main() {
	configPath := flag.String("config", "config.yml", "Path to YAML configuration file")
	flag.Parse()

	// Also support positional argument, e.g.: ./smartmeterBridge /path/to/config.yml
	if flag.NArg() > 0 {
		*configPath = flag.Arg(0)
	}

	if _, err := os.Stat(*configPath); os.IsNotExist(err) {
		log.Fatalf("Config file not found: %s", *configPath)
	}

	var c Config
	c.readConfig(*configPath)

	var webServer *WebServer
	if c.Web.Enabled {
		if c.Web.Port == 0 {
			c.Web.Port = 8080
		}
		webServer = NewWebServer()
		webServer.Start(c.Web.Host, c.Web.Port)
	}

	var tcpServer net.Listener
	if c.Server.Port != 0 {
		var err error
		tcpServer, err = startServer(c.Server.Host, c.Server.Port)
		if err != nil {
			log.Fatalf("Failed to start TCP server on %s:%d: %v", c.Server.Host, c.Server.Port, err)
		}
		log.Printf("Listening for TCP raw telegram clients on %s:%d", c.Server.Host, c.Server.Port)
		defer tcpServer.Close()
	} else {
		log.Println("TCP server disabled (server.port is not set or 0)")
	}

	serialPort, err := openSerialPort(c.SerialPort, c.DsmrVersion)
	if err != nil {
		log.Fatalf("Failed to open serial port: %v", err)
	}
	defer serialPort.Close()

	if c.DsmrVersion == "5L" {
		readBuffer(serialPort)
	}

	telegrams := make(chan string)
	if c.DsmrVersion == "5L" {
		go collectEncryptedTelegrams(serialPort, telegrams, c.AesKey, c.Aad)
	} else {
		go collectTelegrams(serialPort, telegrams)
	}

	handleServerConnections(tcpServer, telegrams, webServer)
}
