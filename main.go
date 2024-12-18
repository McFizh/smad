package main

import (
	"smad/ldap"
	"smad/models"

	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/google/uuid"
)

func main() {
	appConfig := readConfig()

	port := fmt.Sprintf(":%d", appConfig.Configuration.Port)

	var err error
	var listener net.Listener

	if appConfig.Configuration.UseSSL {
		var cert tls.Certificate
		cert, err = tls.LoadX509KeyPair(appConfig.Configuration.CrtFile, appConfig.Configuration.KeyFile)
		if err != nil {
			log.Fatal(err)
		}

		config := &tls.Config{Certificates: []tls.Certificate{cert}}
		listener, err = tls.Listen("tcp", port, config)
	} else {
		listener, err = net.Listen("tcp", port)
	}

	if err != nil {
		log.Printf("Failed to listen to port %d..\n", appConfig.Configuration.Port)
		log.Fatalln(err)
	}
	defer listener.Close()

	connType := "connections"
	if appConfig.Configuration.UseSSL {
		connType = "SSL-connections"
	}
	log.Printf("Listening for %s on port %d\n", connType, appConfig.Configuration.Port)
	log.Printf("Database contains %d user(s) and %d group(s)\n", len(appConfig.Users), len(appConfig.Groups))

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Failed to accept connection", err)
			continue
		}

		go handleConnection(conn, appConfig)
	}
}

func handleConnection(conn net.Conn, appConfig models.AppConfig) {
	request := make([]byte, 1024)
	bindSuccessful := false
	connectId, _ := uuid.NewRandom()

	log.Printf("CID: %s, new connection, waiting for data.\n", connectId)
	for {
		_, err := conn.Read(request)

		if err != nil {
			if err != io.EOF {
				log.Println("Failed to read request", err)
			}
			conn.Close()
			return
		}

		p := ber.DecodePacket(request)

		if len(p.Children) == 2 {
			msgNum := uint8(p.Children[0].ByteValue[0])

			log.Printf("CID: %s, message number %d, tag id: %d\n", connectId, msgNum, p.Children[1].Tag)

			if p.Children[1].ClassType == ber.ClassApplication && p.Children[1].Tag == 0 {
				// Bind request OP
				bindSuccessful = ldap.HandleBindRequest(conn, p.Children[1], msgNum, appConfig.Users)
			} else if p.Children[1].ClassType == ber.ClassApplication && p.Children[1].Tag == 2 {
				// Unbind request OP
				conn.Close()
				break
			} else if p.Children[1].ClassType == ber.ClassApplication && p.Children[1].Tag == 3 {
				// Search request OP
				ldap.HandleSearchRequest(conn, p.Children[1], msgNum, bindSuccessful, appConfig)
			} else {
				ber.PrintPacket(p.Children[1])
			}
		} else {
			log.Println("Unknown packet")
		}
	}

	log.Printf("CID: %s, connection closed.\n", connectId)
}
