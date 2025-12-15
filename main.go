package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
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
