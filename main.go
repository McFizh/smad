package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"slices"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
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

func handleConnection(conn net.Conn, appConfig AppConfig) {
	request := make([]byte, 1024)
	bindSuccessful := false

	log.Println("New connection, waiting for data...")
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

			log.Printf("Message number %d, tag id: %d\n", msgNum, p.Children[1].Tag)

			if p.Children[1].ClassType == ber.ClassApplication && p.Children[1].Tag == 0 {
				// Bind request OP
				bindSuccessful = handleBindRequest(conn, p.Children[1], msgNum, appConfig.Users)
			} else if p.Children[1].ClassType == ber.ClassApplication && p.Children[1].Tag == 2 {
				// Unbind request OP
				conn.Close()
				return
			} else if p.Children[1].ClassType == ber.ClassApplication && p.Children[1].Tag == 3 {
				// Search request OP
				handleSearchRequest(conn, p.Children[1], msgNum, bindSuccessful)
			} else {
				ber.PrintPacket(p.Children[1])
			}
		} else {
			log.Println("Unknown packet")
		}
	}
}

func createResponsePacket(msgNum uint8) *ber.Packet {
	rsp := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	msgNumPacket := ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, msgNum, "")
	rsp.AppendChild(msgNumPacket)
	return rsp
}

func handleSearchRequest(conn net.Conn, p *ber.Packet, msgNum uint8, bindSuccessful bool) {
	if len(p.Children) < 6 {
		log.Println("Unsupported search package")
		return
	}

	rsp := createResponsePacket(msgNum)
	statusCode := 0
	errorMessage := ""

	if !bindSuccessful {
		statusCode = 1
		errorMessage = "000004DC: LdapErr: DSID-0C090CF4, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4563"
	}

	// Create end of search result packet
	searchRspPacket := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 0x05, nil, "")
	codePacket := ber.NewInteger(ber.ClassApplication, ber.TypePrimitive, ber.TagEnumerated, statusCode, "")
	searchRspPacket.AppendChild(codePacket)
	dnPacket := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "")
	searchRspPacket.AppendChild(dnPacket)
	msgPacket := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, errorMessage, "")
	searchRspPacket.AppendChild(msgPacket)

	// Finally transmit the response to client
	rsp.AppendChild(searchRspPacket)
	conn.Write(rsp.Bytes())
}

func handleBindRequest(conn net.Conn, p *ber.Packet, msgNum uint8, users []User) bool {
	if len(p.Children) != 3 {
		log.Println("Unsupported bind package")
		return false
	}

	version := uint8(p.Children[0].ByteValue[0])
	if version != 3 {
		log.Printf("Unknown version %d\n", version)
		return false
	}

	userOk := false

	// Real AD does not trim value, but search is case insensitive so convert given value to lowercase
	user := fmt.Sprintf("%v", p.Children[1].Value)
	user = strings.ToLower(user)
	password := fmt.Sprintf("%v", p.Children[2].Data)

	// See if we can find the user
	userRecordIdx := slices.IndexFunc(users, func(c User) bool { return strings.ToLower(c.Upn) == user })

	statusCode := 0
	msg := ""

	if len(password) == 0 {
		// AD returns bind successful message, but with error message in the actual search result
		// even if user is not found
	} else if userRecordIdx < 0 || users[userRecordIdx].Password != password {
		// Password not empty, and either user not found or password is wrong
		statusCode = 49
		msg = "80090308: LdapErr: DSID-0C090569, comment: AcceptSecurityContext error, data 52e, v4563"
	} else {
		// User found and password matches
		userOk = true
	}

	// Create bind response packet
	rsp := createResponsePacket(msgNum)

	bindRspPacket := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 0x01, nil, "")

	codePacket := ber.NewInteger(ber.ClassApplication, ber.TypePrimitive, ber.TagEnumerated, statusCode, "")
	bindRspPacket.AppendChild(codePacket)
	dnPacket := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "")
	bindRspPacket.AppendChild(dnPacket)
	msgPacket := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, msg, "")
	bindRspPacket.AppendChild(msgPacket)

	rsp.AppendChild(bindRspPacket)

	// Finally transmit the response to client
	conn.Write(rsp.Bytes())

	return userOk
}
