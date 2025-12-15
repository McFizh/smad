package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"smad/ldap"
	"smad/models"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/google/uuid"
)

func logEvent(connectId uuid.UUID, msgNum uint8, tag ber.Tag) {
	prefix := fmt.Sprintf("CID: %s, message number %d, ", connectId, msgNum)

	switch tag {
		case 0:
			log.Printf("%s bind request OP", prefix)
		case 2:
			log.Printf("%s unbind request OP", prefix)
		case 3:
			log.Printf("%s search request OP", prefix)
		case 10:
			log.Printf("%s delete request OP", prefix)
		default:
			log.Printf("%s unsupported OP (tag id: %d)", prefix, tag)
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

		// Packet should have 2 children (message number, and operation)
		if len(p.Children) == 2 {
			msgNum := uint8(p.Children[0].ByteValue[0])

			logEvent(connectId, msgNum, p.Children[1].Tag)

			isCommand := p.Children[1].ClassType == ber.ClassApplication

			if isCommand && p.Children[1].Tag == 0 {
				// Bind request OP
				bindSuccessful = ldap.HandleBindRequest(conn, p.Children[1], msgNum, appConfig.Users)
			} else if isCommand && p.Children[1].Tag == 2 {
				// Unbind request OP
				conn.Close()
				break
			} else if isCommand && p.Children[1].Tag == 3 {
				// Search request OP
				ldap.HandleSearchRequest(conn, p.Children[1], msgNum, bindSuccessful, appConfig)
			} else if isCommand && p.Children[1].Tag == 10 {
				// Delete request OP
				ldap.HandleDeleteRequest(conn, p.Children[1], msgNum, bindSuccessful, appConfig)
			} else {
				ber.PrintPacket(p.Children[1])
			}
		} else {
			log.Println("Unknown packet")
		}
	}

	log.Printf("CID: %s, connection closed.\n", connectId)
}
