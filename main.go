package main

import (
	"fmt"
	"io"
	"net"
	"slices"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func main() {
	appConfig := readConfig()

	port := fmt.Sprintf(":%d", appConfig.Configuration.Port)
	listener, err := net.Listen("tcp", port)

	if err != nil {
		fmt.Printf("Failed to listen to port %d..\n", appConfig.Configuration.Port)
		fmt.Println(err)
		return
	}
	defer listener.Close()

	fmt.Printf("Listening for connections on port %d\n", appConfig.Configuration.Port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Failed to accept connection", err)
			continue
		}

		go handleConnection(conn, appConfig)
	}
}

func handleConnection(conn net.Conn, appConfig AppConfig) {
	request := make([]byte, 1024)

	fmt.Println("Waiting for data")
	for {
		_, err := conn.Read(request)

		if err != nil {
			if err != io.EOF {
				fmt.Println("Failed to read request", err)
			}
			conn.Close()
			return
		}

		p := ber.DecodePacket(request)

		if len(p.Children) == 2 {
			msgNum := uint8(p.Children[0].ByteValue[0])

			fmt.Printf("Message number %d, tag id: %d\n", msgNum, p.Children[1].Tag)

			if p.Children[1].ClassType == ber.ClassApplication && p.Children[1].Tag == 0 {
				// Bind request OP
				handleBindRequest(conn, p.Children[1], msgNum, appConfig.Users)
			} else if p.Children[1].ClassType == ber.ClassApplication && p.Children[1].Tag == 2 {
				// Unbind request OP
				conn.Close()
				return
			} else if p.Children[1].ClassType == ber.ClassApplication && p.Children[1].Tag == 3 {
				// Search request OP
				handleSearchRequest(conn, p.Children[1], msgNum)
			} else {
				ber.PrintPacket(p.Children[1])
			}

		} else {
			fmt.Println("Unknown packet")
		}

	}

}

func handleSearchRequest(conn net.Conn, p *ber.Packet, msgNum uint8) {
	rsp := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")

	msgNumPacket := ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, msgNum, "")
	rsp.AppendChild(msgNumPacket)

	// Create end of search result packet
	searchRspPacket := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 0x05, nil, "")
	codePacket := ber.NewInteger(ber.ClassApplication, ber.TypePrimitive, ber.TagEnumerated, 0, "")
	searchRspPacket.AppendChild(codePacket)
	dnPacket := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "")
	searchRspPacket.AppendChild(dnPacket)
	msgPacket := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "")
	searchRspPacket.AppendChild(msgPacket)

	// Finally transmit the response to client
	rsp.AppendChild(searchRspPacket)
	conn.Write(rsp.Bytes())
}

func handleBindRequest(conn net.Conn, p *ber.Packet, msgNum uint8, users []User) {
	if len(p.Children) != 3 {
		fmt.Println("Unsupported bind package")
		return
	}

	version := uint8(p.Children[0].ByteValue[0])
	if version != 3 {
		fmt.Printf("Unknown version %d\n", version)
		return
	}

	// Real AD does not trim value, but search is case insensitive so convert given value to lowercase
	user := fmt.Sprintf("%v", p.Children[1].Value)
	user = strings.ToLower(user)
	password := fmt.Sprintf("%v", p.Children[2].Data)

	// TODO
	// if len(password) == 0 {
	// This should return bind succesful message, but with error message in the actual search result
	//}

	// See if we can find the user
	userRecordIdx := slices.IndexFunc(users, func(c User) bool { return strings.ToLower(c.Upn) == user })

	statusCode := 0
	dn := ""
	msg := ""

	if userRecordIdx < 0 || users[userRecordIdx].Password != password {
		// User not found
		statusCode = 49
		msg = "80090308: LdapErr: DSID-0C090569, comment: AcceptSecurityContext error, data 52e, v4563"
	}

	// This part of the response is always the same
	rsp := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")

	msgNumPacket := ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, msgNum, "")
	rsp.AppendChild(msgNumPacket)

	bindRspPacket := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 0x01, nil, "")

	codePacket := ber.NewInteger(ber.ClassApplication, ber.TypePrimitive, ber.TagEnumerated, statusCode, "")
	bindRspPacket.AppendChild(codePacket)
	dnPacket := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "")
	bindRspPacket.AppendChild(dnPacket)
	msgPacket := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, msg, "")
	bindRspPacket.AppendChild(msgPacket)

	rsp.AppendChild(bindRspPacket)

	// Finally transmit the response to client
	conn.Write(rsp.Bytes())
}
