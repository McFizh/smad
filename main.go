package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"net"

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

		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
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
				// Bind request
				parseBind(conn, p.Children[1])
			} else if p.Children[1].ClassType == ber.ClassApplication && p.Children[1].Tag == 2 {
				// Unbind request
				conn.Close()
				return
			} else {
				ber.PrintPacket(p.Children[1])
			}

		} else {
			fmt.Println("Unknown packet")
		}

	}

}

func parseBind(conn net.Conn, p *ber.Packet) {
	if len(p.Children) != 3 {
		fmt.Println("Unsupported bind package")
		return
	}

	// version := uint8(p.Children[0].ByteValue[0])
	// user := p.Children[1].Value
	// password := p.Children[2].Value

	rsp := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")

	msgNumPacket := ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 1, "")

	codePacket := ber.NewInteger(ber.ClassApplication, ber.TypePrimitive, ber.TagEnumerated, 49, "")
	dnPacket := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "")
	msgPacket := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "80090308: LdapErr: DSID-0C090569, comment: AcceptSecurityContext error, data 52e, v4563", "")
	bindRspPacket := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.TagBoolean, nil, "")
	bindRspPacket.AppendChild(codePacket)
	bindRspPacket.AppendChild(dnPacket)
	bindRspPacket.AppendChild(msgPacket)

	rsp.AppendChild(msgNumPacket)
	rsp.AppendChild(bindRspPacket)

	str := hex.EncodeToString(rsp.Bytes())
	fmt.Println(str)
	conn.Write(rsp.Bytes())
}
