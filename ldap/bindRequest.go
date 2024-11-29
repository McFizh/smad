package ldap

import (
	"fmt"
	"log"
	"net"
	"slices"
	"smad/models"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func HandleBindRequest(conn net.Conn, p *ber.Packet, msgNum uint8, users []models.User) bool {
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
	userRecordIdx := slices.IndexFunc(users, func(c models.User) bool { return strings.ToLower(c.Upn) == user })

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

	codePacket := ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, statusCode, "")
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
