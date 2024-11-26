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

func finalizeAndSendPkg(conn net.Conn, rsp *ber.Packet, statusCode int, errorMessage string) {
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

func testDomain(baseObject string, domain string) uint8 {
	// If domain has less than 2 parts, it's not valid domain
	domainParts := strings.Split(domain, ".")
	slices.Reverse(domainParts)
	if len(domainParts) < 2 {
		return 1
	}

	baseObjectParts := strings.Split(baseObject, ",")
	slices.Reverse(baseObjectParts)

	dIdx := 0

	for _, part := range baseObjectParts {
		if !strings.HasPrefix(part, "dc=") {
			continue
		}

		if dIdx >= len(domainParts) || part[3:] != domainParts[dIdx] {
			if dIdx < 2 {
				return 1
			} else {
				return 2
			}
		}

		dIdx++
	}

	return 0
}

func HandleSearchRequest(conn net.Conn, p *ber.Packet, msgNum uint8, bindSuccessful bool, config models.AppConfig) {
	if len(p.Children) < 6 {
		log.Println("Unsupported search package")
		return
	}

	rsp := createResponsePacket(msgNum)

	if !bindSuccessful {
		finalizeAndSendPkg(conn, rsp, 1, "000004DC: LdapErr: DSID-0C090CF4, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4563")
		return
	}

	// Make sure domain components in base query match the configuration
	tval := testDomain(fmt.Sprintf("%v", p.Children[0].Value), config.Configuration.Domain)
	if tval > 0 {
		if tval == 1 {
			finalizeAndSendPkg(conn, rsp, 10, "0000202B: RefErr: DSID-0310084A, data 0, 1 access points")
		} else {
			finalizeAndSendPkg(conn, rsp, 32, "0000208D: NameErr: DSID-0310028C, problem 2001 (NO_OBJECT), data 0, best match of:")
		}
		return
	}

	/*
		For time being these are not used:

		scope := p.Children[1].Value
		// (2 = wholeSubtree)
		derefAliases := p.Children[2].Value
		// (0 = neverderefer)
		sizeLimit := p.Children[3].Value
		timeLimit := p.Children[4].Value
		typesOnly := p.Children[5].Value
		filters := p.Children[6]

		ber.PrintPacket(p)
	*/

	finalizeAndSendPkg(conn, rsp, 0, "")
}
