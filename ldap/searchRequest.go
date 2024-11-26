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

func addEndOfSearchPkg(rsp *ber.Packet, statusCode int, errorMessage string) {
	// Create end of search result packet
	searchRspPacket := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 0x05, nil, "")
	codePacket := ber.NewInteger(ber.ClassApplication, ber.TypePrimitive, ber.TagEnumerated, statusCode, "")
	searchRspPacket.AppendChild(codePacket)
	dnPacket := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "")
	searchRspPacket.AppendChild(dnPacket)
	msgPacket := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, errorMessage, "")
	searchRspPacket.AppendChild(msgPacket)
	rsp.AppendChild(searchRspPacket)
}

func createObjectName(domain string, prefix string) string {
	objName := prefix

	domainParts := strings.Split(domain, ".")
	for _, part := range domainParts {
		objName += ",DC=" + part
	}

	return objName
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

func createAttributePkg(p *ber.Packet, attrType string, values []string) {
	attrPkg := ber.NewSequence("")

	typePkg := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, attrType, "")
	attrPkg.AppendChild(typePkg)

	valuesPkg := ber.NewSequence("")
	for _, val := range values {
		valPkg := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, val, "")
		valuesPkg.AppendChild(valPkg)
	}
	attrPkg.AppendChild(valuesPkg)

	p.AppendChild(attrPkg)
}

func createSearchResEntry(p *ber.Packet, domain string, objtype string) {
	searchResEntry := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 0x04, nil, "")

	objectName := createObjectName(domain, "CN=Users")
	msgPacket := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, objectName, "")
	searchResEntry.AppendChild(msgPacket)

	attrPacket := ber.NewSequence("")

	// Create objectClass package
	if objtype == "user" {
		createAttributePkg(attrPacket, "objectClass", []string{"top", "person", "organizationalPerson", objtype})
	} else {
		createAttributePkg(attrPacket, "objectClass", []string{"top", objtype})
	}

	// Attach attributes to response
	searchResEntry.AppendChild(attrPacket)
	p.AppendChild(searchResEntry)
}

func HandleSearchRequest(conn net.Conn, p *ber.Packet, msgNum uint8, bindSuccessful bool, config models.AppConfig) {
	if len(p.Children) < 6 {
		log.Println("Unsupported search package")
		return
	}

	eosp := createResponsePacket(msgNum)

	if !bindSuccessful {
		addEndOfSearchPkg(eosp, 1, "000004DC: LdapErr: DSID-0C090CF4, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4563")
		conn.Write(eosp.Bytes())
		return
	}

	// Make sure domain components in base query match the configuration
	tval := testDomain(fmt.Sprintf("%v", p.Children[0].Value), config.Configuration.Domain)
	if tval > 0 {
		if tval == 1 {
			addEndOfSearchPkg(eosp, 10, "0000202B: RefErr: DSID-0310084A, data 0, 1 access points")
		} else {
			addEndOfSearchPkg(eosp, 32, "0000208D: NameErr: DSID-0310028C, problem 2001 (NO_OBJECT), data 0, best match of:")
		}
		conn.Write(eosp.Bytes())
		return
	}

	// Add groups
	for range config.Groups {
		rspX := createResponsePacket(msgNum)
		createSearchResEntry(rspX, config.Configuration.Domain, "group")
		conn.Write(rspX.Bytes())
	}

	// Add users
	for range config.Users {
		rspX := createResponsePacket(msgNum)
		createSearchResEntry(rspX, config.Configuration.Domain, "user")
		conn.Write(rspX.Bytes())
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

	*/

	addEndOfSearchPkg(eosp, 0, "")
	conn.Write(eosp.Bytes())
}
