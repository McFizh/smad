package ldap

import (
	"fmt"
	"log"
	"net"
	"slices"
	"smad/models"
	"strconv"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func addEndOfSearchPkg(rsp *ber.Packet, statusCode int, errorMessage string) {
	// Create end of search result packet
	searchRspPacket := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 0x05, nil, "")
	codePacket := ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, statusCode, "")
	searchRspPacket.AppendChild(codePacket)
	dnPacket := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "")
	searchRspPacket.AppendChild(dnPacket)
	msgPacket := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, errorMessage, "")
	searchRspPacket.AppendChild(msgPacket)
	rsp.AppendChild(searchRspPacket)
}

func createObjectName(cn string, prefix string, domain string) string {
	objName := "CN=" + cn + "," + prefix

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
			}
			return 2
		}

		dIdx++
	}

	return 0
}

func createAttributePkg(p *ber.Packet, attrType string, values []string) {
	attrPkg := ber.NewSequence("")

	typePkg := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, attrType, "")
	attrPkg.AppendChild(typePkg)

	valuesPkg := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "")
	for _, val := range values {
		valPkg := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, val, "")
		valuesPkg.AppendChild(valPkg)
	}
	attrPkg.AppendChild(valuesPkg)

	p.AppendChild(attrPkg)
}

func createSearchResEntry(objectName string, objectClasses []string, attributes map[string]string) (*ber.Packet, *ber.Packet) {
	searchResEntry := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 0x04, nil, "")

	msgPacket := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, objectName, "")
	searchResEntry.AppendChild(msgPacket)

	attrPacket := ber.NewSequence("")

	// Create objectClass package
	createAttributePkg(attrPacket, "objectClass", objectClasses)

	// Add custom attributes to attribute package
	for key, value := range attributes {
		createAttributePkg(attrPacket, key, []string{value})
	}

	return attrPacket, searchResEntry
}

func joinGroupsAndUsers(config models.AppConfig) []models.LdapElement {
	var allItems []models.LdapElement

	for _, group := range config.Groups {
		newItem := models.LdapElement{Cn: group.Cn, UserAccountControl: -1}
		newItem.ObjectClass = []string{"top", "group"}
		newItem.Attributes = map[string]string{"name": group.Cn}
		allItems = append(allItems, newItem)
	}

	for _, user := range config.Users {
		newItem := models.LdapElement{Cn: user.Cn, UserAccountControl: user.UserAccountControl}
		newItem.ObjectClass = []string{"top", "person", "organizationalPerson", "user"}
		newItem.Attributes = user.Attributes

		for _, ug := range user.Groups {
			groupName := createObjectName(ug, "CN=Users", config.Configuration.Domain)
			newItem.MemberOf = append(newItem.MemberOf, groupName)
		}

		allItems = append(allItems, newItem)
	}

	return allItems
}

func createFilter(rawFilter *ber.Packet) models.LdapFilter {
	var filter models.LdapFilter

	filter.Attribute = strings.ToLower(fmt.Sprintf("%v", rawFilter.Children[0].Value))
	filter.Value = strings.ToLower(fmt.Sprintf("%v", rawFilter.Children[1].Value))

	return filter
}

func isInStringArray(haystack []string, needle string) bool {
	idx := slices.IndexFunc(haystack, func(value string) bool { return strings.ToLower(value) == needle })
	if idx == -1 {
		return false
	}
	return true
}

func filterObjects(rawData []models.LdapElement, filters *ber.Packet) []models.LdapElement {
	var queryFilters []models.LdapFilter
	var filteredElements []models.LdapElement

	if len(filters.Children) == 0 || (filters.TagType == ber.TypePrimitive && filters.Value == nil) {
		// No filters .. do nothing
	} else if filters.TagType == ber.TypeConstructed && filters.Tag == 3 && len(filters.Children) == 2 {
		// Only one filter?
		queryFilters = append(queryFilters, createFilter(filters))
	} else if filters.TagType == ber.TypeConstructed && filters.Tag == 0 {
		// Multiple values
		for _, filter := range filters.Children {
			if filter.Tag == 3 && len(filter.Children) == 2 {
				queryFilters = append(queryFilters, createFilter(filter))
			}
		}
	} else {
		log.Printf("Unsupported search filter package:\n")
		ber.PrintPacket(filters)
		return rawData
	}

	// No filters set
	if len(queryFilters) == 0 {
		return rawData
	}

	// Run filters
	for _, item := range rawData {
		ignoreItem := false
		// For now we only support objectclass filter
		for _, filter := range queryFilters {
			if filter.Attribute == "objectclass" && !isInStringArray(item.ObjectClass, filter.Value) {
				ignoreItem = true
			}
		}

		// Should the item be included in result?
		if !ignoreItem {
			filteredElements = append(filteredElements, item)
		}
	}

	// Return filtered elements
	return filteredElements
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

	// Create response
	allObjectsRaw := joinGroupsAndUsers(config)

	// IDX 6 contains possible filters
	allObjects := filterObjects(allObjectsRaw, p.Children[6])

	// Finally return results
	for _, object := range allObjects {
		rspX := createResponsePacket(msgNum)
		objectName := createObjectName(object.Cn, "CN=Users", config.Configuration.Domain)
		attrPkg, sREPkg := createSearchResEntry(objectName, object.ObjectClass, object.Attributes)

		// Add CN
		createAttributePkg(attrPkg, "cn", []string{object.Cn})

		// Add memberof packages
		if len(object.MemberOf) > 0 {
			createAttributePkg(attrPkg, "memberOf", object.MemberOf)
		}

		if object.UserAccountControl > 0 {
			uacStr := strconv.Itoa(object.UserAccountControl)
			createAttributePkg(attrPkg, "userAccountControl", []string{uacStr})
		}

		// Attach attributes to response, and finally send the response package
		sREPkg.AppendChild(attrPkg)
		rspX.AppendChild(sREPkg)
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

	*/

	addEndOfSearchPkg(eosp, 0, "")
	conn.Write(eosp.Bytes())
}
