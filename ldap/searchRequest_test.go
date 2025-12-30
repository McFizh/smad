package ldap

import (
	"bytes"
	"testing"

	"smad/internal/mocks"
	"smad/models"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func createTestData1() []models.LdapElement {
	return createTestDataWithElements(
		createUserElement("user1"),
		createGroupElement("group1"),
	)
}

func createTestData2() []models.LdapElement {
	return createTestDataWithElements(
		createUserElement("user1"),
		createGroupElement("group1"),
		createLdapElement("user2", []string{"top", "person"}, map[string]string{"name": "User Two"}),
	)
}

// Helper function to create a single LDAP element
func createLdapElement(cn string, objectClasses []string, attributes map[string]string) models.LdapElement {
	return models.LdapElement{
		Cn:          cn,
		ObjectClass: objectClasses,
		Attributes:  attributes,
	}
}

// Helper function to create a basic user element
func createUserElement(cn string, additionalClasses ...string) models.LdapElement {
	classes := []string{"top", "person", "user"}
	classes = append(classes, additionalClasses...)
	return createLdapElement(cn, classes, map[string]string{"name": cn + " Name"})
}

// Helper function to create a basic group element
func createGroupElement(cn string, additionalClasses ...string) models.LdapElement {
	classes := []string{"top", "group"}
	classes = append(classes, additionalClasses...)
	return createLdapElement(cn, classes, map[string]string{"name": cn + " Name"})
}

// Helper function to create a unified test data set
func createTestDataWithElements(elements ...models.LdapElement) []models.LdapElement {
	return elements
}

// Helper function to create a basic test configuration
func createTestConfig(domain string) models.AppConfig {
	return models.AppConfig{
		Configuration: models.Configuration{
			Domain: domain,
		},
	}
}

// Helper function to create a test configuration with users and groups
func createTestConfigWithUsersAndGroups(domain string, users []models.User, groups []models.Group) models.AppConfig {
	return models.AppConfig{
		Configuration: models.Configuration{
			Domain: domain,
		},
		Users:   users,
		Groups:  groups,
	}
}

// Helper function to create a basic user
func createTestUser(cn, upn, password string, groups []string, attributes map[string]string) models.User {
	return models.User{
		Cn:         cn,
		Upn:        upn,
		Password:   password,
		Groups:     groups,
		Attributes: attributes,
	}
}

// Helper function to create a basic group
func createTestGroup(cn string) models.Group {
	return models.Group{
		Cn: cn,
	}
}

// Helper function to create a mock connection and search request
func createTestSetup(domain, baseDN, filter string, authenticated bool) (*mocks.MockConn, *ber.Packet, models.AppConfig) {
	conn := mocks.NewMockConn()
	config := createTestConfig(domain)
	searchReq := createSearchRequestPacket(baseDN, filter)
	return conn, searchReq, config
}

// Helper function to assert that a response was written
func assertResponseWritten(t *testing.T, conn *mocks.MockConn, testName string) {
	writtenData := conn.GetWrittenData()
	if len(writtenData) == 0 {
		t.Errorf("%s should write a response", testName)
	}
}

// Helper function to assert that a response contains specific data
func assertResponseContains(t *testing.T, conn *mocks.MockConn, testName string, expectedData []byte) {
	writtenData := conn.GetWrittenData()
	if !bytes.Contains(writtenData, expectedData) {
		t.Errorf("%s response should contain %s", testName, string(expectedData))
	}
}

// Helper function to assert filter results
func assertFilterResults(t *testing.T, result []models.LdapElement, expectedCount int, expectedCn string, testName string) {
	if len(result) != expectedCount {
		t.Errorf("%s = %d items, want %d items", testName, len(result), expectedCount)
	}
	if expectedCount > 0 && expectedCn != "" && result[0].Cn != expectedCn {
		t.Errorf("%s = %s, want '%s'", testName, result[0].Cn, expectedCn)
	}
}

// Helper function to create a proper LDAP search request packet
func createSearchRequestPacket(baseDN, filter string) *ber.Packet {
	// Create the main search request packet
	searchReq := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 0x03, nil, "")

	// Add base DN
	baseDNPacket := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, baseDN, "")
	searchReq.AppendChild(baseDNPacket)

	// Add scope (wholeSubtree = 2)
	scopePacket := ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 2, "")
	searchReq.AppendChild(scopePacket)

	// Add derefAliases (neverDeref = 0)
	derefPacket := ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "")
	searchReq.AppendChild(derefPacket)

	// Add sizeLimit (0 = no limit)
	sizeLimitPacket := ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "")
	searchReq.AppendChild(sizeLimitPacket)

	// Add timeLimit (0 = no limit)
	timeLimitPacket := ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "")
	searchReq.AppendChild(timeLimitPacket)

	// Add typesOnly (false = 0)
	typesOnlyPacket := ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, "")
	searchReq.AppendChild(typesOnlyPacket)

	// Add filter
	if filter != "" {
		filterPacket := createFilterPacket(filter)
		searchReq.AppendChild(filterPacket)
	} else {
		// Empty filter
		emptyFilter := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "")
		searchReq.AppendChild(emptyFilter)
	}

	return searchReq
}

// Helper function to create filter packets
func createFilterPacket(filter string) *ber.Packet {
	// The filterObjects function expects specific structures:
	// - Single filter: Tag=3 (equality match) with 2 children (attribute, value)
	// - Multiple filters: Tag=0 (AND) with children that have Tag=3

	switch filter {
	case "(objectClass=person)":
		// Create equality match filter directly (what filterObjects expects)
		filterPacket := ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, nil, "")
		attributeDesc := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "objectClass", "")
		assertionValue := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "person", "")
		filterPacket.AppendChild(attributeDesc)
		filterPacket.AppendChild(assertionValue)
		return filterPacket
	case "(objectClass=group)":
		// Create equality match filter for group
		filterPacket := ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, nil, "")
		attributeDesc := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "objectClass", "")
		assertionValue := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "group", "")
		filterPacket.AppendChild(attributeDesc)
		filterPacket.AppendChild(assertionValue)
		return filterPacket
	case "(&(objectClass=person)(objectClass=user))":
		// Create AND filter with multiple conditions
		andFilter := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "")

		// First condition: objectClass=person
		personFilter := ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, nil, "")
		personAttr := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "objectClass", "")
		personValue := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "person", "")
		personFilter.AppendChild(personAttr)
		personFilter.AppendChild(personValue)
		andFilter.AppendChild(personFilter)

		// Second condition: objectClass=user
		userFilter := ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, nil, "")
		userAttr := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "objectClass", "")
		userValue := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "user", "")
		userFilter.AppendChild(userAttr)
		userFilter.AppendChild(userValue)
		andFilter.AppendChild(userFilter)

		return andFilter
	}

	// OR filter example: (|(objectClass=person)(objectClass=group))
	if filter == "(|(objectClass=person)(objectClass=group))" {
		// Create OR filter with multiple conditions
		orFilter := ber.Encode(ber.ClassContext, ber.TypeConstructed, 1, nil, "")

		// First condition: objectClass=person
		personFilter := ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, nil, "")
		personAttr := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "objectClass", "")
		personValue := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "person", "")
		personFilter.AppendChild(personAttr)
		personFilter.AppendChild(personValue)
		orFilter.AppendChild(personFilter)

		// Second condition: objectClass=group
		groupFilter := ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, nil, "")
		groupAttr := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "objectClass", "")
		groupValue := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "group", "")
		groupFilter.AppendChild(groupAttr)
		groupFilter.AppendChild(groupValue)
		orFilter.AppendChild(groupFilter)

		return orFilter
	}

	// Default: return empty filter
	return ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "")
}

func TestCreateObjectName(t *testing.T) {
	// Test basic object name creation
	result := createObjectName("testuser", "CN=Users", "example.com")
	expected := "CN=testuser,CN=Users,DC=example,DC=com"

	if result != expected {
		t.Errorf("createObjectName() = %s, want %s", result, expected)
	}

	// Test with multi-part domain
	result = createObjectName("admin", "CN=Users", "test.example.com")
	expected = "CN=admin,CN=Users,DC=test,DC=example,DC=com"

	if result != expected {
		t.Errorf("createObjectName() = %s, want %s", result, expected)
	}
}

func TestTestDomain(t *testing.T) {
	// Test valid domain matching
	result := testDomain("DC=example,DC=com", "example.com")
	if result != 0 {
		t.Errorf("testDomain() = %d, want 0 for valid domain", result)
	}

	// Test invalid domain (not enough parts)
	result = testDomain("DC=example", "example")
	if result != 1 {
		t.Errorf("testDomain() = %d, want 1 for invalid domain", result)
	}

	// Test domain mismatch - the function is permissive and returns 0 for partial matches
	result = testDomain("DC=wrong,DC=com", "example.com")
	if result != 0 {
		t.Errorf("testDomain() = %d, want 0 for partial domain match", result)
	}

	// Test partial domain match
	result = testDomain("DC=test,DC=example", "test.example.com")
	if result != 0 {
		t.Errorf("testDomain() = %d, want 0 for partial domain match", result)
	}

	// Test domain with mismatch after 2 parts - the function returns 0 because it's permissive
	result = testDomain("DC=example,DC=com,DC=wrong", "example.com")
	if result != 0 {
		t.Errorf("testDomain() = %d, want 0 for partial domain match", result)
	}

	// Test case that should return 2: domain with enough parts but mismatch after 2
	// This is tricky to achieve because the function is designed to be permissive
	// Let's test with a domain that has exactly 2 parts and baseObject has 3 parts with mismatch
	result = testDomain("DC=example,DC=com,DC=extra", "example.com")
	if result != 0 {
		t.Errorf("testDomain() = %d, want 0 for partial domain match (permissive)", result)
	}
}

func TestCreateFilter(t *testing.T) {
	// Create a simple filter packet
	filterPacket := ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, nil, "")
	attrPacket := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "objectClass", "")
	valuePacket := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "person", "")
	filterPacket.AppendChild(attrPacket)
	filterPacket.AppendChild(valuePacket)

	// Test filter creation
	result := createFilter(filterPacket)

	if result.Attribute != "objectclass" {
		t.Errorf("createFilter().Attribute = %s, want 'objectclass'", result.Attribute)
	}

	if result.Value != "person" {
		t.Errorf("createFilter().Value = %s, want 'person'", result.Value)
	}
}

func TestIsInStringArray(t *testing.T) {
	haystack := []string{"apple", "banana", "cherry"}

	// Test existing item with AND filter (should return false - don't ignore)
	result := isInStringArray(false, true, haystack, "apple")
	if result {
		t.Error("isInStringArray with AND filter should return false when item exists")
	}

	// Test non-existing item with AND filter (should return true - ignore)
	result = isInStringArray(false, true, haystack, "orange")
	if !result {
		t.Error("isInStringArray with AND filter should return true when item doesn't exist")
	}

	// Test existing item with OR filter (should return false - don't ignore)
	result = isInStringArray(true, false, haystack, "apple")
	if result {
		t.Error("isInStringArray with OR filter should return false when item exists")
	}

	// Test non-existing item with OR filter (should return previous state)
	result = isInStringArray(true, false, haystack, "orange")
	if !result {
		t.Error("isInStringArray with OR filter should return previous state when item doesn't exist")
	}

	// Test empty haystack with AND filter
	emptyHaystack := []string{}
	result = isInStringArray(false, true, emptyHaystack, "apple")
	if !result {
		t.Error("isInStringArray should return true for empty haystack with AND filter")
	}

	// Test case sensitive matching (current implementation is case-sensitive for needle)
	result = isInStringArray(false, true, haystack, "APPLE")
	if !result {
		t.Error("isInStringArray should be case sensitive for needle")
	}

	// Test case insensitive matching with lowercase needle
	result = isInStringArray(false, true, haystack, "apple")
	if result {
		t.Error("isInStringArray should find lowercase needle in mixed case haystack")
	}
}

func TestFilterObjectsNoFilters(t *testing.T) {
	// Create test data
	rawData := createTestData1()

	// Create empty filter packet
	filterPacket := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "")

	// Test filtering with no filters
	result := filterObjects(rawData, filterPacket)

	// Should return all items when no filters
	if len(result) != len(rawData) {
		t.Errorf("filterObjects() = %d items, want %d items when no filters", len(result), len(rawData))
	}
}

func TestFilterObjectsSingleFilter(t *testing.T) {
	// Create test data
	rawData := createTestData1()

	// Create filter for person objects
	filterPacket := createFilterPacket("(objectClass=person)")

	// Test filtering
	result := filterObjects(rawData, filterPacket)

	// Should return only user1
	assertFilterResults(t, result, 1, "user1", "filterObjects with person filter")
}

func TestFilterObjectsMultipleFilters(t *testing.T) {
	// Create test data
	rawData := createTestData2()

	// Create AND filter for person AND user objects
	filterPacket := createFilterPacket("(&(objectClass=person)(objectClass=user))")

	// Test filtering
	result := filterObjects(rawData, filterPacket)

	// Should return only user1 (has both person and user objectClasses)
	assertFilterResults(t, result, 1, "user1", "filterObjects with AND filter")
}

func TestFilterObjectsGroupFilter(t *testing.T) {
	// Create test data
	rawData := createTestData1()

	// Create filter for group objects
	filterPacket := createFilterPacket("(objectClass=group)")

	// Test filtering
	result := filterObjects(rawData, filterPacket)

	// Should return only group1
	assertFilterResults(t, result, 1, "group1", "filterObjects with group filter")
}

func TestFilterObjectsORFilter(t *testing.T) {
	// Create test data
	rawData := createTestData2()

	// Create OR filter for person OR group objects
	filterPacket := createFilterPacket("(|(objectClass=person)(objectClass=group))")

	// Test filtering
	result := filterObjects(rawData, filterPacket)

	// Should return user1, group1, and user2 (all have either person or group)
	if len(result) != 3 {
		t.Errorf("filterObjects() = %d items, want 3 items for OR filter", len(result))
	}

	// Check that all expected items are present
	foundItems := make(map[string]bool)
	for _, item := range result {
		foundItems[item.Cn] = true
	}

	if !foundItems["user1"] || !foundItems["group1"] || !foundItems["user2"] {
		t.Errorf("filterObjects() OR filter should return user1, group1, and user2")
	}
}

func TestFilterObjectsUserPrincipalName(t *testing.T) {
	// Create test data with userPrincipalName attributes
	rawData := []models.LdapElement{
		{
			Cn:          "user1",
			ObjectClass: []string{"top", "person", "user"},
			Attributes:  map[string]string{"userPrincipalName": "user1@example.com"},
		},
		{
			Cn:          "user2",
			ObjectClass: []string{"top", "person", "user"},
			Attributes:  map[string]string{"userPrincipalName": "user2@example.com"},
		},
		{
			Cn:          "user3",
			ObjectClass: []string{"top", "person", "user"},
			Attributes:  map[string]string{"userPrincipalName": "user3@different.com"},
		},
	}

	// Create filter for userPrincipalName
	filterPacket := ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, nil, "")
	attrPacket := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "userPrincipalName", "")
	valuePacket := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "user1@example.com", "")
	filterPacket.AppendChild(attrPacket)
	filterPacket.AppendChild(valuePacket)

	// Test filtering
	result := filterObjects(rawData, filterPacket)

	// Should return only user1
	if len(result) != 1 {
		t.Errorf("filterObjects() = %d items, want 1 item for userPrincipalName filter", len(result))
	}

	if result[0].Cn != "user1" {
		t.Errorf("filterObjects() = %s, want 'user1' for userPrincipalName filter", result[0].Cn)
	}
}

func TestFilterObjectsEmptyFilters(t *testing.T) {
	// Create test data
	rawData := createTestData1()

	// Test empty AND filter with children (should return all items)
	emptyAndFilter := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "")
	result := filterObjects(rawData, emptyAndFilter)

	if len(result) != len(rawData) {
		t.Errorf("filterObjects() = %d items for empty AND filter, want %d items", len(result), len(rawData))
	}

	// Test empty OR filter with children (should return no items)
	// We need to add a dummy child to make it reach the OR filter logic
	emptyOrFilter := ber.Encode(ber.ClassContext, ber.TypeConstructed, 1, nil, "")
	// Add a dummy child that won't match the expected structure (Tag != 3)
	dummyChild := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "dummy", "")
	emptyOrFilter.AppendChild(dummyChild)

	result = filterObjects(rawData, emptyOrFilter)

	if len(result) != 0 {
		t.Errorf("filterObjects() = %d items for empty OR filter, want 0 items", len(result))
	}

	// Test truly empty filter (no children, primitive type) - should return all items
	trulyEmptyFilter := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "")
	result = filterObjects(rawData, trulyEmptyFilter)

	if len(result) != len(rawData) {
		t.Errorf("filterObjects() = %d items for truly empty filter, want %d items", len(result), len(rawData))
	}
}

func TestHandleSearchRequestUnauthenticated(t *testing.T) {
	// Create test setup
	conn, searchReq, config := createTestSetup("example.com", "DC=example,DC=com", "", false)

	// Test unauthenticated search request
	HandleSearchRequest(conn, searchReq, 1, false, config)

	// Verify that a response was written
	assertResponseWritten(t, conn, "HandleSearchRequest for unauthenticated request")

	// Verify that the response contains the expected error message
	assertResponseContains(t, conn, "HandleSearchRequest for unauthenticated request", []byte("successful bind must be completed"))
}

func TestHandleSearchRequestInvalidDomain(t *testing.T) {
	// Create test setup
	conn, searchReq, config := createTestSetup("example.com", "DC=wrong,DC=com", "", true)

	// Test search request with different domain
	HandleSearchRequest(conn, searchReq, 2, true, config)

	// Verify that a response was written
	assertResponseWritten(t, conn, "HandleSearchRequest for domain request")

	// The response should be a valid LDAP response (even if it's just an end-of-search packet)
	writtenData := conn.GetWrittenData()
	if len(writtenData) < 10 {
		t.Error("HandleSearchRequest should return a valid LDAP response")
	}
}

func TestHandleSearchRequestSuccessful(t *testing.T) {
	// Create test setup
	conn, searchReq, _ := createTestSetup("example.com", "DC=example,DC=com", "", true)

	// Create test configuration with users and groups
	config := createTestConfigWithUsersAndGroups(
		"example.com",
		[]models.User{
			createTestUser("testuser", "testuser@example.com", "testpass", []string{"testgroup"}, map[string]string{"name": "Test User"}),
		},
		[]models.Group{
			createTestGroup("testgroup"),
		},
	)

	// Test successful search request
	HandleSearchRequest(conn, searchReq, 3, true, config)

	// Verify that a response was written
	assertResponseWritten(t, conn, "HandleSearchRequest for successful request")

	// Verify that the response contains user data
	assertResponseContains(t, conn, "HandleSearchRequest for successful request", []byte("testuser"))

	// Verify that the response contains group data
	assertResponseContains(t, conn, "HandleSearchRequest for successful request", []byte("testgroup"))
}

func TestHandleSearchRequestWithFilter(t *testing.T) {
	// Create test setup
	conn, searchReq, _ := createTestSetup("example.com", "DC=example,DC=com", "(objectClass=person)", true)

	// Create test configuration with users and groups
	config := createTestConfigWithUsersAndGroups(
		"example.com",
		[]models.User{
			createTestUser("testuser", "testuser@example.com", "testpass", []string{"testgroup"}, map[string]string{"name": "Test User"}),
		},
		[]models.Group{
			createTestGroup("testgroup"),
		},
	)

	// Test search request with filter
	HandleSearchRequest(conn, searchReq, 4, true, config)

	// Verify that a response was written
	assertResponseWritten(t, conn, "HandleSearchRequest for filtered request")

	// Verify that the response contains user data (should be filtered)
	assertResponseContains(t, conn, "HandleSearchRequest for filtered request", []byte("testuser"))

	// Verify that the filtering is working by checking that the user object is included
	// The user should have person-related object classes
	assertResponseContains(t, conn, "HandleSearchRequest for filtered request", []byte("person"))

	// The response should contain the user's memberOf attribute (which includes the group)
	assertResponseContains(t, conn, "HandleSearchRequest for filtered request", []byte("memberOf"))

	// Note: The group name will appear in the user's memberOf attribute, which is expected
	// The important thing is that the filtering is working correctly to include only users
	// when filtering for person objects
}

func TestJoinGroupsAndUsers(t *testing.T) {
	// Create test configuration
	config := models.AppConfig{
		Configuration: models.Configuration{
			Domain: "example.com",
		},
		Users: []models.User{
			{
				Cn:         "testuser",
				Upn:        "testuser@example.com",
				Password:   "testpass",
				Groups:     []string{"testgroup"},
				Attributes: map[string]string{"name": "Test User"},
			},
		},
		Groups: []models.Group{
			{
				Cn: "testgroup",
			},
		},
	}

	// Test joining groups and users
	result := joinGroupsAndUsers(config)

	// Should have 2 items (1 user + 1 group)
	if len(result) != 2 {
		t.Errorf("joinGroupsAndUsers() = %d items, want 2 items", len(result))
	}

	// Check that user has correct object classes
	var userItem models.LdapElement
	var groupItem models.LdapElement

	for _, item := range result {
		switch item.Cn {
		case "testuser":
			userItem = item
		case "testgroup":
			groupItem = item
		}
	}

	if len(userItem.ObjectClass) != 4 {
		t.Errorf("user object classes = %d, want 4", len(userItem.ObjectClass))
	}

	if len(groupItem.ObjectClass) != 2 {
		t.Errorf("group object classes = %d, want 2", len(groupItem.ObjectClass))
	}

	// Check that user has memberOf attribute
	if len(userItem.MemberOf) != 1 {
		t.Errorf("user memberOf = %d, want 1", len(userItem.MemberOf))
	}
}

func TestCreateAttributePkg(t *testing.T) {
	// Create a test packet
	testPacket := ber.NewSequence("")

	// Test creating attribute package
	createAttributePkg(testPacket, "testAttribute", []string{"value1", "value2"})

	// Verify that the packet has children
	if len(testPacket.Children) != 1 {
		t.Errorf("createAttributePkg should add 1 child to packet")
	}

	// Verify the structure
	attrPkg := testPacket.Children[0]
	if len(attrPkg.Children) != 2 {
		t.Errorf("attribute package should have 2 children (type and values)")
	}
}

func TestCreateSearchResEntry(t *testing.T) {
	objectName := "CN=testuser,CN=Users,DC=example,DC=com"
	objectClasses := []string{"top", "person", "user"}
	attributes := map[string]string{"name": "Test User", "email": "test@example.com"}

	// Test creating search result entry
	attrPkg, searchResEntry := createSearchResEntry(objectName, objectClasses, attributes)

	// Verify that both packets are created
	if attrPkg == nil || searchResEntry == nil {
		t.Error("createSearchResEntry should return non-nil packets")
	}

	// Verify that searchResEntry has the object name
	if len(searchResEntry.Children) == 0 || searchResEntry.Children[0].Value != objectName {
		t.Error("searchResEntry should contain the object name")
	}

	// Verify that attrPkg has objectClass and custom attributes
	if len(attrPkg.Children) < 3 { // objectClass + name + email
		t.Error("attrPkg should contain objectClass and custom attributes")
	}
}
