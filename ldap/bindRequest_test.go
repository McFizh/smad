package ldap

import (
	"bytes"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	"smad/internal/mocks"
	"smad/models"
)

// Helper function to create a proper LDAP message packet containing a bind request
func createLDAPMessageWithBindRequest(username, password string, msgNum uint8) *ber.Packet {
	// Create the main LDAP message packet
	mainPacket := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.TagSequence, nil, "")

	// Add message ID
	msgIdPacket := ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int(msgNum), "")
	mainPacket.AppendChild(msgIdPacket)

	// Create bind request packet (this is what HandleBindRequest expects)
	bindReq := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 0, nil, "")

	// Add LDAP version (3) - as ByteValue
	versionPacket := ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "")
	versionPacket.ByteValue = []byte{3}
	bindReq.AppendChild(versionPacket)

	// Add username - as Value
	namePacket := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, username, "")
	bindReq.AppendChild(namePacket)

	// Add password - as Data (not wrapped in another packet)
	passwordPacket := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, password, "")
	passwordPacket.Data = bytes.NewBufferString(password)
	bindReq.AppendChild(passwordPacket)

	mainPacket.AppendChild(bindReq)

	return mainPacket
}

func TestHandleBindRequestSuccessful(t *testing.T) {
	// Create mock connection
	conn := mocks.NewMockConn()

	// Create test users
	users := []models.User{
		{
			Upn:      "testuser@example.com",
			Password: "correctpassword",
			Groups:   []string{"testgroup"},
		},
	}

	// Create a proper LDAP message with bind request
	mainPacket := createLDAPMessageWithBindRequest("testuser@example.com", "correctpassword", 1)

	// Call HandleBindRequest with the bind request packet (mainPacket.Children[1])
	result := HandleBindRequest(conn, mainPacket.Children[1], 1, users)

	// Verify the result
	if !result {
		t.Error("HandleBindRequest should return true for valid credentials")
	}

	// Verify that a response was written to the connection
	writtenData := conn.GetWrittenData()
	if len(writtenData) == 0 {
		t.Error("HandleBindRequest should write a response to the connection")
	}
}

func TestHandleBindRequestDisabledAccount(t *testing.T) {
	// Create mock connection
	conn := mocks.NewMockConn()

	// Create test users with disabled account
	users := []models.User{
		{
			Upn:                "disableduser@example.com",
			Password:           "password123",
			Groups:             []string{"testgroup"},
			UserAccountControl: 2, // Account disabled flag
		},
	}

	// Create a proper LDAP message with bind request
	mainPacket := createLDAPMessageWithBindRequest("disableduser@example.com", "password123", 2)

	// Call HandleBindRequest with the bind request packet (mainPacket.Children[1])
	result := HandleBindRequest(conn, mainPacket.Children[1], 2, users)

	// Verify the result
	if result {
		t.Error("HandleBindRequest should return false for disabled account")
	}

	// Verify that a response was written to the connection
	writtenData := conn.GetWrittenData()
	if len(writtenData) == 0 {
		t.Error("HandleBindRequest should write a response to the connection")
	}

	// Verify that the response contains the expected error message for disabled account
	// The error message should contain "data 533" which indicates account disabled
	if !bytes.Contains(writtenData, []byte("data 533")) {
		t.Error("HandleBindRequest should return account disabled error message")
	}
}

func TestHandleBindRequestWrongPassword(t *testing.T) {
	// Create mock connection
	conn := mocks.NewMockConn()

	// Create test users
	users := []models.User{
		{
			Upn:      "testuser@example.com",
			Password: "correctpassword",
			Groups:   []string{"testgroup"},
		},
	}

	// Create a proper LDAP message with bind request with wrong password
	mainPacket := createLDAPMessageWithBindRequest("testuser@example.com", "wrongpassword", 3)

	// Call HandleBindRequest with the bind request packet (mainPacket.Children[1])
	result := HandleBindRequest(conn, mainPacket.Children[1], 3, users)

	// Verify the result
	if result {
		t.Error("HandleBindRequest should return false for wrong password")
	}

	// Verify that a response was written to the connection
	writtenData := conn.GetWrittenData()
	if len(writtenData) == 0 {
		t.Error("HandleBindRequest should write a response to the connection")
	}

	// Verify that the response contains the expected error message for wrong password
	// The error message should contain "data 52e" which indicates invalid credentials
	if !bytes.Contains(writtenData, []byte("data 52e")) {
		t.Error("HandleBindRequest should return invalid credentials error message")
	}
}

func TestHandleBindRequestUserNotFound(t *testing.T) {
	// Create mock connection
	conn := mocks.NewMockConn()

	// Create test users (empty list)
	users := []models.User{}

	// Create a proper LDAP message with bind request
	mainPacket := createLDAPMessageWithBindRequest("nonexistent@example.com", "somepassword", 4)

	// Call HandleBindRequest with the bind request packet (mainPacket.Children[1])
	result := HandleBindRequest(conn, mainPacket.Children[1], 4, users)

	// Verify the result
	if result {
		t.Error("HandleBindRequest should return false for non-existent user")
	}

	// Verify that a response was written to the connection
	writtenData := conn.GetWrittenData()
	if len(writtenData) == 0 {
		t.Error("HandleBindRequest should write a response to the connection")
	}

	// Verify that the response contains the expected error message for invalid credentials
	if !bytes.Contains(writtenData, []byte("data 52e")) {
		t.Error("HandleBindRequest should return invalid credentials error message for non-existent user")
	}
}

func TestHandleBindRequestCaseInsensitive(t *testing.T) {
	// Create mock connection
	conn := mocks.NewMockConn()

	// Create test users
	users := []models.User{
		{
			Upn:      "TestUser@Example.COM",
			Password: "TestPassword123",
			Groups:   []string{"testgroup"},
		},
	}

	// Create a proper LDAP message with bind request with different case
	mainPacket := createLDAPMessageWithBindRequest("testuser@example.com", "TestPassword123", 5)

	// Call HandleBindRequest with the bind request packet (mainPacket.Children[1])
	result := HandleBindRequest(conn, mainPacket.Children[1], 5, users)

	// Verify the result
	if !result {
		t.Error("HandleBindRequest should be case-insensitive for usernames")
	}
}
