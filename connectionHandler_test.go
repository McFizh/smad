package main

import (
	"bytes"
	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/google/uuid"
	"smad/internal/mocks"
	"smad/models"
	"testing"
)

// Helper function to create a mock packet for testing
func createMockPacket(msgNum uint8, operationTag ber.Tag, hasTwoChildren bool) *ber.Packet {
	p := &ber.Packet{}

	if hasTwoChildren {
		// Create message number child
		msgNumChild := &ber.Packet{}
		msgNumChild.ByteValue = []byte{msgNum}
		msgNumChild.ClassType = ber.ClassUniversal
		msgNumChild.Tag = ber.TagInteger

		// Create operation child
		opChild := &ber.Packet{}
		opChild.Tag = operationTag
		opChild.ClassType = ber.ClassApplication

		p.Children = []*ber.Packet{msgNumChild, opChild}
	} else {
		// Create packet with only one child (invalid structure)
		msgNumChild := &ber.Packet{}
		msgNumChild.ByteValue = []byte{msgNum}
		msgNumChild.ClassType = ber.ClassUniversal
		msgNumChild.Tag = ber.TagInteger

		p.Children = []*ber.Packet{msgNumChild}
	}

	return p
}

func TestHandlePacketBindRequest(t *testing.T) {
	// Create mock connection
	conn := mocks.NewMockConn()
	connectId, _ := uuid.NewRandom()
	bindSuccessful := false

	// Create test configuration
	appConfig := models.AppConfig{
		Users: []models.User{
			{
				Upn:      "testuser",
				Password: "testpass",
				Groups:   []string{"testgroup"},
			},
		},
	}

	// Create a mock bind request packet
	packet := createMockPacket(1, 0, true) // Tag 0 = Bind Request

	// Test that handlePacket doesn't close connection for bind request
	closeConnection := handlePacket(conn, packet, connectId, &bindSuccessful, appConfig)

	if closeConnection {
		t.Error("handlePacket should not close connection for bind request")
	}

	// Note: We can't easily test bindSuccessful because HandleBindRequest
	// expects specific packet structure that we're not providing in this mock
}

func TestHandlePacketUnbindRequest(t *testing.T) {
	// Create mock connection
	conn := mocks.NewMockConn()
	connectId, _ := uuid.NewRandom()
	bindSuccessful := true

	// Create test configuration
	appConfig := models.AppConfig{}

	// Create a mock unbind request packet
	packet := createMockPacket(2, 2, true) // Tag 2 = Unbind Request

	// Test that handlePacket closes connection for unbind request
	closeConnection := handlePacket(conn, packet, connectId, &bindSuccessful, appConfig)

	if !closeConnection {
		t.Error("handlePacket should close connection for unbind request")
	}

	if !conn.Closed {
		t.Error("connection should be closed after unbind request")
	}
}

func TestHandlePacketSearchRequest(t *testing.T) {
	// Create mock connection
	conn := mocks.NewMockConn()
	connectId, _ := uuid.NewRandom()
	bindSuccessful := true

	// Create test configuration
	appConfig := models.AppConfig{
		Groups: []models.Group{
			{
				Cn: "testgroup",
			},
		},
	}

	// Create a mock search request packet
	packet := createMockPacket(3, 3, true) // Tag 3 = Search Request

	// Test that handlePacket doesn't close connection for search request
	closeConnection := handlePacket(conn, packet, connectId, &bindSuccessful, appConfig)

	if closeConnection {
		t.Error("handlePacket should not close connection for search request")
	}

	// Note: We can't easily test the response because HandleSearchRequest
	// expects specific packet structure that we're not providing in this mock
}

func TestHandlePacketDeleteRequest(t *testing.T) {
	// Create mock connection
	conn := mocks.NewMockConn()
	connectId, _ := uuid.NewRandom()
	bindSuccessful := true

	// Create test configuration
	appConfig := models.AppConfig{
		Groups: []models.Group{
			{
				Cn: "testgroup",
			},
		},
	}

	// Create a mock delete request packet
	packet := createMockPacket(4, 10, true) // Tag 10 = Delete Request

	// Test that handlePacket doesn't close connection for delete request
	closeConnection := handlePacket(conn, packet, connectId, &bindSuccessful, appConfig)

	if closeConnection {
		t.Error("handlePacket should not close connection for delete request")
	}

	// Note: We can't easily test the response because HandleDeleteRequest
	// expects specific packet structure that we're not providing in this mock
}

func TestHandlePacketUnknownPacket(t *testing.T) {
	// Create mock connection
	conn := mocks.NewMockConn()
	connectId, _ := uuid.NewRandom()
	bindSuccessful := false

	// Create test configuration
	appConfig := models.AppConfig{}

	// Create a packet with wrong structure (not 2 children)
	packet := createMockPacket(5, 0, false) // Only one child

	// Test that handlePacket doesn't close connection for unknown packet
	closeConnection := handlePacket(conn, packet, connectId, &bindSuccessful, appConfig)

	if closeConnection {
		t.Error("handlePacket should not close connection for unknown packet")
	}
}

func TestHandlePacketUnsupportedOperation(t *testing.T) {
	// Create mock connection
	conn := mocks.NewMockConn()
	connectId, _ := uuid.NewRandom()
	bindSuccessful := false

	// Create test configuration
	appConfig := models.AppConfig{}

	// Create a packet with unsupported operation tag
	packet := createMockPacket(6, 99, true) // Tag 99 = Unsupported

	// Add some data to the operation child to prevent nil pointer issues
	if len(packet.Children) == 2 {
		packet.Children[1].Data = bytes.NewBuffer([]byte{0x01, 0x02, 0x03})
	}

	// Test that handlePacket doesn't close connection for unsupported operation
	closeConnection := handlePacket(conn, packet, connectId, &bindSuccessful, appConfig)

	if closeConnection {
		t.Error("handlePacket should not close connection for unsupported operation")
	}
}
