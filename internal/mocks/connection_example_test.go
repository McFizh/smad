package mocks_test

import (
	"errors"
	"fmt"
	"testing"

	"smad/internal/mocks"
)

// Example of using MockConn with various configurations
func ExampleMockConn() {
	// Create a basic mock connection
	conn := mocks.NewMockConn()

	// Write some data to the connection
	n, err := conn.Write([]byte("test data"))
	if err != nil {
		panic(err)
	}

	// Get the written data
	writtenData := conn.GetWrittenData()
	fmt.Printf("Written %d bytes: %s\n", n, string(writtenData))

	// Check if connection is closed
	fmt.Printf("Connection closed: %t\n", conn.Closed)

	// Output:
	// Written 9 bytes: test data
	// Connection closed: false
}

// Example of using MockConn with error configurations
func ExampleMockConn_withErrors() {
	// Create a mock connection with read error
	conn := mocks.NewMockConn().WithReadError(errors.New("read error"))

	// Try to read - should return the error
	buf := make([]byte, 10)
	n, err := conn.Read(buf)
	fmt.Printf("Read error: %v, bytes read: %d\n", err, n)

	// Output:
	// Read error: read error, bytes read: 0
}

// Test to verify the examples work
func TestExamples(t *testing.T) {
	// This test just ensures the examples compile and run
	ExampleMockConn()
	ExampleMockConn_withErrors()
}
