package mocks

import (
	"bytes"
	"net"
	"time"
)

// MockConn is a mock implementation of net.Conn interface for testing
type MockConn struct {
	ReadBuf    bytes.Buffer
	WriteBuf   bytes.Buffer
	Closed     bool
	ReadError  error
	WriteError error
	CloseError error
}

// Read implements the net.Conn Read method
func (m *MockConn) Read(b []byte) (n int, err error) {
	if m.ReadError != nil {
		return 0, m.ReadError
	}
	return m.ReadBuf.Read(b)
}

// Write implements the net.Conn Write method
func (m *MockConn) Write(b []byte) (n int, err error) {
	if m.WriteError != nil {
		return 0, m.WriteError
	}
	return m.WriteBuf.Write(b)
}

// Close implements the net.Conn Close method
func (m *MockConn) Close() error {
	m.Closed = true
	return m.CloseError
}

// LocalAddr implements the net.Conn LocalAddr method
func (m *MockConn) LocalAddr() net.Addr {
	return &mockAddr{}
}

// RemoteAddr implements the net.Conn RemoteAddr method
func (m *MockConn) RemoteAddr() net.Addr {
	return &mockAddr{}
}

// SetDeadline implements the net.Conn SetDeadline method
func (m *MockConn) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline implements the net.Conn SetReadDeadline method
func (m *MockConn) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline implements the net.Conn SetWriteDeadline method
func (m *MockConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// mockAddr is a simple implementation of net.Addr for testing
type mockAddr struct{}

// Network implements the net.Addr Network method
func (m *mockAddr) Network() string {
	return "tcp"
}

// String implements the net.Addr String method
func (m *mockAddr) String() string {
	return "localhost:389"
}

// NewMockConn creates a new MockConn with optional error configurations
func NewMockConn() *MockConn {
	return &MockConn{}
}

// WithReadData sets the data that will be returned by Read
func (m *MockConn) WithReadData(data []byte) *MockConn {
	m.ReadBuf.Write(data)
	return m
}

// WithReadError sets an error to be returned by Read
func (m *MockConn) WithReadError(err error) *MockConn {
	m.ReadError = err
	return m
}

// WithWriteError sets an error to be returned by Write
func (m *MockConn) WithWriteError(err error) *MockConn {
	m.WriteError = err
	return m
}

// WithCloseError sets an error to be returned by Close
func (m *MockConn) WithCloseError(err error) *MockConn {
	m.CloseError = err
	return m
}

// GetWrittenData returns all data written to the connection
func (m *MockConn) GetWrittenData() []byte {
	return m.WriteBuf.Bytes()
}

// Reset clears all buffers and flags
func (m *MockConn) Reset() {
	m.ReadBuf.Reset()
	m.WriteBuf.Reset()
	m.Closed = false
	m.ReadError = nil
	m.WriteError = nil
	m.CloseError = nil
}
