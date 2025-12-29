# SMAD Mocks Package

This package provides mock implementations for testing SMAD components.

## MockConn

`MockConn` is a mock implementation of the `net.Conn` interface designed for testing network-related functionality.

### Features

- **Full net.Conn interface implementation**: Can be used anywhere a real connection is expected
- **Configurable behavior**: Set read/write errors and close behavior
- **Inspection capabilities**: Examine what data was written to the connection
- **Reusable**: Reset and reuse mock connections between tests

### Usage

#### Basic Usage

```go
import "smad/internal/mocks"

// Create a new mock connection
conn := mocks.NewMockConn()

// Write data to the connection
n, err := conn.Write([]byte("test data"))

// Get all written data
writtenData := conn.GetWrittenData()

// Check if connection was closed
if conn.Closed {
    // Connection was closed
}
```

#### Advanced Configuration

```go
// Create mock with read data
conn := mocks.NewMockConn().WithReadData([]byte("response data"))

// Create mock with read error
conn := mocks.NewMockConn().WithReadError(errors.New("connection reset"))

// Create mock with write error
conn := mocks.NewMockConn().WithWriteError(errors.New("write failed"))

// Create mock with close error
conn := mocks.NewMockConn().WithCloseError(errors.New("close failed"))
```

#### Method Chaining

```go
// Chain multiple configurations
conn := mocks.NewMockConn()
    .WithReadData([]byte("request"))
    .WithWriteError(errors.New("network error"))
```

### API Reference

#### `NewMockConn() *MockConn`

Creates a new mock connection with default settings.

#### `WithReadData(data []byte) *MockConn`

Sets data that will be returned when `Read()` is called.

#### `WithReadError(err error) *MockConn`

Sets an error to be returned when `Read()` is called.

#### `WithWriteError(err error) *MockConn`

Sets an error to be returned when `Write()` is called.

#### `WithCloseError(err error) *MockConn`

Sets an error to be returned when `Close()` is called.

#### `GetWrittenData() []byte`

Returns all data that was written to the connection via `Write()` calls.

#### `Reset()`

Clears all buffers, flags, and error configurations, resetting the mock to its initial state.

### Properties

- `ReadBuf bytes.Buffer`: Buffer containing data to be read
- `WriteBuf bytes.Buffer`: Buffer containing written data
- `Closed bool`: Flag indicating if connection was closed
- `ReadError error`: Error to return on read operations
- `WriteError error`: Error to return on write operations
- `CloseError error`: Error to return on close operations

### Testing Examples

See `connection_example_test.go` for working examples of how to use `MockConn` in different scenarios.