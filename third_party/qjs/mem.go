package qjs

import (
	"bytes"
	"math"
	"sync"

	"github.com/tetratelabs/wazero/api"
)

// Mem provides a safe interface for WebAssembly memory operations.
// It wraps the underlying wazero api.Memory with bounds checking and error handling.
type Mem struct {
	mu  sync.Mutex
	mem api.Memory
}

// Size returns the current size of the WebAssembly memory in bytes.
func (m *Mem) Size() uint32 {
	return m.mem.Size()
}

// UnpackPtr extracts address and size from a packed 64-bit value in memory.
// It reads 8 bytes from the memory address specified by packedPtr, reconstructs
// the original uint64 value, and then extracts the 32-bit address from the high bits
// and the 32-bit size from the low bits.
//
// Maintains original signature for backward compatibility - panics on error.
func (m *Mem) UnpackPtr(packedPtr uint64) (uint32, uint32) {
	if packedPtr == 0 {
		return 0, 0
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	packedBytes, err := m.Read(uint32(packedPtr), PackedPtrSize)
	if err != nil {
		panic(err)
	}

	// Reconstruct the packed value from little-endian bytes
	packed := uint64(0)
	for i := range PackedPtrSize {
		packed |= uint64(packedBytes[i]) << (i * 8)
	}

	// Extract address (high 32 bits) and size (low 32 bits)
	addr := uint32(packed >> 32)
	size := uint32(packed)

	return addr, size
}

// Read extracts bytes from WebAssembly memory at the specified address.
// Performs comprehensive validation and bounds checking.
func (m *Mem) Read(addr uint32, size uint64) ([]byte, error) {
	err := m.validateMemoryAccess(addr, size)
	if err != nil {
		return nil, err
	}

	if size == 0 {
		return []byte{}, nil
	}

	sizeU32 := uint32(size)

	buf, ok := m.mem.Read(addr, sizeU32)
	if !ok {
		return nil, ErrIndexOutOfRange
	}

	return buf, nil
}

// MustRead is like Read but panics on error.
func (m *Mem) MustRead(addr uint32, size uint64) []byte {
	buf, err := m.Read(addr, size)
	if err != nil {
		panic(err)
	}

	return buf
}

// Write copies the contents of byte slice b to WebAssembly memory starting at the given address.
// Uses Read to validate address and bounds before writing.
func (m *Mem) Write(addr uint32, b []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Validates address and bounds through Read call
	buf, err := m.Read(addr, uint64(len(b)))
	if err != nil {
		return err
	}

	copy(buf, b)

	return nil
}

// MustWrite is like Write but panics on error.
func (m *Mem) MustWrite(addr uint32, b []byte) {
	err := m.Write(addr, b)
	if err != nil {
		panic(err)
	}
}

// ReadUint8 reads a single byte from WebAssembly memory at the specified address.
func (m *Mem) ReadUint8(ptr uint32) (uint8, error) {
	err := m.validatePointer(ptr)
	if err != nil {
		return 0, err
	}

	v, ok := m.mem.ReadByte(ptr)
	if !ok {
		return 0, ErrIndexOutOfRange
	}

	return v, nil
}

// ReadUint32 reads a 32-bit unsigned integer from WebAssembly memory at the specified address.
func (m *Mem) ReadUint32(ptr uint32) (uint32, error) {
	err := m.validatePointer(ptr)
	if err != nil {
		return 0, err
	}

	v, ok := m.mem.ReadUint32Le(ptr)
	if !ok {
		return 0, ErrIndexOutOfRange
	}

	return v, nil
}

// ReadUint64 reads a 64-bit unsigned integer from WebAssembly memory at the specified address.
func (m *Mem) ReadUint64(ptr uint32) (uint64, error) {
	err := m.validatePointer(ptr)
	if err != nil {
		return 0, err
	}

	v, ok := m.mem.ReadUint64Le(ptr)
	if !ok {
		return 0, ErrIndexOutOfRange
	}

	return v, nil
}

// ReadFloat64 reads a 64-bit floating point number from WebAssembly memory at the specified address.
func (m *Mem) ReadFloat64(ptr uint32) (float64, error) {
	uint64Val, err := m.ReadUint64(ptr)
	if err != nil {
		return 0, err
	}

	return math.Float64frombits(uint64Val), nil
}

// WriteUint8 writes a single byte to WebAssembly memory at the specified address.
func (m *Mem) WriteUint8(ptr uint32, v uint8) error {
	err := m.validatePointer(ptr)
	if err != nil {
		return err
	}

	if ok := m.mem.WriteByte(ptr, v); !ok {
		return ErrIndexOutOfRange
	}

	return nil
}

// WriteUint32 writes a 32-bit unsigned integer to WebAssembly memory at the specified address.
func (m *Mem) WriteUint32(ptr uint32, v uint32) error {
	err := m.validatePointer(ptr)
	if err != nil {
		return err
	}

	if ok := m.mem.WriteUint32Le(ptr, v); !ok {
		return ErrIndexOutOfRange
	}

	return nil
}

// WriteUint64 writes a 64-bit unsigned integer to WebAssembly memory at the specified address.
func (m *Mem) WriteUint64(ptr uint32, v uint64) error {
	err := m.validatePointer(ptr)
	if err != nil {
		return err
	}

	if ok := m.mem.WriteUint64Le(ptr, v); !ok {
		return ErrIndexOutOfRange
	}

	return nil
}

// WriteFloat64 writes a 64-bit floating point number to WebAssembly memory at the specified address.
func (m *Mem) WriteFloat64(ptr uint32, v float64) error {
	return m.WriteUint64(ptr, math.Float64bits(v))
}

// ReadString reads a null-terminated string from WebAssembly memory starting at the given address.
// It reads up to maxlen bytes and returns the string without the null terminator.
func (m *Mem) ReadString(addr, maxlen uint32) (string, error) {
	err := m.validatePointer(addr)
	if err != nil {
		return "", err
	}

	if maxlen == 0 {
		return "", nil
	}

	readLen := m.calculateSafeReadLength(addr, maxlen)

	buf, ok := m.mem.Read(addr, readLen)
	if !ok {
		return "", ErrIndexOutOfRange
	}

	// Find null terminator
	nullIndex := bytes.IndexByte(buf, StringTerminator)
	if nullIndex < 0 {
		return "", ErrNoNullTerminator
	}

	return string(buf[:nullIndex]), nil
}

// WriteString writes a null-terminated string to WebAssembly memory.
// It copies the string content to the specified memory address and appends a null terminator.
func (m *Mem) WriteString(ptr uint32, s string) error {
	size := uint64(len(s) + 1) // +1 for null terminator

	// Validates address and bounds through Read call
	buf, err := m.Read(ptr, size)
	if err != nil {
		return err
	}

	copy(buf, s)
	buf[len(s)] = StringTerminator

	return nil
}

// StringFromPackedPtr reads a string from a packed pointer containing address and size.
// Maintains original signature for backward compatibility - panics on error.
func (m *Mem) StringFromPackedPtr(ptr uint64) string {
	addr, size := m.UnpackPtr(ptr)

	str, err := m.ReadString(addr, size)
	if err != nil {
		panic(err)
	}

	return str
}

// validatePointer checks if a pointer is valid (non-null).
func (m *Mem) validatePointer(ptr uint32) error {
	if ptr == NullPtr {
		return ErrInvalidPointer
	}

	return nil
}

// validateSize checks if a size is within valid bounds.
func (m *Mem) validateSize(size uint64) error {
	if size > math.MaxUint32 {
		return ErrIndexOutOfRange
	}

	return nil
}

// validateMemoryAccess performs comprehensive validation for memory operations.
func (m *Mem) validateMemoryAccess(ptr uint32, size uint64) error {
	err := m.validatePointer(ptr)
	if err != nil {
		return err
	}

	if err = m.validateSize(size); err != nil {
		return err
	}

	return nil
}

// calculateSafeReadLength calculates a safe read length for string operations.
func (m *Mem) calculateSafeReadLength(addr, maxlen uint32) uint32 {
	memSize := m.mem.Size()

	if maxlen == math.MaxUint32 {
		return memSize - addr
	}

	// Calculate safe read length including null terminator space
	available := memSize - addr
	if available <= maxlen {
		return available
	}

	return maxlen + 1
}
