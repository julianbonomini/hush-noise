package noise

import (
	"encoding/binary"
	"fmt"
	"io"
)

// writeFrame writes data to w with a 2-byte big-endian length prefix.
func writeFrame(w io.Writer, data []byte) error {
	if len(data) > maxMessageSize {
		return fmt.Errorf("noise: frame too large: %d bytes", len(data))
	}
	header := make([]byte, 2)
	binary.BigEndian.PutUint16(header, uint16(len(data)))
	if _, err := w.Write(header); err != nil {
		return fmt.Errorf("noise: write frame header: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("noise: write frame body: %w", err)
	}
	return nil
}

// readFrame reads a 2-byte big-endian length prefix then the body from r.
func readFrame(r io.Reader) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("noise: read frame header: %w", err)
	}
	size := binary.BigEndian.Uint16(header)
	body := make([]byte, size)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("noise: read frame body: %w", err)
	}
	return body, nil
}

// nopCloser wraps an io.ReadWriter that doesn't implement io.Closer.
type nopCloser struct{ io.ReadWriter }

func (nopCloser) Close() error { return nil }
