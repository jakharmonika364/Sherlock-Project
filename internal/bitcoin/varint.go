package bitcoin

import (
	"encoding/binary"
	"io"
)

// ReadVarInt reads a Bitcoin variable-length integer from an io.Reader.
func ReadVarInt(r io.Reader) (uint64, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}

	header := b[0]
	if header < 0xfd {
		return uint64(header), nil
	}

	if header == 0xfd {
		var v uint16
		if err := binary.Read(r, binary.LittleEndian, &v); err != nil {
			return 0, err
		}
		return uint64(v), nil
	}

	if header == 0xfe {
		var v uint32
		if err := binary.Read(r, binary.LittleEndian, &v); err != nil {
			return 0, err
		}
		return uint64(v), nil
	}

	// header == 0xff
	var v uint64
	if err := binary.Read(r, binary.LittleEndian, &v); err != nil {
		return 0, err
	}
	return v, nil
}
