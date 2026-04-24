package bitcoin

import "bytes"

// ClassifyPathPubKey classifies a script_pubkey into a Bitcoin address type.
func ClassifyScript(script []byte) string {
	n := len(script)
	if n == 25 && script[0] == 0x76 && script[1] == 0xa9 && script[2] == 0x14 && script[23] == 0x88 && script[24] == 0xac {
		return "p2pkh"
	}
	if n == 23 && script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87 {
		return "p2sh"
	}
	if n == 22 && script[0] == 0x00 && script[1] == 0x14 {
		return "p2wpkh"
	}
	if n == 34 && script[0] == 0x00 && script[1] == 0x20 {
		return "p2wsh"
	}
	if n == 34 && script[0] == 0x51 && script[1] == 0x20 {
		return "p2tr"
	}
	if n > 0 && script[0] == 0x6a {
		return "op_return"
	}
	return "unknown"
}

// IsOpReturn checks if a script is an OP_RETURN.
func IsOpReturn(script []byte) bool {
	return len(script) > 0 && script[0] == 0x6a
}

// GetOpReturnProtocol extracts the protocol from an OP_RETURN script.
func GetOpReturnProtocol(script []byte) string {
	if !IsOpReturn(script) {
		return ""
	}
	// Skip OP_RETURN (0x6a) and the push opcode
	if len(script) < 2 {
		return "unknown"
	}

	data := script[2:] // Assume 1-byte push if following standard patterns
	if len(data) == 0 {
		return "unknown"
	}

	if bytes.HasPrefix(data, []byte{0x6f, 0x6d, 0x6e, 0x69}) {
		return "omni"
	}
	if data[0] == 0x08 {
		return "opentimestamps"
	}
	if bytes.HasPrefix(data, []byte{0x52, 0x55, 0x4e, 0x45}) {
		return "runes"
	}
	return "unknown"
}
