package bitcoin

import (
	"bufio"
	"io"
)

type TxUndo struct {
	Inputs []PrevOutput
}

type BlockUndo struct {
	TxUndos []TxUndo
}

func readBitcoinVarInt(r io.Reader) (uint64, error) {
	var n uint64
	var b [1]byte
	for {
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, err
		}
		n = (n << 7) | uint64(b[0]&0x7F)
		if b[0]&0x80 != 0 {
			n++
		} else {
			return n, nil
		}
	}
}

// decompressAmount reverses Bitcoin Core's CompressAmount encoding.
func decompressAmount(x uint64) int64 {
	if x == 0 {
		return 0
	}
	x--
	e := x % 10
	x /= 10
	var n uint64
	if e < 9 {
		d := (x%9) + 1
		x /= 9
		n = x*10 + d
	} else {
		n = x + 1
	}
	for e > 0 {
		n *= 10
		e--
	}
	return int64(n)
}

func readCompressedScript(r io.Reader) ([]byte, error) {
	nSize, err := readBitcoinVarInt(r)
	if err != nil {
		return nil, err
	}
	switch nSize {
	case 0x00: // P2PKH: OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
		hash := make([]byte, 20)
		if _, err := io.ReadFull(r, hash); err != nil {
			return nil, err
		}
		script := make([]byte, 25)
		script[0] = 0x76
		script[1] = 0xa9
		script[2] = 0x14
		copy(script[3:], hash)
		script[23] = 0x88
		script[24] = 0xac
		return script, nil
	case 0x01: // P2SH: OP_HASH160 <20-byte hash> OP_EQUAL
		hash := make([]byte, 20)
		if _, err := io.ReadFull(r, hash); err != nil {
			return nil, err
		}
		script := make([]byte, 23)
		script[0] = 0xa9
		script[1] = 0x14
		copy(script[2:], hash)
		script[22] = 0x87
		return script, nil
	case 0x02, 0x03: // P2PK compressed pubkey
		rest := make([]byte, 32)
		if _, err := io.ReadFull(r, rest); err != nil {
			return nil, err
		}
		pubkey := make([]byte, 33)
		pubkey[0] = byte(nSize)
		copy(pubkey[1:], rest)
		script := make([]byte, 35)
		script[0] = 0x21
		copy(script[1:], pubkey)
		script[34] = 0xac
		return script, nil
	case 0x04, 0x05: // P2PK uncompressed (only X coordinate stored)
		rest := make([]byte, 32)
		if _, err := io.ReadFull(r, rest); err != nil {
			return nil, err
		}
		pubkey := make([]byte, 33)
		pubkey[0] = byte(nSize)
		copy(pubkey[1:], rest)
		script := make([]byte, 35)
		script[0] = 0x21
		copy(script[1:], pubkey)
		script[34] = 0xac
		return script, nil
	default: // General script: nSize = rawLen + 6
		scriptLen := nSize - 6
		script := make([]byte, scriptLen)
		if _, err := io.ReadFull(r, script); err != nil {
			return nil, err
		}
		return script, nil
	}
}

func ParseBlockUndo(r io.Reader) (*BlockUndo, error) {
	br := bufio.NewReader(r)
	txUndoCount, err := ReadVarInt(br) // CompactSize
	if err != nil {
		return nil, err
	}

	blockUndo := &BlockUndo{
		TxUndos: make([]TxUndo, txUndoCount),
	}

	for i := uint64(0); i < txUndoCount; i++ {
		inputUndoCount, err := ReadVarInt(br) // CompactSize
		if err != nil {
			return nil, err
		}

		txUndo := TxUndo{
			Inputs: make([]PrevOutput, inputUndoCount),
		}

		for j := uint64(0); j < inputUndoCount; j++ {
			// code = height * 2 + isCoinbase (Bitcoin Core VARINT)
			_, err := readBitcoinVarInt(br)
			if err != nil {
				return nil, err
			}
			
			next, err := br.Peek(1)
			if err == nil && next[0] == 0x00 {
				br.ReadByte() // Consume the extra 0
			}

			// Amount stored as VARINT(CompressAmount(satoshis))
			compressedVal, err := readBitcoinVarInt(br)
			if err != nil {
				return nil, err
			}
			val := decompressAmount(compressedVal)
			
			// Script in CScriptCompressor format
			script, err := readCompressedScript(br)
			if err != nil {
				return nil, err
			}

			txUndo.Inputs[j] = PrevOutput{
				Value:        val,
				ScriptPubKey: script,
				ScriptType:   ClassifyScript(script),
			}
		}
		blockUndo.TxUndos[i] = txUndo
	}

	return blockUndo, nil
}

func ApplyXor(data []byte, key []byte) {
	if len(key) == 0 {
		return
	}
	allZeros := true
	for _, b := range key {
		if b != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		return
	}

	for i := range data {
		data[i] ^= key[i%len(key)]
	}
}
