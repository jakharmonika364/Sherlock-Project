package bitcoin

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
)

type Input struct {
	PrevTxid   [32]byte
	PrevVout   uint32
	ScriptSig  []byte
	Sequence   uint32
	Witness    [][]byte
	PrevOutput *PrevOutput // From undo data
}

type PrevOutput struct {
	Value        int64
	ScriptPubKey []byte
	ScriptType   string
}

type Output struct {
	Value        int64
	ScriptPubKey []byte
	ScriptType   string
}

type Transaction struct {
	Version  int32
	Inputs   []Input
	Outputs  []Output
	Locktime uint32
	TXID     string
	VSize    int32
	Size     int32
	IsSegwit bool
}

func (tx *Transaction) IsCoinbase() bool {
	if len(tx.Inputs) == 0 {
		return false
	}
	in := tx.Inputs[0]
	allZeros := true
	for _, b := range in.PrevTxid {
		if b != 0 {
			allZeros = false
			break
		}
	}
	return allZeros && in.PrevVout == 0xffffffff
}

func ParseTransaction(r *bytes.Reader) (*Transaction, error) {
	startPos := r.Size() - int64(r.Len())
	tx := &Transaction{}

	if err := binary.Read(r, binary.LittleEndian, &tx.Version); err != nil {
		return nil, err
	}

	// Segwit check
	var marker [2]byte
	if _, err := io.ReadFull(r, marker[:]); err != nil {
		return nil, err
	}
	if marker[0] == 0x00 && marker[1] == 0x01 {
		tx.IsSegwit = true
	} else {
		// Not segwit, seek back 2 bytes
		r.Seek(-2, io.SeekCurrent)
	}

	inputCount, err := ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	tx.Inputs = make([]Input, inputCount)
	for i := uint64(0); i < inputCount; i++ {
		in := &tx.Inputs[i]
		if _, err := io.ReadFull(r, in.PrevTxid[:]); err != nil {
			return nil, err
		}
		if err := binary.Read(r, binary.LittleEndian, &in.PrevVout); err != nil {
			return nil, err
		}
		scriptLen, err := ReadVarInt(r)
		if err != nil {
			return nil, err
		}
		in.ScriptSig = make([]byte, scriptLen)
		if _, err := io.ReadFull(r, in.ScriptSig); err != nil {
			return nil, err
		}
		if err := binary.Read(r, binary.LittleEndian, &in.Sequence); err != nil {
			return nil, err
		}
	}

	outputCount, err := ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	tx.Outputs = make([]Output, outputCount)
	for i := uint64(0); i < outputCount; i++ {
		out := &tx.Outputs[i]
		if err := binary.Read(r, binary.LittleEndian, &out.Value); err != nil {
			return nil, err
		}
		scriptLen, err := ReadVarInt(r)
		if err != nil {
			return nil, err
		}
		out.ScriptPubKey = make([]byte, scriptLen)
		if _, err := io.ReadFull(r, out.ScriptPubKey); err != nil {
			return nil, err
		}
		out.ScriptType = ClassifyScript(out.ScriptPubKey)
	}

	if tx.IsSegwit {
		for i := uint64(0); i < inputCount; i++ {
			witnessCount, err := ReadVarInt(r)
			if err != nil {
				return nil, err
			}
			tx.Inputs[i].Witness = make([][]byte, witnessCount)
			for j := uint64(0); j < witnessCount; j++ {
				itemLen, err := ReadVarInt(r)
				if err != nil {
					return nil, err
				}
				item := make([]byte, itemLen)
				if _, err := io.ReadFull(r, item); err != nil {
					return nil, err
				}
				tx.Inputs[i].Witness[j] = item
			}
		}
	}

	if err := binary.Read(r, binary.LittleEndian, &tx.Locktime); err != nil {
		return nil, err
	}

	endPos := r.Size() - int64(r.Len())
	fullRaw := make([]byte, endPos-startPos)
	r.Seek(startPos, io.SeekStart)
	if _, err := io.ReadFull(r, fullRaw); err != nil {
		return nil, err
	}
	r.Seek(endPos, io.SeekStart)

	tx.Size = int32(len(fullRaw))

	// TXID serialization (non-witness)
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, tx.Version)
	WriteVarInt(&buf, uint64(len(tx.Inputs)))
	for _, in := range tx.Inputs {
		buf.Write(in.PrevTxid[:])
		binary.Write(&buf, binary.LittleEndian, in.PrevVout)
		WriteVarInt(&buf, uint64(len(in.ScriptSig)))
		buf.Write(in.ScriptSig)
		binary.Write(&buf, binary.LittleEndian, in.Sequence)
	}
	WriteVarInt(&buf, uint64(len(tx.Outputs)))
	for _, out := range tx.Outputs {
		binary.Write(&buf, binary.LittleEndian, out.Value)
		WriteVarInt(&buf, uint64(len(out.ScriptPubKey)))
		buf.Write(out.ScriptPubKey)
	}
	binary.Write(&buf, binary.LittleEndian, tx.Locktime)

	nonWitnessSerialization := buf.Bytes()
	txIDHash := doubleSha256(nonWitnessSerialization)
	tx.TXID = hex.EncodeToString(reverse(txIDHash))

	nonWitnessSize := int32(len(nonWitnessSerialization))
	// vsize = max(non_witness_size, (non_witness_size*3 + total_size + 3) / 4)
	vsize := (nonWitnessSize*3 + tx.Size + 3) / 4
	if nonWitnessSize > vsize {
		tx.VSize = nonWitnessSize
	} else {
		tx.VSize = vsize
	}

	return tx, nil
}

func WriteVarInt(w io.Writer, v uint64) error {
	if v < 0xfd {
		return binary.Write(w, binary.LittleEndian, uint8(v))
	} else if v <= 0xffff {
		binary.Write(w, binary.LittleEndian, uint8(0xfd))
		return binary.Write(w, binary.LittleEndian, uint16(v))
	} else if v <= 0xffffffff {
		binary.Write(w, binary.LittleEndian, uint8(0xfe))
		return binary.Write(w, binary.LittleEndian, uint32(v))
	} else {
		binary.Write(w, binary.LittleEndian, uint8(0xff))
		return binary.Write(w, binary.LittleEndian, uint64(v))
	}
}

func doubleSha256(b []byte) []byte {
	h := sha256.Sum256(b)
	h2 := sha256.Sum256(h[:])
	return h2[:]
}

func reverse(b []byte) []byte {
	res := make([]byte, len(b))
	for i := range b {
		res[i] = b[len(b)-1-i]
	}
	return res
}
