package bitcoin

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

type BlockHeader struct {
	Version    int32
	PrevHash   [32]byte
	MerkleRoot [32]byte
	Timestamp  uint32
	Bits       uint32
	Nonce      uint32
}

type Block struct {
	Header       BlockHeader
	Transactions []*Transaction
	Hash         string
	Height       int32
}

const Magic = 0xD9B4BEF9

func ParseBlockBuffer(data []byte) (*Block, error) {
	r := bytes.NewReader(data)
	block := &Block{}

	// Header
	headerRaw := make([]byte, 80)
	if _, err := io.ReadFull(r, headerRaw); err != nil {
		return nil, err
	}

	bh := BlockHeader{}
	hr := bytes.NewReader(headerRaw)
	binary.Read(hr, binary.LittleEndian, &bh.Version)
	io.ReadFull(hr, bh.PrevHash[:])
	io.ReadFull(hr, bh.MerkleRoot[:])
	binary.Read(hr, binary.LittleEndian, &bh.Timestamp)
	binary.Read(hr, binary.LittleEndian, &bh.Bits)
	binary.Read(hr, binary.LittleEndian, &bh.Nonce)
	block.Header = bh

	blockHash := doubleSha256(headerRaw)
	block.Hash = hex.EncodeToString(reverse(blockHash))

	txCount, err := ReadVarInt(r)
	if err != nil {
		return nil, err
	}

	block.Transactions = make([]*Transaction, txCount)
	for i := uint64(0); i < txCount; i++ {
		tx, err := ParseTransaction(r)
		if err != nil {
			return nil, fmt.Errorf("failed to parse tx %d: %v", i, err)
		}
		block.Transactions[i] = tx
	}

	// Height from coinbase (BIP34)
	if len(block.Transactions) > 0 {
		coinbase := block.Transactions[0]
		if len(coinbase.Inputs) > 0 {
			scriptSig := coinbase.Inputs[0].ScriptSig
			if len(scriptSig) > 0 {
				pushLen := int(scriptSig[0])
				if len(scriptSig) >= 1+pushLen {
					heightBytes := scriptSig[1 : 1+pushLen]
					var h uint32
					if pushLen <= 4 {
						temp := make([]byte, 4)
						copy(temp, heightBytes)
						h = binary.LittleEndian.Uint32(temp)
					}
					block.Height = int32(h)
				}
			}
		}
	}

	return block, nil
}

func ReadBlocks(blkData []byte, revData []byte) ([]*Block, error) {
	var blocks []*Block
	blkR := bytes.NewReader(blkData)
	revR := bytes.NewReader(revData)

	for {
		var magic uint32
		if err := binary.Read(blkR, binary.LittleEndian, &magic); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		if magic != Magic {
			continue
		}

		var size uint32
		if err := binary.Read(blkR, binary.LittleEndian, &size); err != nil {
			break
		}

		blockRaw := make([]byte, size)
		if _, err := io.ReadFull(blkR, blockRaw); err != nil {
			break
		}

		block, err := ParseBlockBuffer(blockRaw)
		if err != nil {
			return nil, err
		}

		// Parse corresponding undo data
		if revR != nil {
			var revMagic uint32
			if err := binary.Read(revR, binary.LittleEndian, &revMagic); err == nil {
				if revMagic == Magic {
					var revSize uint32
					if err := binary.Read(revR, binary.LittleEndian, &revSize); err == nil {
						revRaw := make([]byte, revSize)
						if _, err := io.ReadFull(revR, revRaw); err == nil {
							blockUndo, err := ParseBlockUndo(bytes.NewReader(revRaw))
							if err != nil {
								fmt.Fprintf(os.Stderr, "ParseBlockUndo error: %v\n", err)
							} else {
								// Map undo[i] to tx[i+1]
								for i, txUndo := range blockUndo.TxUndos {
									if i+1 < len(block.Transactions) {
										tx := block.Transactions[i+1]
										for j, inputUndo := range txUndo.Inputs {
											if j < len(tx.Inputs) {
												undo := inputUndo // copy
												tx.Inputs[j].PrevOutput = &undo
											}
										}
									}
								}
							}
						}
					}
				} else {
					
					revR.Seek(-4, io.SeekCurrent)
				}
			}
		}

		blocks = append(blocks, block)
	}

	return blocks, nil
}
