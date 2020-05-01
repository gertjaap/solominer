package composer

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil/base58"
	"github.com/gertjaap/solominer/config"
)

var CoinbaseFlags = "/P2SH/Solominer/xxxxxxxx"

func ComposeBlock(rpc *rpcclient.Client, cfg config.MinerConfig) (*wire.MsgBlock, []*chainhash.Hash, int, error) {

	var params = map[string]interface{}{}
	params["rules"] = []string{"segwit"}
	j, err := json.Marshal(params)
	if err != nil {
		return nil, nil, -1, err
	}
	res, err := rpc.RawRequest("getblocktemplate", []json.RawMessage{j})
	if err != nil {
		return nil, nil, -1, err
	}
	err = json.Unmarshal(res, &params)
	if err != nil {
		return nil, nil, -1, err
	}

	prevHash, _ := chainhash.NewHashFromStr(params["previousblockhash"].(string))
	hexBits, _ := hex.DecodeString(params["bits"].(string))
	bits := binary.BigEndian.Uint32(hexBits)

	height := int64(params["height"].(float64))
	coinbaseScript, err := txscript.NewScriptBuilder().AddInt64(height).AddInt64(int64(0)).AddData([]byte(CoinbaseFlags)).Script()
	if err != nil {
		return nil, nil, -1, err
	}

	scriptHash, _, err := base58.CheckDecode(cfg.PayRewardsTo)
	if err != nil {
		return nil, nil, -1, fmt.Errorf("invalid_address")
	}
	if len(scriptHash) != 20 {
		return nil, nil, -1, fmt.Errorf("invalid_address_length")
	}
	pkScript, err := txscript.NewScriptBuilder().AddOp(txscript.OP_HASH160).AddData(scriptHash).AddOp(txscript.OP_EQUAL).Script()
	if err != nil {
		return nil, nil, -1, fmt.Errorf("script_failure")
	}

	coinbaseTx := wire.NewMsgTx(wire.TxVersion)
	var witnessNonce [blockchain.CoinbaseWitnessDataLen]byte
	coinbaseTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: *wire.NewOutPoint(&chainhash.Hash{}, wire.MaxPrevOutIndex),
		SignatureScript:  coinbaseScript,
		Sequence:         wire.MaxTxInSequenceNum,
		Witness:          wire.TxWitness{witnessNonce[:]},
	})
	coinbaseTx.AddTxOut(&wire.TxOut{
		Value:    int64(params["coinbasevalue"].(float64)),
		PkScript: pkScript,
	})

	coinbaseHash := coinbaseTx.TxHash()
	version := int32(params["version"].(float64))
	hdr := wire.NewBlockHeader(version, prevHash, &coinbaseHash, bits, 0)
	blk := wire.NewMsgBlock(hdr)
	blk.Transactions = []*wire.MsgTx{coinbaseTx}

	txs := params["transactions"].([]interface{})
	for _, tx := range txs {
		txMap := tx.(map[string]interface{})
		txBytes, _ := hex.DecodeString(txMap["data"].(string))
		mtx := wire.NewMsgTx(1)
		mtx.Deserialize(bytes.NewReader(txBytes))
		blk.Transactions = append(blk.Transactions, mtx)
	}
	nextPoT := NextPowerOfTwo(len(blk.Transactions))
	arraySize := nextPoT*2 - 1
	merkles := make([]*chainhash.Hash, arraySize)
	witnessMerkles := make([]*chainhash.Hash, arraySize)

	for i, tx := range blk.Transactions {
		if i == 0 {
			var zeroHash chainhash.Hash
			witnessMerkles[i] = &zeroHash
		} else {
			wh := tx.WitnessHash()
			witnessMerkles[i] = &wh
		}
	}
	MerkleStuff(witnessMerkles, nextPoT)

	var witnessPreimage [64]byte
	copy(witnessPreimage[:32], witnessMerkles[arraySize-1][:])
	copy(witnessPreimage[32:], witnessNonce[:])
	witnessCommitment := chainhash.DoubleHashB(witnessPreimage[:])
	witnessScript := append(blockchain.WitnessMagicBytes, witnessCommitment...)
	commitmentOutput := &wire.TxOut{
		Value:    0,
		PkScript: witnessScript,
	}
	coinbaseTx.TxOut = append(coinbaseTx.TxOut, commitmentOutput)

	for i, tx := range blk.Transactions {
		h := tx.TxHash()
		merkles[i] = &h
	}

	MerkleStuff(merkles, nextPoT)
	blk.Header.MerkleRoot = *(merkles[arraySize-1])
	coinbaseProof := NewMerkleProof(merkles, 0)
	return blk, coinbaseProof, int(height), nil
}

func NewMerkleProof(merkleTree []*chainhash.Hash, idx uint64) []*chainhash.Hash {
	treeHeight := calcTreeHeight(uint64((len(merkleTree) + 1) / 2))

	proof := make([]*chainhash.Hash, treeHeight)
	for i := uint(0); i < treeHeight; i++ {
		if merkleTree[idx^1] == nil {
			// From the documentation of BuildMerkleTreeStore: "parent nodes
			// "with only a single left node are calculated by concatenating
			// the left node with itself before hashing."
			proof[i] = merkleTree[idx] // add "ourselves"
		} else {
			proof[i] = merkleTree[idx^1]
		}

		idx = (idx >> 1) | (1 << treeHeight)
	}
	return proof
}

func calcTreeHeight(n uint64) (e uint) {
	for ; (1 << e) < n; e++ {
	}
	return
}

func MerkleStuff(merkles []*chainhash.Hash, offset int) {
	for i := 0; i < len(merkles)-1; i += 2 {
		switch {
		// When there is no left child node, the parent is nil too.
		case merkles[i] == nil:
			merkles[offset] = nil

		// When there is no right child, the parent is generated by
		// hashing the concatenation of the left child with itself.
		case merkles[i+1] == nil:
			newHash := blockchain.HashMerkleBranches(merkles[i], merkles[i])
			merkles[offset] = newHash

		// The normal case sets the parent node to the double sha256
		// of the concatentation of the left and right children.
		default:
			newHash := blockchain.HashMerkleBranches(merkles[i], merkles[i+1])
			merkles[offset] = newHash
		}
		offset++
	}
}

func NextPowerOfTwo(n int) int {
	// Return the number if it's already a power of 2.
	if n&(n-1) == 0 {
		return n
	}

	// Figure out and return the next power of two.
	exponent := uint(math.Log2(float64(n))) + 1
	return 1 << exponent // 2^exponent
}