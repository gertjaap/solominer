package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/gertjaap/solominer/composer"
	"github.com/gertjaap/solominer/config"
	"github.com/gertjaap/solominer/stratum"
	"github.com/gertjaap/solominer/util"

	"github.com/adamcollier1/lyra2rev3"
)

type StratumClient struct {
	ID                     int32
	conn                   *stratum.StratumConnection
	Difficulty             float64
	ExtraNonce1            []byte
	ExtraNonce2Size        int8
	Target                 []byte
	SubscribedToExtraNonce bool
}

var powFunc func(data []byte) ([]byte, error)

var clients = sync.Map{}
var currentBlock *wire.MsgBlock
var currentJob []interface{}
var currentJobID int32
var currentCoinbase1 []byte
var currentCoinbase2 []byte
var currentDiff float64
var submitBlockLock = sync.Mutex{}
var nextClientID int32
var powLimit *big.Float
var rpc *rpcclient.Client

func main() {

	cfg, err := config.GetConfig()
	if err != nil {
		log.Printf("Could not find config. Make sure it exists in the executable path (solominer.json)\n")
		os.Exit(-1)
	}

	switch cfg.PoWFunc {
	case "lyra2rev3":
		powFunc = lyra2rev3.SumV3
	default:
		powFunc = lyra2rev3.SumV3
	}

	rpc, err = rpcclient.New(&rpcclient.ConnConfig{
		HTTPPostMode: true,
		Host:         cfg.RpcHost,
		User:         cfg.RpcUser,
		Pass:         cfg.RpcPassword,
		DisableTLS:   true,
	}, nil)

	if err != nil {
		panic(err)
	}

	if cfg.PayRewardsTo == "" {
		log.Printf("Configured address is empty, generating one through RPC\n")
		addr, err := rpc.RawRequest("getnewaddress", []json.RawMessage{[]byte("\"\"")})
		if err != nil {
			panic(err)
		}
		json.Unmarshal(addr, &cfg.PayRewardsTo)
		log.Printf("Paying rewards to %s\n", cfg.PayRewardsTo)
	}
	h, err := rpc.GetBlockHash(0)
	if err != nil {
		panic(err)
	}

	hdr, err := rpc.GetBlockHeader(h)
	if err != nil {
		panic(err)
	}

	powLimitInt := blockchain.CompactToBig(hdr.Bits)
	powLimit = big.NewFloat(0)
	powLimit.SetInt(powLimitInt)

	srv, err := stratum.NewStratumListener(cfg.StratumPort)
	if err != nil {
		panic(err)
	}

	log.Printf("Stratum server listening on port %d\n", cfg.StratumPort)

	blk, merkles, height, err := composer.ComposeBlock(rpc, cfg)
	if err != nil {
		panic(err)
	}
	setCurrentJob(blk, merkles, height)

	go func() {
		for {
			time.Sleep(time.Second * 5)
			blk, merkles, height, err := composer.ComposeBlock(rpc, cfg)
			if err == nil && !blk.Header.MerkleRoot.IsEqual(&currentBlock.Header.MerkleRoot) {
				setCurrentJob(blk, merkles, height)
				resetWork()
			}
		}
	}()

	for {
		conn, err := srv.Accept()

		clientID := atomic.AddInt32(&nextClientID, 1)

		if err != nil {
			panic(err)
		}

		extraNonce1 := make([]byte, 4)
		binary.LittleEndian.PutUint32(extraNonce1, uint32(clientID))

		clt := StratumClient{
			ID:                     clientID,
			conn:                   conn,
			Difficulty:             0,
			ExtraNonce2Size:        4,
			ExtraNonce1:            extraNonce1,
			Target:                 []byte{},
			SubscribedToExtraNonce: false,
		}

		/*conn.LogOutput = func(logs []stratum.CommEvent) {
			for _, l := range logs {
				j, _ := json.Marshal(l.Message)
				dir := "> "
				if l.In {
					dir = "< "
				}
				log.Printf("%s %s", dir, string(j))
			}
		}*/

		clients.Store(clientID, &clt)

		go serveClient(&clt)
	}

}

func resetWork() {
	clients.Range(func(k interface{}, c interface{}) bool {
		clt, ok := c.(*StratumClient)
		if !ok {
			return true
		}
		clt.SendWork()
		return true
	})
}

func serveClient(client *StratumClient) {
	log.Printf("New stratum client connected: %d", client.ID)
	for {
		close := false
		select {
		case msg := <-client.conn.Incoming:
			processStratumMessage(client, msg)
		case <-client.conn.Disconnected:
			log.Printf("Stratum client %d disconnected", client.ID)
			close = true
		}

		if close {
			clients.Delete(client.ID)
			break
		}
	}
	client.conn.Stop()
}

func setCurrentJob(block *wire.MsgBlock, coinbaseMerkleProof []*chainhash.Hash, height int) {
	log.Printf("Configuring new job at height %d\n", height)
	jobId := atomic.AddInt32(&currentJobID, 1)

	target := blockchain.CompactToBig(block.Header.Bits)
	targetFloat := big.NewFloat(0).SetInt(target)
	currentDiff, _ = big.NewFloat(0).Quo(powLimit, targetFloat).Float64()
	currentDiff /= 10
	coinbaseMerkles := make([]string, len(coinbaseMerkleProof))
	for i, m := range coinbaseMerkleProof {
		coinbaseMerkles[i] = fmt.Sprintf("%x", m.CloneBytes())
	}

	var buf bytes.Buffer
	block.Transactions[0].SerializeNoWitness(&buf)

	coinbaseBytes := buf.Bytes()
	extraNoncePosition := bytes.IndexAny(coinbaseBytes, "xxxxxxxx") // Position of the extranonce data
	versionBytes := make([]byte, 4)
	nBits := make([]byte, 4)
	timestamp := make([]byte, 4)
	binary.BigEndian.PutUint32(versionBytes, uint32(block.Header.Version))
	binary.BigEndian.PutUint32(nBits, block.Header.Bits)
	binary.BigEndian.PutUint32(timestamp, uint32(block.Header.Timestamp.Unix()))

	currentCoinbase1 = coinbaseBytes[0:extraNoncePosition]
	currentCoinbase2 = coinbaseBytes[extraNoncePosition+8:]

	currentJob = []interface{}{
		fmt.Sprintf("%x", jobId),
		fmt.Sprintf("%x", util.RevHashBytes(util.ReverseByteArray(block.Header.PrevBlock.CloneBytes()))),
		fmt.Sprintf("%x", currentCoinbase1),
		fmt.Sprintf("%x", currentCoinbase2),
		coinbaseMerkles,
		fmt.Sprintf("%x", versionBytes),
		fmt.Sprintf("%x", nBits),
		fmt.Sprintf("%x", timestamp),
		true,
	}

	currentBlock = block
	log.Printf("Job ready!\n")

}

func (client *StratumClient) SendWork() {
	log.Printf("Sending job to miner")
	if client.Difficulty != currentDiff {
		client.conn.Outgoing <- stratum.StratumMessage{
			RemoteMethod: "mining.set_difficulty",
			Parameters:   []interface{}{currentDiff},
		}
		client.Difficulty = currentDiff
	}

	client.conn.Outgoing <- stratum.StratumMessage{
		RemoteMethod: "mining.notify",
		Parameters:   currentJob,
	}
}

func processStratumMessage(client *StratumClient, msg stratum.StratumMessage) {
	err := msg.Error
	if err != nil {
		log.Printf("Error response received: %v\n", err)
	}

	switch msg.RemoteMethod {
	case "mining.authorize":
		client.conn.Outgoing <- stratum.StratumMessage{
			MessageID: msg.Id(),
			Result:    true,
		}
	case "mining.extranonce.subscribe":
		client.SubscribedToExtraNonce = true
		client.conn.Outgoing <- stratum.StratumMessage{
			MessageID: msg.Id(),
			Result:    true,
		}
		client.conn.Outgoing <- stratum.StratumMessage{
			RemoteMethod: "mining.set_extranonce",
			Parameters: []interface{}{
				fmt.Sprintf("%x", client.ExtraNonce1),
				client.ExtraNonce2Size,
			},
		}

	case "mining.subscribe":
		b := make([]byte, 8)
		rand.Read(b)
		clientID := fmt.Sprintf("%x", b)

		client.conn.Outgoing <- stratum.StratumMessage{
			MessageID: msg.Id(),
			Result: []interface{}{
				[][]string{{"mining.notify", clientID}, {"mining.set_difficulty", clientID}},
				fmt.Sprintf("%x", client.ExtraNonce1),
				client.ExtraNonce2Size,
			},
		}
		client.SendWork()
	case "mining.configure":
		client.conn.Outgoing <- stratum.StratumMessage{
			MessageID: msg.Id(),
			Result:    nil,
		}
	case "mining.get_transactions":
		client.conn.Outgoing <- stratum.StratumMessage{
			MessageID: msg.Id(),
			Result:    []interface{}{},
		}
	case "mining.submit":
		success := false
		var err error

		params := msg.Parameters.([]interface{})

		en2, err := hex.DecodeString(params[2].(string))
		if err != nil {
			log.Printf("Error parsing extranonce2: %s", err.Error())
		}

		b, _ := hex.DecodeString(params[4].(string))
		nonce := binary.LittleEndian.Uint32(b)
		/*nonceint, _ := strconv.ParseInt(params[4].(string), 16, 64)
		nonce := uint32(nonceint)*/
		timeint, _ := strconv.ParseInt(params[3].(string), 16, 64)
		timestamp := uint32(timeint)

		submitBlockLock.Lock()

		log.Printf("%v", params)

		coinbaseTx := wire.NewMsgTx(wire.TxVersion)
		coinbaseBytes := make([]byte, len(currentCoinbase1)+len(currentCoinbase2)+8)
		copy(coinbaseBytes, currentCoinbase1)
		copy(coinbaseBytes[len(currentCoinbase1):], client.ExtraNonce1)
		copy(coinbaseBytes[len(currentCoinbase1)+4:], en2)
		copy(coinbaseBytes[len(currentCoinbase1)+8:], currentCoinbase2)

		err = coinbaseTx.Deserialize(bytes.NewReader(coinbaseBytes))
		if err != nil {
			log.Printf("Error deserializing TX: %s", err.Error())
		}
		coinbaseTx.TxIn[0].Witness = currentBlock.Transactions[0].TxIn[0].Witness
		nextPoT := composer.NextPowerOfTwo(len(currentBlock.Transactions))
		arraySize := nextPoT*2 - 1
		merkles := make([]*chainhash.Hash, arraySize)

		for i, tx := range currentBlock.Transactions {
			if i == 0 {
				h := coinbaseTx.TxHash()
				merkles[i] = &h
			} else {
				h := tx.TxHash()
				merkles[i] = &h
			}

		}

		composer.MerkleStuff(merkles, nextPoT)

		submitBlock := wire.NewMsgBlock(&wire.BlockHeader{
			Nonce:      nonce,
			Timestamp:  time.Unix(int64(timestamp), 0),
			MerkleRoot: *(merkles[arraySize-1]),
			PrevBlock:  currentBlock.Header.PrevBlock,
			Bits:       currentBlock.Header.Bits,
			Version:    currentBlock.Header.Version,
		})
		submitBlock.Transactions = make([]*wire.MsgTx, len(currentBlock.Transactions))
		submitBlock.Transactions[0] = coinbaseTx
		if len(currentBlock.Transactions) > 1 {
			copy(submitBlock.Transactions[1:], currentBlock.Transactions[1:])
		}
		var blockBuf bytes.Buffer
		submitBlock.Serialize(&blockBuf)

		var headerBuf bytes.Buffer
		submitBlock.Header.Serialize(&headerBuf)
		powHash, _ := powFunc(headerBuf.Bytes())
		target := blockchain.CompactToBig(currentBlock.Header.Bits)
		ch, _ := chainhash.NewHash(powHash[:])
		bnHash := blockchain.HashToBig(ch)
		off := bnHash.Cmp(target)
		if off != 0 {
			result, err := rpc.RawRequest("submitblock", []json.RawMessage{[]byte(fmt.Sprintf("\"%s\"", hex.EncodeToString(blockBuf.Bytes())))})
			if string(result) != "null" {
				log.Printf("Submit block 1 failed: %s", string(result))
			}
			success = (err == nil && string(result) == "null")
		}
		submitBlockLock.Unlock()

		client.conn.Outgoing <- stratum.StratumMessage{
			MessageID: msg.Id(),
			Result:    success,
		}

	default:
		log.Printf("Received unknown message [%s]\n", msg.RemoteMethod)
	}
}
