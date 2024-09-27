package main

import (
	"context"
	"crypto/ecdsa"
	"log"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash/mimc"
)

// StateTransitionCircuit 目前沒有用 垃圾 要改成merkle tree path proof(先取得一整棵樹, 然後用leaf tx hash當input, 再用電路跑出來的root hash跟原本的root hash做比較)
type StateTransitionCircuit struct {
	PreviousStateRoot frontend.Variable   `gnark:",public"`
	NewStateRoot      frontend.Variable   `gnark:",public"`
	BlockNumber       frontend.Variable   `gnark:",public"`
	TokenID           frontend.Variable   `gnark:",public"`
	From              frontend.Variable   `gnark:",public"`
	To                frontend.Variable   `gnark:",public"`
	MerklePath        []frontend.Variable `gnark:",private"`
}

// StateTransitionCircuit 目前沒有用 垃圾 要改成merkle tree path proof(先取得一整棵樹, 然後用leaf tx hash當input, 再用電路跑出來的root hash跟原本的root hash做比較)
func (circuit *StateTransitionCircuit) Define(api frontend.API) error {
	mimc, _ := mimc.NewMiMC(api)

	// 驗證 Merkle 路徑
	currentHash := circuit.From
	for _, sibling := range circuit.MerklePath {
		mimc.Reset()
		mimc.Write(currentHash)
		mimc.Write(sibling)
		leftBranch := mimc.Sum()

		mimc.Reset()
		mimc.Write(sibling)
		mimc.Write(currentHash)
		rightBranch := mimc.Sum()

		currentHash = api.Select(sibling, leftBranch, rightBranch)
	}
	api.AssertIsEqual(currentHash, circuit.PreviousStateRoot)

	// 計算新的狀態根
	mimc.Reset()
	mimc.Write(circuit.To)
	mimc.Write(circuit.TokenID)
	newHash := mimc.Sum()
	api.AssertIsEqual(newHash, circuit.NewStateRoot)

	// 驗證區塊號的遞增
	api.AssertIsEqual(circuit.BlockNumber, api.Add(circuit.BlockNumber, 1))

	return nil
}

// 還要改
type ZKBridgeOracle struct {
	ethClient        *ethclient.Client
	bscClient        *ethclient.Client
	proverContract   *ProverContract
	verifierContract *VerifierContract
	privateKey       *ecdsa.PrivateKey
	transactionTree  *merkletree.Tree
}

// 大概改完了？
func NewZKBridgeOracle(ethRPC, bscRPC, proverAddress, verifierAddress string, privateKey *ecdsa.PrivateKey) (*ZKBridgeOracle, error) {
	ethClient, err := ethclient.Dial(ethRPC)
	if err != nil {
		return nil, err
	}

	bscClient, err := ethclient.Dial(bscRPC)
	if err != nil {
		return nil, err
	}

	proverContract, err := NewProverContract(common.HexToAddress(proverAddress), ethClient)
	if err != nil {
		return nil, err
	}

	verifierContract, err := NewVerifierContract(common.HexToAddress(verifierAddress), bscClient)
	if err != nil {
		return nil, err
	}
	h := crypto.NewKeccakState()
	transactionTree := merkletree.New(h)
	if err != nil {
		return nil, err
	}

	return &ZKBridgeOracle{
		ethClient:        ethClient,
		bscClient:        bscClient,
		proverContract:   proverContract,
		verifierContract: verifierContract,
		privateKey:       privateKey,
		transactionTree:  transactionTree,
	}, nil
}

// Monitor event on chain via ctx
func (zbo *ZKBridgeOracle) Start(ctx context.Context) {
	logs := make(chan types.Log)
	sub, err := zbo.ethClient.SubscribeFilterLogs(ctx, ethereum.FilterQuery{
		Addresses: []common.Address{zbo.proverContract.Address()},
	}, logs)
	if err != nil {
		log.Fatal(err)
	}

	for {
		select {
		case err := <-sub.Err():
			log.Fatal(err)
		case vLog := <-logs:
			zbo.handleLog(vLog)
		case <-ctx.Done():
			return
		}
	}
}

// Handle log from chain, used by handleLog
func (zkb *ZKBridgeOracle) handleLog(vLog types.Log) {
	event, err := zkb.proverContract.DepositERC20(vLog)
	if err != nil {
		log.Printf("Failed to parse log: %v", err)
		return
	}

	newStateRoot, merklePath, err := zkb.transactionTree.Update(event.TokenID, event.From, event.TokenAddress)
	if err != nil {
		log.Printf("Failed to update state tree: %v", err)
		return
	}

	proof, err := zkb.generateProof(zkb.transactionTree.Root(), newStateRoot, vLog.BlockNumber, event.TokenID, event.From, event.TokenAddress, merklePath)
	if err != nil {
		log.Printf("Failed to generate proof: %v", err)
		return
	}

	err = zkb.submitProofToBSC(proof)
	if err != nil {
		log.Printf("Failed to submit proof to BSC: %v", err)
		return
	}

	log.Printf("Successfully processed NFT deposit for token ID %s from %s", event.TokenID, event.From.Hex())
}

func (zkb *ZKBridgeOracle) generateProof(
	previousStateRoot []byte,
	newStateRoot []byte,
	blockNumber uint64,
	tokenID *big.Int,
	from common.Address,
	to common.Address,
	merklePath [][]byte,
) ([]byte, error) {
	var circuit StateTransitionCircuit

	field := ecc.BN254.ScalarField()

	cs, err := frontend.Compile(field, r1cs.NewBuilder, &circuit, frontend.WithCapacity(1000))
	if err != nil {
		return nil, err
	}

	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		return nil, err
	}

	// 将 merklePath 转换为 []frontend.Variable
	merklePathVariables := make([]frontend.Variable, len(merklePath))
	for i, path := range merklePath {
		merklePathVariables[i] = path
	}

	// 创建 witness 赋值
	assignment := StateTransitionCircuit{
		PreviousStateRoot: previousStateRoot,
		NewStateRoot:      newStateRoot,
		BlockNumber:       blockNumber,
		TokenID:           tokenID,
		From:              from.Bytes(),
		To:                to.Bytes(),
		MerklePath:        merklePathVariables,
	}

	// 使用 NewWitness 创建符合 witness.Witness 接口的对象
	witness, err := frontend.NewWitness(&assignment, field)
	if err != nil {
		return nil, err
	}

	// 生成证明
	proof, err := groth16.Prove(cs, pk, witness)
	if err != nil {
		return nil, err
	}

	return proof.MarshalBinary()
}

func (zbo *ZKBridgeOracle) submitProofToBSC(proof []byte) error {
	auth, err := bind.NewKeyedTransactorWithChainID(zbo.privateKey, big.NewInt(97)) // BSC testnet chain ID
	if err != nil {
		return err
	}

	tx, err := zbo.verifierContract.VerifyProof(auth, proof)
	if err != nil {
		return err
	}

	log.Printf("Proof submitted in transaction: %s", tx.Hash().Hex())

	receipt, err := bind.WaitMined(context.Background(), zbo.bscClient, tx)
	if err != nil {
		return err
	}

	log.Printf("Proof verified in block %d", receipt.BlockNumber)

	return nil
}

type ProverContractOnSepolia struct {
	TokenID      *big.Int
	From         common.Address
	TokenAddress common.Address // 其他需要的字段...
}

func NewProverContract(address common.Address, client *ethclient.Client) (*ProverContract, error) {
	return &ProverContract{
		address: address,
		client:  client,
	}, nil
}

func (pc *ProverContract) Address() common.Address {
	return pc.address
}

func (pc *ProverContract) ParseNFTDeposited(log types.Log) (struct {
	TokenID      *big.Int
	From         common.Address
	TokenAddress common.Address
}, error) {
	// 實現事件解析邏輯
	return struct {
		TokenID      *big.Int
		From         common.Address
		TokenAddress common.Address
	}{}, nil
}

type VerifierContract struct {
	// 合約相關字段
}

func NewVerifierContract(address common.Address, client *ethclient.Client) (*VerifierContract, error) {
	// 實現合約初始化邏輯
	return &VerifierContract{}, nil
}

func (vc *VerifierContract) VerifyProof(opts *bind.TransactOpts, proof []byte) (*types.Transaction, error) {
	// 實現證明驗證邏輯
	return nil, nil
}

func main() {
	privateKey, _ := crypto.HexToECDSA("YOURprivatekey")
	oracle, err := NewZKBridgeOracle(
		"https://sepolia.infura.io/v3/YOURapikey",
		"https://bsc-testnet.infura.io/v3//YOURapikey",
		"0x your_prover_contract_address_here",
		"0x your_verifier_contract_address_here",
		privateKey,
	)
	if err != nil {
		log.Fatalf("Failed to create ZK Bridge Oracle: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	oracle.Start(ctx)
}
