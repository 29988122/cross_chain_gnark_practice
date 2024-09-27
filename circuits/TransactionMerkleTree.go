package circuits

import (
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/sha3"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

type Circuit struct {
	MerkleRoot frontend.Variable `gnark:",public"`
	Inputs     []frontend.Variable
}

func (circuit *Circuit) Define(api frontend.API) error {

	for _, input := range circuit.Inputs {
		tree.Push(input)
	}

	// 計算根並與公開輸入比較
	computedRoot := tree.Root()
	api.AssertIsEqual(computedRoot, circuit.MerkleRoot)

	return nil
}

func main() {
	var circuit Circuit
	var circuitInputs []frontend.Variable
	keccak256 := sha3.NewLegacyKeccak256()
	tree := merkletree.New(keccak256)

	inputs := []string{
		"0x42f8771f524c9ffabe2bd8a87f6b6e005ee6dcb239316f00e6c584dc68eeb7e4",
		"0xb6b6d97a1298423bb18f7ea18b4e1bb51464fb0969ebd796bbebd891bcae7736",
		"0xce64de4faa3d399aa1c5537728429726b1440b169e26aa887c329feed0d4e964",
		"0x42f8771f524c9ffabe2bd8a87f6b6e005ee6dcb239316f00e6c584dc68eeb7e4",
	}
	for _, input := range inputs {
		data, err := hex.DecodeString(input[2:])
		if err != nil {
			panic(fmt.Sprintf("Failed to decode hex string: %v", err))
		}
		tree.Push(data)
	}

	ccs, err := frontend.Compile(ecc.BN254, frontend.R1CS, &circuit)
	if err != nil {
		panic(err)
	}

	// 注意：在實際應用中，你需要正確計算 Merkle 根
	computedMerkleRoot := frontend.Variable("placeholder_root")

	assignment := &Circuit{
		MerkleRoot: computedMerkleRoot,
		Inputs:     inputs,
	}

	witness, err := frontend.NewWitness(assignment, ecc.BN254)
	if err != nil {
		panic(err)
	}

	publicWitness, err := frontend.NewWitness(assignment, ecc.BN254, frontend.PublicOnly())
	if err != nil {
		panic(err)
	}

	fmt.Println("Circuit compiled and witness generated successfully")
}
