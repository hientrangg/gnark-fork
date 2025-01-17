/*
Copyright © 2020 ConsenSys

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package merklesum

import (
	"bytes"
	"crypto/rand"
	merkleSum "github.com/consensys/gnark-crypto/accumulator/merklesumtree"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/test"
	"os"
	"testing"
)

// MerkleProofTest used for testing only
type MerkleProofTest struct {
	M    MerkleSumProof
	Leaf Leaf
	Index frontend.Variable
}

func (mp *MerkleProofTest) Define(api frontend.API) error {

	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	mp.M.VerifyProof(api, &h, mp.Leaf)

	return nil
}

func TestVerify(t *testing.T) {

	assert := test.NewAssert(t)
	numLeaves := 32
	depth := 5

	type testData struct {
		hash        hash.Hash
		segmentSize int
		curve       ecc.ID
	}

	confs := []testData{
		{hash.MIMC_BN254, 32, ecc.BN254},
	}

	for _, tData := range confs {

		// create the circuit
		var circuit MerkleProofTest
		circuit.M.PathHash = make([]frontend.Variable, depth+1)
		circuit.M.PathSum = make([]frontend.Variable, depth+1)
		cc, err := frontend.Compile(tData.curve.ScalarField(), r1cs.NewBuilder, &circuit)
		if err != nil {
			t.Fatal(err)
		}

		mod := tData.curve.ScalarField()
		modNbBytes := len(mod.Bytes())

		// we test the circuit for all leaves...
		for proofIndex := uint64(0); proofIndex < 32; proofIndex++ {

			// generate random data, the Merkle tree will be of depth log(64) = 6
			var buf1 bytes.Buffer
			for i := 0; i < numLeaves; i++ {
				leaf, err := rand.Int(rand.Reader, mod)
				assert.NoError(err)
				b := leaf.Bytes()
				buf1.Write(make([]byte, modNbBytes-len(b)))
				buf1.Write(b)
			}

			var buf2 bytes.Buffer
			for i := 0; i < numLeaves; i++ {
				leaf, err := rand.Int(rand.Reader, mod)
				assert.NoError(err)
				b := leaf.Bytes()
				buf2.Write(make([]byte, modNbBytes-len(b)))
				buf2.Write(b)
			}

			// create the proof using the go code
			hFunc := tData.hash.New()
			merkleRoot, proofPath, numLeaves, err := merkleSum.BuildReaderProof(&buf1, &buf2, hFunc, tData.segmentSize, proofIndex)
			if err != nil {
				t.Fatal(err)
				os.Exit(-1)
			}

			// verfiy the proof in plain go
			verified := merkleSum.VerifyProof(hFunc, merkleRoot, proofPath, proofIndex, numLeaves)
			if !verified {
				t.Fatal("The merkle proof in plain go should pass")
			}

			// witness
			var witness MerkleProofTest
			witness.Index = proofIndex
			witness.M.RootHash = merkleRoot.Hash
			witness.M.RootSum = merkleRoot.Sum
			witness.M.PathHash = make([]frontend.Variable, depth+1)
			witness.M.PathSum = make([]frontend.Variable, depth+1)
			for i := 0; i < depth+1; i++ {
				witness.M.PathHash[i] = proofPath.Hash[i]
				witness.M.PathSum[i] = proofPath.Sum[i]
			}

			w, err := frontend.NewWitness(&witness, tData.curve.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			logger.SetOutput(os.Stdout)
			err = cc.IsSolved(w, backend.IgnoreSolverError(), backend.WithCircuitLogger(logger.Logger()))
			if err != nil {
				t.Fatal(err)
			}

			// verify the circuit
			assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(tData.curve))
		}

	}

}
