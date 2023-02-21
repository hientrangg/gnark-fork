/*
	Original Copyright 2015 https://gitlab.com/NebulousLabs
*/

/*
The MIT License (MIT)

Copyright (c) 2015 Nebulous

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

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

// Package merkle provides a ZKP-circuit function to verify merkle proofs.
package merklesum

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
)

// MerkleProof stores the path, the root hash and an helper for the Merkle proof.
type MerkleSumProof struct {

	// RootHash root of the Merkle tree
	RootHash, RootSum frontend.Variable

	// Path path of the Merkle proof
	PathHash, PathSum []frontend.Variable
}

type Leaf struct {
	data	 frontend.Variable
	balance	 frontend.Variable
}
// leafHash returns the hash created from data inserted to form a leaf.
// Without domain separation.
func leafHash(api frontend.API, h hash.Hash, data frontend.Variable) frontend.Variable {

	h.Reset()
	h.Write(data)
	res := h.Sum()

	return res
}

// nodeSum returns the hash created from data inserted to form a leaf.
// Without domain separation.
func nodeHash(api frontend.API, h hash.Hash, a, b frontend.Variable) frontend.Variable {

	h.Reset()
	h.Write(a, b)
	res := h.Sum()

	return res
}

// nodeSum returns the sum created from data inserted to form a leaf.
// Without domain separation.
func nodeSum(api frontend.API, a, b frontend.Variable) frontend.Variable {
	res := api.Add(a, b)
	return res
}

// VerifyProof takes a Merkle root, a proofSet, and a proofIndex and returns
// true if the first element of the proof set is a leaf of data in the Merkle
// root. False is returned if the proof set or Merkle root is nil, and if
// 'numLeaves' equals 0.
func (mp *MerkleSumProof) VerifyProof(api frontend.API, h hash.Hash, leaf Leaf) {

	depth := len(mp.PathHash) - 1
	hash := leafHash(api, h, mp.PathHash[0])
	sum := mp.PathSum[0]

	// The binary decomposition is the bitwise negation of the order of hashes ->
	// If the path in the plain go code is 					0 1 1 0 1 0
	// The binary decomposition of the leaf index will be 	1 0 0 1 0 1 (little endian)
	binLeaf := api.ToBinary(leaf.data, depth)

	for i := 1; i < len(mp.PathHash); i++ { // the size of the loop is fixed -> one circuit per size
		d1 := api.Select(binLeaf[i-1], mp.PathHash[i], hash)
		d2 := api.Select(binLeaf[i-1], hash, mp.PathHash[i])
		hash = nodeHash(api, h, d1, d2)
		sum = nodeSum(api,sum, mp.PathSum[i])
	}

	// Compare our calculated Merkle root to the desired Merkle root.
	api.AssertIsEqual(hash, mp.RootHash)
	api.AssertIsEqual(sum, mp.RootSum)
}
