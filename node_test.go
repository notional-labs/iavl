package iavl

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	iavlrand "github.com/cosmos/iavl/internal/rand"
)

func TestNodeKey_encode_decode(t *testing.T) {
	testcases := map[string]struct {
		nodeKey *NodeKey
	}{
		"small_version/small_nonce": {nodeKey: &NodeKey{
			version: 2,
			nonce:   1,
		}},
		"big_version/small_nonce": {nodeKey: &NodeKey{
			version: 2384892734987234,
			nonce:   1,
		}},
		"small_version/big_nonce": {nodeKey: &NodeKey{
			version: 5,
			nonce:   948357934,
		}},
		"big_version/big_nonce": {nodeKey: &NodeKey{
			version: 2384892734987234,
			nonce:   328479213,
		}},
	}
	for name, tc := range testcases {
		t.Run(name, func(t *testing.T) {
			bz := [100]byte{}
			expectedSize := EncodeNodeKeyTo(tc.nodeKey, bz[:])
			actualNodeKey, actualSize := DecodeNodeKeyFrom(bz[:])

			require.Equal(t, expectedSize, actualSize)
			require.Equal(t, tc.nodeKey.String(), actualNodeKey.String())

		})
	}
}

func TestNode_encode_decode(t *testing.T) {
	testcases := map[string]struct {
		node        *Node
		expectHex   string
		expectError bool
	}{
		"nil": {nil, "", true},
		"inner": {&Node{
			subtreeHeight: 3,
			size:          7,
			key:           []byte("key"),
			nodeKey: &NodeKey{
				version: 2,
				nonce:   1,
			},
			leftNodeKey: &NodeKey{
				version: 1,
				nonce:   1,
			},
			rightNodeKey: &NodeKey{
				version: 1,
				nonce:   1,
			},
			hash: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
		}, "03000700036b65790102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200001000100010001", false},
		"leaf": {&Node{
			subtreeHeight: 0,
			size:          1,
			key:           []byte("key"),
			value:         []byte("value"),
			nodeKey: &NodeKey{
				version: 3,
				nonce:   1,
			},
			hash: []byte{0x7f, 0x68, 0x90, 0xca, 0x16, 0xde, 0xa6, 0xe8, 0x89, 0x3d, 0x96, 0xf0, 0xa3, 0xd, 0xa, 0x14, 0xe5, 0x55, 0x59, 0xfc, 0x9b, 0x83, 0x4, 0x91, 0xe3, 0xd2, 0x45, 0x1c, 0x81, 0xf6, 0xd1, 0xe},
		}, "00000100036b657976616c7565", false},
	}
	for name, tc := range testcases {
		t.Run(name, func(t *testing.T) {
			bz, err := tc.node.Encode()
			if tc.expectError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expectHex, hex.EncodeToString(bz))

			node, err := MakeNode(tc.node.nodeKey, bz)
			require.NoError(t, err)
			// since key and value is always decoded to []byte{} we augment the expected struct here
			if tc.node.key == nil {
				tc.node.key = []byte{}
			}
			if tc.node.value == nil && tc.node.subtreeHeight == 0 {
				tc.node.value = []byte{}
			}
			require.Equal(t, tc.node, node)
		})
	}
}

func TestNode_validate(t *testing.T) {
	k := []byte("key")
	v := []byte("value")
	nk := &NodeKey{
		version: 1,
		nonce:   1,
	}
	c := &Node{key: []byte("child"), value: []byte("x"), size: 1}

	testcases := map[string]struct {
		node  *Node
		valid bool
	}{
		"nil node":                 {nil, false},
		"leaf":                     {&Node{key: k, value: v, nodeKey: nk, size: 1}, true},
		"leaf with nil key":        {&Node{key: nil, value: v, size: 1}, false},
		"leaf with empty key":      {&Node{key: []byte{}, value: v, nodeKey: nk, size: 1}, true},
		"leaf with nil value":      {&Node{key: k, value: nil, size: 1}, false},
		"leaf with empty value":    {&Node{key: k, value: []byte{}, nodeKey: nk, size: 1}, true},
		"leaf with version 0":      {&Node{key: k, value: v, size: 1}, false},
		"leaf with version -1":     {&Node{key: k, value: v, size: 1}, false},
		"leaf with size 0":         {&Node{key: k, value: v, size: 0}, false},
		"leaf with size 2":         {&Node{key: k, value: v, size: 2}, false},
		"leaf with size -1":        {&Node{key: k, value: v, size: -1}, false},
		"leaf with left node key":  {&Node{key: k, value: v, size: 1, leftNodeKey: nk}, false},
		"leaf with left child":     {&Node{key: k, value: v, size: 1, leftNode: c}, false},
		"leaf with right node key": {&Node{key: k, value: v, size: 1, rightNodeKey: nk}, false},
		"leaf with right child":    {&Node{key: k, value: v, size: 1, rightNode: c}, false},
		"inner":                    {&Node{key: k, size: 1, subtreeHeight: 1, nodeKey: nk, leftNodeKey: nk, rightNodeKey: nk}, true},
		"inner with nil key":       {&Node{key: nil, value: v, size: 1, subtreeHeight: 1, leftNodeKey: nk, rightNodeKey: nk}, false},
		"inner with value":         {&Node{key: k, value: v, size: 1, subtreeHeight: 1, leftNodeKey: nk, rightNodeKey: nk}, false},
		"inner with empty value":   {&Node{key: k, value: []byte{}, size: 1, subtreeHeight: 1, leftNodeKey: nk, rightNodeKey: nk}, false},
		"inner with left child":    {&Node{key: k, size: 1, subtreeHeight: 1, nodeKey: nk, leftNodeKey: nk}, true},
		"inner with right child":   {&Node{key: k, size: 1, subtreeHeight: 1, nodeKey: nk, rightNodeKey: nk}, true},
		"inner with no child":      {&Node{key: k, size: 1, subtreeHeight: 1}, false},
		"inner with height 0":      {&Node{key: k, size: 1, subtreeHeight: 0, leftNodeKey: nk, rightNodeKey: nk}, false},
	}

	for desc, tc := range testcases {
		tc := tc // appease scopelint
		t.Run(desc, func(t *testing.T) {
			err := tc.node.validate()
			if tc.valid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func BenchmarkNode_WriteBytes(b *testing.B) {
	nk := &NodeKey{
		version: rand.Int63n(10000000),
		nonce:   rand.Int31n(10000000),
	}
	node := &Node{
		key:           iavlrand.RandBytes(25),
		value:         iavlrand.RandBytes(100),
		nodeKey:       nk,
		subtreeHeight: 1,
		size:          rand.Int63n(10000000),
		leftNodeKey:   nk,
		rightNodeKey:  nk,
	}
	b.ResetTimer()
	b.Run("OldMethod/NoPreAllocate", func(sub *testing.B) {
		sub.ReportAllocs()
		for i := 0; i < sub.N; i++ {
			var buf bytes.Buffer
			_ = node.writeBytes2(&buf)
		}
	})
	b.Run("OldMethod/PreAllocate", func(sub *testing.B) {
		sub.ReportAllocs()
		for i := 0; i < sub.N; i++ {
			var buf bytes.Buffer
			buf.Grow(node.encodedSize())
			_ = node.writeBytes2(&buf)
		}
	})
	b.Run("NewMethod", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			node.Encode()
		}
	})
}

func BenchmarkNode_HashNode(b *testing.B) {
	node := &Node{
		key:   iavlrand.RandBytes(25),
		value: iavlrand.RandBytes(100),
		nodeKey: &NodeKey{
			version: rand.Int63n(10000000),
			nonce:   rand.Int31n(10000000),
		},
		subtreeHeight: 0,
		size:          rand.Int63n(10000000),
		hash:          iavlrand.RandBytes(32),
	}
	b.ResetTimer()
	b.Run("NoBuffer", func(sub *testing.B) {
		sub.ReportAllocs()
		for i := 0; i < sub.N; i++ {
			h := sha256.New()
			require.NoError(b, node.writeHashBytes(h, node.nodeKey.version))
			_ = h.Sum(nil)
		}
	})
	b.Run("PreAllocate", func(sub *testing.B) {
		sub.ReportAllocs()
		for i := 0; i < sub.N; i++ {
			h := sha256.New()
			buf := new(bytes.Buffer)
			buf.Grow(node.encodedSize())
			require.NoError(b, node.writeHashBytes(buf, node.nodeKey.version))
			_, err := h.Write(buf.Bytes())
			require.NoError(b, err)
			_ = h.Sum(nil)
		}
	})
	b.Run("NoPreAllocate", func(sub *testing.B) {
		sub.ReportAllocs()
		for i := 0; i < sub.N; i++ {
			h := sha256.New()
			buf := new(bytes.Buffer)
			require.NoError(b, node.writeHashBytes(buf, node.nodeKey.version))
			_, err := h.Write(buf.Bytes())
			require.NoError(b, err)
			_ = h.Sum(nil)
		}
	})
}
