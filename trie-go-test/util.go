package trie_go

import (
	"github.com/centrifuge/go-substrate-rpc-client/v4/xxhash"
)

// CreateStorageKeyPrefix creates a key prefix for keys of a map.
// Can be used as an input to the state.GetKeys() RPC, in order to list the keys of map.
func CreateStorageKeyPrefix(prefix, method string) []byte {
	return append(xxhash.New128([]byte(prefix)).Sum(nil), xxhash.New128([]byte(method)).Sum(nil)...)
}
