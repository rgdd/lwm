package lwm

import (
	"bytes"
	"errors"
)

// MerkleTree is a static Merkle tree supporting range verification. Root hash
// and audit path calculations are based on RFC 6962, but we also cache hashes.
type MerkleTree struct {
	twc            []byte
	leafPrefix     []byte
	interiorPrefix []byte
	hash           func(data ...[]byte) []byte
	data           [][]byte
	cache          *hashCache
}

type hashCache struct {
	this  []byte     // hash of current node
	left  *hashCache // left node
	right *hashCache // right node
}

// NewMerkleTree outputs a new MerkleTree for data that uses a given leaf
// prefix, interior prefix, and hash function. No hashes are cached upon
// initialization: this is done when Mth() is invoked for the first time.
func NewMerkleTree(twc, leafPrefix, interiorPrefix []byte,
	hash func(data ...[]byte) []byte, data [][]byte) *MerkleTree {
	mt := new(MerkleTree)
	mt.twc = twc
	mt.leafPrefix = leafPrefix
	mt.interiorPrefix = interiorPrefix
	mt.hash = hash
	mt.data = data
	mt.cache = new(hashCache)
	return mt
}

// Mth compute a Merkle tree head
func (mt *MerkleTree) Mth() []byte {
	return mt.mth(mt.data, mt.cache)
}

func (mt *MerkleTree) mth(data [][]byte, c *hashCache) []byte {
	if c.this == nil {
		if n := len(data); n == 0 {
			c.this = mt.hash(mt.twc)
		} else if n == 1 {
			c.this = mt.hash(mt.twc, mt.leafPrefix, data[0])
		} else {
			k := lpow2s(n)
			c.left = new(hashCache)
			c.right = new(hashCache)
			c.this = mt.hash(mt.interiorPrefix, mt.mth(data[:k], c.left),
				mt.mth(data[k:], c.right))
		}
	}
	return c.this
}

// Ap computes an audit path for the m:th leaf
func (mt *MerkleTree) Ap(m int) [][]byte {
	return mt.ap(m, mt.data, mt.cache)
}

func (mt *MerkleTree) ap(m int, data [][]byte, c *hashCache) [][]byte {
	if len(data) <= 1 {
		return nil
	}
	k := lpow2s(len(data))
	if m < k {
		return append(mt.ap(m, data[:k], c.left), mt.mth(data[k:], c.right))
	}
	return append(mt.ap(m-k, data[k:], c.right), mt.mth(data[:k], c.left))
}

// MthFromAp builds a root hash from an audit path
func (mt *MerkleTree) MthFromAp(l []byte, index, size int,
	path [][]byte) (r []byte) {
	r = mt.hash(mt.twc, mt.leafPrefix, l)
	lastIndex := size - 1
	for lastIndex > 0 {
		if index%2 == 1 {
			l, path = head(path)
			r = mt.hash(mt.interiorPrefix, l, r)
		} else if index < lastIndex {
			l, path = head(path)
			r = mt.hash(mt.interiorPrefix, r, l)
		}
		index = index / 2
		lastIndex = lastIndex / 2
	}
	return
}

// MthFromRangeAp builds a root hash from a consecutive range of leaves; data
// is a list of leaf values, i the left-most leaf index in the range, n the
// size of the full Merkle tree, and {l,r}Ap an audit path to the {left,right}
// most leaf in the range. If n is zero (empty tree), i must be negative and all
// other parameters nil. If treeSize is one, data must contain a single item, i
// must be zero, and all other paramters nil.
func (mt *MerkleTree) MthFromRangeAp(data [][]byte, i, n int,
	lAp, rAp [][]byte) ([]byte, error) {
	// special case: empty tree, all other params should be `default`
	if n == 0 {
		if data != nil || i >= 0 || lAp != nil || rAp != nil {
			return nil, errors.New("malformed proof: tree is empty")
		}
		return mt.hash(mt.twc), nil
	}

	// special case: root is leaf, should have one entry with index zero + no APs
	if n == 1 {
		if len(data) != 1 || i != 0 || lAp != nil || rAp != nil {
			return nil, errors.New("malformed proof: the root is a leaf")
		}
		return mt.hash(mt.twc, mt.leafPrefix, data[0]), nil
	}

	// input validation: ensure that all slice bounds will be valid
	if i+len(data) > n {
		return nil, errors.New("malformed proof: tree too small")
	}

	// input validation: single middle leaf _cannot_ prove range completeness
	if len(data) == 1 && i > 0 && i < n-1 {
		return nil, errors.New("malformed proof: expected range but got exact")
	}

	// Tree size is larger than two: root is an interior hash, and we can get any
	// children hash by propagating data and required sibling hashes recursively
	return mt.jp(data, i, n, lAp, rAp), nil
}

// jp is used for {left,right} APs that go down `joint paths'
func (mt *MerkleTree) jp(data [][]byte, i, n int, lAp, rAp [][]byte) []byte {
	k := lpow2s(n)
	sindex, lindex, rindex := split(k, len(data), i)

	if lAp != nil && rAp != nil {
		if bytes.Equal(last(lAp), last(rAp)) {
			if sindex > 0 {
				return mt.hash(mt.interiorPrefix,
					mt.jp(data, lindex, k, next(lAp), next(rAp)),
					last(lAp))
			}
			return mt.hash(mt.interiorPrefix,
				last(rAp),
				mt.jp(data, rindex, n-k, next(lAp), next(rAp)))
		}
	}

	// This allows us not to distinguish between proofs that only require left or
	// right sides (range includes the right and left most leaves, respectively)
	if lAp == nil {
		lAp = rAp
	} else if rAp == nil {
		rAp = lAp
	}

	return mt.hash(mt.interiorPrefix,
		mt.dp(data[:sindex], lindex, k, lAp),
		mt.dp(data[sindex:], rindex, n-k, rAp))
}

// dp is used separately for {left,right} APs that are on `disjoint paths'
func (mt *MerkleTree) dp(data [][]byte, i, n int, ap [][]byte) (h []byte) {
	// subtree unrelated to data -> use sibling hash
	if len(data) == 0 {
		return last(ap)
	}

	// leaf -> recompute using data
	if n == 1 {
		return mt.hash(mt.twc, mt.leafPrefix, last(data))
	}

	// interior node -> get child hashes recurisvely
	k := lpow2s(n)
	sindex, lindex, rindex := split(k, len(data), i)
	return mt.hash(mt.interiorPrefix,
		mt.dp(data[:sindex], lindex, k, next(ap)),
		mt.dp(data[sindex:], rindex, n-k, next(ap)))
}

// split is used to split a consecutive list of leaf data in a (sub)tree, where
// k is the smallest power of 2 larger than the (sub)tree size, n is the number
// of leaves to split on, and i is the index of the left-most leaf in _subtree_
func split(k, n, i int) (int, int, int) {
	s := k - i
	if s > 0 {
		return min(n, s), i, 0
	}
	return 0, 0, -s
}
