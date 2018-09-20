package lwm

import (
	"bytes"
	radix "github.com/armon/go-radix"
	"sort"
)

var (
	leafPrefix     = []byte{0x00}
	interiorPrefix = []byte{0x01}
)


// Answer is a wildcard answer that contains a list of matching subject names
// and associated payloads
type Answer struct {
	subject []string
	payload [][][]byte
}

// Proof contains information to prove that an answer is authentic and complete
type Proof struct {
	hash     func(data ...[]byte) []byte // hash function used by merkle tree
	twc      []byte                      // tree-wide constant
	index    int                         // first mt index (or where it should be)
	ll, rl   []byte                      // left and right leaf data (nil->na)
	lap, rap [][]byte                    // left and right audit paths (nil->n/a)
}

// WildcardTree is a an authenticated data structure that supports cryptographic
// (non-)membership proofs for wildcard prefixes
type WildcardTree struct {
	r  *radix.Tree
	mt *MerkleTree
}

type radixValue struct {
	payload [][]byte // an ordered list of data values
	index   int      // merkle tree index for payload[0]
}

// NewWildcardTree outputs a new WildcardTree based on a tree-wide constant
// twc, a hash function h, and a map of key-value pairs. Every key must be in
// reversed order (e.g., foo.com->moc.foo), and the associated value a [][]byte.
func NewWildcardTree(twc []byte, h func(data ...[]byte) []byte,
	m map[string]interface{}) *WildcardTree {
	wt := new(WildcardTree)
	// Order key-value pairs in radix order, creating a Merkle tree and saving
	// the resulting indices in a new (final) radix tree for easy look-up
	r := radix.NewFromMap(m)
	tmp, index := make(map[string]interface{}), 0
	var data [][]byte
	r.WalkPrefix("", func(k string, v interface{}) bool {
		p, ok := v.([][]byte)
		if !ok {
			panic("This should never happen given the function's precondition")
		}
		tmp[k], index = radixValue{payload: p, index: index}, index+1
		data = append(data, append([]byte(k), h(p...)...))
		return false
	})
	wt.r = radix.NewFromMap(tmp)
	wt.mt = NewMerkleTree(twc, leafPrefix, interiorPrefix, h, data)
	return wt
}

// Snapshot outputs the root hash of the underlying Merkle tree
func (wt *WildcardTree) Snapshot() []byte {
	return wt.mt.Mth()
}

// Get outputs a verifiable wildcard answer for key
func (wt *WildcardTree) Get(key string) (answer Answer, proof Proof) {
	proof.hash = wt.mt.hash
	proof.twc = wt.mt.twc
	proof.index = -1

	// special case: empty tree
	if len(wt.mt.data) == 0 {
		proof.index = -1
		return
	}

	// tree size > 0: find matches and first index
	wt.r.WalkPrefix(key, func(subject string, value interface{}) bool {
		data, ok := value.(radixValue)
		if !ok {
			panic("This should never happen")
		}
		answer.subject = append(answer.subject, subject)
		answer.payload = append(answer.payload, data.payload)
		if proof.index < 0 {
			proof.index = data.index
		}
		return false
	})

	// if there's no match: make proof for the range where this key should be
	if proof.index < 0 {
		proof.index = sort.Search(len(wt.mt.data), func(i int) bool {
			return mkKey(wt.mt.data[i]) >= key
		})

		if proof.index == len(wt.mt.data) { // value last -> need left proof
			proof.index -= 1
			proof.lap = wt.mt.Ap(proof.index)
			proof.ll = wt.mt.data[proof.index]
		} else if proof.index == 0 { // value first -> need right proof
			proof.rap = wt.mt.Ap(proof.index)
			proof.rl = wt.mt.data[proof.index]
		} else { // value in between, need both proofs
			proof.index -= 1
			proof.lap, proof.rap = wt.mt.Ap(proof.index), wt.mt.Ap(proof.index+1)
			proof.ll, proof.rl = wt.mt.data[proof.index], wt.mt.data[proof.index+1]
		}
		return
	}

	// if there's at least one match: make range proof
	if rindex := proof.index + len(answer.subject); rindex < len(wt.mt.data) {
		proof.rap = wt.mt.Ap(rindex)
		proof.rl = wt.mt.data[rindex]
	}
	if proof.index > 0 {
		proof.index -= 1
		proof.lap = wt.mt.Ap(proof.index)
		proof.ll = wt.mt.data[proof.index]
	}
	return
}

// Verify outputs true if answer is valid for key, proof, size, and snapshot
func (p Proof) Verify(key string, a Answer, size int, snapshot []byte) bool {
	lindex, rindex := indices(&p, &a)
	// check that ends are provided if expected
	if (p.ll == nil && lindex > 0) || (p.rl == nil && rindex+1 < size) {
		return false
	}
	// check that ends are valid for key
	if (p.ll != nil && key < mkKey(p.ll)) || (p.rl != nil && key > mkKey(p.rl)) {
		return false
	}
	// check that leaf data is ordered
	data, ok := mkLeafData(&p, &a)
	if !ok {
		return false
	}
	// check that leaf data is valid for Merkle tree (size+location+snapshot)
	mt := NewMerkleTree(p.twc, leafPrefix, interiorPrefix, p.hash, nil)
	snapshotp, err := mt.MthFromRangeAp(data, lindex, size, p.lap, p.rap)
	return err == nil && bytes.Equal(snapshot, snapshotp)
}

// indices returns the {left,right} inclusive range for a proof and an answer
func indices(p *Proof, a *Answer) (lindex, rindex int) {
	if lindex = p.index; lindex >= 0 {
		rindex = lindex + len(a.subject) - 1
		if p.ll != nil {
			rindex += 1
		}
		if p.rl != nil {
			rindex += 1
		}
	}
	return
}

// mkLeafData makes a consecutive range of leaf data from a proof and an answer
func mkLeafData(p *Proof, a *Answer) ([][]byte, bool) {
	n := len(a.subject)
	if n != len(a.payload) {
		return nil, false
	}

	// left side
	var d [][]byte
	if p.ll != nil {
		d = append(d, p.ll)
		if n > 0 && mkKey(p.ll) > a.subject[0] {
			return nil, false // bad leaf order
		}
	}

	// actual range
	for i := 0; i < n; i++ {
		if i > 0 && a.subject[i-1] >= a.subject[i] {
			return nil, false // bad leaf order
		}
		d = append(d, append([]byte(a.subject[i]), p.hash(a.payload[i]...)...))
	}

	// right side
	if p.rl != nil {
		if n > 0 && mkKey(p.rl) < a.subject[n-1] {
			return nil, false // bad leaf order
		}
		d = append(d, p.rl)
	}

	return d, true
}

// mkKey outputs the key of a leaf's data
func mkKey(data []byte) string {
	if n := len(data); n >= hashLen {
		return string(data[:n-hashLen])
	}
	return "" // invalid data
}
