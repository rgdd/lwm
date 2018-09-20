package lwm

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

var (
	testTwc []byte = nil
	lp             = []byte("l") // leaf prefix
	ip             = []byte("i") // interior prefix
)

func TestMth(t *testing.T) {
	for _, table := range []struct {
		data [][]byte
		root []byte
	}{
		{leafData(0), r0()}, {leafData(1), r1()}, {leafData(2), r2()},
		{leafData(3), r3()}, {leafData(4), r4()}, {leafData(5), r5()},
		{leafData(6), r6()}, {leafData(7), r7()}, {leafData(8), r8()},
		{leafData(9), r9()}, {leafData(10), r10()}, {leafData(13), r13()},
		{leafData(16), r16()}, {leafData(17), r17()}, {leafData(23), r23()},
	} {
		mt := NewMerkleTree(testTwc, lp, ip, hash, table.data)
		if root := mt.Mth(); !bytes.Equal(root, table.root) {
			t.Errorf("Bad root hash =>\ngot:  %v\nwant: %v", root, table.root)
		}
	}
}

func TestAp(t *testing.T) {
	for i := 0; i <= 256; i++ {
		data := leafData(i)
		mt := NewMerkleTree(testTwc, lp, ip, hash, data)
		r := mt.Mth()
		for i := 0; i < len(data); i++ {
			rp := mt.MthFromAp(data[i], i, len(data), mt.Ap(i))
			if !bytes.Equal(r, rp) {
				t.Errorf("Bad recomputed root hash =>\ngot:  %v\nwant: %v", r, rp)
			}
		}
	}
}

func TestRangeAp(t *testing.T) {
	// Check reconstruct for an empty tree (valid parameters)
	var d [][]byte
	mt := NewMerkleTree(testTwc, lp, ip, hash, nil)
	r := mt.Mth()
	if rp, err := mt.MthFromRangeAp(nil, -1, 0, nil, nil); err != nil {
		t.Errorf("Valid parameters rejected")
	} else if !bytes.Equal(r, rp) {
		t.Errorf("Bad recomputed range root hash =>\ngot:  %v\nwant: %v", r, rp)
	}

	// Check reconstuct when the root is a leaf
	d = leafData(1)
	mt = NewMerkleTree(testTwc, lp, ip, hash, d)
	r = mt.Mth()
	if rp, err := mt.MthFromRangeAp(d, 0, len(d), nil, nil); err != nil {
		t.Errorf("Valid parameters rejected: %v", err)
	} else if !bytes.Equal(r, rp) {
		t.Errorf("Bad recomputed range root =>\ngot:  %v\nwant: %v", r, rp)
	}

	for leaves := 2; leaves <= 32; leaves++ {
		d := leafData(leaves)
		n := len(d)
		mt := NewMerkleTree(testTwc, lp, ip, hash, d)
		r := mt.Mth()
		// try all possible range proofs that can prove completeness
		for i := 0; i < n; i++ {
			for j := 1; j <= n; j++ {
				if j > i && (j-i > 1 || i == 0 || j == n) {
					var lAp, rAp [][]byte
					if i != 0 {
						lAp = mt.Ap(i)
					}
					if j != n {
						rAp = mt.Ap(j - 1)
					}
					if rp, err := mt.MthFromRangeAp(d[i:j], i, n, lAp, rAp); err != nil {
						t.Errorf("Valid parameters rejected")
					} else if !bytes.Equal(r, rp) {
						t.Errorf("Bad recomputed range root =>\ngot:  %v\nwant: %v", r, rp)
					}
				}
			}
		}
	}
}

// Manually computed roots
func r0() []byte  { return decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") }
func r1() []byte  { return decode("2804bad6fe94a55f18b2b37e300919a5fd517b95aa81e95db574c0ba069a3740") }
func r2() []byte  { return decode("6f35cb865486e1e8757d2aad67bba7ba27473a1df147c4962a71c3090e65ea9d") }
func r3() []byte  { return decode("f3c719f4b011cdee46e575307a16fcedd8c6d2c75cdebd9ee6b15a2329adfe08") }
func r4() []byte  { return decode("3f8cce54847883daa5d43c915b4b44743b78c24fde8e99e693100e2a8ee14090") }
func r5() []byte  { return decode("7502e0d50b8a5de1d75dda023ccf83632bff7e16c712af6d8c710e12e760b566") }
func r6() []byte  { return decode("aaaf6df6b3ea3e6b3dd7f4e9d9d108e50bdd7139e73dbababcf20131973d26ab") }
func r7() []byte  { return decode("c16de5134fe8c6fbbf69cf72c80ff7f84e2c92abe92e55bf8e81b341bbd0f4bf") }
func r8() []byte  { return decode("ef820f0e50ac432d0c72734bd8b15e0ec2f328619248bb09779a103b516512bb") }
func r9() []byte  { return decode("a0700051ee032f5c9278eb39e909ebd8959054b67c697d583a51cbe8af2f539f") }
func r10() []byte { return decode("9d2023106a968e21219a5594e1945a2b4c906a2db1796181660bae5bddf8d666") }
func r13() []byte { return decode("7801f67fde9b8fef89e5b49f0c3c4db67fedff3da25829d1a50dfb223eed006d") }
func r16() []byte { return decode("f14421581dff522792ada45dd6182268ace84ec1639f8999994bc25a418f7757") }
func r17() []byte { return decode("d6e5f8d335dc1d91fdd7e18793c07ebf8202dd5169675dbf13afe277de98f8d6") }
func r23() []byte { return decode("43f3ab6312588b5de0abe9e71f2eb2356293645280b1c8d0df9d3439eeae31f0") }

func decode(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("failed to decode from hex")
	}
	return b
}

func leafData(n int) (data [][]byte) {
	for i := 1; i <= n; i++ {
		data = append(data, []byte(fmt.Sprintf("%d", i)))
	}
	return data
}
