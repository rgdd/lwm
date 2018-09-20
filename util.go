package lwm

import (
	"crypto/sha256"
	"math"
	"math/big"
)

const (
	hashLen = 32
)

// hash concatenates data and outputs a sha256 hash
func hash(data ...[]byte) []byte {
	h := sha256.New()
	for i := 0; i < len(data); i++ {
		h.Write(data[i])
	}
	return h.Sum(nil)
}

// min outputs the smallest number
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func head(data [][]byte) (h []byte, tail [][]byte) {
	if n := len(data); n == 0 {
		h, tail = nil, nil // capture nil to avoid error checking in caller
	} else if n == 1 {
		h, tail = data[0], nil
	} else {
		h, tail = data[0], data[1:]
	}
	return
}

// last outputs the last entry from a sequence of data (if any)
func last(data [][]byte) []byte {
	if n := len(data); n > 0 {
		return data[n-1]
	}
	return nil
}

// next removes the last entry from a sequence of data (if any)
func next(data [][]byte) [][]byte {
	if n := len(data); n > 1 {
		return data[:n-1]
	}
	return nil
}

// lpow2s outputs the largest power of 2 smaller than n
func lpow2s(n int) int {
	return int(math.Pow(2, float64(big.NewInt(int64(n-1)).BitLen()-1)))
}
