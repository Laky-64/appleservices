package escrow

import (
	"crypto/sha256"
	"math/big"
)

func leftPad(b []byte, width int) []byte {
	if len(b) >= width {
		return b
	}
	out := make([]byte, width)
	copy(out[width-len(b):], b)
	return out
}

func computeEscrowM(N, g, a, A, B *big.Int, salt []byte, identity, passcode string) (M, K []byte) {
	pad := func(x *big.Int) []byte {
		return leftPad(x.Bytes(), 256)
	}
	h := func(parts ...[]byte) []byte {
		s := sha256.New()
		for _, p := range parts {
			s.Write(p)
		}
		return s.Sum(nil)
	}
	inner := h([]byte(identity + ":" + passcode))
	x := new(big.Int).SetBytes(h(salt, inner))
	k := new(big.Int).SetBytes(h(pad(N), pad(g)))
	u := new(big.Int).SetBytes(h(pad(A), pad(B)))
	gx := new(big.Int).Exp(g, x, N)
	kgx := new(big.Int).Mod(new(big.Int).Mul(k, gx), N)
	base := new(big.Int).Mod(new(big.Int).Sub(B, kgx), N)
	exp := new(big.Int).Add(a, new(big.Int).Mul(u, x))
	S := new(big.Int).Exp(base, exp, N)
	K = h(pad(S))
	hN, hg := h(pad(N)), h(pad(g))
	xorNG := make([]byte, len(hN))
	for i := range hN {
		xorNG[i] = hN[i] ^ hg[i]
	}
	M = h(xorNG, h([]byte(identity)), salt, pad(A), pad(B), K)
	return M, K
}
