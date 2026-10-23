package escrow

import (
	"crypto/sha256"
	"errors"
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

func computeEscrowM(N, g, a, A, B *big.Int, salt []byte, identity, passcode string, minimal bool) (M, K []byte, err error) {
	if B.Sign() <= 0 || new(big.Int).Mod(B, N).Sign() == 0 {
		return nil, nil, errors.New("escrow: invalid SRP server public value")
	}
	pad := func(x *big.Int) []byte {
		return leftPad(x.Bytes(), 256)
	}
	wire := pad
	if minimal {
		wire = func(x *big.Int) []byte { return x.Bytes() }
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
	u := new(big.Int).SetBytes(h(wire(A), wire(B)))
	if u.Sign() == 0 {
		return nil, nil, errors.New("escrow: invalid SRP scrambling parameter")
	}
	gx := new(big.Int).Exp(g, x, N)
	kgx := new(big.Int).Mod(new(big.Int).Mul(k, gx), N)
	base := new(big.Int).Mod(new(big.Int).Sub(B, kgx), N)
	exp := new(big.Int).Add(a, new(big.Int).Mul(u, x))
	S := new(big.Int).Exp(base, exp, N)
	K = h(wire(S))
	hN, hg := h(pad(N)), h(pad(g))
	xorNG := make([]byte, len(hN))
	for i := range hN {
		xorNG[i] = hN[i] ^ hg[i]
	}
	M = h(xorNG, h([]byte(identity)), salt, wire(A), wire(B), K)
	return M, K, nil
}
