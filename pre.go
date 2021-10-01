package pre

import (
	"fmt"
	"math/big"
	"math/rand"

	"github.com/Nik-U/pbc"
)

type Params struct {
	params  *pbc.Params
	pairing *pbc.Pairing
	g       *pbc.Element
	x       *pbc.Element
	M       *big.Int
}

type Key struct {
	sk *big.Int
	pk *pbc.Element
}

type Cipher1 struct {
	c []byte
	D *pbc.Element
	s *big.Int
}

type Cipher2 struct {
	c []byte
	r *pbc.Element
	k *pbc.Element
	s *pbc.Element
}

func randBigInt() *big.Int {
	r := rand.Int63()
	return big.NewInt(r)
}

func Test(sysParams *Params) {
	g2 := sysParams.g.NewFieldElement().PowBig(sysParams.g, big.NewInt(2))
	g3 := sysParams.g.NewFieldElement().PowBig(sysParams.g, big.NewInt(3))
	gm := sysParams.g.NewFieldElement().Mul(g2, g3)
	g5 := sysParams.g.NewFieldElement().PowBig(sysParams.g, big.NewInt(5))
	fmt.Println(gm)
	fmt.Println(g5)
}

func SetUp() *Params {
	sysParams := &Params{}
	// In a real application, generate this once and publish it
	//sysParams.params = pbc.GenerateA(160, 512)
	primeString := "177063952254247468442551580053342368327499090129576076593456095179110145482221127802300029621710952060074685608751501831462376397779876930022359697910305224075863907137186101979794835202925437047634527332308873034226271280499593280136380355378181622959990712265130941130456200783571951898972639997057144921207"
	prime := new(big.Int)
	prime.SetString(primeString, 10)
	sysParams.M = prime
	sysParams.params = pbc.GenerateA1(prime)

	sysParams.pairing = sysParams.params.NewPairing()
	// Initialize group elements. pbc automatically handles garbage collection.
	sysParams.g = sysParams.pairing.NewG1().Rand()
	sysParams.x = sysParams.pairing.NewGT().Rand()

	return sysParams
}

func KeyGen(sysParams *Params) *Key {
	key := &Key{}
	key.sk = randBigInt()
	key.pk = sysParams.g.NewFieldElement().PowBig(sysParams.g, key.sk)
	return key
}

func RKeyGen(sysParams *Params, kSender *Key, kReviever *Key) *pbc.Element {
	ska := kSender.sk
	pkb := kReviever.pk

	n := new(big.Int)
	n.Mul(ska, ska)
	n.Mod(n, sysParams.M)

	return sysParams.g.NewFieldElement().PowBig(pkb, n)
}

func xor(msg, mask []byte) []byte {
	enc := make([]byte, len(msg))
	for i := range msg {
		enc[i] = msg[i] ^ mask[i%len(mask)]
	}
	return enc
}

func Signc(sysParams *Params, key *Key, msg []byte) *Cipher1 {
	r := randBigInt()
	r.Mod(r, sysParams.M)
	// step 1
	// R = g ^ r, T = e(pka, pka) ^ r
	R := sysParams.g.NewFieldElement().PowBig(sysParams.g, r)
	T := sysParams.x.NewFieldElement().Pair(key.pk, key.pk)
	T.PowBig(T, r)
	// step 2
	// warning the number of n
	// k1 = H1(g ^ r), k2 = H2(T), k3 = H3(T)
	k1 := R.Bytes()
	k2 := T.Bytes()
	k3 := T.Bytes()
	// c = m xor k2, h = H4(pka,k1,k2,k3,c), D = g ^ (ska * h), s = r - ska * h
	c := xor(msg, k2)
	th := make([]byte, 0)
	th = append(th, key.pk.Bytes()...)
	th = append(th, k1...)
	th = append(th, k3...)
	th = append(th, c...)
	h := new(big.Int).SetBytes(th)
	h.Mod(h, sysParams.M)

	tn := new(big.Int)
	tn.Mul(h, key.sk)
	tn.Mod(tn, sysParams.M)
	D := sysParams.g.NewFieldElement()
	D.PowBig(sysParams.g, tn)

	s := new(big.Int)
	s.Sub(r, tn)
	s.Mod(s, sysParams.M)

	return &Cipher1{
		c: c,
		D: D,
		s: s,
	}
}

func UnSignc1(sysParams *Params, cipher1 *Cipher1, key *Key) ([]byte, bool) {
	R := sysParams.g.NewFieldElement().PowBig(sysParams.g, cipher1.s)
	R.Mul(R, cipher1.D)

	k1 := R.Bytes()
	tk3 := sysParams.x.NewFieldElement()
	tk3.Pair(R, key.pk)
	tk3.PowBig(tk3, key.sk)
	k3 := tk3.Bytes()

	tn := make([]byte, 0)
	tn = append(tn, key.pk.Bytes()...)
	tn = append(tn, k1...)
	tn = append(tn, k3...)
	tn = append(tn, cipher1.c...)
	n := new(big.Int).SetBytes(tn)
	n.Mod(n, sysParams.M)

	V := sysParams.g.NewFieldElement()
	V.PowBig(key.pk, n)
	isValid := (cipher1.D.X().Cmp(V.X()) == 0) && (cipher1.D.Y().Cmp(V.Y()) == 0)

	tk2 := sysParams.x.NewFieldElement()
	tk2.Pair(R, key.pk)
	tk2.PowBig(tk2, key.sk)
	k2 := tk2.Bytes()
	return xor(cipher1.c, k2), isValid
}

func ReSinc(sysParams *Params, cipher1 *Cipher1, rk *pbc.Element) *Cipher2 {
	// c = cipher1.c
	c := make([]byte, len(cipher1.c))
	copy(c, cipher1.c)
	// r' = g ^ r = (g ^ s) * D
	gs := sysParams.g.NewFieldElement().PowBig(sysParams.g, cipher1.s)
	r := sysParams.g.NewFieldElement().Mul(gs, cipher1.D)
	// k = e(g, g) ^ (ska^2 * skb^r) = e(r', rk)
	k := sysParams.x.NewFieldElement()
	k.Pair(r, rk)
	// s' = H5(H1(r'), D, c, k) ^ s
	// s' -> G1
	ts := make([]byte, 0)
	ts = append(ts, r.Bytes()...)
	ts = append(ts, cipher1.D.Bytes()...)
	ts = append(ts, cipher1.c...)
	ts = append(ts, k.Bytes()...)
	s := sysParams.g.NewFieldElement()
	s.SetBytes(ts)
	s.PowBig(s, cipher1.s)

	return &Cipher2{
		c: c,
		r: r,
		s: s,
		k: k,
	}
}

func UnSignc2(sysParams *Params, cipher2 *Cipher2, skey *Key, pkey *Key) ([]byte, bool) {
	invSk := new(big.Int).ModInverse(skey.sk, sysParams.M)
	k2 := sysParams.x.NewFieldElement().PowBig(cipher2.k, invSk)

	k1 := cipher2.r.Bytes()
	k3 := k2.Bytes()
	th := make([]byte, 0)
	th = append(th, pkey.pk.Bytes()...)
	th = append(th, k1...)
	th = append(th, k3...)
	th = append(th, cipher2.c...)
	h1 := new(big.Int).SetBytes(th)
	h1.Mod(h1, sysParams.M)
	//invH1 := new(big.Int).ModInverse(h1, sysParams.M)
	//invH1 := new(big.Int).Sub(h1, sysParams.M)
	//invH1.Mod(invH1, sysParams.M)
	negH1 := new(big.Int).Neg(h1)
	negH1.Mod(negH1, sysParams.M)

	pkh1 := sysParams.g.NewFieldElement().PowBig(pkey.pk, h1)
	th = make([]byte, 0)
	th = append(th, k1...)
	th = append(th, pkh1.Bytes()...)
	th = append(th, cipher2.c...)
	th = append(th, cipher2.k.Bytes()...)
	h2 := sysParams.g.NewFieldElement().SetBytes(th)

	v1 := sysParams.x.NewFieldElement().Pair(cipher2.s, sysParams.g)
	v21 := sysParams.x.NewFieldElement().Pair(h2, cipher2.r)
	v22 := sysParams.x.NewFieldElement().Pair(h2, pkey.pk)
	v22.PowBig(v22, negH1)
	v2 := sysParams.x.NewFieldElement().Mul(v21, v22)

	isValid := (v1.X().Cmp(v2.X()) == 0) && (v1.Y().Cmp(v2.Y()) == 0)

	return xor(cipher2.c, k2.Bytes()), isValid
}
