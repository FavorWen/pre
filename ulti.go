package pre

import (
	"bytes"
	"encoding/binary"
	"math/big"

	"github.com/Nik-U/pbc"
)

type Err struct {
	Msg string
}

func (err *Err) Error() string {
	return err.Msg
}

//int to []byte
func IntToBytes(n int) []byte {
	x := int32(n)

	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, x)
	return bytesBuffer.Bytes()
}

//[]byte to int
func BytesToInt(b []byte) int {
	bytesBuffer := bytes.NewBuffer(b)

	var x int32
	binary.Read(bytesBuffer, binary.BigEndian, &x)

	return int(x)
}

func ExportRK(rk *pbc.Element) []byte {
	return rk.Bytes()
}

func LoadRK(sys *Params, buf []byte) *pbc.Element {
	return sys.g.NewFieldElement().SetBytes(buf)
}

func (sys *Params) Load(buf []byte) error {
	// sys.M
	idx := 0
	l := BytesToInt(buf[idx : idx+4])
	idx += 4
	sys.M = new(big.Int).SetBytes(buf[idx : idx+l])
	idx += l
	// sys.params
	l = BytesToInt(buf[idx : idx+4])
	idx += 4
	s := string(buf[idx : idx+l])
	idx += l
	var err error
	sys.params, err = pbc.NewParamsFromString(s)
	if err != nil {
		return err
	}
	sys.pairing = sys.params.NewPairing()
	// sys.g
	l = BytesToInt(buf[idx : idx+4])
	idx += 4
	sys.g = sys.pairing.NewG1().Rand().SetBytes(buf[idx : idx+l])
	idx += l
	//sys.x
	l = BytesToInt(buf[idx : idx+4])
	idx += 4
	sys.x = sys.pairing.NewGT().Rand().SetBytes(buf[idx : idx+l])

	return nil
}

func (sys *Params) Export() ([]byte, error) {
	var buf []byte
	// sys.M
	l := len(sys.M.Bytes())
	buf = append(IntToBytes(l), sys.M.Bytes()...)
	// sys.params
	s := sys.params.String()
	l = len([]byte(s))
	buf = append(buf, IntToBytes(l)...)
	buf = append(buf, []byte(s)...)
	// sys.g
	l = len(sys.g.Bytes())
	buf = append(buf, IntToBytes(l)...)
	buf = append(buf, sys.g.Bytes()...)
	// sys.x
	l = len(sys.x.Bytes())
	buf = append(buf, IntToBytes(l)...)
	buf = append(buf, sys.x.Bytes()...)
	return buf, nil
}

// Export Key.pk, and ignore key.sk
func (key *Key) ExportPubKey() ([]byte, error) {
	k := new(Key)
	k.pk = key.pk
	k.sk = nil
	return k.GobEncoder()
}

// Export Key.sk, and ignore key.pk
func (key *Key) ExportSecKey() ([]byte, error) {
	k := new(Key)
	k.pk = nil
	k.sk = key.sk
	return k.GobEncoder()
}

// Export Key
func (key *Key) ExportKey() ([]byte, error) {
	k := new(Key)
	k.pk = key.pk
	k.sk = key.sk
	return k.GobEncoder()
}

func (key *Key) Load(buf []byte) error {
	return key.GobDecoder(buf)
}

func (key *Key) GobEncoder() ([]byte, error) {
	if key.pk == nil && key.sk == nil {
		return nil, &Err{
			Msg: "sk and pk are nil",
		}
	}
	var pkb, skb []byte
	var pkl int
	if key.pk != nil {
		pkb = key.pk.Bytes()
		pkl = len(pkb)
	} else {
		pkl = 0
	}
	if key.sk != nil {
		skb = key.sk.Bytes()
	}
	var buf []byte
	if pkl == 0 {
		buf = append(IntToBytes(pkl), skb...)
	} else {
		buf = append(IntToBytes(pkl), pkb...)
		buf = append(buf, skb...)
	}
	return buf, nil
}

func (key *Key) GobDecoder(buf []byte) error {
	if buf == nil {
		return &Err{
			Msg: "buf is nil",
		}
	} else if len(buf) <= 4 {
		return &Err{
			Msg: "buf is broken",
		}
	}
	pkl := BytesToInt(buf[:4])
	skl := len(buf) - pkl - 4
	if len(buf) < pkl+4 {
		return &Err{
			Msg: "buf is broken",
		}
	}
	if pkl != 0 {
		key.pk.SetBytes(buf[4 : pkl+4])
	} else {
		key.pk = nil
	}
	if skl != 0 {
		key.sk.SetBytes(buf[4+pkl:])
	} else {
		key.sk = nil
	}
	return nil
}

func (c1 *Cipher1) Export() ([]byte, error) {
	var buf []byte
	buf = append(IntToBytes(len(c1.c)), c1.c...)
	buf = append(buf, IntToBytes(len(c1.D.Bytes()))...)
	buf = append(buf, c1.D.Bytes()...)
	buf = append(buf, IntToBytes(len(c1.s.Bytes()))...)
	buf = append(buf, c1.s.Bytes()...)
	return buf, nil
}

func (c1 *Cipher1) Load(sys *Params, buf []byte) error {
	if buf == nil {
		return &Err{"buf is nil"}
	}
	// c1.c
	idx := 0
	l := BytesToInt(buf[idx : idx+4])
	idx += 4
	c1.c = buf[idx : idx+l]
	idx += l
	// c1.D
	l = BytesToInt(buf[idx : idx+4])
	idx += 4
	c1.D = sys.g.NewFieldElement().SetBytes(buf[idx : idx+l])
	idx += l
	// c1.s
	l = BytesToInt(buf[idx : idx+4])
	idx += 4
	c1.s = new(big.Int).SetBytes(buf[idx : idx+l])
	idx += l
	return nil
}

func (c2 *Cipher2) Export() ([]byte, error) {
	var buf []byte
	buf = append(IntToBytes(len(c2.c)), c2.c...)
	buf = append(buf, IntToBytes(len(c2.r.Bytes()))...)
	buf = append(buf, c2.r.Bytes()...)
	buf = append(buf, IntToBytes(len(c2.s.Bytes()))...)
	buf = append(buf, c2.s.Bytes()...)
	buf = append(buf, IntToBytes(len(c2.k.Bytes()))...)
	buf = append(buf, c2.k.Bytes()...)
	return buf, nil
}

func (c2 *Cipher2) Load(sys *Params, buf []byte) error {
	if buf == nil {
		return &Err{"buf is nil"}
	}
	// c2.c
	idx := 0
	l := BytesToInt(buf[idx : idx+4])
	idx += 4
	c2.c = buf[idx : idx+l]
	idx += l
	// c2.r
	l = BytesToInt(buf[idx : idx+4])
	idx += 4
	c2.r = sys.g.NewFieldElement().SetBytes(buf[idx : idx+l])
	idx += l
	// c2.s
	l = BytesToInt(buf[idx : idx+4])
	idx += 4
	c2.s = sys.g.NewFieldElement().SetBytes(buf[idx : idx+l])
	idx += l
	// c2.k
	l = BytesToInt(buf[idx : idx+4])
	idx += 4
	c2.k = sys.x.NewFieldElement().SetBytes(buf[idx : idx+l])
	idx += l
	return nil
}

func ExportVerifyParams(sys *Params, c2 *Cipher2, pkey *Key) ([]byte, error) {
	sysBytes, _ := sys.Export()
	c2Bytes, _ := c2.Export()
	keyBytes, _ := pkey.ExportPubKey()

	var buf []byte
	buf = append(IntToBytes(len(sysBytes)), sysBytes...)
	buf = append(buf, IntToBytes(len(c2Bytes))...)
	buf = append(buf, c2Bytes...)
	buf = append(buf, IntToBytes(len(keyBytes))...)
	buf = append(buf, keyBytes...)
	return buf, nil

}

func LoadVerifyParams(buf []byte) (sys *Params, c2 *Cipher2, key *Key) {
	// sys
	idx := 0
	l := BytesToInt(buf[idx : idx+4])
	idx += 4
	sys = new(Params)
	sys.Load(buf[idx : idx+l])
	idx += l
	// c2
	l = BytesToInt(buf[idx : idx+4])
	idx += 4
	c2 = new(Cipher2)
	c2.Load(sys, buf[idx:idx+l])
	idx += l
	// key
	l = BytesToInt(buf[idx : idx+4])
	idx += 4
	key = KeyGen(sys)
	key.Load(buf[idx : idx+l])
	idx += l
	return
}
