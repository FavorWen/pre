package pre

import (
	"fmt"
	"testing"
)

func TestSerialization(t *testing.T) {
	sys := SetUp()
	buf, _ := sys.Export()
	s := new(Params)
	s.Load(buf)
}

func TestSample(t *testing.T) {
	var err error
	sysA := SetUp()
	keyA := KeyGen(sysA)
	pubABytes, _ := keyA.ExportPubKey()

	buf, _ := sysA.Export()
	sysB := new(Params)
	sysB.Load(buf)

	keyB := KeyGen(sysB)
	pubBBytes, _ := keyB.ExportPubKey()

	keyAB := KeyGen(sysA)
	keyAB.Load(pubBBytes)

	keyBA := KeyGen(sysB)
	keyBA.Load(pubABytes)

	rkA := RKeyGen(sysA, keyA, keyAB)
	rkBytes := ExportRK(rkA)
	rkB := LoadRK(sysB, rkBytes)

	msg := []byte{1, 2, 3, 4, 5, 6}
	// A do Signc
	c1 := Signc(sysA, keyA, msg)
	c1b, err := c1.Export()
	if err != nil {
		fmt.Println("c1 export fail")
		return
	}
	// Server do ReSinc
	c1S := new(Cipher1)
	c1S.Load(sysB, c1b)
	c2 := ReSinc(sysB, c1S, rkB)
	c2b, err := c2.Export()
	if err != nil {
		fmt.Println("c2 export fail")
		return
	}
	// A do UnSignc1
	m1, valid1 := UnSignc1(sysA, c1, keyA)
	// B do UnSignc2
	c2B := new(Cipher2)
	c2B.Load(sysB, c2b)
	m2, valid2 := UnSignc2(sysB, c2B, keyB, keyBA)
	fmt.Printf("m':%v,isValid:%v\n", m1, valid1)
	fmt.Printf("m':%v,isValid:%v\n", m2, valid2)
	//-----------------------------------------------------
	//-----------------------------------------------------
	//-----------------------------------------------------
	msg = []byte{9, 8, 7, 6, 5, 4}
	// A do Signc
	c1 = Signc(sysA, keyA, msg)
	c1b, err = c1.Export()
	if err != nil {
		fmt.Println("c1 export fail")
		return
	}
	// Server do ReSinc
	c1S = new(Cipher1)
	c1S.Load(sysB, c1b)
	c2 = ReSinc(sysB, c1S, rkB)
	c2b, err = c2.Export()
	if err != nil {
		fmt.Println("c2 export fail")
		return
	}
	// A do UnSignc1
	m1, valid1 = UnSignc1(sysA, c1, keyA)
	// B do UnSignc2
	c2B = new(Cipher2)
	c2B.Load(sysB, c2b)
	m2, valid2 = UnSignc2(sysB, c2B, keyB, keyBA)
	fmt.Printf("m':%v,isValid:%v\n", m1, valid1)
	fmt.Printf("m':%v,isValid:%v\n", m2, valid2)
}
