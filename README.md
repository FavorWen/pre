# An implementaion of PRE with publicly verification
Proxy Re-Encryption with publicly verification, pre in short, is proposed in [Signcryption of proxy re-encryption with publicly verificatio](http://www.joca.cn/CN/abstract/abstract16309.shtml).

This implementaion is based on [pbc](https://github.com/Nik-U/pbc). Thanks for pbc's contributors.

## Algorithm
1. SetUp(lamda) -> public params
2. KeyGen() -> key pairs
3. RkeyGen() -> re-encryption key
4. Signc() -> original cipher
5. ReSignc() -> re-encryption cipher
6. UnSignc() -> plaintext
if you want to know how it works, go to read the [paper](http://www.joca.cn/CN/abstract/abstract16309.shtml).

## Usage
- pre.go implemented the core Algorithm
- ulti.go implemented how to seriliaze the data structures in pre
This project is based on [pbc](https://github.com/Nik-U/pbc), so you need to install pbc first. And a very important thing is you need to modify [element.go](https://github.com/Nik-U/pbc/blob/master/element.go) or the serialization will fail!
```go
func checkFieldsMatch(f1, f2 *C.struct_field_s) {
    if f1 != f2 {
		return
	}
    /*
	if f1 != f2 {
		panic(ErrIncompatible)
	}*/
}
```
Usage sample is in `pre_test.go`-TestSample()

