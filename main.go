// jwt project main.go
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"strings"
)

const authorization = `XBL3.0 x=5381178999727281455;eyJlbmMiOiJBMTI4Q0JDK0hTMjU2IiwiYWxnIjoiUlNBLU9BRVAiLCJjdHkiOiJKV1QiLCJ6aXAiOiJERUYiLCJ4NXQiOiI4VmUyZ0x6NEZUYXZEN0xwV2psdXg2TTVZd2sifQ.hYOvo3BJqGXOFLIXaQkNwssLkSYdv8TjDKcEmrBjGhFku7TmGg3BekhUGNwDiReDwhGPvfYxikcLd38lj0kHxYq7_BU_yL0z5vTv5VckD0L7QORCftFA3JERobe7z7HoLzSM7LyyTR6yGAlMs-vHBF4drsjX-oWrkwo22nposlA1zkPC2NjTvNaQrmkz0qdWjKVl2jK2y-gxQXTAY5KGqQ0jWcg0Ne0_YvyyepY2SYCXTtctnNdeguXOJ3VJ0A5NWJrpPofH4AgFh5T2iLAeJR1Elf-prMLBFfBw5tv0rbEcY2HDrekRYWZ2WSQrRIAT3i_MqggPjwa3kB6vIcqHag.kM3aobqF1XjFLFvRh4FXOg.BGqHU0mtnLf_EMRUAvEiLwpdCP6ItVV4BOza-6i3pJDsLadd8XK09Wb_5vYregxdwWuIREOt55vZI655PWWandXKt193ZVSCKYg9TdkOJomoBkXCFI1PJHTg6_crtLyT6ZmOyv4sY2XbqdK1IpLkfzBr5lWO_S6bVV-FvzN3jNrIXLbVW1afF9sPrjYLQ1nUAqV804IJVIMYEdvRLnbVmq3gtrt2yIuPAB7i3xXtQItJ3MwbfEqKRLf382GaMJ8tJGdP76A_wMyZwjMs1kjGK4N1HJt0BoXEiB-bXFJLPEWXZEAm6S4euwggdQ2PVQpT0v3cTJcbQUfpJtnH7cB1fivYQrunZLxPIi6S2AoaY5XW0nYBPeMy5T1jC1luOowDsYQjsAdKgL4eflu8pNpsMX6U1TAygEJpxn_6ZLIFP2iiCRUVjVws8EAM5WiHLx94aXjFYpLwBHeIUYGoTzPUqdKrU__FHcioobgmDU9g1yHHwtVCseKNM1bHlPa6u1-kc0GiftcF7LmpnHtL-XWKvuGjIuoP52E9AC7ARk4tTT3CSafYHEiDti4zaO1x9AAZpHuRsSDJJyuiAhPaEJVOJuuPJIaP-zr8gfy_kYyf0ENehwayRLSIXZZdNzRbD5aic2iB3lHX1vnao7vUTuNGplIqugUOdc6ymxlbxsTpwttWeJM3yBL569-OGvL4-ZKIMmlDJGXNW5p6fGRVUePZi3V3fHa826UQ2ZJFLaRSRpdWsqYpsvb0HdBzDccNHphl89Q2KHAKhlkWKOYSljwFRAbKHM_O6f0jRhIY2rv3qlJa5uWKKFB-jg3JdVfmMHUdWxNF5o2vbZlJcQ-ym0VXWnnphuZ74IRq9dQ4W_G3IdxkX8I-chgoNfbYyYWsDd_Kd9GdlkPBOu00TkREQgDOqq59nuaDycIHwv7PoBlsmhcWH7vDaOW5Tl2vmFXA3A8YLlhmIhBc3fhWQ_l7KjntNGw4XribhEz_0myunb5C730vJpKrXPFlD8Q-H7H_RKRco-ZE-dXgblQZgbvbD8u1nKOHRV5PdtDiFTuil04w67h_5M1u7nRoJqtUCxNvXEyfNbZOQ0O51_Y3JZH8vq98womp78ahFwORS0m0hI8XtJgoa7j5cdCrobtZGNIs-8jeILztbbVZgFhGp-TYyLd_7Yy69MTyHFOgBaRvmFKMrHDfPKIAZ0ZU9fMjh5FDAIsY5jZToefGPiEDclNZpRwu8S-AMqqqli3-yPKzexCUJ0iTEJcnU_SJqMURWuJHlR3q.pKRsk9pEpMXAkNoUXmfzVjXRB6DKw4PROgw_WkyyiUg`

type JwtHeader struct {
	Zip        string `json:"zip"` //NONE or DEF
	Thumbprint string `json:"x5t"` //x509 token
	Enc        string `json:"enc"` //A128CBC+HS256, not A128CBC-HS256
	Alg        string `json:"alg"` //RSA-OAEP
	Cty        string `json:"cty"` //JWT
}

type JsonObjectEncrypted struct {
	UserId string
	Header JwtHeader
	Key    []byte // encrypted and plain
	Iv     []byte
	Text   []byte
	Tag    []byte
}

var (
	invalid_format = errors.New("invalid format")
)

func load_pkcs8_pem(fn string) (*rsa.PrivateKey, error) {
	d, err := ioutil.ReadFile(fn)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(d)
	if block == nil {
		return nil, invalid_format
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	return k.(*rsa.PrivateKey), err
}
func parse_jwtheader(x []byte) (header JwtHeader, err error) {
	err = json.Unmarshal(x, &header)
	return
}
func parse_userid(x string) (uid string, err error) {
	fields := strings.Split(x, "=")
	if len(fields) != 2 {
		return "", invalid_format
	}
	return fields[1], nil
}
func base64decode_fields(x string) ([][]byte, error) {
	fields := strings.Split(x, ".")
	if len(fields) != 5 {
		return nil, invalid_format
	}
	v := make([][]byte, len(fields))
	for i, f := range fields {
		if data, err := base64.StdEncoding.DecodeString(f); err != nil {
			return nil, err
		} else {
			v[i] = data
		}
	}
	return v, nil
}
func parse_jwe_joe(x string) (joe *JsonObjectEncrypted, err error) {
	fields := strings.Split(x, ";")
	if len(fields) != 2 {
		return nil, invalid_format
	}
	joe = &JsonObjectEncrypted{}
	if joe.UserId, err = parse_userid(fields[0]); err != nil {
		return
	}
	var bfields [][]byte
	if bfields, err = base64decode_fields(fields[1]); err != nil {
		return
	}
	if joe.Header, err = parse_jwtheader(bfields[0]); err != nil {
		return
	}
	joe.Key, joe.Iv, joe.Text, joe.Tag = bfields[1], bfields[2], bfields[3], bfields[4]
	return
}
func print_joe(auth *JsonObjectEncrypted) {
	log.Println("user:", auth.UserId)
	log.Println("jwt-header:", auth.Header)
}

//ignore mac key
//key-type = "A128CBC+HS256"
//key-size = 128
func concat_kdf(cek []byte) []byte {
	buf := &bytes.Buffer{}

	binary.Write(buf, binary.BigEndian, uint32(1))
	binary.Write(buf, binary.BigEndian, cek)
	binary.Write(buf, binary.BigEndian, uint32(128))
	binary.Write(buf, binary.BigEndian, []byte("A128CBC+HS256"))
	binary.Write(buf, binary.BigEndian, uint32(0))
	binary.Write(buf, binary.BigEndian, uint32(0))
	binary.Write(buf, binary.BigEndian, []byte("Encryption"))

	h := sha256.New()
	io.Copy(h, buf)

	return h.Sum(nil)[:128/8]
}

//why use sha1
func rsa_oaep_unwrap(cek []byte, key *rsa.PrivateKey) ([]byte, error) {
	v, err := rsa.DecryptOAEP(sha1.New(), nil, key, cek, []byte{})
	return v, err
}

//AES/CBC/PKCS5Padding
func a128_cbc_hs256(bin []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	bm := cipher.NewCBCDecrypter(block, iv)
	bm.CryptBlocks(bin, bin)
	return bin, nil
}

const pk = `K:\ws\AAA_1.3.0_XBOX_build20150126\resource\xsts.auth.bestv.com.pkcs8_der.key.pem`

func main() {
	enced, err := parse_jwe_joe(authorization)
	if err != nil {
		panic(err)
	}
	print_joe(enced)
	private_key, err := load_pkcs8_pem(pk)
	if err != nil {
		panic(err)
	}
	cek, err := rsa_oaep_unwrap(enced.Key, private_key)
	aeskey := concat_kdf(cek)                                  // non-standard
	plain, err := a128_cbc_hs256(enced.Text, aeskey, enced.Iv) //a128-cbc+hs256
	log.Println(err, plain)
}
