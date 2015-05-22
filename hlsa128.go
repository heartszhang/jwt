// xbox-bestv-drm project main.go
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"
)

var aes_key []byte

func init() {
	aes_key, _ = hex.DecodeString("2B9B2C2035347F8FC3D2C0C97BA19762")
}

func main_a128() {
	key, err := x_ext_to_a128key(`METHOD=AES-128,URI="bestvdrm://hdnba1/20150516/",IV=0x4D5F8DAF68D0B88142222D0612A15243`)
	log.Println("key", len(key), " ", hex.EncodeToString(key), err)
}
func x_ext_to_a128key(xext string) (key []byte, err error) { //`METHOD=AES-128,URI="bestvdrm://hdnba1/20150516/",IV=0x4D5F8DAF68D0B88142222D0612A15243`
	var uri string
	fields := strings.Split(xext, `,`) //method, uri and iv
	for _, field := range fields {
		kv := strings.Split(field, `=`)
		if len(kv) == 2 && kv[0] == `URI` {
			uri = kv[1]
			break
		}
	}
	if len(uri) == 0 {
		err = errors.New(`LIEK THIS METHOD=AES-128,URI="bestvdrm://hdnba1/20150516/",IV=0x4D5F8DAF68D0B88142222D0612A15243"`)
		return
	}
	return bestvdrm_to_a128key(uri)
}
func bestvdrm_to_a128key(key_url string) (key []byte, err error) { //var key_url = "bestvdrm://hdnba1/20150522/"

	var p = key_params(key_url)
	if len(p) < 2 {
		p = append(p, "")
	}
	var source = fmt.Sprintf("Code=%v&&Date=%v&&DeviceInfo=BESTV&&Sdk=XBOXONE&&ValidTime=%v", p[0], p[1], time.Now().Unix())

	enced, err := aes_ecb_pkcs5padding(aes_key, []byte(source))
	if err != nil {
		return
	}
	var s = []byte(hex.EncodeToString(enced))
	char_switch(s)

	var uri = "http://drmkey.bestvcdn.com/Public/GenerateKey?s=" + string(s)
	resp, err := http.Get(uri)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}

	char_switch(content)
	enced, err = hex.DecodeString(string(content))
	if err != nil {
		return
	}
	s = aes_ecb_pkcs5unpadding(aes_key, enced)
	return hex.DecodeString(string(s))
}
func char_swap(data []byte, a, b byte) {
	for i, c := range data {
		if c == a {
			data[i] = b
		} else if c == b {
			data[i] = a
		}
	}
}

//MATRIX: [["1", "9"], ["2", "4"], ["a", "e"], ["c", "d"]],
func char_switch(data []byte) {
	char_swap(data, '1', '9')
	char_swap(data, '2', '4')
	char_swap(data, 'a', 'e')
	char_swap(data, 'c', 'd')
}
func key_params(s string) []string {
	fields := strings.Split(s, "/")
	return fields[2:]
}
func aes_ecb_pkcs5padding(key, content []byte) (v []byte, err error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	padded := pkcs5_padding(content, b.BlockSize())
	v = make([]byte, len(padded))
	for dst := v; len(padded) > 0; dst = dst[b.BlockSize():] {
		b.Encrypt(dst, padded[:b.BlockSize()])
		padded = padded[b.BlockSize():]
	}
	return
}

//pkcs5_padding is necessary
func a128_cbc_pkcs5padding(bin, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aes := cipher.NewCBCEncrypter(block, iv)
	bin = pkcs5_padding(bin, block.BlockSize())
	aes.CryptBlocks(bin, bin)
	return bin, err
}
func aes_ecb_pkcs5unpadding(key, enced []byte) (v []byte) {
	b, _ := aes.NewCipher(key)
	v = make([]byte, len(enced))
	for dst := v; len(enced) > 0; dst = dst[b.BlockSize():] {
		b.Decrypt(dst, enced)
		enced = enced[b.BlockSize():]
	}
	return pkcs5_unpadding(v)
}
