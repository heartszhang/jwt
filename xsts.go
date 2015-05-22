// jwt project main.go
package main

import (
	"bytes"
	"compress/flate"
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
	"io/ioutil"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type JoseHeader struct {
	Zip        string `json:"zip"` //NONE or DEF
	Thumbprint string `json:"x5t"` //x509 token
	Enc        string `json:"enc"` //A128CBC+HS256, not A128CBC-HS256
	Alg        string `json:"alg"` //RSA-OAEP
	Cty        string `json:"cty"` //JWT
}

type JsonObjectEncrypted struct {
	UserId string
	Header JoseHeader
	Key    []byte // encrypted and plain
	Iv     []byte
	Text   []byte
	Tag    []byte
}

func (joe JsonObjectEncrypted) ToString() string {
	header, _ := json.Marshal(joe.Header)
	f0 := base64.URLEncoding.EncodeToString(header)
	f1 := base64.URLEncoding.EncodeToString(joe.Key)
	f2 := base64.URLEncoding.EncodeToString(joe.Iv)
	f3 := base64.URLEncoding.EncodeToString(joe.Text)
	f4 := base64.URLEncoding.EncodeToString(joe.Tag)

	return "XBL3.0 x=" + joe.UserId + ";" + f0 + "." + f1 + "." + f2 + "." + f3 + "." + f4
}

//rsa private key, pkc8.pem
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

//http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html
func parse_jwtheader(x []byte) (header JoseHeader, err error) {
	err = json.Unmarshal(x, &header)
	return
}

//xbox userid, 023513000031081 can be used as default
//XBL3.0 x=023513000031081
func parse_userid(x string) (uid string, err error) {
	fields := strings.Split(x, "=")
	if len(fields) != 2 {
		return "", invalid_format
	}
	return fields[1], nil
}

//RawURLEncoding was remove from golang's base64 package. I don't know the reason
func base64_decode_padding(x string) ([]byte, error) {
	for i := len(x) % 4; i > 0 && i < 4; i++ {
		x += "="
	}
	return base64.URLEncoding.DecodeString(x)
}

//jwtheader . cek . iv . text . tag
//compact jose
func base64decode_parts(x string) (v [][]byte, err error) {
	fields := strings.Split(x, ".")
	if len(fields) != 5 {
		return nil, invalid_format
	}
	for _, f := range fields {
		if data, err := base64_decode_padding(f); err != nil {
			return nil, err
		} else {
			v = append(v, data)
		}
	}
	return v, nil
}

//http-header authorization XBL3.0..., se const 'authorization'
func parse_jwe_joe(x string) (joe *JsonObjectEncrypted, err error) {
	fields := strings.Split(x, ";")
	if len(fields) != 2 {
		return nil, invalid_format
	}
	joe = &JsonObjectEncrypted{}
	if joe.UserId, err = parse_userid(fields[0]); err != nil {
		return
	}

	var parts [][]byte
	if parts, err = base64decode_parts(fields[1]); err != nil {
		return
	}
	if joe.Header, err = parse_jwtheader(parts[0]); err != nil {
		return
	}
	joe.Key, joe.Iv, joe.Text, joe.Tag = parts[1], parts[2], parts[3], parts[4]
	return
}

//print jose's field, different from ToString
func print_joe(auth *JsonObjectEncrypted) {
	//	log.Println("user:", auth.UserId)
	//	log.Println("jwt-header:", auth.Header)
}

//ignore mac key
//key-type = "A128CBC+HS256"
//key-size = 128
//I dont' know why bestv just use concat and sha256 only. it's very different from hmac+sha256
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
	h.Write(buf.Bytes())

	return h.Sum(nil)[:128/8]
}

//I don't know why to use sha1, but it does work.
func rsa_oaep_unwrap(cek []byte, key *rsa.PrivateKey) ([]byte, error) {
	return rsa.DecryptOAEP(sha1.New(), nil, key, cek, []byte{})
}

//AES/CBC/PKCS5Padding
//pkcs5_unpadding is unnecessary
func a128_cbc_hs256_decrypt(bin []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aes := cipher.NewCBCDecrypter(block, iv)
	aes.CryptBlocks(bin, bin)
	//return pkcs5_unpadding(bin), nil
	return bin, nil
}

//pkcs5_padding is necessary
func a128_cbc_hs256_encrypy(bin []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aes := cipher.NewCBCEncrypter(block, iv)
	bin = pkcs5_padding(bin, block.BlockSize())
	aes.CryptBlocks(bin, bin)
	return bin, err
}

func inflate(in []byte) (v []byte, err error) {
	reader := flate.NewReader(bytes.NewReader(in))
	v, err = ioutil.ReadAll(reader)
	reader.Close()
	return
}

func deflate(in []byte) []byte {
	buf := &bytes.Buffer{}
	writer, _ := flate.NewWriter(buf, -1)
	writer.Write(in)
	writer.Close()
	return buf.Bytes()
}

//make expire a week later, leave any other fields unchanged
//base64, plain, base64
func patch_xsts_token(header, token, sig string) []byte {
	expire := time.Now().Add(time.Hour * 7 * 24).Unix()
	re := regexp.MustCompile(`"exp":\d+`)
	token = re.ReplaceAllString(token, `"exp":`+strconv.FormatInt(expire, 10)) //fmt.Sprint(`"exp":`, expire)
	token = base64.URLEncoding.EncodeToString([]byte(token))
	return []byte(header + "." + string(token) + sig)
}

func pkcs5_padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func pkcs5_unpadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}

//you should put pem file in the same dir with jwt.exe. it can be created as below
//openssl pkcs8 -inform DER -in xsts.auth.bestv.com.pkcs8_der.key  -outform PEM -out xsts.auth.bestv.com.pkcs8_der.key.pem
const pk = `xsts.auth.bestv.com.pkcs8_der.key.pem`

func create_xsts_token(uid string) (xsts_token string, err error) {
	private_key, err := load_pkcs8_pem(pk)
	if err != nil {
		return
	}
	joe, err := parse_jwe_joe(authorization)
	if err != nil {
		return
	}
	print_joe(joe)

	cek, err := rsa_oaep_unwrap(joe.Key, private_key)
	if err != nil {
		return
	}
	aeskey := concat_kdf(cek)                                      // non-standard
	plain, err := a128_cbc_hs256_decrypt(joe.Text, aeskey, joe.Iv) //a128-cbc+hs256
	if err != nil {
		return
	}
	if joe.Header.Zip == "DEF" {
		plain, err = inflate(plain)
	}
	if err != nil {
		return
	}
	fields := strings.Split(string(plain), ".")
	if len(fields) < 3 {
		err = invalid_format
	}
	token, _ := base64_decode_padding(fields[1])
	header, sig := fields[0], fields[2]

	//xsts_token
	plain = patch_xsts_token(header, string(token), sig) //header.token.signature
	if joe.Header.Zip == "DEF" {
		plain = deflate(plain)
	}

	joe.Text, err = a128_cbc_hs256_encrypy(plain, aeskey, joe.Iv)
	if err != nil {
		return
	}
	joe.UserId = uid
	xsts_token = joe.ToString()
	return
}
