package main

import (
	//"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math"
	"time"
)

func keyGenOption(keyLen int) (*string, *string, error) {
	var RSApublic, RSAprivate string
	if math.Mod(float64(keyLen), 8) != 0 {
		return nil, nil, errors.New("Key length not vaild!!!")
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, keyLen)
	if err != nil {
		return nil, nil, err
	}

	publicKey := &privateKey.PublicKey
	PubASN1, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, nil, err
	}
	pemPublickey := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: PubASN1,
	}
	bytePublic := pem.EncodeToMemory(pemPublickey)
	RSApublic = hex.EncodeToString(bytePublic[:])

	Priv := x509.MarshalPKCS1PrivateKey(privateKey)
	pemPrivatekey := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: Priv,
	}
	bytePrivate := pem.EncodeToMemory(pemPrivatekey)
	RSAprivate = hex.EncodeToString(bytePrivate[:])
	return &RSApublic, &RSAprivate, nil
}

func (s *User) Sign(message []byte) ([]byte, error) {
	privatekeyFile, err := hex.DecodeString(s.RSAprivate)
	if err != nil {
		return nil, err
	}
	privatekey, err := readPKCSKeyFormat(privatekeyFile)
	if err != nil {
		return nil, err
	}
	rsaPriv := privatekey.(*rsa.PrivateKey)
	doplain, err := signOpt(message, rsaPriv)

	if err != nil {
		return nil, err
	}

	return doplain, nil
}

func (s *User) Verify(message, sig []byte) error {
	publickeyFile, err := hex.DecodeString(s.RSApublic)

	if err != nil {
		return err
	}
	publickey, err1 := readPKCSKeyFormat(publickeyFile)
	if err1 != nil {
		return err1
	}
	rsaPub := publickey.(*rsa.PublicKey)
	verify := unsignOpt(message, sig, rsaPub)
	return verify
}

func readPKCSKeyFormat(filedata []byte) (interface{}, error) {
	data, _ := pem.Decode([]byte(filedata))
	if data == nil {
		return nil, errors.New("No key found")
	}

	var raw interface{}
	switch data.Type {
	case "RSA PRIVATE KEY":
		private, err := x509.ParsePKCS1PrivateKey(data.Bytes)
		if err != nil {
			return nil, err
		}
		raw = private
	case "RSA PUBLIC KEY":
		public, err := x509.ParsePKIXPublicKey(data.Bytes)
		if err != nil {
			return nil, err
		}
		raw = public
	}

	return raw, nil
}

func handErr(err error, exit bool) {
	fmt.Println(err.Error())
}

func signOpt(data []byte, r *rsa.PrivateKey) ([]byte, error) {
	d := sha256.Sum256(data)
	return rsa.SignPKCS1v15(rand.Reader, r, crypto.SHA256, d[:])
}

func unsignOpt(mess []byte, sig []byte, r *rsa.PublicKey) error {
	d := sha256.Sum256(mess)
	return rsa.VerifyPKCS1v15(r, crypto.SHA256, d[:], sig[:])
}

//su dung AES voi CFB block mode
func (s *User) AESencrypt(input []byte) ([]byte, error) {
	//Hệ thống tự phát sinh ra 1 khóa bí mật (secret key Ks) có độ dài phù hợp với thuật toán
	pass := []byte(s.PassSaltHash)
	times := []byte(time.Now().Format(time.RFC850))
	pass = append(pass, times...)

	k := sha256.Sum256(pass)

	block, err := aes.NewCipher(k[:])
	if err != nil {
		return nil, err
	}
	data := make([]byte, base64.StdEncoding.EncodedLen(len(input)))
	base64.StdEncoding.Encode(data, input)

	cipherBytes := make([]byte, aes.BlockSize+len(data))

	iv := cipherBytes[:aes.BlockSize]
	io.ReadFull(rand.Reader, iv)

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherBytes[aes.BlockSize:], data)

	signKey, _ := s.RSAencrypt(k[:])
	return append(signKey, cipherBytes...), nil
}

func (s *User) AESdecrypt(data []byte) ([]byte, error) {
	//Hệ thống tự phát sinh ra 1 khóa bí mật (secret key Ks) có độ dài phù hợp với thuật toán
	/*block, err := aes.NewCipher(k[:])*/
	//if err != nil {
	//return nil, err
	//}
	privatekeyFile, _ := hex.DecodeString(s.RSAprivate)
	privatekey, _ := readPKCSKeyFormat(privatekeyFile)
	rsaPriv := privatekey.(*rsa.PrivateKey)

	lenKey := rsaPriv.N.BitLen() / 8
	keySign, cipherBytes := data[:lenKey], data[lenKey:]

	key, _ := s.RSAdecrypt(keySign)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := cipherBytes[:aes.BlockSize]
	data = cipherBytes[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(data, data)

	dataMess := make([]byte, base64.StdEncoding.DecodedLen(len(data)))

	if _, err := base64.StdEncoding.Decode(dataMess, data); err != nil {
		return nil, err
	}
	return dataMess, nil
}

func (s *User) RSAencrypt(message []byte) ([]byte, error) {
	var rsaPub *rsa.PublicKey
	//PKCS1PrivateKey standard
	publicKeyFile, err := hex.DecodeString(s.RSApublic)
	if err != nil {
		return nil, err
	}
	data, err := readPKCSKeyFormat(publicKeyFile)
	if err != nil {
		return nil, err
	}
	rsaPub = data.(*rsa.PublicKey)
	return rsa.EncryptPKCS1v15(rand.Reader, rsaPub, message)
}

func (s *User) RSAdecrypt(cipher []byte) ([]byte, error) {

	var rsaPriv *rsa.PrivateKey

	privateKeyFile, err := hex.DecodeString(s.RSAprivate)
	if err != nil {
		return nil, err
	}
	data, err := readPKCSKeyFormat(privateKeyFile)
	if err != nil {
		return nil, err
	}
	rsaPriv = data.(*rsa.PrivateKey)

	return rsa.DecryptPKCS1v15(rand.Reader, rsaPriv, cipher)
}
