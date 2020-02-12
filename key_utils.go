package jwt

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"encoding/json"
	"reflect"

	"github.com/dgrijalva/jwt-go"
)

type PublicKeyMarshal struct {
	Key interface{}
}

func (key *PublicKeyMarshal) MarshalJSON() ([]byte, error) {
	var ty string

	if IsRsaPublicKey(key) {
		ty = "rsa"
	} else if IsEcdsaPublicKey(key) {
		ty = "ecdsa"
	} else {
		return nil, fmt.Errorf("Invalid public key type")
	}

	value := struct {
		Type string `json:"type"`
		Value interface{} `json:"value"`
	}{Type: ty, Value: key.Key}

	return json.Marshal(&value)
}

func (key *PublicKeyMarshal) UnmarshalJSON(data []byte) error {
	value, err := UnmarshalCustomValue(data, "type", "value", map[string]reflect.Type{
		"rsa": reflect.TypeOf(rsa.PublicKey{}),
		"ecdsa": reflect.TypeOf(ecdsa.PublicKey{}),
	})
	if err != nil {
		return err
	}

	key.Key = value

	return nil
}

func ParsePublicKey(pem []byte) (interface{}, error) {
	result, err := jwt.ParseRSAPublicKeyFromPEM(pem)
	if err != nil {
		result2, err2 := jwt.ParseECPublicKeyFromPEM(pem)
		if err2 == nil {
			return result2, nil
		}
	}
	return result, err
}

func ReadPublicKeyFile(filepath string) (interface{}, error) {
	content, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	return ParsePublicKey(content)
}

func IsRsaPublicKey(key interface{}) bool {
	_, ok := key.(*rsa.PublicKey)
	return ok
}

func IsEcdsaPublicKey(key interface{}) bool {
	_, ok := key.(*ecdsa.PublicKey)
	return ok
}

func IsRsaToken(token *jwt.Token) bool {
	_, ok := token.Method.(*jwt.SigningMethodRSA)
	return ok
}

func IsEcdsaToken(token *jwt.Token) bool {
	_, ok := token.Method.(*jwt.SigningMethodECDSA)
	return ok
}

func IsHmacToken(token *jwt.Token) bool {
	_, ok := token.Method.(*jwt.SigningMethodHMAC)
	return ok
}

func AssertPublicKeyAndTokenCombination(publicKey interface{}, token *jwt.Token) error {
	if IsRsaPublicKey(publicKey) && !IsRsaToken(token) {
		return fmt.Errorf("expect token signed with RSA but got %v", token.Header["alg"])
	}
	if IsEcdsaPublicKey(publicKey) && !IsEcdsaToken(token) {
		return fmt.Errorf("expect token signed with ECDSA but got %v", token.Header["alg"])
	}
	return nil
}

func AssertHmacToken(token *jwt.Token) error {
	if !IsHmacToken(token) {
		return fmt.Errorf("expect token signed with HMAC but got %v", token.Header["alg"])
	}
	return nil
}

func UnmarshalCustomValue(data []byte, typeJsonField, valueJsonField string, customTypes map[string]reflect.Type) (interface{}, error) {
	m := map[string]interface{}{}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}

	typeName := m[typeJsonField].(string)
	var value interface{}
	if ty, found := customTypes[typeName]; found {
		value = reflect.New(ty).Interface()
	}

	valueBytes, err := json.Marshal(m[valueJsonField])
	if err != nil {
		return nil, err
	}

	if err = json.Unmarshal(valueBytes, &value); err != nil {
		return nil, err
	}

	return value, nil
}