package jwt

import (
	"fmt"
	"io/ioutil"
	"os"
	"time"
	"encoding/json"
	"reflect"

	"github.com/dgrijalva/jwt-go"
)

const ENV_PUBLIC_KEY = "JWT_PUBLIC_KEY"
const ENV_SECRET = "JWT_SECRET"

// KeyBackend provides a generic interface for providing key material for HS, RS, and ES algorithms
type KeyBackend interface {
	ProvideKey(token *jwt.Token) (interface{}, error)
}

// LazyPublicKeyBackend contains state to manage lazy key loading for RS and ES family algorithms
type LazyPublicKeyBackend struct {
	filename  string
	modTime   time.Time
	publicKey PublicKeyMarshal
}

// NewLazyPublicKeyFileBackend returns a new LazyPublicKeyBackend
func NewLazyPublicKeyFileBackend(value string) (*KeyBackendHolder, error) {
	if len(value) <= 0 {
		return nil, fmt.Errorf("empty filename for public key provided")
	}
	return &KeyBackendHolder {
		Value: &LazyPublicKeyBackend{
			filename: value,
		},
	}, nil
}

// ProvideKey will lazily load a secret key in a file, using a cached value if the key
// material has not changed.  An error is returned if the token does not match the
// expected signing algorithm.
func (instance *LazyPublicKeyBackend) ProvideKey(token *jwt.Token) (interface{}, error) {
	err := instance.loadIfRequired()
	if err != nil {
		return nil, err
	}
	if err := AssertPublicKeyAndTokenCombination(instance.publicKey.Key, token); err != nil {
		return nil, err
	}
	return instance.publicKey.Key, nil
}

func (instance *LazyPublicKeyBackend) loadIfRequired() error {
	finfo, err := os.Stat(instance.filename)
	if os.IsNotExist(err) {
		return fmt.Errorf("public key file '%s' does not exist", instance.filename)
	}
	if instance.publicKey.Key == nil || !finfo.ModTime().Equal(instance.modTime) {
		instance.publicKey.Key, err = ReadPublicKeyFile(instance.filename)
		if err != nil {
			return fmt.Errorf("could not load public key file '%s': %v", instance.filename, err)
		}
		if instance.publicKey.Key == nil {
			return fmt.Errorf("no public key contained in file '%s'", instance.filename)
		}
	}
	return nil
}

// LazyHmacKeyBackend contains state to manage lazy key loading for HS family algorithms
type LazyHmacKeyBackend struct {
	filename string
	modTime  time.Time
	secret   []byte
}

// NewLazyHmacKeyBackend creates a new LazyHmacKeyBackend
func NewLazyHmacKeyBackend(value string) (*KeyBackendHolder, error) {
	if len(value) <= 0 {
		return nil, fmt.Errorf("empty filename for secret provided")
	}
	return &KeyBackendHolder {
		Value: &LazyHmacKeyBackend{
			filename: value,
		},
	}, nil
}

// ProvideKey will lazily load a secret key in a file, using a cached value if the key
// material has not changed.  An error is returned if the token does not match the
// expected signing algorithm.
func (instance *LazyHmacKeyBackend) ProvideKey(token *jwt.Token) (interface{}, error) {
	err := instance.loadIfRequired()
	if err != nil {
		return nil, err
	}
	if err := AssertHmacToken(token); err != nil {
		return nil, err
	}
	return instance.secret, nil
}

func (instance *LazyHmacKeyBackend) loadIfRequired() error {
	finfo, err := os.Stat(instance.filename)
	if os.IsNotExist(err) {
		return fmt.Errorf("secret file '%s' does not exist", instance.filename)
	}
	if instance.secret == nil || !finfo.ModTime().Equal(instance.modTime) {
		instance.secret, err = ioutil.ReadFile(instance.filename)
		if err != nil {
			return fmt.Errorf("could not load secret file '%s': %v", instance.filename, err)
		}
		if instance.secret == nil {
			return fmt.Errorf("no secret contained in file '%s'", instance.filename)
		}
	}
	return nil
}

// NewDefaultKeyBackends will read from the environment and return key backends based on
// values from environment variables JWT_SECRET or JWT_PUBLIC_KEY.  An error is returned if
// the keys are not able to be parsed or if an inconsistent configuration is found.
func NewDefaultKeyBackends() ([]KeyBackendHolder, error) {
	result := []KeyBackendHolder{}

	secret := os.Getenv(ENV_SECRET)
	if len(secret) > 0 {
		result = append(result, KeyBackendHolder {
			Value: &HmacKeyBackend{
				secret: []byte(secret),
			},
		})
	}

	envPubKey := os.Getenv(ENV_PUBLIC_KEY)
	if len(envPubKey) > 0 {
		pub, err := ParsePublicKey([]byte(envPubKey))
		if err != nil {
			return nil, fmt.Errorf("public key provided in environment variable %s could not be read: %v", ENV_PUBLIC_KEY, err)
		}
		result = append(result, KeyBackendHolder {
			Value: &PublicKeyBackend{
				publicKey: PublicKeyMarshal {
					Key: pub,
				},
			},
		})
	}

	// If no backend exist, let's hope loginsrv will set one up later
	if len(result) == 0 {
		result = append(result, KeyBackendHolder {
			Value: &EnvHmacKeyBackend{},
		})
	}
	if len(result) > 1 {
		return nil, fmt.Errorf("cannot configure both HMAC and RSA/ECDSA tokens on the same site")
	}

	return result, nil
}

// PublicKeyBackend is an RSA or ECDSA key provider
type PublicKeyBackend struct {
	publicKey PublicKeyMarshal
}

// ProvideKey will asssert that the token signing algorithm and the configured key match
func (instance *PublicKeyBackend) ProvideKey(token *jwt.Token) (interface{}, error) {
	if err := AssertPublicKeyAndTokenCombination(instance.publicKey.Key, token); err != nil {
		return nil, err
	}
	return instance.publicKey.Key, nil
}

// HmacKeyBacked is an HMAC-SHA key provider
type HmacKeyBackend struct {
	secret []byte `json:"secret,omitempty"`
}

// ProvideKey will assert that the token signing algorithm and the configured key match
func (instance *HmacKeyBackend) ProvideKey(token *jwt.Token) (interface{}, error) {
	if err := AssertHmacToken(token); err != nil {
		return nil, err
	}
	return instance.secret, nil
}

// NoopKeyBackend always returns an error when no key signing method is specified
type NoopKeyBackend struct{}

// ProvideKey always returns an error when no key signing method is specified
func (instance *NoopKeyBackend) ProvideKey(token *jwt.Token) (interface{}, error) {
	return nil, fmt.Errorf("there is no keybackend available")
}

type EnvHmacKeyBackend struct{
	secret []byte `json:"secret,omitempty"`
}

// ProvideKey always returns an error when no key signing method is specified
func (instance *EnvHmacKeyBackend) ProvideKey(token *jwt.Token) (interface{}, error) {
	if err := AssertHmacToken(token); err != nil {
		return nil, err
	}
	if len(instance.secret) == 0 {
		secret := os.Getenv(ENV_SECRET)
		if len(secret) == 0 {
			return nil, fmt.Errorf("Env variable not set.")
		}
		instance.secret = []byte(secret)
	}

	return instance.secret, nil
}

// Holder for a KeyBackend to get serialized properly
type KeyBackendHolder struct {
	Value KeyBackend
}

func (backend *KeyBackendHolder) MarshalJSON() ([]byte, error) {
	var ty string

	switch backend.Value.(type) {
		case *HmacKeyBackend:
			ty = "hmac_key_backend"
		case *LazyHmacKeyBackend:
			ty = "lazy_hmac_key_backend"
		case*EnvHmacKeyBackend:
			ty = "env_hmac_key_backend"
		case *PublicKeyBackend:
			ty = "public_key_backend"
		case *LazyPublicKeyBackend:
			ty = "lazy_public_key_backend"
	}

	value := struct {
		Type string `json:"type"`
		Value interface{} `json:"value"`
	}{Type: ty, Value: backend.Value}

	return json.Marshal(&value)
}

func (keys *KeyBackendHolder) UnmarshalJSON(data []byte) error {
	value, err := UnmarshalCustomValue(data, "type", "value", map[string]reflect.Type{
		"env_hmac_key_backend": reflect.TypeOf(EnvHmacKeyBackend{}),
		"hmac_key_backend": reflect.TypeOf(HmacKeyBackend{}),
		"lazy_hmac_key_backend": reflect.TypeOf(LazyHmacKeyBackend{}),
		"public_key_backend": reflect.TypeOf(PublicKeyBackend{}),
		"lazy_public_key_backend": reflect.TypeOf(LazyPublicKeyBackend{}),
	})
	if err != nil {
		return err
	}

	keys.Value = value.(KeyBackend)

	return nil
}