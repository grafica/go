package tls

import (
	"fmt"

	"github.com/cisco/go-hpke"

	"golang.org/x/crypto/cryptobyte"
)

// ECHProvider specifies the interface of an ECH service provider that decrypts
// ClientHelloInner on behalf of the client-facing server. It also defines the
// set of acceptable ECH configurations.
type ECHProvider interface {
	// SetupServerContext attempts to construct the HPKE context used by the
	// client-facing server for decryption. (See draft-irtf-cfrg-hpke-05,
	// Section 5.2.)
	//
	// handle encodes the parameters of client's in the "encrypted_client_hello"
	// extension that are needed to construct the context. In
	// draft-ietf-tls-esni-08, these are the ECH cipher suite, the identity of
	// the ECH configuration, and the encapsulated key.
	//
	// hrrPsk is the PSK used to construct the context. This is set by the
	// caller in case the server previously sent a HelloRetryRequest in this
	// connection. Otherwise, len(hrrPsk) == 0.
	//
	// version is the version of ECH indicated by the client.
	//
	// If an error is returned, then the caller must abort the handshake with
	// the alert indicated by res.Alert.
	GetServerContext(handle, hrrPsk []byte, version uint16) (res ECHProviderResult, err error)

	// GetPublicNames returns the public names for which this provider is
	// authoritative. The client-facing server bypasses ECH unless the server
	// name indicated in the ClientHelloOuter is one of these public names.
	GetPublicNames() (names []string, err error)
}

// ECHProviderResult represents the result of invoking the ECH provider.
type ECHProviderResult struct {
	// Rejected indicates whether the caller must reject ECH.
	Rejected bool

	// Alert is the alert sent by the caller in case of an error.
	Alert uint8

	// RetryConfigs is the sequence of ECH configs to offer to the client for
	// retrying the handshake. This may be set in case of rejection.
	RetryConfigs []byte

	// Context is the client-facing server's HPKE context. This is set if ECH is
	// not rejected by the provider and no error was reported.
	Context []byte
}

// ECHKeySet implements the ECHProvider interface for a sequence of ECHKey
// objects.
type ECHKeySet struct {
	// The serialized ECHConfigs, in order of the server's preference.
	configs []byte

	// Maps a configuration identifier to its secret key.
	sk map[[maxHpkeKdfExtractLen]byte]ECHKey

	// The unique public names valid for this key set.
	names []string
}

// NewECHKeySet constructs an ECHKeySet.
func NewECHKeySet(keys []ECHKey) (*ECHKeySet, error) {
	keySet := new(ECHKeySet)
	keySet.sk = make(map[[maxHpkeKdfExtractLen]byte]ECHKey)
	keySet.names = make([]string, 0)
	for _, key := range keys {
		// Compute the set of KDF algorithms supported by this configuration.
		kdfIds := make(map[uint16]bool)
		for _, suite := range key.config.suites {
			kdfIds[suite.kdfId] = true
		}

		// Compute the configuration identifier for each KDF.
		for kdfId, _ := range kdfIds {
			kdf, err := echCreateHpkeKdf(kdfId)
			if err != nil {
				return nil, err
			}
			configId := kdf.Expand(kdf.Extract(nil, key.config.raw), []byte(echHpkeInfoConfigId), kdf.OutputSize())
			var id [maxHpkeKdfExtractLen]byte // Initialized to zero
			copy(id[:len(configId)], configId)
			keySet.sk[id] = key
		}

		// Add the public name to the list of unique public names.
		name := string(key.config.rawPublicName)
		found := false
		for i, _ := range keySet.names {
			if keySet.names[i] == name {
				found = true
				break
			}
		}
		if !found {
			keySet.names = append(keySet.names, name)
		}

		keySet.configs = append(keySet.configs, key.config.raw...)
	}
	return keySet, nil
}

// GetServerContext is required by the ECHProvider interface.
func (keySet *ECHKeySet) GetServerContext(rawHandle, hrrPsk []byte, version uint16) (res ECHProviderResult, err error) {
	// Ensure we know how to proceed. Currently only draft-ietf-tls-esni-08 is
	// supported.
	if version != extensionECH {
		res.Alert = uint8(alertInternalError)
		return res, fmt.Errorf("version not supported") // Abort
	}

	// Parse the handle.
	handle, err := echUnmarshalContextHandle(rawHandle)
	if err != nil {
		res.Alert = uint8(alertIllegalParameter)
		return res, err
	}

	// Look up the secret key for the configuration indicated by the client.
	var id [maxHpkeKdfExtractLen]byte // Initialized to zero
	copy(id[:len(handle.configId)], handle.configId)
	key, ok := keySet.sk[id]
	if !ok {
		res.Rejected = true
		res.RetryConfigs = keySet.configs
		return res, nil // Reject
	}

	// Ensure that support for the selected ciphersuite is indicated by the
	// configuration.
	suite := handle.suite
	if !key.config.isPeerCipherSuiteSupported(suite) {
		res.Alert = uint8(alertIllegalParameter)
		return res, fmt.Errorf("peer cipher suite is not supported") // Abort
	}

	// Ensure the version indicated by the client matches the version supported
	// by the configuration.
	if version != key.config.version {
		res.Alert = uint8(alertIllegalParameter)
		return res, fmt.Errorf("peer version not supported") // Abort
	}

	// Compute the decryption context.
	context, err := key.setupServerContext(handle.enc, hrrPsk, suite)
	if err != nil {
		res.Alert = uint8(alertDecryptError)
		return res, err // Abort
	}

	res.Context, err = context.marshalServer()
	if err != nil {
		res.Alert = uint8(alertInternalError)
		return res, err // Abort
	}
	return
}

// GetPubllcNames is required by the ECHProvider interface.
func (keySet *ECHKeySet) GetPublicNames() (names []string, err error) {
	return keySet.names, nil
}

// ECHKey represents an ECH key and its corresponding configuration.
type ECHKey struct {
	config ECHConfig
	sk     hpke.KEMPrivateKey
}

// UnmarshalECHKeys parses a sequence of ECH keys.
func UnmarshalECHKeys(raw []byte) ([]ECHKey, error) {
	s := cryptobyte.String(raw)
	keys := make([]ECHKey, 0)
	var key ECHKey
	for !s.Empty() {
		var rawSecretKey, rawConfig cryptobyte.String
		if !s.ReadUint16LengthPrefixed(&rawSecretKey) ||
			!s.ReadUint16LengthPrefixed(&rawConfig) {
			return nil, fmt.Errorf("error parsing key")
		}
		config, err := echUnmarshalConfig(rawConfig)
		if err != nil {
			return nil, err
		}
		key.config = *config
		key.sk, err = echUnmarshalHpkeSecretKey(rawSecretKey, key.config.kemId)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// setupServerContext computes the HPKE context used by the server in the ECH
// extension. If hrrPsk is set, then SetupPSKS() is used to generate the
// context. Otherwise, SetupBaseR() is used. (See irtf-cfrg-hpke-05 for
// details.)
func (key *ECHKey) setupServerContext(enc, hrrPsk []byte, suite echCipherSuite) (*echContext, error) {
	hpkeSuite, err := echAssembleHpkeCipherSuite(key.config.kemId, suite.kdfId, suite.aeadId)
	if err != nil {
		return nil, err
	}

	var decryptechContext *hpke.DecryptContext
	if hrrPsk != nil {
		decryptechContext, err = hpke.SetupPSKR(hpkeSuite, key.sk, enc, hrrPsk, []byte(echHpkeHrrKeyId), []byte(echHpkeInfoSetupHrr))
		if err != nil {
			return nil, err
		}
	} else {
		decryptechContext, err = hpke.SetupBaseR(hpkeSuite, key.sk, enc, []byte(echHpkeInfoSetup))
		if err != nil {
			return nil, err
		}
	}
	return &echContext{nil, decryptechContext, false, hpkeSuite}, nil
}
