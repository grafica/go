// Copyright 2020 Cloudflare, Inc. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package tls

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"
	"time"

	"github.com/cisco/go-hpke"

	"golang.org/x/crypto/cryptobyte"
)

const echTestBackendServerName = "example.com"
const echTestClientFacingServerName = "cloudflare-esni.com"

const echTestCertRootPEM = `
-----BEGIN CERTIFICATE-----
MIICQTCCAeigAwIBAgIUYGSqOFcpxSleCzSCaveKL8lV4N0wCgYIKoZIzj0EAwIw
fzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNh
biBGcmFuY2lzY28xHzAdBgNVBAoTFkludGVybmV0IFdpZGdldHMsIEluYy4xDDAK
BgNVBAsTA1dXVzEUMBIGA1UEAxMLZXhhbXBsZS5jb20wHhcNMjAwOTIyMTcwNjAw
WhcNMjUwOTIxMTcwNjAwWjB/MQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZv
cm5pYTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEfMB0GA1UEChMWSW50ZXJuZXQg
V2lkZ2V0cywgSW5jLjEMMAoGA1UECxMDV1dXMRQwEgYDVQQDEwtleGFtcGxlLmNv
bTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNcFaBtPRgekRBKTBvuKdTy3raqs
4IizMLFup434MfQ5oH71mYpKndfBzxcZDTMYeocKlt1pVYwvZ3ZdpRsW6yWjQjBA
MA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQ2GJIW
+4m3/qpkage5tEvMg3NwPTAKBggqhkjOPQQDAgNHADBEAiB6J8UqRvdhLOiaDYqH
KG+TuveHOqlfQqQgXo4/hNKMiAIgV79TTPHu+Ymn/tcCy9LVWZcpgnCEjrZi0ou5
et8BX9s=
-----END CERTIFICATE-----`

// Certificate of the client-facing server. The server name is
// "cloudflare-esni.com".
const echTestCertClientFacingPEM = `
-----BEGIN CERTIFICATE-----
MIICIjCCAcigAwIBAgIUCXySp2MadlDlcvFrSm4BtLUY70owCgYIKoZIzj0EAwIw
fzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNh
biBGcmFuY2lzY28xHzAdBgNVBAoTFkludGVybmV0IFdpZGdldHMsIEluYy4xDDAK
BgNVBAsTA1dXVzEUMBIGA1UEAxMLZXhhbXBsZS5jb20wHhcNMjAwOTIyMTcxMDAw
WhcNMjEwOTIyMTcxMDAwWjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7nP/
Txinb0JPE/xdjv5d3zrWJqXo7qwP67oVaMKJp5ausJ+0IZfiMWz8pa6T7pyyLrC5
xvQNkfVkpP9/FxmNFaOBoDCBnTAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYI
KwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFNN7Afv+
CgPAxRr4QdZn8JFvQ9nTMB8GA1UdIwQYMBaAFDYYkhb7ibf+qmRqB7m0S8yDc3A9
MB4GA1UdEQQXMBWCE2Nsb3VkZmxhcmUtZXNuaS5jb20wCgYIKoZIzj0EAwIDSAAw
RQIgZ4VlBtjTRludP/JwfaNQyGKZFWFqRsECvGPbk+ZHLZwCIQCTjuMAFrnjf/j5
3RNw67l7+QQPrmurSO86l1IlDWNtcA==
-----END CERTIFICATE-----`

// Signing key of the client-facing server.
const echTestKeyClientFacingPEM = `
-----BEGIN PRIVATE KEY-----
MHcCAQEEIPpCcU8mu+h4xHAm18NJvn73Ko9fjH9QxDCpRt7kCIq9oAoGCCqGSM49
AwEHoUQDQgAE7nP/Txinb0JPE/xdjv5d3zrWJqXo7qwP67oVaMKJp5ausJ+0IZfi
MWz8pa6T7pyyLrC5xvQNkfVkpP9/FxmNFQ==
-----END PRIVATE KEY-----`

// Certificate of the backend server. The server name is "example.com".
const echTestCertBackendPEM = `
-----BEGIN CERTIFICATE-----
MIICGTCCAcCgAwIBAgIUQJSSdOZs9wag1Toanlt9lol0uegwCgYIKoZIzj0EAwIw
fzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNh
biBGcmFuY2lzY28xHzAdBgNVBAoTFkludGVybmV0IFdpZGdldHMsIEluYy4xDDAK
BgNVBAsTA1dXVzEUMBIGA1UEAxMLZXhhbXBsZS5jb20wHhcNMjAwOTIyMTcwOTAw
WhcNMjEwOTIyMTcwOTAwWjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElq+q
E01Z87KIPHWdEAk0cWssHkRnS4aQCDfstoxDIWQ4rMwHvrWGFy/vytRwyjhHuX9n
tc5ArCpwbAmY+oW/46OBmDCBlTAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYI
KwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFPz9Ct9U
EIjBEcUpv/yxHYccUDo1MB8GA1UdIwQYMBaAFDYYkhb7ibf+qmRqB7m0S8yDc3A9
MBYGA1UdEQQPMA2CC2V4YW1wbGUuY29tMAoGCCqGSM49BAMCA0cAMEQCICDBEzzE
DF529x9Z4BkOKVxNDicfWSjxrcMohevjeCWDAiBaxXS5+6I2fcred0JGMsJgo7ts
S8GYhuKE99mQA0/mug==
-----END CERTIFICATE-----`

// Signing key of the backend server.
const echTestKeyBackendPEM = `
-----BEGIN PRIVATE KEY-----
MHcCAQEEIIJsLXmfzw6FDlqyRRLhY6lVB6ws5ewjUQjnS4DXsQ60oAoGCCqGSM49
AwEHoUQDQgAElq+qE01Z87KIPHWdEAk0cWssHkRnS4aQCDfstoxDIWQ4rMwHvrWG
Fy/vytRwyjhHuX9ntc5ArCpwbAmY+oW/4w==
-----END PRIVATE KEY-----`

// The sequence of ECH configurations used by the client.
const echTestConfigs = `
-----BEGIN ECH CONFIGS-----
/wgATwATY2xvdWRmbGFyZS1lc25pLmNvbQAg9TnMu6X6Ose16StWz13tPrif6Wv6
jfc460Irsehz5wwAIAAQAAEAAQABAAMAAgABAAIAAwAAAAD/CABwABNjbG91ZGZs
YXJlLWVzbmkuY29tAEEEV8c38cbv33J44VadzbIEjSfp8FWkhI6/oV/47oro5q8o
EVQN3iGOAdUxalq+7d53wtwi5HO6AGaKUlMpIEWyFAAQABAAAQABAAEAAwACAAEA
AgADAAAAAA==
-----END ECH CONFIGS-----`

// An invalid sequence of ECH configurations.
const echTestInvalidConfigs = `
-----BEGIN ECH CONFIGS-----
/wgATwATY2xvdWRmbGFyZS1lc25pLmNvbQAgHLbNdmfuwob4yoXLD2IeTRwcLC/+
u1dCMgG3fkdLVUkAIAAQAAEAAQABAAMAAgABAAIAAwAAAAA=
-----END ECH CONFIGS-----`

// The ECH keys corresponding to echTestConfigs, used by the client-facing
// server.
const echTestKeys = `
-----BEGIN ECH KEYS-----
ACDiAt1w8ZmE76qHiveg38sIoZRGTWv3t/lbmATLbcfQOABT/wgATwATY2xvdWRm
bGFyZS1lc25pLmNvbQAg9TnMu6X6Ose16StWz13tPrif6Wv6jfc460Irsehz5wwA
IAAQAAEAAQABAAMAAgABAAIAAwAAAAAAIJJaBxxAWmptddCJ6U6CeFzXbm+tMnCD
sxCARKx0UdLOAHT/CABwABNjbG91ZGZsYXJlLWVzbmkuY29tAEEEV8c38cbv33J4
4VadzbIEjSfp8FWkhI6/oV/47oro5q8oEVQN3iGOAdUxalq+7d53wtwi5HO6AGaK
UlMpIEWyFAAQABAAAQABAAEAAwACAAEAAgADAAAAAA==
-----END ECH KEYS-----`

// echKeySet implements the ECHProvider interface for a sequence of ECH keys.
type echKeySet struct {
	// The serialized ECHConfigs, in order of the server's preference.
	configs []byte

	// Maps a configuration identifier to its secret key.
	sk map[[maxHpkeKdfExtractLen]byte]echKey

	// The unique public names valid for this key set.
	names []string
}

// echNewKeySet constructs an echKeySet.
func echNewKeySet(keys []echKey) (*echKeySet, error) {
	keySet := new(echKeySet)
	keySet.sk = make(map[[maxHpkeKdfExtractLen]byte]echKey)
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
func (keySet *echKeySet) GetServerContext(rawHandle, hrrPsk []byte, version uint16) (res ECHProviderResult, err error) {
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
func (keySet *echKeySet) GetPublicNames() (names []string, err error) {
	return keySet.names, nil
}

// echKey represents an ECH key and its corresponding configuration. The
// encoding of an ECH Key has following structure (in TLS syntax):
//
// struct {
//     opaque key<0..2^16-1>
//     uint16 length<0..2^16-1> // length of config
//     ECHConfig config;        // as defined in draft-ietf-tls-esni-08
// } ECHKey;
//
// NOTE(cjpatton): This format is not specified in the ECH draft.
type echKey struct {
	config ECHConfig
	sk     hpke.KEMPrivateKey
}

// echUnmarshalKeys parses a sequence of ECH keys.
func echUnmarshalKeys(raw []byte) ([]echKey, error) {
	s := cryptobyte.String(raw)
	keys := make([]echKey, 0)
	var key echKey
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
func (key *echKey) setupServerContext(enc, hrrPsk []byte, suite echCipherSuite) (*echContext, error) {
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

func loadEchTestConfigs(pemData string) []ECHConfig {
	block, rest := pem.Decode([]byte(pemData))
	if block == nil || block.Type != "ECH CONFIGS" || len(rest) > 0 {
		panic("pem decoding fails")
	}

	configs, err := UnmarshalECHConfigs(block.Bytes)
	if err != nil {
		panic(err)
	}

	return configs
}

func loadEchTestKeySet() *echKeySet {
	block, rest := pem.Decode([]byte(echTestKeys))
	if block == nil || block.Type != "ECH KEYS" || len(rest) > 0 {
		panic("pem decoding fails")
	}

	keys, err := echUnmarshalKeys(block.Bytes)
	if err != nil {
		panic(err)
	}

	keySet, err := echNewKeySet(keys)
	if err != nil {
		panic(err)
	}

	return keySet
}

// Returns the base configurations for the client and client-facing server,
func setupEchTest() (clientConfig, serverConfig *Config) {
	echTestNow := time.Date(2020, time.September, 23, 0, 0, 0, 0, time.UTC)
	echTestConfig := &Config{
		Time: func() time.Time {
			return echTestNow
		},
		Rand:               rand.Reader,
		CipherSuites:       allCipherSuites(),
		InsecureSkipVerify: false,
	}

	clientFacingCert, err := X509KeyPair([]byte(echTestCertClientFacingPEM), []byte(echTestKeyClientFacingPEM))
	if err != nil {
		panic(err)
	}

	backendCert, err := X509KeyPair([]byte(echTestCertBackendPEM), []byte(echTestKeyBackendPEM))
	if err != nil {
		panic(err)
	}

	block, rest := pem.Decode([]byte(echTestCertRootPEM))
	if block == nil || block.Type != "CERTIFICATE" || len(rest) > 0 {
		panic("pem decoding fails")
	}

	rootCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(err)
	}

	clientConfig = echTestConfig.Clone()
	clientConfig.ServerName = echTestBackendServerName
	clientConfig.RootCAs = x509.NewCertPool()
	clientConfig.RootCAs.AddCert(rootCert)

	serverConfig = echTestConfig.Clone()
	serverConfig.ECHEnabled = true
	serverConfig.GetCertificate = func(info *ClientHelloInfo) (*Certificate, error) {
		if info.ServerName == echTestBackendServerName {
			return &backendCert, nil
		} else if info.ServerName == echTestClientFacingServerName {
			return &clientFacingCert, nil
		}
		return nil, nil
	}
	return
}

type echTestCase struct {
	name                      string
	expectClientAbort         bool
	expectServerAbort         bool
	expectOffered             bool
	expectAccepted            bool
	expectRejected            bool
	expectRetryConfigs        bool
	expectGrease              bool
	expectBackendServerName   bool
	clientEnabled             bool
	clientInvalidConfigs      bool
	clientNoConfigs           bool
	clientInvalidVersion      bool
	serverInvalidVersion      bool
	serverProviderError       bool
	serverNoProvider          bool
	triggerHRR                bool
	triggerECHBypassAfterHRR  bool
	triggerECHBypassBeforeHRR bool
}

// TODO(cjpatton): Add test cases for PSK interactions:
//  - ECH bypassed, backend server consumes early data (baseline test config)
//  - ECH accepted, backend server consumes early data
//  - ECH rejected, client-facing server ignores early data intended for backend
var echTestCases = []echTestCase{
	{
		name:                    "success / accepted",
		expectBackendServerName: true,
		expectOffered:           true,
		expectAccepted:          true,
		clientEnabled:           true,
	},
	{
		name:                    "success / bypassed: grease",
		expectGrease:            true,
		expectBackendServerName: true,
		clientEnabled:           true,
		clientNoConfigs:         true,
	},
	{
		name:                    "success / bypassed: not offered",
		expectBackendServerName: true,
		clientNoConfigs:         true,
	},
	{
		name:                    "success / bypassed: client invalid version",
		expectGrease:            true,
		expectBackendServerName: true,
		clientInvalidVersion:    true,
		clientEnabled:           true,
	},
	{
		name:                 "success / rejected: invalid config",
		expectOffered:        true,
		expectRetryConfigs:   true,
		clientInvalidConfigs: true,
		clientEnabled:        true,
	},
	{
		name:                 "success / rejected: client-facing invalid version",
		expectOffered:        true,
		serverInvalidVersion: true,
		clientEnabled:        true,
	},
	{
		name:             "success / rejected: not supported by client-facing server",
		expectOffered:    true,
		serverNoProvider: true,
		clientEnabled:    true,
	},
	{
		name:                "server abort: provider internal error",
		expectServerAbort:   true,
		expectClientAbort:   true,
		expectOffered:       true,
		serverProviderError: true,
		clientEnabled:       true,
	},
	{
		name:                    "hrr / accepted",
		expectBackendServerName: true,
		expectOffered:           true,
		expectAccepted:          true,
		triggerHRR:              true,
		clientEnabled:           true,
	},
	{
		name:                    "hrr / bypassed: grease",
		expectGrease:            true,
		expectBackendServerName: true,
		clientEnabled:           true,
		clientNoConfigs:         true,
		triggerHRR:              true,
	},
	{
		name:                 "hrr / rejected: invalid config",
		expectOffered:        true,
		expectRetryConfigs:   true,
		clientEnabled:        true,
		clientInvalidConfigs: true,
		triggerHRR:           true,
	},
	{
		name:                      "hrr, server abort: offer after bypass",
		expectServerAbort:         true,
		expectClientAbort:         true,
		clientEnabled:             true,
		triggerHRR:                true,
		triggerECHBypassBeforeHRR: true,
	},
	{
		name:                     "hrr, server abort: bypass after offer",
		expectServerAbort:        true,
		expectClientAbort:        true,
		clientEnabled:            true,
		triggerHRR:               true,
		triggerECHBypassAfterHRR: true,
	},
}

// echTestBadProvider mocks a provider that, in response to any request, it sets
// an alert and returns an error. The client-facing server must abort the
// handshake.
type echTestBadProvider struct{}

// Required by the ECHProvider interface.
func (p echTestBadProvider) GetServerContext(_, _ []byte, _ uint16) (res ECHProviderResult, err error) {
	res.Alert = uint8(alertInternalError)
	return res, fmt.Errorf("provider failed")
}

// Required by the ECHProvider interface.
func (p echTestBadProvider) GetPublicNames() ([]string, error) {
	return []string{echTestClientFacingServerName}, nil
}

// echTestResult represents the ECH status and error status of a connection.
type echTestResult struct {
	st           ECHStatus
	retryConfigs bool
	err          error
}

// echTestConn runs the handshake and returns the ECH and error status of the
// client and server. It also returns the server name verified by the client.
func echTestConn(t *testing.T, clientConfig, serverConfig *Config) (serverName string, clientRes, serverRes echTestResult) {
	ln := newLocalListener(t)
	defer ln.Close()

	serverCh := make(chan echTestResult, 1)
	go func() {
		var res echTestResult
		serverConn, err := ln.Accept()
		if err != nil {
			res.err = err
			serverCh <- res
			return
		}
		server := Server(serverConn, serverConfig)
		if err := server.Handshake(); err != nil {
			res.err = err
			serverCh <- res
			return
		}
		res.st = server.ConnectionState().ECHStatus
		res.retryConfigs = len(server.ech.retryConfigs) > 0
		serverCh <- res
		server.Close()
	}()

	client, err := Dial("tcp", ln.Addr().String(), clientConfig)
	serverRes = <-serverCh
	if err != nil {
		clientRes.err = err
		return
	}

	serverName = client.ConnectionState().ServerName
	clientRes.st = client.ConnectionState().ECHStatus
	clientRes.retryConfigs = len(client.ech.retryConfigs) > 0
	client.Close()
	return
}

func TestECHHandshake(t *testing.T) {
	defer func() {
		testingTriggerHRR = false
		testingTriggerECHBypassAfterHRR = false
		testingTriggerECHBypassBeforeHRR = false
	}()

	clientConfig, serverConfig := setupEchTest()
	for i, test := range echTestCases {
		// Configure the client.
		invalidConfigs := loadEchTestConfigs(echTestInvalidConfigs)
		if !test.clientInvalidConfigs && !test.clientNoConfigs {
			clientConfig.ClientECHConfigs = loadEchTestConfigs(echTestConfigs)
		} else if test.clientInvalidConfigs && !test.clientNoConfigs {
			clientConfig.ClientECHConfigs = invalidConfigs
		} else if !test.clientInvalidConfigs && test.clientNoConfigs {
			clientConfig.ClientECHConfigs = nil
		} else {
			panic("invalid test configuration")
		}

		if test.clientEnabled {
			clientConfig.ECHEnabled = true
		} else {
			clientConfig.ECHEnabled = false
		}

		if test.clientInvalidVersion {
			clientConfig.MinVersion = VersionTLS10
			clientConfig.MaxVersion = VersionTLS12
		} else {
			clientConfig.MinVersion = VersionTLS10
			clientConfig.MaxVersion = VersionTLS13
		}

		// Configure the client-facing server.
		if !test.serverProviderError && !test.serverNoProvider {
			serverConfig.ServerECHProvider = loadEchTestKeySet()
		} else if test.serverProviderError && !test.serverNoProvider {
			serverConfig.ServerECHProvider = &echTestBadProvider{}
		} else if !test.serverProviderError && test.serverNoProvider {
			serverConfig.ServerECHProvider = nil
		} else {
			panic("invalid test configuration")
		}

		if test.serverInvalidVersion {
			serverConfig.MinVersion = VersionTLS10
			serverConfig.MaxVersion = VersionTLS12
		} else {
			serverConfig.MinVersion = VersionTLS10
			serverConfig.MaxVersion = VersionTLS13
		}

		// Trigger HRR or not.
		if test.triggerHRR {
			testingTriggerHRR = true
		} else {
			testingTriggerHRR = false
		}

		if test.triggerECHBypassAfterHRR {
			testingTriggerECHBypassAfterHRR = true
		} else {
			testingTriggerECHBypassAfterHRR = false
		}

		if test.triggerECHBypassBeforeHRR {
			testingTriggerECHBypassBeforeHRR = true
		} else {
			testingTriggerECHBypassBeforeHRR = false
		}

		t.Logf("test #%d: %s", i, test.name)

		// Run the handshake.
		serverName, client, server := echTestConn(t, clientConfig, serverConfig)
		if !test.expectClientAbort && client.err != nil {
			t.Errorf("test #%d: client aborts; want success", i)
		}

		if !test.expectServerAbort && server.err != nil {
			t.Errorf("test #%d: server aborts; want success", i)
		}

		if test.expectClientAbort && client.err == nil {
			t.Errorf("test #%d: client succeeds; want abort", i)
		} else {
			t.Logf("test #%d: client err: %s", i, client.err)
		}

		if test.expectServerAbort && server.err == nil {
			t.Errorf("test #%d: server succeeds; want abort", i)
		} else {
			t.Logf("test #%d: server err: %s", i, server.err)
		}

		if server.err != nil || client.err != nil {
			continue
		}

		if test.expectOffered != client.st.Offered {
			t.Errorf("test #%d: got offered=%v; want offered=%v", i, client.st.Offered, test.expectOffered)
		}

		if test.expectAccepted != client.st.Accepted {
			t.Errorf("test #%d: got accepted=%v; want accepted=%v", i, client.st.Accepted, test.expectAccepted)
		}

		if test.expectRetryConfigs != client.retryConfigs {
			t.Errorf("test #%d: got retry configs=%v; want %v", i, client.retryConfigs, test.expectRetryConfigs)
		}

		if test.expectGrease != client.st.Grease {
			t.Errorf("test #%d: got grease=%v; want %v", i, client.st.Grease, test.expectGrease)
		}

		if test.expectBackendServerName != (serverName == echTestBackendServerName) {
			t.Errorf("test #%d: got backend server name=%v; want %v", i, serverName == echTestBackendServerName, test.expectBackendServerName)
		}

		if client.st.Accepted != server.st.Accepted ||
			client.st.Grease != server.st.Grease ||
			client.retryConfigs != client.retryConfigs {
			t.Errorf("test #%d: client and server disagree on usage", i)
			t.Errorf("test #%d: client: %+v", i, client)
			t.Errorf("test #%d: server: %+v", i, server)
		}
	}
}
