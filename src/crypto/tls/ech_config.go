// Copyright 2020 Cloudflare, Inc. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package tls

import (
	"fmt"
	"io"

	"github.com/cisco/go-hpke"

	"golang.org/x/crypto/cryptobyte"
)

// ECHConfig represents an ECH configuration.
type ECHConfig struct {
	pk  hpke.KEMPublicKey
	raw []byte

	// Parsed from raw
	version           uint16
	rawPublicName     []byte
	rawPublicKey      []byte
	kemId             uint16
	suites            []echCipherSuite
	maxNameLen        uint16
	ignoredExtensions []byte
}

// UnmarshalECHConfigs parses a sequence of ECH configurations.
func UnmarshalECHConfigs(raw []byte) ([]ECHConfig, error) {
	var err error
	var config ECHConfig
	s := cryptobyte.String(raw)
	configs := make([]ECHConfig, 0)
	for !s.Empty() {
		n, ok := echReadConfig(&s, &config)
		if !ok {
			return nil, fmt.Errorf("error parsing config")
		}
		config.pk, err = echUnmarshalHpkePublicKey(config.rawPublicKey, config.kemId)
		if err != nil {
			return nil, err
		}
		config.raw = raw[:n]
		raw = raw[n:]
		configs = append(configs, config)
	}
	return configs, nil
}

func echUnmarshalConfig(raw []byte) (*ECHConfig, error) {
	var err error
	s := cryptobyte.String(raw)
	config := new(ECHConfig)
	if _, ok := echReadConfig(&s, config); !ok || !s.Empty() {
		return nil, fmt.Errorf("error parsing config")
	}
	config.pk, err = echUnmarshalHpkePublicKey(config.rawPublicKey, config.kemId)
	if err != nil {
		return nil, err
	}
	config.raw = raw
	return config, nil
}

func echReadConfig(s *cryptobyte.String, config *ECHConfig) (int, bool) {
	// Parse the version and ensure we know how to proceed before attempting to
	// parse the configuration contents. Currently on draft-ietf-tls-esni-08 is
	// supported.
	if !s.ReadUint16(&config.version) {
		return 0, false
	}
	n := 2

	if config.version != extensionECH {
		return 0, false
	}

	var contents cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&contents) {
		return 0, false
	}
	n += 2 + len(contents)

	var t cryptobyte.String
	if !contents.ReadUint16LengthPrefixed(&t) ||
		!t.ReadBytes(&config.rawPublicName, len(t)) ||
		!contents.ReadUint16LengthPrefixed(&t) ||
		!t.ReadBytes(&config.rawPublicKey, len(t)) ||
		!contents.ReadUint16(&config.kemId) ||
		!contents.ReadUint16LengthPrefixed(&t) ||
		len(t)%4 != 0 {
		return 0, false
	}

	for !t.Empty() {
		var kdfId, aeadId uint16
		if !t.ReadUint16(&kdfId) || !t.ReadUint16(&aeadId) {
			// This indicates an internal bug.
			panic("internal error while parsing contents.cipher_suites")
		}
		config.suites = append(config.suites, echCipherSuite{kdfId, aeadId})
	}

	if !contents.ReadUint16(&config.maxNameLen) ||
		!contents.ReadUint16LengthPrefixed(&t) ||
		!t.ReadBytes(&config.ignoredExtensions, len(t)) ||
		!contents.Empty() {
		return 0, false
	}
	return n, true
}

// setupClientContext generates the client's HPKE context for use with the ECH
// extension. Returns the context and corresponding encapsulated key. If hrrPsK
// is set, then SetupPSKS() is used to generate the context. Otherwise,
// SetupBaseR() is used. (See irtf-cfrg-hpke-05 for details.)
func (config *ECHConfig) setupClientContext(hrrPsk []byte, rand io.Reader) (ctx *echContext, enc []byte, err error) {
	// Ensure we know how to proceed. Currently only draft-ietf-tls-esni-08 is
	// supported.
	if config.version != extensionECH {
		return nil, nil, fmt.Errorf("version not supported")
	}

	// Pick a ciphersuite supported by both the client and client-facing server.
	suite, err := config.negotiateCipherSuite()
	if err != nil {
		return nil, nil, err
	}

	hpkeSuite, err := echAssembleHpkeCipherSuite(config.kemId, suite.kdfId, suite.aeadId)
	if err != nil {
		return nil, nil, err
	}

	var encryptechContext *hpke.EncryptContext
	if hrrPsk != nil {
		enc, encryptechContext, err = hpke.SetupPSKS(hpkeSuite, rand, config.pk, hrrPsk, []byte(echHpkeHrrKeyId), []byte(echHpkeInfoSetupHrr))
		if err != nil {
			return nil, nil, err
		}
	} else {
		enc, encryptechContext, err = hpke.SetupBaseS(hpkeSuite, rand, config.pk, []byte(echHpkeInfoSetup))
		if err != nil {
			return nil, nil, err
		}
	}
	return &echContext{encryptechContext, nil, true, hpkeSuite}, enc, nil
}

// IsSupported returns true if the caller supports the KEM and at least one ECH
// ciphersuite indicated by this configuration.
func (config *ECHConfig) isSupported() bool {
	_, err := config.negotiateCipherSuite()
	if err != nil || !echIsKemSupported(config.kemId) {
		return false
	}
	return true
}

// isPeerCipherSuiteSupported returns true if this configuration indicates
// support for the given ciphersuite.
func (config *ECHConfig) isPeerCipherSuiteSupported(suite echCipherSuite) bool {
	for _, configSuite := range config.suites {
		if suite == configSuite {
			return true
		}
	}
	return false
}

// negotiateCipherSuite returns the first ciphersuite indicated by this
// configuration that is supported by the caller.
func (config *ECHConfig) negotiateCipherSuite() (echCipherSuite, error) {
	for i, _ := range config.suites {
		if echIsCipherSuiteSupported(config.suites[i]) {
			return config.suites[i], nil
		}
	}
	return echCipherSuite{}, fmt.Errorf("could not negotiate a ciphersuite")
}
