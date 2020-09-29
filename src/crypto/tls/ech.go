// Copyright 2020 Cloudflare, Inc. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package tls

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"

	// NOTE: The vendored version of "github.com/cisco/go-hpke" MUST implement
	// draft-irtf-cfrg-hpke-05 and MUST support X25519, HKDF-SHA256, and
	// AES128-GCM.
	"github.com/cisco/go-hpke"

	"golang.org/x/crypto/cryptobyte"
)

const (
	// Constants for HPKE operations
	echTls13LabelAcceptConfirm    = "ech accept confirmation"
	echHpkeInfoInnerDigest        = "tls13 ech inner digest"
	echHpkeInfoConfigId           = "tls13 ech config id"
	echHpkeInfoSetup              = "tls13 ech"
	echHpkeInfoSetupHrr           = "tls13 ech hrr"
	echHpkeHrrKeyExportechContext = "tls13 ech hrr key"
	echHpkeHrrKeyId               = "hrr key"
	echHpkeHrrKeyLen              = 16

	// Stand-in values for algorithms that are unknown prior to a particular
	// operation.
	//
	// There is a slight mismatch between the API exported by HPKE and the API
	// required to implement the ECH logic in the TLS stack. Namely, an "HPKE
	// ciphersuite" is a (KEM, KDF, AEAD) triple, and as such, the API of the
	// HPKE implementation we use, github.com/cisco/go-hpke, presumes all three
	// algorithms are known prior to any HPKE operation. In contrast, an "ECH
	// ciphersuite" is a (KDF, AEAD) pair, meaning the KDF and AEAD may not be
	// known when doing a KEM operation, e.g., generating a KEM key pair. This
	// library provides a thin wrapper around github.com/cisco/go-hpke that
	// resolves this mismatch.
	dummyKemId  = uint16(hpke.DHKEM_X25519)
	dummyKdfId  = uint16(hpke.KDF_HKDF_SHA256)
	dummyAeadId = uint16(hpke.AEAD_AESGCM128)

	// The ciphertext expansion incurred by the AEAD identified by dummyAeadId.
	dummyAeadOverheadLen = 16

	// The output size of "Expand()" for the KDF identified by dummyKdfId.
	dummyKdfOutputLen = 32

	// The maximum output length of the Extract() operation among the set of
	// supported KDFs. Currently this is 64, which is the number of extracted
	// bytes for HKDF-SHA512.
	maxHpkeKdfExtractLen uint16 = 64
)

// The public used to generate covertext for the ECH extension. This is a random
// 32-byte string, which will be interpreted as an X25519 public key.
var echDummyPublicKey = []byte{
	143, 38, 37, 36, 12, 6, 229, 30, 140, 27, 167, 73, 26, 100, 203, 107, 216,
	81, 163, 222, 52, 211, 54, 210, 46, 37, 78, 216, 157, 97, 241, 244,
}

func (c *Conn) echOfferOrBypass(helloBase *clientHelloMsg) (hello, helloInner *clientHelloMsg, err error) {
	config := c.config

	if !config.ECHEnabled {
		// Bypass ECH without providing covertext.
		return helloBase, nil, nil
	}

	// Trigger failure scenarios, if testing.
	testingBypass := false
	if (c.hrrTriggered && testingTriggerECHBypassAfterHRR) ||
		(!c.hrrTriggered && testingTriggerECHBypassBeforeHRR) {
		testingBypass = true
	}

	// Decide whether to offer the ECH extension in this connection, If offered,
	// then hello is set to the ClientHelloOuter and helloInner is set to the
	// ClientHelloInner.
	if echConfig := config.echSelectConfig(); echConfig != nil &&
		!testingBypass && config.MaxVersion >= VersionTLS13 {

		// Prepare the ClientHelloInner.
		helloInner = new(clientHelloMsg)
		*helloInner = *helloBase

		// Set "encrypted_client_hello" with an empty payload.
		helloInner.encryptedClientHelloOffered = true

		// Ensure that only TLS 1.3 and above are offered.
		if v := helloInner.supportedVersions; v[len(v)-1] < VersionTLS13 {
			return nil, nil, errors.New("tls: ech: invalid version for ClientHelloInner")
		}

		// Set "random".
		if c.ech.hrrInnerRandom != nil {
			// After HRR, use the "random" sent in the first ClientHelloInner.
			helloInner.random = c.ech.hrrInnerRandom
		} else {
			// Generate a fresh "random".
			helloInner.random = make([]byte, 32)
			_, err := io.ReadFull(config.rand(), helloInner.random)
			if err != nil {
				return nil, nil, errors.New("tls: short read from Rand: " + err.Error())
			}
		}

		// Prepare the ClientHelloOuter.
		hello, _, err = c.makeClientHello(config.MinVersion)
		if err != nil {
			return nil, nil, fmt.Errorf("tls: ech: %s", err)
		}

		// Set "random".
		hello.random = helloBase.random

		// Set "legacy_session_id" to be the same as ClientHelloInner.
		hello.sessionId = helloBase.sessionId

		// Set "key_share" to the same as ClientHelloInner.
		hello.keyShares = helloBase.keyShares

		// Set "server_name" to be the client-facing server.
		hello.serverName = hostnameInSNI(string(echConfig.rawPublicName))

		// Prepare the encryption context. Note that c.ech.hrrPsk is initially
		// nil, meaning no PSK is used for encrypting the first ClientHelloInner
		// in case of HRR.
		ctx, enc, err := echConfig.setupClientContext(c.ech.hrrPsk, config.rand())
		if err != nil {
			return nil, nil, fmt.Errorf("tls: ech: %s", err)
		}

		// Compress the ClientHelloInner using the "outer_extension" mechanism,
		// incorporating the "key_share" extension from ClientHelloOuter.
		//
		// NOTE(cjpatton): It would be nice to incorporate more extensions, but
		// "key_share" is the last extension to appear in the ClientHello before
		// "pre_shared_key". As a result, the only contiguous sequence of outer
		// extensions that contains "key_share" is "key_share" itself. Note that
		// we cannot change the order of extensions in the ClientHello, as the
		// unit tests expect "key_share" to be second to last extension.
		innerDigest := ctx.innerDigest(helloInner.marshal())
		rawCompressedHello, ok := echIncorporateOuterExtensions(helloInner.marshal(), innerDigest, extensionKeyShare)
		if !ok {
			return nil, nil, errors.New("tls: ech: compression of ClientHelloInner failed")
		}

		// Set "encrypted_client_hello".
		var ech echClient
		ech.handle.suite = ctx.cipherSuite()
		ech.handle.configId = ctx.configId(echConfig.raw)
		ech.handle.enc = enc
		ech.payload = ctx.encrypt(rawCompressedHello)
		hello.encryptedClientHelloOffered = true
		hello.encryptedClientHello = ech.marshal()

		// Update the HRR pre-shared-key. This is used to encrypt the second
		// ClientHelloInner in case the server sends an HRR.
		c.ech.hrrPsk = ctx.hrrPsk()

		// Record the "random" sent in the ClientHelloInner. This value will be
		// used for the second ClientHelloInner in case the server sends an HRR.
		c.ech.hrrInnerRandom = helloInner.random

		// Offer ECH.
		c.ech.st.Offered = true
		helloInner.raw = nil
		hello.raw = nil
		return hello, helloInner, nil
	}

	hello = new(clientHelloMsg)
	*hello = *helloBase

	hpkeSuite, err := echAssembleHpkeCipherSuite(dummyKemId, dummyKdfId, dummyAeadId)
	if err != nil {
		return nil, nil, fmt.Errorf("tls: ech covertext: %s", err)
	}

	pk, err := hpkeSuite.KEM.Deserialize(echDummyPublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("tls: ech covertext: %s", err)
	}

	var dummyEch echClient
	dummyEch.handle.suite.kdfId = dummyKdfId
	dummyEch.handle.suite.aeadId = dummyAeadId

	dummyEch.handle.configId = make([]byte, dummyKdfOutputLen)
	if _, err = io.ReadFull(config.rand(), dummyEch.handle.configId); err != nil {
		return nil, nil, fmt.Errorf("tls: ech covertext: %s", err)
	}

	dummyEch.handle.enc, _, err = hpke.SetupBaseS(hpkeSuite, config.rand(), pk, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("tls: ech covertext: %s", err)
	}

	dummyEch.payload = make([]byte, len(hello.marshal())+dummyAeadOverheadLen)
	if _, err = io.ReadFull(config.rand(), dummyEch.payload); err != nil {
		return nil, nil, fmt.Errorf("tls: ech covertext: %s", err)
	}

	hello.encryptedClientHelloOffered = true
	hello.encryptedClientHello = dummyEch.marshal()

	// NOTE(cjpatton): The length of the dummy ciphertext "sticks out".
	//
	// Bypass ECH and provide covertext.
	c.ech.st.Grease = true
	hello.raw = nil
	return hello, nil, nil
}

func (c *Conn) echAcceptOrBypass(hello *clientHelloMsg) (*clientHelloMsg, error) {
	config := c.config
	echProvider := config.ServerECHProvider

	// Determine if ECH was offered.
	offered := false
	if config.echCanAccept() && hello.encryptedClientHelloOffered {
		publicNames, err := echProvider.GetPublicNames()
		if err != nil {
			c.sendAlert(alertInternalError)
			return nil, fmt.Errorf("ech: could not resolve public names: %s", err)
		}
		for _, name := range publicNames {
			if hello.serverName == name {
				offered = true
			}
		}
	}

	// Decide whether to bypass ECH.
	//
	// TODO(cjpatton): BLOCKER: Ensure that
	// https://github.com/tlswg/draft-ietf-tls-esni/pull/311 merges.
	if !offered || !config.echCanAccept() ||
		!hello.encryptedClientHelloOffered {
		if c.hrrTriggered && c.ech.st.Offered {
			c.sendAlert(alertIllegalParameter)
			return nil, fmt.Errorf("ech: hrr: bypass after offer")
		}

		if config.echCanAccept() && hello.encryptedClientHelloOffered {
			// If the "encrypted_client_hello" extension was set, then presume
			// it was covertext.
			c.ech.st.Grease = true
		}

		// Bypass ECH.
		return hello, nil
	}

	if c.hrrTriggered && !c.ech.st.Offered {
		c.sendAlert(alertIllegalParameter)
		return nil, fmt.Errorf("ech: hrr: offer after bypass")
	}
	c.ech.st.Offered = true

	// Parse the payload of the ECH extension.
	rawClientEch := hello.encryptedClientHello
	clientEch, err := echUnmarshalClient(rawClientEch)
	if err != nil {
		c.sendAlert(alertIllegalParameter)
		return nil, fmt.Errorf("ech: %s", err)
	}

	// Ask the ECH provider for the decryption context. Note that c.ech.hrrPsk
	// is initially nil, meaning no PSK is used for encrypting the first
	// ClientHelloInner.
	res, err := echProvider.GetServerContext(clientEch.handle.marshal(), c.ech.hrrPsk, extensionECH)
	if err != nil {
		// This condition indicates the connection must be aborted.
		c.sendAlert(alert(res.Alert))
		return nil, fmt.Errorf("ech: %s", err)
	}

	if res.Rejected {
		// Reject ECH.
		c.ech.retryConfigs = res.RetryConfigs
		return hello, nil
	}

	ctx, err := echUnmarshalServerContext(res.Context)
	if err != nil {
		c.sendAlert(alertInternalError)
		return nil, fmt.Errorf("ech: %s", err)
	}

	rawCompressedHelloInner, err := ctx.decrypt(clientEch.payload)
	if err != nil {
		c.sendAlert(alertDecryptError)
		return nil, fmt.Errorf("ech: %s", err)
	}

	rawHelloInner, innerDigest, ok := echUnincorporateOuterExtensions(rawCompressedHelloInner, hello.marshal())
	if !ok {
		c.sendAlert(alertIllegalParameter)
		return nil, fmt.Errorf("ech: %s", err)
	}

	if innerDigest != nil {
		if subtle.ConstantTimeCompare(innerDigest, ctx.innerDigest(rawHelloInner)) != 1 {
			c.sendAlert(alertDecryptError)
			return nil, fmt.Errorf("ech: outer extensions: inner digest validation fails")
		}
	}

	helloInner := new(clientHelloMsg)
	if !helloInner.unmarshal(rawHelloInner) {
		c.sendAlert(alertIllegalParameter)
		return nil, fmt.Errorf("ech: %s", err)
	}

	// Update the HRR pre-shared-key. This is used to encrypt the second
	// ClientHelloInner in case the server sends an HRR.
	c.ech.hrrPsk = ctx.hrrPsk()

	// Accept ECH.
	c.ech.st.Accepted = true
	return helloInner, nil
}

// echCipherSuite represents an ECH ciphersuite, a KDF/AEAD algorithm pair. This
// is different from an HPKE ciphersuite, which represents a KEM, KDF, and an
// AEAD algorithm.
type echCipherSuite struct {
	kdfId, aeadId uint16
}

// echAssembleHpkeCipherSuite maps the codepoints for an HPKE ciphersuite to the
// ciphersuite's internal representation, verifying that the host supports the
// cipher suite.
func echAssembleHpkeCipherSuite(kemId, kdfId, aeadId uint16) (hpke.CipherSuite, error) {
	// Verify that the ciphersuite is supported by github.com/cisco/go-hpke and
	// return the ciphersuite's internal representation.
	return hpke.AssembleCipherSuite(hpke.KEMID(kemId), hpke.KDFID(kdfId), hpke.AEADID(aeadId))
}

// echUnmarshalHpkePublicKey parses a serialized public key for the KEM algorithm
// identified by `kemId`.
func echUnmarshalHpkePublicKey(raw []byte, kemId uint16) (hpke.KEMPublicKey, error) {
	// NOTE: Stand-in values for KDF/AEAD algorithms are ignored.
	hpkeSuite, err := echAssembleHpkeCipherSuite(kemId, dummyKdfId, dummyAeadId)
	if err != nil {
		return nil, err
	}
	return hpkeSuite.KEM.Deserialize(raw)
}

// echUnmarshalHpkeSecretKey parses a serialized secret key for the KEM algorithm
// identified by `kemId`.
func echUnmarshalHpkeSecretKey(raw []byte, kemId uint16) (hpke.KEMPrivateKey, error) {
	// NOTE: Stand-in values for KDF/AEAD algorithms are ignored.
	hpkeSuite, err := echAssembleHpkeCipherSuite(kemId, dummyKdfId, dummyAeadId)
	if err != nil {
		return nil, err
	}
	return hpkeSuite.KEM.DeserializePrivate(raw)
}

// echCreateHpkeKdf returns an HPKE KDF scheme.
func echCreateHpkeKdf(kdfId uint16) (hpke.KDFScheme, error) {
	// NOTE: Stand-in values for KEM/AEAD algorithms are ignored.
	hpkeSuite, err := echAssembleHpkeCipherSuite(dummyKemId, kdfId, dummyAeadId)
	if err != nil {
		return nil, err
	}
	return hpkeSuite.KDF, nil
}

func echIsCipherSuiteSupported(suite echCipherSuite) bool {
	// NOTE: Stand-in values for KEM algorithm is ignored.
	_, err := echAssembleHpkeCipherSuite(dummyKemId, suite.kdfId, suite.aeadId)
	return err == nil
}

func echIsKemSupported(kemId uint16) bool {
	// NOTE: Stand-in values for KDF/AEAD algorithms are ignored.
	_, err := echAssembleHpkeCipherSuite(kemId, dummyKdfId, dummyAeadId)
	return err == nil
}

// echContent represents an HPKE context (irtf-cfrg-hpke-05).
type echContext struct {
	enc       *hpke.EncryptContext
	dec       *hpke.DecryptContext
	client    bool
	hpkeSuite hpke.CipherSuite
}

// cipherSuite returns the ECH ciphersuite for this HPKE context.
func (ctx *echContext) cipherSuite() echCipherSuite {
	return echCipherSuite{
		kdfId:  uint16(ctx.hpkeSuite.KDF.ID()),
		aeadId: uint16(ctx.hpkeSuite.AEAD.ID()),
	}
}

// echUnmarshalServerContext parses the server's HPKE context.
func echUnmarshalServerContext(raw []byte) (*echContext, error) {
	decryptechContext, err := hpke.UnmarshalDecryptContext(raw)
	if err != nil {
		return nil, err
	}

	hpkeSuite, err := echAssembleHpkeCipherSuite(uint16(decryptechContext.KEMID), uint16(decryptechContext.KDFID), uint16(decryptechContext.AEADID))
	if err != nil {
		return nil, err
	}

	return &echContext{nil, decryptechContext, false, hpkeSuite}, nil
}

// marshalServer returns the server's serialized HPKE context
func (ctx *echContext) marshalServer() ([]byte, error) {
	return ctx.dec.Marshal()
}

// encrypt seals the ClientHelloInner in the client's HPKE context.
func (ctx *echContext) encrypt(inner []byte) (payload []byte) {
	if !ctx.client {
		panic("encrypt() is not defined for server")
	}
	return ctx.enc.Seal(nil, inner)
}

// decrypt opens the encrypted ClientHelloInner in the server's HPKE context.
func (ctx *echContext) decrypt(payload []byte) (inner []byte, err error) {
	if ctx.client {
		panic("decrypt() is not defined for client")
	}
	return ctx.dec.Open(nil, payload)
}

// hrrPsk returns the PSK used to bind the first ClientHelloOuter to the second
// in case the backend server sends a HelloRetryRequest.
func (ctx *echContext) hrrPsk() []byte {
	if ctx.client {
		return ctx.enc.Export([]byte(echHpkeHrrKeyExportechContext), echHpkeHrrKeyLen)
	}
	return ctx.dec.Export([]byte(echHpkeHrrKeyExportechContext), echHpkeHrrKeyLen)
}

// innerDigest computes OuterExtensions.inner_digest.
func (ctx *echContext) innerDigest(inner []byte) []byte {
	kdf := ctx.hpkeSuite.KDF
	return kdf.Expand(kdf.Extract(nil, inner), []byte(echHpkeInfoInnerDigest), kdf.OutputSize())
}

// configId computes the configuration identifier for a serialized ECHConfig.
func (ctx *echContext) configId(config []byte) []byte {
	kdf := ctx.hpkeSuite.KDF
	return kdf.Expand(kdf.Extract(nil, config), []byte(echHpkeInfoConfigId), kdf.OutputSize())
}

// echClient represents a ClientECH structure, the payload of the client's
// "encrypted_client_hello" extension.
type echClient struct {
	raw []byte

	// Parsed from raw
	handle  echContextHandle
	payload []byte
}

// ecgUnmarshalClient parses a ClientECH structure. The caller provides the ECH
// version indicated by the client.
func echUnmarshalClient(raw []byte) (*echClient, error) {
	// Parse the payload as a ClientECH structure.
	ech := new(echClient)
	ech.raw = raw

	// Parse the context handle.
	s := cryptobyte.String(raw)
	if !echReadContextHandle(&s, &ech.handle) {
		return nil, fmt.Errorf("error parsing context handle")
	}
	ech.handle.raw = raw[:len(raw)-len(s)]

	// Parse the payload
	var t cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&t) ||
		!t.ReadBytes(&ech.payload, len(t)) || !s.Empty() {
		return nil, fmt.Errorf("error parsing payload")
	}

	return ech, nil
}

func (ech *echClient) marshal() []byte {
	if ech.raw != nil {
		return ech.raw
	}
	var b cryptobyte.Builder
	b.AddBytes(ech.handle.marshal())
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(ech.payload)
	})
	return b.BytesOrPanic()
}

// echContexttHandle represents the prefix of a ClientECH structure used by
// the server to compute the HPKE context.
type echContextHandle struct {
	raw []byte

	// Parsed from raw
	suite    echCipherSuite
	configId []byte
	enc      []byte
}

func (handle *echContextHandle) marshal() []byte {
	if handle.raw != nil {
		return handle.raw
	}
	var b cryptobyte.Builder
	b.AddUint16(handle.suite.kdfId)
	b.AddUint16(handle.suite.aeadId)
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(handle.configId)
	})
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(handle.enc)
	})
	return b.BytesOrPanic()
}

// ecgUnmarshalClient parses the prefix of the ClientECH used by the server to
// setup its HPKE context.
func echUnmarshalContextHandle(raw []byte) (*echContextHandle, error) {
	s := cryptobyte.String(raw)
	handle := new(echContextHandle)
	if !echReadContextHandle(&s, handle) || !s.Empty() {
		return nil, fmt.Errorf("error parsing context handle")
	}
	handle.raw = raw
	return handle, nil
}

func echReadContextHandle(s *cryptobyte.String, handle *echContextHandle) bool {
	var t cryptobyte.String
	if !s.ReadUint16(&handle.suite.kdfId) ||
		!s.ReadUint16(&handle.suite.aeadId) ||
		!s.ReadUint8LengthPrefixed(&t) ||
		!t.ReadBytes(&handle.configId, len(t)) ||
		!s.ReadUint16LengthPrefixed(&t) ||
		!t.ReadBytes(&handle.enc, len(t)) {
		return false
	}
	return true
}

// echIncorporateOuterExtension interprets data as a ClientHelloInner message
// and transforms it as specified by the "outer_extension" extension. It returns
// the transformed ClientHelloInner and a bit indicating if parsing succeeded.
//
// outerExtension specifies the single extension that will be incorporated. The
// mechanism allows more than one extension, but we will only compress one for
// now.
func echIncorporateOuterExtensions(data, innerDigest []byte, outerExtension uint16) ([]byte, bool) {
	headerData, extensionsData, ok := splitClientHelloExtensions(data)
	if !ok {
		return nil, false
	}

	var b cryptobyte.Builder
	b.AddBytes(headerData)

	s := cryptobyte.String(extensionsData)
	if s.Empty() {
		return b.BytesOrPanic(), true
	}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return nil, false
	}

	var errReadFailure = errors.New("read failure")
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for !extensions.Empty() {
			var ext uint16
			var extData cryptobyte.String
			if !extensions.ReadUint16(&ext) ||
				!extensions.ReadUint16LengthPrefixed(&extData) {
				panic(cryptobyte.BuildError{Err: errReadFailure})
			}

			if ext == outerExtension {
				// Replace outer extensions with "outer_extension" extension.
				b.AddUint16(extensionECHOuterExtensions)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddUint16(outerExtension)
					})
					b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddBytes(innerDigest)
					})
				})
			} else {
				b.AddUint16(ext)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddBytes(extData)
				})
			}
		}
	})

	compressedData, err := b.Bytes()
	if err == errReadFailure {
		return nil, false // Reading failed
	} else if err != nil {
		panic(err) // Writing failed
	}

	return compressedData, true
}

// echUnincorporateOuterExtensions interprets data as a ClientHelloInner message
// and substitutes the "outer_extension" extension with extensions from
// outerData, interpreted as the ClientHelloOuter message. Returns the
// transformed ClientHelloInner, the digest of the ClientHelloInner contained in
// the "outer_extension" extension, and a bit indicating whether parsing
// succeeded.
func echUnincorporateOuterExtensions(data []byte, outerData []byte) ([]byte, []byte, bool) {
	headerData, extensionsData, ok := splitClientHelloExtensions(data)
	if !ok {
		return nil, nil, false
	}

	var b cryptobyte.Builder
	b.AddBytes(headerData)

	s := cryptobyte.String(extensionsData)
	if s.Empty() {
		return b.BytesOrPanic(), nil, true
	}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return nil, nil, false
	}

	var innerDigest cryptobyte.String
	var errReadFailure = errors.New("read failure")
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		var handledOuterExtensions bool
		for !extensions.Empty() {
			var ext uint16
			var extData cryptobyte.String
			if !extensions.ReadUint16(&ext) ||
				!extensions.ReadUint16LengthPrefixed(&extData) {
				panic(cryptobyte.BuildError{Err: errReadFailure})
			}

			if ext == extensionECHOuterExtensions {
				if handledOuterExtensions {
					// It is an error to send any extension more than once in a
					// single message.
					panic(cryptobyte.BuildError{Err: errReadFailure})
				}
				handledOuterExtensions = true

				// Read the set of outer extension code points.
				outer := make(map[uint16]bool)
				var outerExtData cryptobyte.String
				if !extData.ReadUint16LengthPrefixed(&outerExtData) || len(outerExtData)%2 != 0 {
					panic(cryptobyte.BuildError{Err: errReadFailure})
				}
				for !outerExtData.Empty() {
					if !outerExtData.ReadUint16(&ext) {
						panic(cryptobyte.BuildError{Err: errReadFailure})
					}
					outer[ext] = true
				}

				// Read the digest of the ClientHelloInner.
				if !extData.ReadUint8LengthPrefixed(&innerDigest) {
					panic(cryptobyte.BuildError{Err: errReadFailure})
				}
				if !extData.Empty() {
					panic(cryptobyte.BuildError{Err: errReadFailure})
				}

				// Add the outer extensions from the ClientHelloOuter into the
				// ClientHelloInner.
				ok := processClientHelloExtensions(outerData, func(ext uint16, extData cryptobyte.String) bool {
					if _, ok = outer[ext]; ok {
						b.AddUint16(ext)
						b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
							b.AddBytes(extData)
						})
					}
					return true
				})
				if !ok {
					panic(cryptobyte.BuildError{Err: errReadFailure})
				}
			} else {
				b.AddUint16(ext)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddBytes(extData)
				})
			}
		}
	})

	decompressedData, err := b.Bytes()
	if err == errReadFailure {
		return nil, nil, false // Reading failed
	} else if err != nil {
		panic(err) // Writing failed
	}

	return decompressedData, innerDigest, true
}

// processClientHelloExtensions interprets data as a ClientHello and applies a
// function proc to each extension. Returns a bit indicating whether parsing
// succeeded.
func processClientHelloExtensions(data []byte, proc func(ext uint16, extData cryptobyte.String) bool) bool {
	_, extensionsData, ok := splitClientHelloExtensions(data)
	if !ok {
		return false
	}

	s := cryptobyte.String(extensionsData)
	if s.Empty() {
		return true
	}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return false
	}

	for !extensions.Empty() {
		var ext uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&ext) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return false
		}
		if ok := proc(ext, extData); !ok {
			return false
		}
	}
	return true
}

// splitClientHelloExtensions interprets data as a ClientHello message and
// return the start of the extensions. It also returns a bit indicating whether
// parsing succeeded.
func splitClientHelloExtensions(data []byte) ([]byte, []byte, bool) {
	s := cryptobyte.String(data)

	var ignored uint16
	var t cryptobyte.String
	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint16(&ignored) || !s.Skip(32) || // vers, random
		!s.ReadUint8LengthPrefixed(&t) { // session_id
		return nil, nil, false
	}

	if !s.ReadUint16LengthPrefixed(&t) { // cipher_suites
		return nil, nil, false
	}

	if !s.ReadUint8LengthPrefixed(&t) { // compression_methods
		return nil, nil, false
	}

	return data[:len(data)-len(s)], s, true
}

func (c *Config) echSelectConfig() *ECHConfig {
	for _, echConfig := range c.ClientECHConfigs {
		// A suitable configuration is one that offers an HPKE ciphersuite that
		// is supported by the client and indicates the version of ECH
		// implemented by this TLS client.
		if echConfig.isSupported() && extensionECH == echConfig.version {
			return &echConfig
		}
	}
	return nil
}

func (c *Config) echCanOffer() bool {
	if c == nil {
		return false
	}

	return c.ECHEnabled && c.echSelectConfig() != nil && c.MaxVersion >= VersionTLS13
}

func (c *Config) echCanAccept() bool {
	if c == nil {
		return false
	}
	return c.ECHEnabled && c.ServerECHProvider != nil && c.MaxVersion >= VersionTLS13
}

func (c *Config) supportedVersionsFromMin(minVersion uint16) []uint16 {
	versions := make([]uint16, 0, len(supportedVersions))
	for _, v := range supportedVersions {
		if c != nil && c.MinVersion != 0 && v < c.MinVersion {
			continue
		}
		if c != nil && c.MaxVersion != 0 && v > c.MaxVersion {
			continue
		}
		if v < minVersion {
			continue
		}
		versions = append(versions, v)
	}
	return versions
}
