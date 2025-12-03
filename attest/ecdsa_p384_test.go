// Copyright 2021 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

//go:build !localtest && cgo && !gofuzz
// +build !localtest,cgo,!gofuzz

package attest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

// TestECDSAP384Support explicitly verifies that ECDSA P-384 keys are supported.
// It creates a key, signs a digest, and verifies the signature using the standard crypto library.
func TestECDSAP384Support(t *testing.T) {
	// Setup a simulated TPM
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()

	// Create an Attestation Key (AK) - required parent for the application key
	ak, err := tpm.NewAK(nil)
	if err != nil {
		t.Fatalf("NewAK() failed: %v", err)
	}
	defer ak.Close(tpm)

	// Define configuration for ECDSA P-384 key
	keyConfig := &KeyConfig{
		Algorithm: ECDSA,
		Size:      384,
	}

	// Create the key
	key, err := tpm.NewKey(ak, keyConfig)
	if err != nil {
		t.Fatalf("NewKey() failed with ECDSA P-384 config: %v", err)
	}
	defer key.Close()

	// Verify the public key is indeed P-384
	pubKey, ok := key.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("Public key is not *ecdsa.PublicKey, got %T", key.Public())
	}

	if pubKey.Curve != elliptic.P384() {
		t.Errorf("Public key curve is not P-384. Got: %v", pubKey.Curve)
	}

	// Test Signing
	digest := []byte("123456789012345678901234567890121234567890123456") // 48 bytes for SHA-384
	signer, err := key.Private(key.Public())
	if err != nil {
		t.Fatalf("Failed to get signer: %v", err)
	}

	cryptoSigner, ok := signer.(crypto.Signer)
	if !ok {
		t.Fatalf("Private key does not implement crypto.Signer")
	}

	signature, err := cryptoSigner.Sign(rand.Reader, digest, nil)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}

	// Verify signature using standard library
	// Note: VerifyECDSA helper is defined in application_key_test.go, but we can just call it here or duplicate the check
	// nicely. Since we are in the same package 'attest', we can use verifyECDSA from application_key_test.go if it's available.
	// But to be self-contained and "proving" it, let's use the explicit verify logic.

	verifyECDSA(t, pubKey, digest, signature)
}
