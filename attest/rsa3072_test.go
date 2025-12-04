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
	"strings"
	"testing"
)

func TestSimKeyCreateAndLoadRSA3072(t *testing.T) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()

	test := struct {
		name string
		opts *KeyConfig
	}{
		name: "RSA-3072",
		opts: &KeyConfig{
			Algorithm: RSA,
			Size:      3072,
		},
	}

	t.Run(test.name, func(t *testing.T) {
		ak, err := tpm.NewAK(nil)
		if err != nil {
			t.Fatalf("NewAK() failed: %v", err)
		}
		defer ak.Close(tpm)

		sk, err := tpm.NewKey(ak, test.opts)
		if err != nil {
			// If the simulator doesn't support RSA 3072, we skip the test.
			// The error message from simulator for unsupported key size is "value is out of range".
			if strings.Contains(err.Error(), "value is out of range") {
				t.Skip("Skipping RSA 3072 test as it is not supported by the simulator")
			}
			t.Fatalf("NewKey() failed: %v", err)
		}
		defer sk.Close()

		enc, err := sk.Marshal()
		if err != nil {
			t.Fatalf("sk.Marshal() failed: %v", err)
		}
		if err := sk.Close(); err != nil {
			t.Fatalf("sk.Close() failed: %v", err)
		}

		loaded, err := tpm.LoadKey(enc)
		if err != nil {
			t.Fatalf("LoadKey() failed: %v", err)
		}
		defer loaded.Close()
	})
}

func TestSimKeySignRSA3072(t *testing.T) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()

	ak, err := tpm.NewAK(nil)
	if err != nil {
		t.Fatalf("NewAK() failed: %v", err)
	}
	defer ak.Close(tpm)

	for _, test := range []struct {
		name     string
		keyOpts  *KeyConfig
		signOpts crypto.SignerOpts
		digest   []byte
	}{
		{
			name: "RSA3072-PKCS1v15-SHA256",
			keyOpts: &KeyConfig{
				Algorithm: RSA,
				Size:      3072,
			},
			signOpts: crypto.SHA256,
			digest:   []byte("12345678901234567890123456789012"),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			sk, err := tpm.NewKey(ak, test.keyOpts)
			if err != nil {
				if strings.Contains(err.Error(), "value is out of range") {
					t.Skip("Skipping RSA 3072 test as it is not supported by the simulator")
				}
				t.Fatalf("NewKey() failed: %v", err)
			}
			defer sk.Close()

			pub := sk.Public()
			priv, err := sk.Private(pub)
			if err != nil {
				t.Fatalf("sk.Private() failed: %v", err)
			}
			signer, ok := priv.(crypto.Signer)
			if !ok {
				t.Fatalf("want crypto.Signer, got %T", priv)
			}
			sig, err := signer.Sign(nil, test.digest, test.signOpts)
			if err != nil {
				t.Fatalf("signer.Sign() failed: %v", err)
			}

			verifyRSA(t, pub, test.digest, sig, test.signOpts)
		})
	}
}
