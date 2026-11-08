package stego

import (
	"bytes"
	"errors"
	"testing"
)

func TestReedSolomonRecoversCorruptedShards(t *testing.T) {
	data := bytes.Repeat([]byte("hide-payload-"), 200)
	encoded, err := addReedSolomon(data)
	if err != nil {
		t.Fatal(err)
	}
	stride := len(encoded) / (rsDataShards + rsParityShards)

	// Damage two shards (the parity limit): one data shard and one parity shard.
	damaged := append([]byte(nil), encoded...)
	damaged[5] ^= 0xFF
	damaged[5*stride+3] ^= 0x01

	got, err := removeReedSolomon(damaged)
	if err != nil {
		t.Fatalf("expected recovery from 2 damaged shards, got error: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("recovered data does not match the original")
	}
}

func TestReedSolomonRejectsTooManyCorruptedShards(t *testing.T) {
	data := bytes.Repeat([]byte("hide-payload-"), 200)
	encoded, err := addReedSolomon(data)
	if err != nil {
		t.Fatal(err)
	}
	stride := len(encoded) / (rsDataShards + rsParityShards)

	damaged := append([]byte(nil), encoded...)
	for _, shard := range []int{0, 1, 2} {
		damaged[shard*stride] ^= 0xFF
	}

	if _, err := removeReedSolomon(damaged); !errors.Is(err, ErrTooManyCorruptShards) {
		t.Fatalf("expected ErrTooManyCorruptShards, got %v", err)
	}
}
