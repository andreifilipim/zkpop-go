// Kyber original bindings, just for comparison purposes
package zkpop

/*
#include "kyber/api_kyber.h" // Contém as definições para Kyber512, 768, 1024 KEM
#include <stdint.h>
#include <stdlib.h>
#include <openssl/evp.h> //from OpenSSL 1.1.1
#include <openssl/aes.h>
*/
import "C"

import (
	"fmt"
	"unsafe"
)

//binding for pqcrystals_kyber512_avx2_keypair (Mantenha o código existente)
func KeyPairKyber512() ([]byte, []byte, error) {
	pk := make([]byte, C.pqcrystals_kyber512_PUBLICKEYBYTES)
	sk := make([]byte, C.pqcrystals_kyber512_SECRETKEYBYTES)

	ret := C.pqcrystals_kyber512_avx2_keypair((*C.uint8_t)(unsafe.Pointer(&pk[0])),
		(*C.uint8_t)(unsafe.Pointer(&sk[0])))

	if ret != 0 {
		return nil, nil, fmt.Errorf("failed to generate keypair")
	}
	return pk, sk, nil
}

//Encapsulation for a given public key pk (Mantenha o código existente)
func EncapsKyber512(pk []byte) ([]byte, []byte, error) {
	ss := make([]byte, C.pqcrystals_kyber512_BYTES)
	ct := make([]byte, C.pqcrystals_kyber512_CIPHERTEXTBYTES)

	ret := C.pqcrystals_kyber512_avx2_enc((*C.uint8_t)(unsafe.Pointer(&ct[0])),
		(*C.uint8_t)(unsafe.Pointer(&ss[0])),
		(*C.uint8_t)(unsafe.Pointer(&pk[0])))
	if ret != 0 {
		return nil, nil, fmt.Errorf("failed to encaps")
	}
	return ct, ss, nil
}

//Given a ciphertext ct and a private key sk (Mantenha o código existente)
func DecapsKyber512(ct []byte, sk []byte) ([]byte, error) {
	css := make([]byte, C.pqcrystals_kyber512_BYTES)

	ret := C.pqcrystals_kyber512_avx2_dec((*C.uint8_t)(unsafe.Pointer(&css[0])),
		(*C.uint8_t)(unsafe.Pointer(&ct[0])),
		(*C.uint8_t)(unsafe.Pointer(&sk[0])))
	if ret != 0 {
		return nil, fmt.Errorf("failed to perform decapsulation")
	}
	return css, nil
}

// --- NOVO: KYBER768 KEM ---

// KeyPairKyber768 gera um par de chaves Kyber768.
func KeyPairKyber768() ([]byte, []byte, error) {
	pk := make([]byte, C.pqcrystals_kyber768_PUBLICKEYBYTES)
	sk := make([]byte, C.pqcrystals_kyber768_SECRETKEYBYTES)

	ret := C.pqcrystals_kyber768_avx2_keypair( // Nome da função C de api.h
		(*C.uint8_t)(unsafe.Pointer(&pk[0])),
		(*C.uint8_t)(unsafe.Pointer(&sk[0])),
	)

	if ret != 0 {
		return nil, nil, fmt.Errorf("failed to generate Kyber768 keypair: %d", ret)
	}
	return pk, sk, nil
}

// EncapsKyber768 encapsula uma chave de sessão usando a chave pública Kyber768.
func EncapsKyber768(pk []byte) (ct, ss []byte, err error) {
	ss = make([]byte, C.pqcrystals_kyber768_BYTES)           // Tamanho do shared secret
	ct = make([]byte, C.pqcrystals_kyber768_CIPHERTEXTBYTES) // Tamanho do ciphertext

	ret := C.pqcrystals_kyber768_avx2_enc( // Nome da função C de api.h
		(*C.uint8_t)(unsafe.Pointer(&ct[0])),
		(*C.uint8_t)(unsafe.Pointer(&ss[0])),
		(*C.uint8_t)(unsafe.Pointer(&pk[0])),
	)
	if ret != 0 {
		return nil, nil, fmt.Errorf("failed to encaps Kyber768: %d", ret)
	}
	return ct, ss, nil
}

// DecapsKyber768 decapsula uma chave de sessão usando o texto cifrado e a chave privada Kyber768.
func DecapsKyber768(ct []byte, sk []byte) ([]byte, error) {
	css := make([]byte, C.pqcrystals_kyber768_BYTES) // Tamanho do shared secret

	ret := C.pqcrystals_kyber768_avx2_dec( // Nome da função C de api.h
		(*C.uint8_t)(unsafe.Pointer(&css[0])),
		(*C.uint8_t)(unsafe.Pointer(&ct[0])),
		(*C.uint8_t)(unsafe.Pointer(&sk[0])),
	)
	if ret != 0 {
		return nil, fmt.Errorf("failed to decapsulate Kyber768: %d", ret)
	}
	return css, nil
}

// --- NOVO: KYBER1024 KEM ---

// KeyPairKyber1024 gera um par de chaves Kyber1024.
func KeyPairKyber1024() ([]byte, []byte, error) {
	pk := make([]byte, C.pqcrystals_kyber1024_PUBLICKEYBYTES)
	sk := make([]byte, C.pqcrystals_kyber1024_SECRETKEYBYTES)

	ret := C.pqcrystals_kyber1024_avx2_keypair( // Nome da função C de api.h
		(*C.uint8_t)(unsafe.Pointer(&pk[0])),
		(*C.uint8_t)(unsafe.Pointer(&sk[0])),
	)

	if ret != 0 {
		return nil, nil, fmt.Errorf("failed to generate Kyber1024 keypair: %d", ret)
	}
	return pk, sk, nil
}

// EncapsKyber1024 encapsula uma chave de sessão usando a chave pública Kyber1024.
func EncapsKyber1024(pk []byte) (ct, ss []byte, err error) {
	ss = make([]byte, C.pqcrystals_kyber1024_BYTES)           // Tamanho do shared secret
	ct = make([]byte, C.pqcrystals_kyber1024_CIPHERTEXTBYTES) // Tamanho do ciphertext

	ret := C.pqcrystals_kyber1024_avx2_enc( // Nome da função C de api.h
		(*C.uint8_t)(unsafe.Pointer(&ct[0])),
		(*C.uint8_t)(unsafe.Pointer(&ss[0])),
		(*C.uint8_t)(unsafe.Pointer(&pk[0])),
	)
	if ret != 0 {
		return nil, nil, fmt.Errorf("failed to encaps Kyber1024: %d", ret)
	}
	return ct, ss, nil
}

// DecapsKyber1024 decapsula uma chave de sessão usando o texto cifrado e a chave privada Kyber1024.
func DecapsKyber1024(ct []byte, sk []byte) ([]byte, error) {
	css := make([]byte, C.pqcrystals_kyber1024_BYTES) // Tamanho do shared secret

	ret := C.pqcrystals_kyber1024_avx2_dec( // Nome da função C de api.h
		(*C.uint8_t)(unsafe.Pointer(&css[0])),
		(*C.uint8_t)(unsafe.Pointer(&ct[0])),
		(*C.uint8_t)(unsafe.Pointer(&sk[0])),
	)
	if ret != 0 {
		return nil, fmt.Errorf("failed to decapsulate Kyber1024: %d", ret)
	}
	return css, nil
}