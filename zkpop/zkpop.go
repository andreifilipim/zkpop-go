// zkpop/zkpop.go
package zkpop

/*
#include "api_frodo640.h" //

// Headers específicos do Kyber
#include "kyber/api_kyber.h"       // Para constantes de tamanho como pqcrystals_kyber*_PUBLICKEYBYTES
#include "kyber/api_kyber_zkpop.h" // Para as declarações MACRO das funções NIZKPoP Kyber
#include "kyber/params.h"          // Define KYBER_K=2 por padrão, expondo apenas Kyber512 via macros

#include <stdint.h>
#include <stdlib.h>

// Declarações explícitas para Cgo encontrar as funções Kyber768 e Kyber1024
// Essas assinaturas devem corresponder às funções exportadas pelas suas bibliotecas .so compiladas.

// Para KYBER_K = 3 (Kyber768)
// Estas são as funções que seriam geradas por KYBER_NAMESPACE(crypto_kem_keypair_nizkpop) e KYBER_NAMESPACE(crypto_nizkpop_verify)
// se KYBER_K fosse 3 durante o pré-processamento dos headers pelo Cgo.
int pqcrystals_kyber768_avx2_crypto_kem_keypair_nizkpop(uint8_t *pk, uint8_t *sk, uint8_t **zkpop, size_t *zkpop_size);
int pqcrystals_kyber768_avx2_crypto_nizkpop_verify(const unsigned char *pk, const unsigned char *zkpop, unsigned long zkpop_size);

// Para KYBER_K = 4 (Kyber1024)
int pqcrystals_kyber1024_avx2_crypto_kem_keypair_nizkpop(uint8_t *pk, uint8_t *sk, uint8_t **zkpop, size_t *zkpop_size);
int pqcrystals_kyber1024_avx2_crypto_nizkpop_verify(const unsigned char *pk, const unsigned char *zkpop, unsigned long zkpop_size);

*/
import "C"

import (
	"fmt"
	"unsafe"
)

// Frodo640-Keypair with NIZKPoP
func KeyPairFrodo640NIZKPoP() ([]byte, []byte, []byte, error) {
	pk := make([]byte, C.CRYPTO_PUBLICKEYBYTES) //
	sk := make([]byte, C.CRYPTO_SECRETKEYBYTES) //
	var zkpop_c *C.uint8_t
	var zkpop_size_c C.size_t

	ret := C.crypto_kem_keypair_nizkpop_Frodo640( //
		(*C.uint8_t)(unsafe.Pointer(&pk[0])),
		(*C.uint8_t)(unsafe.Pointer(&sk[0])),
		&zkpop_c,
		&zkpop_size_c)

	if ret != 0 {
		return nil, nil, nil, fmt.Errorf("failed to generate Frodo640 keypair with NIZKPoP: %d", ret)
	}

	zkpopGo := C.GoBytes(unsafe.Pointer(zkpop_c), C.int(zkpop_size_c))
	C.free(unsafe.Pointer(zkpop_c))

	return pk, sk, zkpopGo, nil
}

func VerifyFrodo640ZKPop(pk []byte, zkpop []byte) bool {
	ret := C.crypto_nizkpop_verify_Frodo640( //
		(*C.uchar)(unsafe.Pointer(&pk[0])),
		(*C.uchar)(unsafe.Pointer(&zkpop[0])),
		C.ulong(len(zkpop)))
	return ret == 0
}

// Kyber512-Keypair with NIZKPoP
func KeyPairKyber512NIZKPoP() ([]byte, []byte, []byte, error) {
	pk := make([]byte, C.pqcrystals_kyber512_PUBLICKEYBYTES) //
	sk := make([]byte, C.pqcrystals_kyber512_SECRETKEYBYTES) //
	var zkpop_c *C.uint8_t
	var zkpop_size_c C.size_t

	// A função C `pqcrystals_kyber512_avx2_crypto_kem_keypair_nizkpop` é declarada via macro em api_kyber_zkpop.h quando KYBER_K=2.
	// Cgo deve encontrá-la se params.h for processado com KYBER_K=2 (padrão).
	ret := C.pqcrystals_kyber512_avx2_crypto_kem_keypair_nizkpop(
		(*C.uint8_t)(unsafe.Pointer(&pk[0])),
		(*C.uint8_t)(unsafe.Pointer(&sk[0])),
		&zkpop_c,
		&zkpop_size_c,
	)

	if ret != 0 {
		return nil, nil, nil, fmt.Errorf("failed to generate Kyber512 keypair with NIZKPoP: %d", ret)
	}

	zkpopGo := C.GoBytes(unsafe.Pointer(zkpop_c), C.int(zkpop_size_c))
	C.free(unsafe.Pointer(zkpop_c))

	return pk, sk, zkpopGo, nil
}

func VerifyKyber512ZKPop(pk []byte, zkpop []byte) bool {
	ret := C.pqcrystals_kyber512_avx2_crypto_nizkpop_verify(
		(*C.uchar)(unsafe.Pointer(&pk[0])),
		(*C.uchar)(unsafe.Pointer(&zkpop[0])),
		C.ulong(len(zkpop)),
	)
	return ret == 0
}

// --- KYBER768 NIZKPoP ---
// Os números de linha 102 e 119 nos erros da sua imagem correspondem a estas funções.
func KeyPairKyber768NIZKPoP() ([]byte, []byte, []byte, error) {
	// A constante pqcrystals_kyber768_PUBLICKEYBYTES vem de api_kyber.h
	pk := make([]byte, C.pqcrystals_kyber768_PUBLICKEYBYTES)
	sk := make([]byte, C.pqcrystals_kyber768_SECRETKEYBYTES)
	var zkpop_c *C.uint8_t
	var zkpop_size_c C.size_t

	// Cgo usará a declaração explícita fornecida no topo deste bloco C.
	ret := C.pqcrystals_kyber768_avx2_crypto_kem_keypair_nizkpop(
		(*C.uint8_t)(unsafe.Pointer(&pk[0])),
		(*C.uint8_t)(unsafe.Pointer(&sk[0])),
		&zkpop_c,
		&zkpop_size_c,
	)

	if ret != 0 {
		return nil, nil, nil, fmt.Errorf("failed to generate Kyber768 keypair with NIZKPoP: %d", ret)
	}
	zkpopGo := C.GoBytes(unsafe.Pointer(zkpop_c), C.int(zkpop_size_c))
	C.free(unsafe.Pointer(zkpop_c))
	return pk, sk, zkpopGo, nil
}

func VerifyKyber768ZKPop(pk []byte, zkpop []byte) bool {
	// Cgo usará a declaração explícita.
	ret := C.pqcrystals_kyber768_avx2_crypto_nizkpop_verify(
		(*C.uchar)(unsafe.Pointer(&pk[0])),
		(*C.uchar)(unsafe.Pointer(&zkpop[0])),
		C.ulong(len(zkpop)),
	)
	return ret == 0
}

// --- KYBER1024 NIZKPoP ---
// Os números de linha 135 e 152 nos erros da sua imagem correspondem a estas funções.
func KeyPairKyber1024NIZKPoP() ([]byte, []byte, []byte, error) {
	pk := make([]byte, C.pqcrystals_kyber1024_PUBLICKEYBYTES) //
	sk := make([]byte, C.pqcrystals_kyber1024_SECRETKEYBYTES) //
	var zkpop_c *C.uint8_t
	var zkpop_size_c C.size_t

	// Cgo usará a declaração explícita.
	ret := C.pqcrystals_kyber1024_avx2_crypto_kem_keypair_nizkpop(
		(*C.uint8_t)(unsafe.Pointer(&pk[0])),
		(*C.uint8_t)(unsafe.Pointer(&sk[0])),
		&zkpop_c,
		&zkpop_size_c,
	)

	if ret != 0 {
		return nil, nil, nil, fmt.Errorf("failed to generate Kyber1024 keypair with NIZKPoP: %d", ret)
	}
	zkpopGo := C.GoBytes(unsafe.Pointer(zkpop_c), C.int(zkpop_size_c))
	C.free(unsafe.Pointer(zkpop_c))
	return pk, sk, zkpopGo, nil
}

func VerifyKyber1024ZKPop(pk []byte, zkpop []byte) bool {
	// Cgo usará a declaração explícita.
	ret := C.pqcrystals_kyber1024_avx2_crypto_nizkpop_verify(
		(*C.uchar)(unsafe.Pointer(&pk[0])),
		(*C.uchar)(unsafe.Pointer(&zkpop[0])),
		C.ulong(len(zkpop)),
	)
	return ret == 0
}