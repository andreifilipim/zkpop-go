package zkpop

/*
#cgo LDFLAGS: -lpqcrystals_kyber768_avx2
#define KYBER_K 3
#include "kyber/params.h"
#include "kyber/api_kyber.h"
#include "kyber/api_kyber_zkpop.h"
#include <stdint.h>
#include <stdlib.h>
int pqcrystals_kyber768_avx2_crypto_kem_keypair_nizkpop(uint8_t *pk, uint8_t *sk, uint8_t **zkpop, size_t *zkpop_size);
int pqcrystals_kyber768_avx2_crypto_nizkpop_verify(const unsigned char *pk, const unsigned char *zkpop, unsigned long zkpop_size);
*/
import "C"
import (
	"fmt"
	"unsafe"
)

func KeyPairKyber768NIZKPoP() ([]byte, []byte, []byte, error) {
	pk := make([]byte, C.pqcrystals_kyber768_PUBLICKEYBYTES)
	sk := make([]byte, C.pqcrystals_kyber768_SECRETKEYBYTES)
	var zkpop_c *C.uint8_t
	var zkpop_size_c C.size_t
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
	ret := C.pqcrystals_kyber768_avx2_crypto_nizkpop_verify(
		(*C.uchar)(unsafe.Pointer(&pk[0])),
		(*C.uchar)(unsafe.Pointer(&zkpop[0])),
		C.ulong(len(zkpop)),
	)
	return ret == 0
}
