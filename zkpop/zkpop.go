// zkpop/zkpop.go
package zkpop

/*
#include "api_frodo640.h"
#include <stdint.h>
#include <stdlib.h>
int crypto_kem_keypair_nizkpop_Frodo640(uint8_t *pk, uint8_t *sk, uint8_t **zkpop, size_t *zkpop_size);
int crypto_nizkpop_verify_Frodo640(const unsigned char *pk, const unsigned char *zkpop, unsigned long zkpop_size);
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// Frodo640-Keypair with NIZKPoP
func KeyPairFrodo640NIZKPoP() ([]byte, []byte, []byte, error) {
	pk := make([]byte, C.CRYPTO_PUBLICKEYBYTES)
	sk := make([]byte, C.CRYPTO_SECRETKEYBYTES)
	var zkpop_c *C.uint8_t
	var zkpop_size_c C.size_t

	ret := C.crypto_kem_keypair_nizkpop_Frodo640(
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
	ret := C.crypto_nizkpop_verify_Frodo640(
		(*C.uchar)(unsafe.Pointer(&pk[0])),
		(*C.uchar)(unsafe.Pointer(&zkpop[0])),
		C.ulong(len(zkpop)))
	return ret == 0
}