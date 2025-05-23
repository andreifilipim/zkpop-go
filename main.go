// main.go
package main

/*
#cgo CFLAGS: -I/home/andrei/zkpop-go/external/KEM-NIZKPoP/frodo-zkpop/frodo640/ -I/home/andrei/zkpop-go/external/KEM-NIZKPoP/kyber-zkpop/avx2/ -I/usr/include/
#cgo LDFLAGS: -L/home/andrei/zkpop-go/external/KEM-NIZKPoP/frodo-zkpop/frodo640/ -L/home/andrei/zkpop-go/external/KEM-NIZKPoP/kyber-zkpop/avx2/ -L/usr/lib/ -lfrodo -lpqcrystals_kyber512_avx2 -lpqcrystals_kyber768_avx2 -lpqcrystals_kyber1024_avx2 -lpqcrystals_aes256ctr_avx2 -lpqcrystals_fips202_ref -lpqcrystals_fips202x4_avx2 -lssl -lcrypto
*/
import "C"

import (
	"bytes"
	"fmt"
	"log"
	"math"
	"time"

	"zkpop-go/zkpop"
)

func calculateStats(durations []time.Duration) (float64, float64) {
	if len(durations) == 0 {
		return 0.0, 0.0
	}

	var sum time.Duration
	for _, d := range durations {
		sum += d
	}
	average := float64(sum) / float64(len(durations))

	var sumSqDiff float64
	for _, d := range durations {
		diff := float64(d) - average
		sumSqDiff += diff * diff
	}
	variance := sumSqDiff / float64(len(durations))
	stdDev := math.Sqrt(variance)

	return average, stdDev
}

//test FrodoKEM in N+1 iterations (mantido como está)
func testFrodoKEM(N int) {
	fmt.Println("Testing FrodoKEM...")

	//warmup
	pk, sk, err := zkpop.KeyPairFrodo640()
	if err != nil {
		log.Fatalf("Error generating keypair: %v", err)
	}

	//test N keygens
	for i := 0; i < N; i++ {
		pk, sk, err = zkpop.KeyPairFrodo640()
	}

	//warmup Encaps
	ct, ss, err := zkpop.EncapsFrodo640(pk)
	if err != nil {
		log.Fatalf("Failed FrodoKEM encapsulation: %v", err)
	}

	//test N Encaps
	for i := 0; i < N; i++ {
		ct, ss, err = zkpop.EncapsFrodo640(pk)
	}

	//warmup Decaps
	css, err := zkpop.DecapsFrodo640(ct, sk)
	if err != nil || !bytes.Equal(ss, css) {
		log.Fatalf("Failed FrodoKEM decapsulation.")
	}

	//test N Decaps
	for i := 0; i < N; i++ {
		css, err = zkpop.DecapsFrodo640(ct, sk)
	}

}

//test FrodoKEM-NIZKPoP in N+1 iterations (mantido como está)
func testFrodoKEMNIZKPoP(N int) {
	fmt.Println("Testing FrodoKEM-NIZKPoP...")

	//warmup
	pk, _, zkpopProof, err := zkpop.KeyPairFrodo640NIZKPoP()
	if err != nil {
		log.Fatalf("Error generating keypair: %v", err)
	}

	//test N keygens
	for i := 0; i < N; i++ {
		pk, _, zkpopProof, err = zkpop.KeyPairFrodo640NIZKPoP()
	}

	//warmup
	valid := zkpop.VerifyFrodo640ZKPop(pk, zkpopProof)
	if !valid {
		log.Fatalf("Error verifying ZKPoP: %v", err)
	}

	//test N verifications
	for i := 0; i < N; i++ {
		valid = zkpop.VerifyFrodo640ZKPop(pk, zkpopProof)
	}
}

// testKyberNIZKPoP para Kyber512, Kyber768, Kyber1024
func testKyberNIZKPoP(N int) {
	fmt.Println("---")
	fmt.Println("Testing Kyber512-NIZKPoP...")

	// Warmup
	pk, _, zkpopProof, err := zkpop.KeyPairKyber512NIZKPoP()
	if err != nil {
		log.Fatalf("Error generating keypair: %v", err)
	}

	// Test N keygens
	keygenDurations := make([]time.Duration, N)
	for i := 0; i < N; i++ {
		startTime := time.Now()
		pk, _, zkpopProof, err = zkpop.KeyPairKyber512NIZKPoP()
		keygenDurations[i] = time.Since(startTime)
	}
	avgKG, stdDevKG := calculateStats(keygenDurations)
	fmt.Printf("Tempo gasto para geracao de chaves (Kyber512-NIZKPoP):\n")
	fmt.Printf("  Média: %f segundos\n", avgKG/float64(time.Second))
	fmt.Printf("  Desvio Padrão: %f segundos\n", stdDevKG/float64(time.Second))

	// Warmup
	valid := zkpop.VerifyKyber512ZKPop(pk, zkpopProof)
	if !valid {
		log.Fatalf("Error verifying ZKPoP: %v", err)
	}

	// Test N verifications
	verifyDurations := make([]time.Duration, N)
	for i := 0; i < N; i++ {
		startTime := time.Now()
		valid = zkpop.VerifyKyber512ZKPop(pk, zkpopProof)
		verifyDurations[i] = time.Since(startTime)
	}
	avgVerify, stdDevVerify := calculateStats(verifyDurations)
	fmt.Printf("Tempo gasto para verificar (Kyber512-NIZKPoP):\n")
	fmt.Printf("  Média: %f segundos\n", avgVerify/float64(time.Second))
	fmt.Printf("  Desvio Padrão: %f segundos\n", stdDevVerify/float64(time.Second))

	fmt.Println("------------------------------")
	fmt.Println("Testing Kyber768-NIZKPoP...")

	// Warmup
	pk, _, zkpopProof, err = zkpop.KeyPairKyber768NIZKPoP()
	if err != nil {
		log.Fatalf("Error generating keypair: %v", err)
	}

	// Test N keygens
	keygenDurations = make([]time.Duration, N)
	for i := 0; i < N; i++ {
		startTime := time.Now()
		pk, _, zkpopProof, err = zkpop.KeyPairKyber768NIZKPoP()
		keygenDurations[i] = time.Since(startTime)
	}
	avgKG, stdDevKG = calculateStats(keygenDurations)
	fmt.Printf("Tempo gasto para geracao de chaves (Kyber768-NIZKPoP):\n")
	fmt.Printf("  Média: %f segundos\n", avgKG/float64(time.Second))
	fmt.Printf("  Desvio Padrão: %f segundos\n", stdDevKG/float64(time.Second))

	// Warmup
	valid = zkpop.VerifyKyber768ZKPop(pk, zkpopProof)
	if !valid {
		log.Fatalf("Error verifying ZKPoP: %v", err)
	}

	// Test N verifications
	verifyDurations = make([]time.Duration, N)
	for i := 0; i < N; i++ {
		startTime := time.Now()
		valid = zkpop.VerifyKyber768ZKPop(pk, zkpopProof)
		verifyDurations[i] = time.Since(startTime)
	}
	avgVerify, stdDevVerify = calculateStats(verifyDurations)
	fmt.Printf("Tempo gasto para verificar (Kyber768-NIZKPoP):\n")
	fmt.Printf("  Média: %f segundos\n", avgVerify/float64(time.Second))
	fmt.Printf("  Desvio Padrão: %f segundos\n", stdDevVerify/float64(time.Second))

	fmt.Println("------------------------------")
	fmt.Println("Testing Kyber1024-NIZKPoP...")

	// Warmup
	pk, _, zkpopProof, err = zkpop.KeyPairKyber1024NIZKPoP()
	if err != nil {
		log.Fatalf("Error generating keypair: %v", err)
	}

	// Test N keygens
	keygenDurations = make([]time.Duration, N)
	for i := 0; i < N; i++ {
		startTime := time.Now()
		pk, _, zkpopProof, err = zkpop.KeyPairKyber1024NIZKPoP()
		keygenDurations[i] = time.Since(startTime)
	}
	avgKG, stdDevKG = calculateStats(keygenDurations)
	fmt.Printf("Tempo gasto para geracao de chaves (Kyber1024-NIZKPoP):\n")
	fmt.Printf("  Média: %f segundos\n", avgKG/float64(time.Second))
	fmt.Printf("  Desvio Padrão: %f segundos\n", stdDevKG/float64(time.Second))

	// Warmup
	valid = zkpop.VerifyKyber1024ZKPop(pk, zkpopProof)
	if !valid {
		log.Fatalf("Error verifying ZKPoP: %v", err)
	}

	// Test N verifications
	verifyDurations = make([]time.Duration, N)
	for i := 0; i < N; i++ {
		startTime := time.Now()
		valid = zkpop.VerifyKyber1024ZKPop(pk, zkpopProof)
		verifyDurations[i] = time.Since(startTime)
	}
	avgVerify, stdDevVerify = calculateStats(verifyDurations)
	fmt.Printf("Tempo gasto para verificar (Kyber1024-NIZKPoP):\n")
	fmt.Printf("  Média: %f segundos\n", avgVerify/float64(time.Second))
	fmt.Printf("  Desvio Padrão: %f segundos\n", stdDevVerify/float64(time.Second))
}

func testKyber(N int) {
	fmt.Println("----------------------")
	fmt.Println("Testing Kyber512...")
	// Warmup
	pk, sk, err := zkpop.KeyPairKyber512()
	if err != nil {
		log.Fatalf("Error generating keypair: %v", err)
	}

	// Test N keygens
	keygenDurations := make([]time.Duration, N)
	for i := 0; i < N; i++ {
		startTime := time.Now()
		pk, sk, err = zkpop.KeyPairKyber512()
		keygenDurations[i] = time.Since(startTime)
	}
	avgKG, stdDevKG := calculateStats(keygenDurations)
	fmt.Printf("Tempo gasto para geracao de chaves (Kyber512):\n")
	fmt.Printf("  Média: %f segundos\n", avgKG/float64(time.Second))
	fmt.Printf("  Desvio Padrão: %f segundos\n", stdDevKG/float64(time.Second))

	// Warmup Encaps
	ct, ss, err := zkpop.EncapsKyber512(pk)
	if err != nil {
		log.Fatalf("Failed Kyber512 encapsulation: %v", err)
	}

	// Test N Encaps
	encapsDurations := make([]time.Duration, N)
	for i := 0; i < N; i++ {
		startTime := time.Now()
		ct, ss, err = zkpop.EncapsKyber512(pk)
		encapsDurations[i] = time.Since(startTime)
	}
	avgE, stdDevE := calculateStats(encapsDurations)
	fmt.Printf("Tempo gasto para encapsular (Kyber512):\n")
	fmt.Printf("  Média: %f segundos\n", avgE/float64(time.Second))
	fmt.Printf("  Desvio Padrão: %f segundos\n", stdDevE/float64(time.Second))

	// Warmup Decaps
	css, err := zkpop.DecapsKyber512(ct, sk)
	if err != nil || !bytes.Equal(ss, css) {
		log.Fatalf("Failed Kyber512 decapsulation.")
	}

	// Test N Decaps
	decapsDurations := make([]time.Duration, N)
	for i := 0; i < N; i++ {
		startTime := time.Now()
		css, err = zkpop.DecapsKyber512(ct, sk)
		decapsDurations[i] = time.Since(startTime)
	}
	avgD, stdDevD := calculateStats(decapsDurations)
	fmt.Printf("Tempo gasto para decapsular (Kyber512):\n")
	fmt.Printf("  Média: %f segundos\n", avgD/float64(time.Second))
	fmt.Printf("  Desvio Padrão: %f segundos\n", stdDevD/float64(time.Second))

	fmt.Println("------------------")
	fmt.Println("Testing Kyber768...")
	// Warmup
	pk, sk, err = zkpop.KeyPairKyber768()
	if err != nil {
		log.Fatalf("Error generating keypair: %v", err)
	}

	// Test N keygens
	keygenDurations = make([]time.Duration, N)
	for i := 0; i < N; i++ {
		startTime := time.Now()
		pk, sk, err = zkpop.KeyPairKyber768()
		keygenDurations[i] = time.Since(startTime)
	}
	avgKG, stdDevKG = calculateStats(keygenDurations)
	fmt.Printf("Tempo gasto para geracao de chaves (Kyber768):\n")
	fmt.Printf("  Média: %f segundos\n", avgKG/float64(time.Second))
	fmt.Printf("  Desvio Padrão: %f segundos\n", stdDevKG/float64(time.Second))

	// Warmup Encaps
	ct, ss, err = zkpop.EncapsKyber768(pk)
	if err != nil {
		log.Fatalf("Failed Kyber768 encapsulation: %v", err)
	}

	// Test N Encaps
	encapsDurations = make([]time.Duration, N)
	for i := 0; i < N; i++ {
		startTime := time.Now()
		ct, ss, err = zkpop.EncapsKyber768(pk)
		encapsDurations[i] = time.Since(startTime)
	}
	avgE, stdDevE = calculateStats(encapsDurations)
	fmt.Printf("Tempo gasto para encapsular (Kyber768):\n")
	fmt.Printf("  Média: %f segundos\n", avgE/float64(time.Second))
	fmt.Printf("  Desvio Padrão: %f segundos\n", stdDevE/float64(time.Second))

	// Warmup Decaps
	css, err = zkpop.DecapsKyber768(ct, sk)
	if err != nil || !bytes.Equal(ss, css) {
		log.Fatalf("Failed Kyber512 decapsulation.")
	}

	// Test N Decaps
	decapsDurations = make([]time.Duration, N)
	for i := 0; i < N; i++ {
		startTime := time.Now()
		css, err = zkpop.DecapsKyber768(ct, sk)
		decapsDurations[i] = time.Since(startTime)
	}
	avgD, stdDevD = calculateStats(decapsDurations)
	fmt.Printf("Tempo gasto para decapsular (Kyber768):\n")
	fmt.Printf("  Média: %f segundos\n", avgD/float64(time.Second))
	fmt.Printf("  Desvio Padrão: %f segundos\n", stdDevD/float64(time.Second))

	fmt.Println("--------------------")
	fmt.Println("Testing Kyber1024...")
	// Warmup
	pk, sk, err = zkpop.KeyPairKyber1024()
	if err != nil {
		log.Fatalf("Error generating keypair: %v", err)
	}

	// Test N keygens
	keygenDurations = make([]time.Duration, N)
	for i := 0; i < N; i++ {
		startTime := time.Now()
		pk, sk, err = zkpop.KeyPairKyber1024()
		keygenDurations[i] = time.Since(startTime)
	}
	avgKG, stdDevKG = calculateStats(keygenDurations)
	fmt.Printf("Tempo gasto para geracao de chaves (Kyber1024):\n")
	fmt.Printf("  Média: %f segundos\n", avgKG/float64(time.Second))
	fmt.Printf("  Desvio Padrão: %f segundos\n", stdDevKG/float64(time.Second))

	// Warmup Encaps
	ct, ss, err = zkpop.EncapsKyber1024(pk)
	if err != nil {
		log.Fatalf("Failed Kyber1024 encapsulation: %v", err)
	}

	// Test N Encaps
	encapsDurations = make([]time.Duration, N)
	for i := 0; i < N; i++ {
		startTime := time.Now()
		ct, ss, err = zkpop.EncapsKyber1024(pk)
		encapsDurations[i] = time.Since(startTime)
	}
	avgE, stdDevE = calculateStats(encapsDurations)
	fmt.Printf("Tempo gasto para encapsular (Kyber1024):\n")
	fmt.Printf("  Média: %f segundos\n", avgE/float64(time.Second))
	fmt.Printf("  Desvio Padrão: %f segundos\n", stdDevE/float64(time.Second))

	// Warmup Decaps
	css, err = zkpop.DecapsKyber1024(ct, sk)
	if err != nil || !bytes.Equal(ss, css) {
		log.Fatalf("Failed Kyber1024 decapsulation.")
	}

	// Test N Decaps
	decapsDurations = make([]time.Duration, N)
	for i := 0; i < N; i++ {
		startTime := time.Now()
		css, err = zkpop.DecapsKyber1024(ct, sk)
		decapsDurations[i] = time.Since(startTime)
	}
	avgD, stdDevD = calculateStats(decapsDurations)
	fmt.Printf("Tempo gasto para decapsular (Kyber1024):\n")
	fmt.Printf("  Média: %f segundos\n", avgD/float64(time.Second))
	fmt.Printf("  Desvio Padrão: %f segundos\n", stdDevD/float64(time.Second))
}

func main() {
	N := 1000
	fmt.Printf("Testing %d iterations for each algorithm...\n", N)

	//Kyber
	testKyber(N)
	testKyberNIZKPoP(N)

	fmt.Println("End of testing.")
}