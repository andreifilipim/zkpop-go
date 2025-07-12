cmake_minimum_required(VERSION 3.10)

project(KEM_NIZKPoP_AVX2 C)

# Set the path to the avx2 directory
set(AVX2_DIR "${CMAKE_SOURCE_DIR}/external/KEM-NIZKPoP/kyber-zkpop/avx2")

# Set common compilation flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -mavx2")
set(CMAKE_C_FLAGS_AES "${CMAKE_C_FLAGS} -maes -mbmi2")

# Source files with relative paths
set(SOURCES
    ${AVX2_DIR}/PQCgenKAT_kem.c
    ${AVX2_DIR}/shuffle.S
    ${AVX2_DIR}/speed_print.c
    ${AVX2_DIR}/symmetric-shake.c
    ${AVX2_DIR}/rejsample.c
    ${AVX2_DIR}/basemul.S
    ${AVX2_DIR}/fq.S
    ${AVX2_DIR}/invntt.S
    ${AVX2_DIR}/aes256ctr.c
    ${AVX2_DIR}/consts.c
    ${AVX2_DIR}/cpucycles.c
    ${AVX2_DIR}/indcpa.c
    ${AVX2_DIR}/kem.c
    ${AVX2_DIR}/kex.c
    ${AVX2_DIR}/randombytes.c
    ${AVX2_DIR}/reduce.h
    ${AVX2_DIR}/rng.c
    ${AVX2_DIR}/sha2.h
    ${AVX2_DIR}/symmetric.h
    ${AVX2_DIR}/verify.c
    ${AVX2_DIR}/align.h
    ${AVX2_DIR}/api.h
    ${AVX2_DIR}/cbd.c
    ${AVX2_DIR}/fips202.c
    ${AVX2_DIR}/fips202x4.c
    ${AVX2_DIR}/poly.c
    ${AVX2_DIR}/polyvec.c
    ${AVX2_DIR}/params.h
    ${AVX2_DIR}/ntt.h
    ${AVX2_DIR}/log.h
    ${AVX2_DIR}/zkpop.c
    ${AVX2_DIR}/speed_test.c
)

# Create object files
add_library(zkpop_objs OBJECT ${SOURCES})

# Specify separate compilation flags for rejsample.c and aes256ctr.c
set_source_files_properties(${AVX2_DIR}/rejsample.c PROPERTIES COMPILE_FLAGS "${CMAKE_C_FLAGS_AES}")
set_source_files_properties(${AVX2_DIR}/aes256ctr.c PROPERTIES COMPILE_FLAGS "${CMAKE_C_FLAGS_AES}")

# Create static library
add_library(libzkpop STATIC
    $<TARGET_OBJECTS:zkpop_objs>
)

# Archive static library
set_target_properties(libzkpop PROPERTIES
    OUTPUT_NAME "zkpop"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
)

add_executable(speed_test ${AVX2_DIR}/speed_test.c)
target_link_libraries(speed_test libzkpop)