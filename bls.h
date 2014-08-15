#ifndef __BLS_H__
#define __BLS_H__

//pairing-based signatures library

#include <pbc.h>

struct bls_sys_param_s {
    pairing_ptr pairing;
    element_t g;
    int signature_length;
};
typedef struct bls_sys_param_s bls_sys_param_t[1];
typedef struct bls_sys_param_s *bls_sys_param_ptr;

struct bls_private_key_s {
    bls_sys_param_ptr param;
    element_t x;
};
typedef struct bls_private_key_s bls_private_key_t[1];
typedef struct bls_private_key_s *bls_private_key_ptr;

struct bls_public_key_s {
    bls_sys_param_ptr param;
    element_t gx;
};
typedef struct bls_public_key_s bls_public_key_t[1];
typedef struct bls_public_key_s *bls_public_key_ptr;

void bls_gen_sys_param(bls_sys_param_ptr param, pairing_ptr pairing);
void bls_clear_sys_param(bls_sys_param_ptr param);
void bls_gen(bls_public_key_ptr pk, bls_private_key_ptr sk, bls_sys_param_ptr param);
void bls_clear_public_key(bls_public_key_ptr pk);
void bls_clear_private_key(bls_private_key_ptr sk);
void bls_sign(unsigned char *sig, unsigned int hashlen, unsigned char *hash,
	bls_private_key_ptr sk);
int bls_verify(unsigned char *sig, unsigned int hashlen, unsigned char *hash,
	bls_public_key_ptr pk);

typedef struct {
    unsigned long state[5];
    unsigned long count[2];
    unsigned char buffer[64];
} SHA1_CTX;

struct hash_ctx_s {
    SHA1_CTX context;
};
typedef struct hash_ctx_s hash_ctx_t[1];
typedef struct hash_ctx_s *hash_ctx_ptr;

void hash_init(hash_ctx_t context);
void hash_update(hash_ctx_t context, unsigned char *msg, unsigned int len);
void hash_final(unsigned char *digest, hash_ctx_t context);

enum {
    hash_length = 20,
};
#endif //__BLS_H__
