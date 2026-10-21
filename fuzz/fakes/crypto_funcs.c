/*
 * Copyright 2021 Google LLC
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

// Fake corecrypto backend.
//
// The real kernel registers a populated crypto_functions_t at boot (see
// register_crypto()).  The network fuzzer does not run that path, so
// g_crypto_funcs used to be a NULL stub in stubs.c.  Several compiled
// wrappers (corecrypto_sha2.c, corecrypto_des.c,
// corecrypto_chacha20poly1305.c) dereference g_crypto_funcs -- and the
// ccdigest_info / ccmode_ecb structs it points at -- without a NULL check.
// They are reachable from a PF_KEY socket performing SADB_ADD followed by a
// matching ESP/AH packet (esp_schedule/esp_input, ah_core), which turned a
// legitimately reachable code path into a spurious NULL-deref crash and hid
// all IPsec crypto coverage.
//
// This lives in its own translation unit (rather than stubs.c) on purpose:
// pulling in <libkern/crypto/register_crypto.h> drags in the corecrypto KPI
// prototypes (cchmac_init/update/final, ccsha256_di, ...), which conflict
// with the loosely-typed catch-all stubs still provided by stubs.c.
//
// We do NOT implement real crypto here: this fuzzer exercises IPsec parsing
// and SA state machinery, not cryptographic correctness.  The fakes are the
// minimum that keeps the wrappers structurally happy: block ciphers behave as
// identity transforms, digests emit deterministic bytes, and every
// init/schedule/verify entry point reports success so processing proceeds.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <libkern/crypto/register_crypto.h>

// --- digest fakes -----------------------------------------------------------

static void
fake_ccdigest_compress(ccdigest_state_t state, size_t nblocks, const void *data)
{
	(void)state;
	(void)nblocks;
	(void)data;
}

// Matches the struct ccdigest_info::final member: fills the caller's buffer
// with deterministic bytes sized to the digest's output_size.
static void
fake_ccdigest_di_final(const struct ccdigest_info *di, ccdigest_ctx_t ctx,
    unsigned char *digest)
{
	(void)ctx;
	if (di != NULL && digest != NULL) {
		memset(digest, 0xA5, di->output_size);
	}
}

// Top-level ccdigest_{init,update,final,} function-pointer fakes.
static void
fake_ccdigest_init_fn(const struct ccdigest_info *di, ccdigest_ctx_t ctx)
{
	(void)di;
	(void)ctx;
}

static void
fake_ccdigest_update_fn(const struct ccdigest_info *di, ccdigest_ctx_t ctx,
    unsigned long len, const void *data)
{
	(void)di;
	(void)ctx;
	(void)len;
	(void)data;
}

static void
fake_ccdigest_final_fn(const struct ccdigest_info *di, ccdigest_ctx_t ctx,
    void *digest)
{
	fake_ccdigest_di_final(di, ctx, digest);
}

static void
fake_ccdigest_fn(const struct ccdigest_info *di, unsigned long len,
    const void *data, void *digest)
{
	(void)len;
	(void)data;
	if (di != NULL && digest != NULL) {
		memset(digest, 0xA5, di->output_size);
	}
}

// state_size / block_size are chosen so that ccdigest_di_size() matches the
// corresponding SHA*_CTX in sha2.h, keeping the context-fits assertions in
// corecrypto_sha2.c happy.
static const struct ccdigest_info fake_md5_di = {
	.output_size = 16,
	.state_size = 16,
	.block_size = 64,
	.oid_size = 0,
	.oid = NULL,
	.initial_state = NULL,
	.compress = fake_ccdigest_compress,
	.final = fake_ccdigest_di_final,
};

static const struct ccdigest_info fake_sha1_di = {
	.output_size = 20,
	.state_size = 20,
	.block_size = 64,
	.oid_size = 0,
	.oid = NULL,
	.initial_state = NULL,
	.compress = fake_ccdigest_compress,
	.final = fake_ccdigest_di_final,
};

static const struct ccdigest_info fake_sha256_di = {
	.output_size = CCSHA256_OUTPUT_SIZE,
	.state_size = CCSHA256_STATE_SIZE,
	.block_size = CCSHA256_BLOCK_SIZE,
	.oid_size = 0,
	.oid = NULL,
	.initial_state = NULL,
	.compress = fake_ccdigest_compress,
	.final = fake_ccdigest_di_final,
};

static const struct ccdigest_info fake_sha384_di = {
	.output_size = CCSHA384_OUTPUT_SIZE,
	.state_size = CCSHA512_STATE_SIZE,
	.block_size = CCSHA512_BLOCK_SIZE,
	.oid_size = 0,
	.oid = NULL,
	.initial_state = NULL,
	.compress = fake_ccdigest_compress,
	.final = fake_ccdigest_di_final,
};

static const struct ccdigest_info fake_sha512_di = {
	.output_size = CCSHA512_OUTPUT_SIZE,
	.state_size = CCSHA512_STATE_SIZE,
	.block_size = CCSHA512_BLOCK_SIZE,
	.oid_size = 0,
	.oid = NULL,
	.initial_state = NULL,
	.compress = fake_ccdigest_compress,
	.final = fake_ccdigest_di_final,
};

// --- block-cipher (ECB) fakes ------------------------------------------------

static int
fake_ccecb_init(const struct ccmode_ecb *ecb, ccecb_ctx *ctx,
    size_t key_nbytes, const void *key)
{
	(void)ecb;
	(void)ctx;
	(void)key_nbytes;
	(void)key;
	return 0;
}

// Identity transform: DES/3DES operate on 8-byte blocks, so copy nblocks
// blocks of 8 bytes straight through.
static int
fake_ccecb_ecb(const ccecb_ctx *ctx, size_t nblocks, const void *in, void *out)
{
	(void)ctx;
	if (in != NULL && out != NULL) {
		memmove(out, in, nblocks * 8);
	}
	return 0;
}

// A single mode works for both DES and 3DES, encrypt and decrypt: the context
// size is tiny (well under the DES*_ECB_CTX_MAX_SIZE schedule buffers) and the
// transform is identity either direction.
static const struct ccmode_ecb fake_ecb_mode = {
	.size = 8,
	.block_size = 8,
	.init = fake_ccecb_init,
	.ecb = fake_ccecb_ecb,
	.roundkey = NULL,
};

static int
fake_ccdes_key_is_weak(void *key, unsigned long length)
{
	(void)key;
	(void)length;
	return 0; // never weak
}

// --- chacha20poly1305 fakes --------------------------------------------------

static const struct ccchacha20poly1305_info fake_chacha_info_struct;

static const struct ccchacha20poly1305_info *
fake_chacha_info(void)
{
	return &fake_chacha_info_struct;
}

static int
fake_chacha_init(const struct ccchacha20poly1305_info *info,
    ccchacha20poly1305_ctx *ctx, const uint8_t *key)
{
	(void)info;
	(void)ctx;
	(void)key;
	return 0;
}

static int
fake_chacha_reset(const struct ccchacha20poly1305_info *info,
    ccchacha20poly1305_ctx *ctx)
{
	(void)info;
	(void)ctx;
	return 0;
}

static int
fake_chacha_setnonce(const struct ccchacha20poly1305_info *info,
    ccchacha20poly1305_ctx *ctx, const uint8_t *nonce)
{
	(void)info;
	(void)ctx;
	(void)nonce;
	return 0;
}

static int
fake_chacha_incnonce(const struct ccchacha20poly1305_info *info,
    ccchacha20poly1305_ctx *ctx, uint8_t *nonce)
{
	(void)info;
	(void)ctx;
	(void)nonce;
	return 0;
}

static int
fake_chacha_aad(const struct ccchacha20poly1305_info *info,
    ccchacha20poly1305_ctx *ctx, size_t nbytes, const void *aad)
{
	(void)info;
	(void)ctx;
	(void)nbytes;
	(void)aad;
	return 0;
}

static int
fake_chacha_encrypt(const struct ccchacha20poly1305_info *info,
    ccchacha20poly1305_ctx *ctx, size_t nbytes, const void *ptext, void *ctext)
{
	(void)info;
	(void)ctx;
	if (ptext != NULL && ctext != NULL) {
		memmove(ctext, ptext, nbytes);
	}
	return 0;
}

static int
fake_chacha_finalize(const struct ccchacha20poly1305_info *info,
    ccchacha20poly1305_ctx *ctx, uint8_t *tag)
{
	(void)info;
	(void)ctx;
	if (tag != NULL) {
		memset(tag, 0, 16); // poly1305 tag length
	}
	return 0;
}

static int
fake_chacha_decrypt(const struct ccchacha20poly1305_info *info,
    ccchacha20poly1305_ctx *ctx, size_t nbytes, const void *ctext, void *ptext)
{
	(void)info;
	(void)ctx;
	if (ctext != NULL && ptext != NULL) {
		memmove(ptext, ctext, nbytes);
	}
	return 0;
}

static int
fake_chacha_verify(const struct ccchacha20poly1305_info *info,
    ccchacha20poly1305_ctx *ctx, const uint8_t *tag)
{
	(void)info;
	(void)ctx;
	(void)tag;
	return 0; // report the tag as valid so decrypt processing proceeds
}

static const struct ccchacha20poly1305_fns fake_chacha_fns = {
	.info = fake_chacha_info,
	.init = fake_chacha_init,
	.reset = fake_chacha_reset,
	.setnonce = fake_chacha_setnonce,
	.incnonce = fake_chacha_incnonce,
	.aad = fake_chacha_aad,
	.encrypt = fake_chacha_encrypt,
	.finalize = fake_chacha_finalize,
	.decrypt = fake_chacha_decrypt,
	.verify = fake_chacha_verify,
};

// --- the registered crypto backend ------------------------------------------

static struct crypto_functions fake_crypto_functions = {
	.ccdigest_init_fn = fake_ccdigest_init_fn,
	.ccdigest_update_fn = fake_ccdigest_update_fn,
	.ccdigest_final_fn = fake_ccdigest_final_fn,
	.ccdigest_fn = fake_ccdigest_fn,

	.ccmd5_di = &fake_md5_di,
	.ccsha1_di = &fake_sha1_di,
	.ccsha256_di = &fake_sha256_di,
	.ccsha384_di = &fake_sha384_di,
	.ccsha512_di = &fake_sha512_di,

	.ccdes_ecb_encrypt = &fake_ecb_mode,
	.ccdes_ecb_decrypt = &fake_ecb_mode,
	.cctdes_ecb_encrypt = &fake_ecb_mode,
	.cctdes_ecb_decrypt = &fake_ecb_mode,
	.ccdes_key_is_weak_fn = fake_ccdes_key_is_weak,

	.ccchacha20poly1305_fns = &fake_chacha_fns,
};

crypto_functions_t g_crypto_funcs = &fake_crypto_functions;
