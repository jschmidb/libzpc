/*
 * Copyright IBM Corp. 2025
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdbool.h>

#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "zpc/hmac.h"
#include "zpc/error.h"

#include "hmac_local.h"
#include "hmac_key_local.h"

#include "cpacf.h"
#include "globals.h"
#include "misc.h"
#include "debug.h"
#include "zkey/pkey.h"


static void __hmac_init(struct zpc_hmac *hmac);
static void __hmac_update_protkey(struct zpc_hmac *, u8 *);
static int __hmac_kmac_crypt(struct zpc_hmac *, u8 *, size_t, const u8 *, size_t);
static void __hmac_reset(struct zpc_hmac *);
static void __hmac_reset_state(struct zpc_hmac *);

const int hfunc2fc[] = {
	CPACF_KMAC_ENCRYPTED_SHA_224,
	CPACF_KMAC_ENCRYPTED_SHA_256,
	CPACF_KMAC_ENCRYPTED_SHA_384,
	CPACF_KMAC_ENCRYPTED_SHA_512,
};

extern const size_t hfunc2blksize[];

const char hmac_sha224_init_values[] = {
	0xC1,0x05,0x9E,0xD8,0x36,0x7C,0xD5,0x07,0x30,0x70,0xDD,0x17,
	0xF7,0x0E,0x59,0x39,0xFF,0xC0,0x0B,0x31,0x68,0x58,0x15,0x11,
	0x64,0xF9,0x8F,0xA7,0xBE,0xFA,0x4F,0xA4,
};

const char hmac_sha256_init_values[] = {
	0x6A,0x09,0xE6,0x67,0xBB,0x67,0xAE,0x85,0x3C,0x6E,0xF3,0x72,
	0xA5,0x4F,0xF5,0x3A,0x51,0x0E,0x52,0x7F,0x9B,0x05,0x68,0x8C,
	0x1F,0x83,0xD9,0xAB,0x5B,0xE0,0xCD,0x19,
};

const char hmac_sha384_init_values[] = {
	0xCB,0xBB,0x9D,0x5D,0xC1,0x05,0x9E,0xD8,0x62,0x9A,0x29,0x2A,
	0x36,0x7C,0xD5,0x07,0x91,0x59,0x01,0x5A,0x30,0x70,0xDD,0x17,
	0x15,0x2F,0xEC,0xD8,0xF7,0x0E,0x59,0x39,0x67,0x33,0x26,0x67,
	0xFF,0xC0,0x0B,0x31,0x8E,0xB4,0x4A,0x87,0x68,0x58,0x15,0x11,
	0xDB,0x0C,0x2E,0x0D,0x64,0xF9,0x8F,0xA7,0x47,0xB5,0x48,0x1D,
	0xBE,0xFA,0x4F,0xA4,
};

const char hmac_sha512_init_values[] = {
	0x6A,0x09,0xE6,0x67,0xF3,0xBC,0xC9,0x08,0xBB,0x67,0xAE,0x85,
	0x84,0xCA,0xA7,0x3B,0x3C,0x6E,0xF3,0x72,0xFE,0x94,0xF8,0x2B,
	0xA5,0x4F,0xF5,0x3A,0x5F,0x1D,0x36,0xF1,0x51,0x0E,0x52,0x7F,
	0xAD,0xE6,0x82,0xD1,0x9B,0x05,0x68,0x8C,0x2B,0x3E,0x6C,0x1F,
	0x1F,0x83,0xD9,0xAB,0xFB,0x41,0xBD,0x6B,0x5B,0xE0,0xCD,0x19,
	0x13,0x7E,0x21,0x79,
};

int zpc_hmac_alloc(struct zpc_hmac **hmac)
{
	struct zpc_hmac *new_hmac = NULL;
	int rc;

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (!hwcaps.hmac_kmac) {
		rc = ZPC_ERROR_HWCAPS;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (hmac == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	new_hmac = calloc(1, sizeof(*new_hmac));
	if (new_hmac == NULL) {
		rc = ZPC_ERROR_MALLOC;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	DEBUG("hmac context at %p: allocated", new_hmac);
	*hmac = new_hmac;
	rc = 0;
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int zpc_hmac_set_key(struct zpc_hmac *hmac, struct zpc_hmac_key *hmac_key)
{
	int rc, rv;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (!hwcaps.hmac_kmac) {
		rc = ZPC_ERROR_HWCAPS;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}
	if (hmac == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	if (hmac_key == NULL) {
		/* If another key is already set, unset it and decrease
		 * refcount. */
		DEBUG("hmac context at %p: key unset", hmac);
		__hmac_reset(hmac);
		rc = 0;
		DEBUG("return %d (%s)", rc, zpc_error_string(rc));
		return rc;
	}

	rv = pthread_mutex_lock(&hmac_key->lock);
	assert(rv == 0);

	rc = hmac_key_check(hmac_key);
	if (rc)
		goto ret;

	if (hmac->hmac_key == hmac_key) {
		__hmac_reset_state(hmac);
		DEBUG("hmac context at %p: key at %p already set", hmac, hmac_key);
		rc = 0;
		goto ret;
	}

	hmac_key->refcount++;
	DEBUG("hmac key at %p: refcount %llu", hmac_key, hmac_key->refcount);

	if (hmac->key_set) {
		/* If another key is already set, unset it and decrease  refcount. */
		DEBUG("hmac context at %p: key unset", hmac);
		__hmac_reset(hmac);
	}

	/* Set new key. */
	assert(!hmac->key_set);

	DEBUG("hmac context at %p: key at %p set, uninitialized", hmac, hmac_key);

	hmac->initialized = 0;
	hmac->hmac_key = hmac_key;
	hmac->key_set = 1;

	rc = 0;
ret:
	rv = pthread_mutex_unlock(&hmac_key->lock);
	assert(rv == 0);
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

/*
 * Valid tag lengths according to:
 * https://csrc.nist.gov/CSRC/media/Projects/
 * Cryptographic-Algorithm-Validation-Program/documents/mac/HMACVS.pdf
 */
static int is_valid_taglen(struct zpc_hmac *hmac, size_t taglen)
{
	switch (hmac->hmac_key->hfunc) {
	case ZPC_HMAC_HASHFUNC_SHA_224:
		switch (taglen) {
		case 14:
		case 16:
		case 20:
		case 24:
		case 28:
			return 1;
		}
		break;
	case ZPC_HMAC_HASHFUNC_SHA_256:
		switch (taglen) {
		case 16:
		case 24:
		case 32:
			return 1;
		}
		break;
	case ZPC_HMAC_HASHFUNC_SHA_384:
		switch (taglen) {
		case 24:
		case 32:
		case 40:
		case 48:
			return 1;
		}
		break;
	case ZPC_HMAC_HASHFUNC_SHA_512:
		switch (taglen) {
		case 32:
		case 40:
		case 48:
		case 56:
		case 64:
			return 1;
		}
		break;
	default:
		break;
	}

	return 0;
}

int zpc_hmac_sign(struct zpc_hmac *hmac, u8 * tag, size_t taglen,
		const u8 * m, size_t mlen)
{
	struct hmac_protkey *protkey;
	int rc, rv;

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		goto ret;
	}
	if (!hwcaps.hmac_kmac) {
		rc = ZPC_ERROR_HWCAPS;
		goto ret;
	}
	if (hmac == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		goto ret;
	}
	if (taglen > 0 && tag == NULL) {
		rc = ZPC_ERROR_ARG2NULL;
		goto ret;
	}
	if (!hmac->key_set) {
		rc = ZPC_ERROR_KEYNOTSET;
		goto ret;
	}
	if (tag != NULL && !is_valid_taglen(hmac, taglen)) {
		rc = ZPC_ERROR_TAGSIZE;
		goto ret;
	}

	if (!hmac->initialized) {
		__hmac_init(hmac);
	}

	if (mlen > 0 && mlen % hmac->blksize != 0 && tag == NULL) {
		rc = ZPC_ERROR_ARG5RANGE;
		goto ret;
	}

	rc = -1;

	protkey = &hmac->hmac_key->prot;

	for (;;) {

		rc = __hmac_kmac_crypt(hmac, tag, taglen, m, mlen);
		if (rc == 0) {
			break;
		} else {
			if (hmac->hmac_key->rand_protk) {
				rc = ZPC_ERROR_PROTKEYONLY;
				goto ret;
			}
			if (rc == ZPC_ERROR_WKVPMISMATCH) {
				rv = pthread_mutex_lock(&hmac->hmac_key->lock);
				assert(rv == 0);
				DEBUG
					("hmac context at %p: re-derive protected key from pvsecret ID from hmac key at %p",
					hmac, hmac->hmac_key);
				rc = hmac_key_sec2prot(hmac->hmac_key);
				__hmac_update_protkey(hmac, protkey->protkey);
				rv = pthread_mutex_unlock(&hmac->hmac_key->lock);
				assert(rv == 0);
			}
			if (rc)
				break;
		}
	}

ret:
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

int zpc_hmac_verify(struct zpc_hmac *hmac, const u8 * tag, size_t taglen,
		const u8 * m, size_t mlen)
{
	struct hmac_protkey *protkey;
	int rc, rv;
	u8 tmp[64];

	UNUSED(rv);

	if (pkeyfd < 0) {
		rc = ZPC_ERROR_DEVPKEY;
		goto ret;
	}
	if (!hwcaps.hmac_kmac) {
		rc = ZPC_ERROR_HWCAPS;
		goto ret;
	}
	if (hmac == NULL) {
		rc = ZPC_ERROR_ARG1NULL;
		goto ret;
	}
	if (taglen > 0 && tag == NULL) {
		rc = ZPC_ERROR_ARG2NULL;
		goto ret;
	}
	if (!hmac->key_set) {
		rc = ZPC_ERROR_KEYNOTSET;
		goto ret;
	}
	if (tag != NULL && !is_valid_taglen(hmac, taglen)) {
		rc = ZPC_ERROR_TAGSIZE;
		goto ret;
	}

	if (!hmac->initialized) {
		__hmac_init(hmac);
	}

	if (mlen > 0 && mlen % hmac->blksize != 0 && tag == NULL) {
		rc = ZPC_ERROR_ARG5RANGE;
		goto ret;
	}

	rc = -1;

	protkey = &hmac->hmac_key->prot;

	for (;;) {

		rc = __hmac_kmac_crypt(hmac, tag == NULL ? NULL : tmp,
					tag == NULL ? 0 : sizeof(tmp), m, mlen);
		if (rc == 0) {
			if (tag != NULL) {
				rc = memcmp_consttime(tmp, tag, taglen);
				if (rc != 0)
					rc = ZPC_ERROR_TAGMISMATCH;
			}
			break;
		} else {
			if (hmac->hmac_key->rand_protk) {
				rc = ZPC_ERROR_PROTKEYONLY;
				goto ret;
			}
			if (rc == ZPC_ERROR_WKVPMISMATCH) {
				rv = pthread_mutex_lock(&hmac->hmac_key->lock);
				assert(rv == 0);
				DEBUG
					("hmac context at %p: re-derive protected key from pvsecret ID from hmac key at %p",
					hmac, hmac->hmac_key);
				rc = hmac_key_sec2prot(hmac->hmac_key);
				__hmac_update_protkey(hmac, protkey->protkey);
				rv = pthread_mutex_unlock(&hmac->hmac_key->lock);
				assert(rv == 0);
			}
			if (rc)
				break;
		}
	}

ret:
	DEBUG("return %d (%s)", rc, zpc_error_string(rc));
	return rc;
}

void zpc_hmac_free(struct zpc_hmac **hmac)
{
	if (hmac == NULL)
		return;
	if (*hmac == NULL)
		return;

	if ((*hmac)->key_set) {
		/* Decrease hmac_key's refcount. */
		zpc_hmac_key_free(&(*hmac)->hmac_key);
		(*hmac)->key_set = 0;
	}

	__hmac_reset(*hmac);

	free(*hmac);
	*hmac = NULL;
	DEBUG("return");
}

static void __hmac_init(struct zpc_hmac *hmac)
{
	memset(&hmac->param_kmac, 0, sizeof(hmac->param_kmac));
	switch (hmac->hmac_key->hfunc) {
	case ZPC_HMAC_HASHFUNC_SHA_224:
		memcpy(&hmac->param_kmac.hmac_224_256.h, hmac_sha224_init_values,
			sizeof(hmac_sha224_init_values));
		memcpy(&hmac->param_kmac.hmac_224_256.protkey, hmac->hmac_key->prot.protkey,
			sizeof(hmac->param_kmac.hmac_224_256.protkey));
		break;
	case ZPC_HMAC_HASHFUNC_SHA_256:
		memcpy(&hmac->param_kmac.hmac_224_256.h, hmac_sha256_init_values,
			sizeof(hmac_sha256_init_values));
		memcpy(&hmac->param_kmac.hmac_224_256.protkey, hmac->hmac_key->prot.protkey,
			sizeof(hmac->param_kmac.hmac_224_256.protkey));
		break;
	case ZPC_HMAC_HASHFUNC_SHA_384:
		memcpy(&hmac->param_kmac.hmac_384_512.h, hmac_sha384_init_values,
			sizeof(hmac_sha384_init_values));
		memcpy(&hmac->param_kmac.hmac_384_512.protkey, hmac->hmac_key->prot.protkey,
			sizeof(hmac->param_kmac.hmac_384_512.protkey));
		break;
	case ZPC_HMAC_HASHFUNC_SHA_512:
		memcpy(&hmac->param_kmac.hmac_384_512.h, hmac_sha512_init_values,
			sizeof(hmac_sha512_init_values));
		memcpy(&hmac->param_kmac.hmac_384_512.protkey, hmac->hmac_key->prot.protkey,
			sizeof(hmac->param_kmac.hmac_384_512.protkey));
		break;
	}

	hmac->blksize = hfunc2blksize[hmac->hmac_key->hfunc];
	hmac->fc = hfunc2fc[hmac->hmac_key->hfunc];
	hmac->initialized = 1;
}

static void __hmac_update_protkey(struct zpc_hmac *hmac, u8 *protkey)
{
	switch (hmac->hmac_key->hfunc) {
	case ZPC_HMAC_HASHFUNC_SHA_224:
	case ZPC_HMAC_HASHFUNC_SHA_256:
		memcpy(&hmac->param_kmac.hmac_224_256.protkey, protkey,
			sizeof(hmac->param_kmac.hmac_224_256.protkey));
		break;
	case ZPC_HMAC_HASHFUNC_SHA_384:
	case ZPC_HMAC_HASHFUNC_SHA_512:
		memcpy(&hmac->param_kmac.hmac_384_512.protkey, protkey,
			sizeof(hmac->param_kmac.hmac_384_512.protkey));
		break;
	}
}

static void __update_imbl(struct zpc_hmac *hmac, long bitlen)
{
	switch (hmac->hmac_key->hfunc) {
	case ZPC_HMAC_HASHFUNC_SHA_224:
	case ZPC_HMAC_HASHFUNC_SHA_256:
		hmac->param_kmac.hmac_224_256.imbl += bitlen;
		break;
	case ZPC_HMAC_HASHFUNC_SHA_384:
	case ZPC_HMAC_HASHFUNC_SHA_512:
		hmac->param_kmac.hmac_384_512.imbl += bitlen;
		break;
	default:
		break;
	}
}

static int __hmac_kmac_crypt(struct zpc_hmac *hmac, u8 * tag, size_t taglen,
		const u8 * in, size_t inlen)
{
	int rc, cc;
	unsigned int flags = 0;

	assert(hmac != NULL);
	assert((tag != NULL) || (tag == NULL && inlen % hmac->blksize == 0));

	if (tag == NULL)
		flags |= CPACF_KMAC_IIMP;
	if (hmac->ikp)
		flags |= CPACF_KMAC_IKP;

	__update_imbl(hmac, inlen * 8);

	cc = cpacf_kmac(hmac->fc | flags, &hmac->param_kmac, in, inlen);
	assert(cc == 0 || cc == 1);
	if (cc == 1) {
		__update_imbl(hmac, -inlen * 8); /* decrease imbl for retry */
		rc = ZPC_ERROR_WKVPMISMATCH;
		goto err;
	}

	hmac->ikp = 1;

	if (tag != NULL) {
		switch (hmac->hmac_key->hfunc) {
		case ZPC_HMAC_HASHFUNC_SHA_224:
			memcpy(tag, &hmac->param_kmac.hmac_224_256.h, taglen);
			break;
		case ZPC_HMAC_HASHFUNC_SHA_256:
			memcpy(tag, &hmac->param_kmac.hmac_224_256.h, taglen);
			break;
		case ZPC_HMAC_HASHFUNC_SHA_384:
			memcpy(tag, &hmac->param_kmac.hmac_384_512.h, taglen);
			break;
		case ZPC_HMAC_HASHFUNC_SHA_512:
			memcpy(tag, &hmac->param_kmac.hmac_384_512.h, taglen);
			break;
		}
		__hmac_reset_state(hmac);
	}

	rc = 0;
err:
	return rc;
}

static void __hmac_reset(struct zpc_hmac *hmac)
{
	assert(hmac != NULL);

	__hmac_reset_state(hmac);
	memset(&hmac->param_kmac, 0, sizeof(hmac->param_kmac));

	if (hmac->hmac_key != NULL)
		zpc_hmac_key_free(&hmac->hmac_key);
	hmac->key_set = 0;

	hmac->fc = 0;
}

static void __hmac_reset_state(struct zpc_hmac *hmac)
{
	assert(hmac != NULL);

	hmac->initialized = 0;
	hmac->ikp = 0;
	memset(&hmac->param_kmac.hmac_224_256.h, 0, sizeof(hmac->param_kmac.hmac_224_256.h));
	memset(&hmac->param_kmac.hmac_224_256.imbl, 0, sizeof(hmac->param_kmac.hmac_224_256.imbl));
	memset(&hmac->param_kmac.hmac_384_512.h, 0, sizeof(hmac->param_kmac.hmac_384_512.h));
	memset(&hmac->param_kmac.hmac_384_512.imbl, 0, sizeof(hmac->param_kmac.hmac_384_512.imbl));
}
