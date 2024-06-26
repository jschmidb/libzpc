/*
 * zkey - Generate, re-encipher, and validate secure keys
 *
 * Copyright IBM Corp. 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "zpc/error.h"

#include <dlfcn.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_alg.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>

#include "lib/util_base.h"
#include "lib/util_libc.h"
#include "lib/util_panic.h"

#include "pkey.h"
#include "utils.h"

/**
 * Check if the specified key is a CCA AESDATA key token.
 *
 * @param[in] key           the secure key token
 * @param[in] key_size      the size of the secure key
 *
 * @returns true if the key is an CCA AESDATA token type
 */
bool is_cca_aes_data_key(const u8 *key, size_t key_size)
{
	struct tokenheader *hdr = (struct tokenheader *)key;

	if (key == NULL || key_size < AESDATA_KEY_SIZE)
		return false;

	if (hdr->type != TOKEN_TYPE_CCA_INTERNAL)
		return false;
	if (hdr->version != TOKEN_VERSION_AESDATA)
		return false;

	return true;
}

/**
 * Check if the specified key is a CCA AESCIPHER key token.
 *
 * @param[in] key           the secure key token
 * @param[in] key_size      the size of the secure key
 *
 * @returns true if the key is an CCA AESCIPHER token type
 */
bool is_cca_aes_cipher_key(const u8 *key, size_t key_size)
{
	struct aescipherkeytoken *cipherkey = (struct aescipherkeytoken *)key;

	if (key == NULL || key_size < AESCIPHER_KEY_SIZE_ENCR_V0)
		return false;

	if (cipherkey->type != TOKEN_TYPE_CCA_INTERNAL)
		return false;
	if (cipherkey->version != TOKEN_VERSION_AESCIPHER)
		return false;
	if (cipherkey->length > key_size)
		return false;

	if (cipherkey->kms != 0x03) /* key wrapped by master key */
		return false;
	if (cipherkey->kwm != 0x02) /* key wrapped using AESKW */
		return false;
	if (cipherkey->pfv != 0x00 && cipherkey->pfv != 0x01) /* V0 or V1 */
		return false;
	if (cipherkey->adv != 0x01) /* Should have ass. data sect. version 1 */
		return false;
	if (cipherkey->at != 0x02) /* Algorithm: AES */
		return false;
	if (cipherkey->kt != 0x0001) /* Key type: CIPHER */
		return false;
	if (cipherkey->adl != 26) /* Ass. data section length should be 26 */
		return false;
	if (cipherkey->kll != 0) /* Should have no key label */
		return false;
	if (cipherkey->eadl != 0) /* Should have no ext associated data */
		return false;
	if (cipherkey->uadl != 0) /* Should have no user associated data */
		return false;
	if (cipherkey->kufc != 2) /* Should have 2 KUFs */
		return false;
	if (cipherkey->kmfc != 3) /* Should have 3 KMFs */
		return false;

	return true;
}

/**
 * Check if the specified key is a CCA ECC key token.
 *
 * @param[in] key           the secure key token
 * @param[in] key_size      the size of the secure key
 *
 * @returns true if the key is an CCA ECC token type
 */
bool is_cca_ec_key(const u8 *key, size_t key_size)
{
	struct ccakeytoken *cipherkey = (struct ccakeytoken *)key;

	if (key == NULL || key_size < sizeof(struct ccakeytoken))
		return false;

	if (cipherkey->type != 0x1F) /* internal header */
		return false;
	if (cipherkey->privtok != 0x20) /* private section */
		return false;
	if (cipherkey->key_format != 0x08) /* encrypted internal EC key */
		return false;

	switch (cipherkey->curve_type) {
	case 0: /* prime */
	case 2: /* edwards */
		break;
	default:
		return false;
	}

	switch (cipherkey->p_len) {
	case 255: /* ed25519 */
	case 256: /* p256 */
	case 384: /* p384 */
	case 521: /* p521 */
	case 448: /* ed448 */
		break;
	default:
		return false;
	}

	return true;
}

/**
 * Check if the specified EP11 type 6 (TOKVER_EP11_AES_WITH_HEADER) AES key
 * token is session bound, i.e. has a non-zero session id.
 *
 * @param[in] key           the type 6 secure key token
 * @param[in] key_size      the size of the secure key
 *
 * @returns true if the key is a session-bound type 6 EP11 AES key token
 */
bool is_session_bound(const u8 *key, size_t key_size)
{
	const unsigned char null_session[32] = { 0, };

	if (!is_ep11_aes_key_with_header(key, key_size))
		return false;

	if (memcmp(key + sizeof(struct ep11kblob_header),
			null_session, sizeof(null_session)) == 0)
		return false;

	return true;
}

/**
 * Check if the specified key is a type 3 (TOKVER_EP11_AES) EP11 AES key token.
 * Type 3 keys always have their session id field overlayed by the key token
 * header, so they cannot contain a valid session id. Let's require that the
 * 2nd 16 bytes of the session id field are always zero, otherwise consider
 * the key as corrupted.
 *
 * @param[in] key           the secure key token
 * @param[in] key_size      the size of the secure key
 *
 * @returns true if the key is an EP11 AES token type
 */
bool is_ep11_aes_key(const u8 *key, size_t key_size)
{
	struct ep11keytoken *ep11key = (struct ep11keytoken *)key;
	const unsigned char nulls[16] = { 0, };

	if (key == NULL || key_size < (EP11_KEY_SIZE - sizeof(ep11key->padding)))
		return false;

	if (ep11key->head.type != TOKEN_TYPE_NON_CCA)
		return false;
	if (ep11key->head.version != TOKEN_VERSION_EP11_AES)
		return false;
	if (ep11key->head.length > key_size)
		return false;

	if (ep11key->version != EP11_STRUCT_MAGIC)
		return false;

	if (memcmp(key + 16, nulls, 16) != 0)
		return false;

	return true;
}

/*
 * Check if the specified key is a EP11 AES key token with header.
 *
 * @param[in] key           the secure key token
 * @param[in] key_size      the size of the secure key
 *
 * @returns true if the key is an EP11 AES key token with header
 */
bool is_ep11_aes_key_with_header(const u8 *key, size_t key_size)
{
	struct ep11kblob_header *hdr = (struct ep11kblob_header *)key;
	struct ep11keytoken *ep11key = (struct ep11keytoken *)(key + sizeof(struct ep11kblob_header));

	if (key_size < (sizeof(struct ep11kblob_header) + EP11_KEY_SIZE - sizeof(ep11key->padding)))
		return 0;

	if (hdr->type != TOKEN_TYPE_NON_CCA)
		return 0;
	if (hdr->hver != 0x00)
		return 0;
	if (hdr->version != TOKVER_EP11_AES_WITH_HEADER)
		return 0;
	if (hdr->len > key_size)
		return 0;
	if (hdr->len < (sizeof(struct ep11kblob_header) + EP11_KEY_SIZE - sizeof(ep11key->padding)))
		return 0;

	if (ep11key->version != EP11_STRUCT_MAGIC)
		return 0;

	return 1;
}

/**
 * Check if the specified key is an EP11 ECC key token with header
 * (TOKVER_EP11_ECC_WITH_HEADER). This means we have a 16-byte ep11kblob_header
 * followed by a ep11keytoken struct. We assume that the blob does not contain
 * a filled out ep11keytoken header in the session field.
 *
 * @param[in] key           the secure key token
 * @param[in] key_size      the size of the secure key
 *
 * @returns true if the key is an EP11 ECC token type
 */
bool is_ep11_ec_key_with_header(const u8 *key, size_t key_size)
{
	struct ep11kblob_header *ep11hdr;
	struct ep11keytoken *ep11key;

	if (key == NULL || key_size < MIN_EC_BLOB_SIZE || key_size > MAX_EC_BLOB_SIZE)
		return false;

	ep11hdr = (struct ep11kblob_header *)key;
	ep11key = (struct ep11keytoken *)(key + sizeof(struct ep11kblob_header));

	if (ep11hdr->version != TOKVER_EP11_ECC_WITH_HEADER)
		return false;

	if (ep11key->version != EP11_STRUCT_MAGIC)
		return false;

	return true;
}

/**
 * Check if the specified key is an XTS type key
 *
 * @param[in] key           the secure key token
 * @param[in] key_size      the size of the secure key
 *
 * @returns true if the key is an XTS key type
 */
bool is_xts_key(const u8 *key, size_t key_size)
{
	if (is_cca_aes_data_key(key, key_size)) {
		if (key_size == 2 * AESDATA_KEY_SIZE &&
		    is_cca_aes_data_key(key + AESDATA_KEY_SIZE,
					key_size - AESDATA_KEY_SIZE))
			return true;
	} else if (is_cca_aes_cipher_key(key, key_size)) {
		if (key_size == 2 * AESCIPHER_KEY_SIZE &&
		    is_cca_aes_cipher_key(key + AESCIPHER_KEY_SIZE,
					  key_size - AESCIPHER_KEY_SIZE))
			return true;
	} else if (is_ep11_aes_key(key, key_size)) {
		if (key_size == 2 * EP11_KEY_SIZE &&
		    is_ep11_aes_key(key + EP11_KEY_SIZE,
					  key_size - EP11_KEY_SIZE))
			return true;
	}

	return false;
}

/*
 * Returns list of napqns in apqns that match the mkvp and key type.
 * Caller takes ownership of apqns.
 * Returns 0 on success. Otherwise, an appropriate ZPC_ERROR is returned.
 */
int alloc_apqns_from_mkvp(int pkeyfd, struct pkey_apqn **apqns, size_t *napqns,
							const unsigned char mkvp[], int type)
{
	struct pkey_apqns4keytype apqns4keytype;
	int rc;

	assert(apqns != NULL);
	assert(napqns != NULL);
	assert(mkvp != NULL);

	*apqns = NULL;
	*napqns = 0;

	for (;;) {
		if (*napqns > 0) {
			*apqns = calloc(*napqns, sizeof(**apqns));
			if (*apqns == NULL) {
				rc = ZPC_ERROR_MALLOC;
				goto ret;
			}
		}

		memset(&apqns4keytype, 0, sizeof(apqns4keytype));
		apqns4keytype.type = type;
		memcpy(apqns4keytype.cur_mkvp, mkvp,
		    sizeof(apqns4keytype.cur_mkvp));
		memcpy(apqns4keytype.alt_mkvp, mkvp,
		    sizeof(apqns4keytype.alt_mkvp));
		apqns4keytype.flags = PKEY_FLAGS_MATCH_CUR_MKVP;
		apqns4keytype.apqns = *apqns;
		apqns4keytype.apqn_entries = *napqns;

		rc = ioctl(pkeyfd, PKEY_APQNS4KT, &apqns4keytype);
		if (rc && (*napqns == 0 || (*napqns > 0 && rc != ENOSPC))) {
			rc = ZPC_ERROR_IOCTLAPQNS4KT;
			goto ret;
		} else if (rc == 0 && apqns4keytype.apqn_entries == 0) {
			rc = ZPC_ERROR_APQNNOTFOUND;
			goto ret;
		} else if (rc == 0 && *napqns > 0) {
			break;
		}

		free(*apqns);
		*apqns = NULL;

		*napqns = apqns4keytype.apqn_entries;
	}
	rc = 0;
ret:
	return rc;
}

/*
 * Some ECC related utility arrays. Array index is the curve's
 * enumeration from zpc_ec_curve_t.
 */
const size_t curve2publen[] = {
	EC_PUBLEN_P256,
	EC_PUBLEN_P384,
	EC_PUBLEN_P521,
	EC_PUBLEN_ED25519,
	EC_PUBLEN_ED448
};

const size_t curve2privlen[] = {
	EC_PRIVLEN_P256,
	EC_PRIVLEN_P384,
	EC_PRIVLEN_P521,
	EC_PRIVLEN_ED25519,
	EC_PRIVLEN_ED448
};

const uint16_t curve2bitlen[] = {
	EC_BITLEN_P256,
	EC_BITLEN_P384,
	EC_BITLEN_P521,
	EC_BITLEN_ED25519,
	EC_BITLEN_ED448
};

const size_t curve2siglen[] = {
	EC_SIGLEN_P256,
	EC_SIGLEN_P384,
	EC_SIGLEN_P521,
	EC_SIGLEN_ED25519,
	EC_SIGLEN_ED448,
};

const size_t curve2puboffset[] = {
	sizeof(p256_maced_spki_t) - EC_PUBLEN_P256 - EP11_SPKI_MACLEN,
	sizeof(p384_maced_spki_t) - EC_PUBLEN_P384 - EP11_SPKI_MACLEN,
	sizeof(p521_maced_spki_t) - EC_PUBLEN_P521 - EP11_SPKI_MACLEN,
	sizeof(ed25519_maced_spki_t) - EC_PUBLEN_ED25519 - EP11_SPKI_MACLEN,
	sizeof(ed448_maced_spki_t) - EC_PUBLEN_ED448 - EP11_SPKI_MACLEN,
};

const size_t curve2macedspkilen[] = {
	sizeof(p256_maced_spki_t),
	sizeof(p384_maced_spki_t),
	sizeof(p521_maced_spki_t),
	sizeof(ed25519_maced_spki_t),
	sizeof(ed448_maced_spki_t),
};

const size_t curve2rawspkilen[] = {
	sizeof(p256_maced_spki_t) - EP11_SPKI_MACLEN,
	sizeof(p384_maced_spki_t) - EP11_SPKI_MACLEN,
	sizeof(p521_maced_spki_t) - EP11_SPKI_MACLEN,
	sizeof(ed25519_maced_spki_t) - EP11_SPKI_MACLEN,
	sizeof(ed448_maced_spki_t) - EP11_SPKI_MACLEN,
};

const u32 curve2pkey_keytype[] = {
	PKEY_KEYTYPE_ECC_P256,
	PKEY_KEYTYPE_ECC_P384,
	PKEY_KEYTYPE_ECC_P521,
	PKEY_KEYTYPE_ECC_ED25519,
	PKEY_KEYTYPE_ECC_ED448,
};
