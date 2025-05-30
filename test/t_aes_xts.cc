/*
 * Copyright IBM Corp. 2021
 *
 * libzpc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "testlib.h"

#include "gtest/gtest.h"
#include "zpc/aes_xts.h"
#include "zpc/error.h"

#include "aes_key_local.h"  /* de-opaquify struct zpc_aes_key */
#include "aes_xts_local.h"  /* de-opaquify struct zpc_aes_xts */

#include <json-c/json.h>
#include <stdio.h>
#include <thread>
#include <unistd.h>

static void __run_json(const char *json);

TEST(aes_xts, alloc)
{
	struct zpc_aes_xts *aes_xts;
	int rc;

	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_XTS_HW_CAPS_CHECK();

	rc = zpc_aes_xts_alloc(NULL);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	aes_xts = NULL;
	rc = zpc_aes_xts_alloc(&aes_xts);
	EXPECT_EQ(rc, 0);
	zpc_aes_xts_free(&aes_xts);
	EXPECT_EQ(aes_xts, nullptr);

	aes_xts = (struct zpc_aes_xts *)&aes_xts;
	rc = zpc_aes_xts_alloc(&aes_xts);
	EXPECT_EQ(rc, 0);
	zpc_aes_xts_free(&aes_xts);
	EXPECT_EQ(aes_xts, nullptr);
}

TEST(aes_xts, free)
{
	struct zpc_aes_xts *aes_xts;
	int rc;

	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_XTS_HW_CAPS_CHECK();

	zpc_aes_xts_free(NULL);

	aes_xts = NULL;
	zpc_aes_xts_free(&aes_xts);
	EXPECT_EQ(aes_xts, nullptr);

	rc = zpc_aes_xts_alloc(&aes_xts);
	EXPECT_EQ(rc, 0);
	zpc_aes_xts_free(&aes_xts);
	EXPECT_EQ(aes_xts, nullptr);
}

TEST(aes_xts, set_key)
{
	struct zpc_aes_key *aes_key1, *aes_key2;
	struct zpc_aes_xts *aes_xts;
	u8 clearkey1[32], clearkey2[32], iv[16];
	unsigned int flags = 0;
	const char *mkvp, *apqns[257];
	int rc, size, type;

	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_XTS_HW_CAPS_CHECK();

	size = testlib_env_aes_key_size();
	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	TESTLIB_AES_KERNEL_CAPS_CHECK(type);

	TESTLIB_AES_SW_CAPS_CHECK(type);

	TESTLIB_APQN_CAPS_CHECK(apqns, mkvp, type, size, flags);

	TESTLIB_AES_XTS_KEY_SIZE_CHECK(size);

	rc = zpc_aes_key_alloc(&aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_alloc(&aes_key2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_alloc(&aes_xts);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_set_key(aes_xts, aes_key1, aes_key2);
	EXPECT_EQ(rc, ZPC_ERROR_KEYNOTSET);

	rc = zpc_aes_key_set_size(aes_key1, size);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_type(aes_key1, type);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_aes_key_set_mkvp(aes_key1, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_aes_key_set_apqns(aes_key1, apqns);
		EXPECT_EQ(rc, 0);
	}
	rc = zpc_aes_key_set_flags(aes_key1, flags);
	EXPECT_EQ(rc, 0);

	if (type != ZPC_AES_KEY_TYPE_PVSECRET) {
		rc = zpc_aes_key_import_clear(aes_key1, clearkey1);
		EXPECT_EQ(rc, 0);
	} else {
		rc = testlib_set_aes_key_from_pvsecret(aes_key1, size);
		if (rc)
			goto ret;
	}

	rc = zpc_aes_xts_set_key(aes_xts, aes_key1, aes_key2);
	EXPECT_EQ(rc, ZPC_ERROR_KEYNOTSET);

	rc = zpc_aes_key_set_size(aes_key2, size);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_type(aes_key2, type);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_aes_key_set_mkvp(aes_key2, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_aes_key_set_apqns(aes_key2, apqns);
		EXPECT_EQ(rc, 0);
	}
	rc = zpc_aes_key_set_flags(aes_key2, flags);
	EXPECT_EQ(rc, 0);

	if (type != ZPC_AES_KEY_TYPE_PVSECRET) {
		rc = zpc_aes_key_import_clear(aes_key2, clearkey2);
		EXPECT_EQ(rc, 0);
	} else {
		rc = testlib_set_aes_key_from_pvsecret(aes_key2, size);
		if (rc)
			goto ret;
	}

	rc = zpc_aes_xts_set_key(NULL, NULL, NULL);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_aes_xts_set_key(NULL, aes_key1, aes_key2);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	rc = zpc_aes_xts_set_key(aes_xts, NULL, NULL);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_set_iv(aes_xts, iv);
	EXPECT_EQ(rc, ZPC_ERROR_KEYNOTSET);
	rc = zpc_aes_xts_set_key(aes_xts, aes_key1, aes_key2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_set_iv(aes_xts, iv);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_set_key(aes_xts, aes_key2, aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_set_iv(aes_xts, iv);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_set_key(aes_xts, aes_key1, NULL);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_set_key(aes_xts, NULL, aes_key1);
	EXPECT_EQ(rc, 0);

ret:
	zpc_aes_xts_free(&aes_xts);
	EXPECT_EQ(aes_xts, nullptr);
	zpc_aes_key_free(&aes_key1);
	EXPECT_EQ(aes_key1, nullptr);
	zpc_aes_key_free(&aes_key2);
	EXPECT_EQ(aes_key2, nullptr);
}

TEST(aes_xts, set_iv)
{
	struct zpc_aes_key *aes_key1, *aes_key2;
	struct zpc_aes_xts *aes_xts;
	const char *mkvp, *apqns[257];
	u8 iv[16];
	int rc, size, type;
	unsigned int flags;

	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_XTS_HW_CAPS_CHECK();

	size = testlib_env_aes_key_size();
	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	TESTLIB_AES_KERNEL_CAPS_CHECK(type);

	TESTLIB_AES_SW_CAPS_CHECK(type);

	TESTLIB_APQN_CAPS_CHECK(apqns, mkvp, type, size, flags);

	TESTLIB_AES_XTS_KEY_SIZE_CHECK(size);

	rc = zpc_aes_key_alloc(&aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_alloc(&aes_key2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_alloc(&aes_xts);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_set_iv(NULL, NULL);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);
	rc = zpc_aes_xts_set_iv(NULL, iv);
	EXPECT_EQ(rc, ZPC_ERROR_ARG1NULL);

	rc = zpc_aes_xts_set_iv(aes_xts, NULL);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_set_iv(aes_xts, iv);
	EXPECT_EQ(rc, ZPC_ERROR_KEYNOTSET);

	rc = zpc_aes_key_set_size(aes_key1, size);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_type(aes_key1, type);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_flags(aes_key1, flags);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_aes_key_set_mkvp(aes_key1, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_aes_key_set_apqns(aes_key1, apqns);
		EXPECT_EQ(rc, 0);
	}

	if (type != ZPC_AES_KEY_TYPE_PVSECRET) {
		rc = zpc_aes_key_generate(aes_key1);
		EXPECT_EQ(rc, 0);
	} else {
		rc = testlib_set_aes_key_from_pvsecret(aes_key1, size);
		if (rc)
			goto ret;
	}

	rc = zpc_aes_key_set_size(aes_key2, size);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_type(aes_key2, type);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_flags(aes_key2, flags);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_aes_key_set_mkvp(aes_key2, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_aes_key_set_apqns(aes_key2, apqns);
		EXPECT_EQ(rc, 0);
	}

	if (type != ZPC_AES_KEY_TYPE_PVSECRET) {
		rc = zpc_aes_key_generate(aes_key2);
		EXPECT_EQ(rc, 0);
	} else {
		rc = testlib_set_aes_key_from_pvsecret(aes_key2, size);
		if (rc)
			goto ret;
	}

	rc = zpc_aes_xts_set_iv(aes_xts, iv);
	EXPECT_EQ(rc, ZPC_ERROR_KEYNOTSET);

	rc = zpc_aes_xts_set_key(aes_xts, aes_key1, aes_key2);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_set_iv(aes_xts, iv);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_set_iv(aes_xts, iv);
	EXPECT_EQ(rc, 0);

ret:
	zpc_aes_xts_free(&aes_xts);
	EXPECT_EQ(aes_xts, nullptr);
	zpc_aes_key_free(&aes_key1);
	EXPECT_EQ(aes_key1, nullptr);
	zpc_aes_key_free(&aes_key2);
	EXPECT_EQ(aes_key2, nullptr);
}

TEST(aes_xts, encrypt)
{
	struct zpc_aes_key *aes_key1, *aes_key2;
	struct zpc_aes_xts *aes_xts;
	const char *mkvp, *apqns[257];
	u8 iv[16], m[64], c[64];
	unsigned int flags;
	int rc, size, type;

	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_XTS_HW_CAPS_CHECK();

	size = testlib_env_aes_key_size();
	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	TESTLIB_AES_KERNEL_CAPS_CHECK(type);

	TESTLIB_AES_SW_CAPS_CHECK(type);

	TESTLIB_APQN_CAPS_CHECK(apqns, mkvp, type, size, flags);

	TESTLIB_AES_XTS_KEY_SIZE_CHECK(size);

	rc = zpc_aes_key_alloc(&aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_alloc(&aes_key2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_alloc(&aes_xts);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_set_type(aes_key1, type);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_aes_key_set_mkvp(aes_key1, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_aes_key_set_apqns(aes_key1, apqns);
		EXPECT_EQ(rc, 0);
	}
	rc = zpc_aes_key_set_size(aes_key1, size);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_flags(aes_key1, flags);
	EXPECT_EQ(rc, 0);

	if (type != ZPC_AES_KEY_TYPE_PVSECRET) {
		rc = zpc_aes_key_generate(aes_key1);
		EXPECT_EQ(rc, 0);
	} else {
		rc = testlib_set_aes_key_from_pvsecret(aes_key1, size);
		if (rc)
			goto ret;
	}

	rc = zpc_aes_key_set_type(aes_key2, type);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_aes_key_set_mkvp(aes_key2, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_aes_key_set_apqns(aes_key2, apqns);
		EXPECT_EQ(rc, 0);
	}
	rc = zpc_aes_key_set_size(aes_key2, size);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_flags(aes_key2, flags);
	EXPECT_EQ(rc, 0);

	if (type != ZPC_AES_KEY_TYPE_PVSECRET) {
		rc = zpc_aes_key_generate(aes_key2);
		EXPECT_EQ(rc, 0);
	} else {
		rc = testlib_set_aes_key_from_pvsecret(aes_key2, size);
		if (rc)
			goto ret;
	}

	rc = zpc_aes_xts_set_key(aes_xts, aes_key1, aes_key2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_set_iv(aes_xts, iv);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_encrypt(aes_xts, c, m, 64);
	EXPECT_EQ(rc, 0);

ret:
	zpc_aes_xts_free(&aes_xts);
	EXPECT_EQ(aes_xts, nullptr);
	zpc_aes_key_free(&aes_key1);
	EXPECT_EQ(aes_key1, nullptr);
	zpc_aes_key_free(&aes_key2);
	EXPECT_EQ(aes_key2, nullptr);
}

TEST(aes_xts, decrypt)
{
	struct zpc_aes_key *aes_key1, *aes_key2;
	struct zpc_aes_xts *aes_xts;
	const char *mkvp, *apqns[257];
	u8 iv[16], m[64], c[64];
	unsigned int flags;
	int rc, size, type;

	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_XTS_HW_CAPS_CHECK();

	size = testlib_env_aes_key_size();
	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	TESTLIB_AES_KERNEL_CAPS_CHECK(type);

	TESTLIB_AES_SW_CAPS_CHECK(type);

	TESTLIB_APQN_CAPS_CHECK(apqns, mkvp, type, size, flags);

	TESTLIB_AES_XTS_KEY_SIZE_CHECK(size);

	rc = zpc_aes_key_alloc(&aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_alloc(&aes_key2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_alloc(&aes_xts);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_set_type(aes_key1, type);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_aes_key_set_mkvp(aes_key1, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_aes_key_set_apqns(aes_key1, apqns);
		EXPECT_EQ(rc, 0);
	}
	rc = zpc_aes_key_set_size(aes_key1, size);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_flags(aes_key1, flags);
	EXPECT_EQ(rc, 0);

	if (type != ZPC_AES_KEY_TYPE_PVSECRET) {
		rc = zpc_aes_key_generate(aes_key1);
		EXPECT_EQ(rc, 0);
	} else {
		rc = testlib_set_aes_key_from_pvsecret(aes_key1, size);
		if (rc)
			goto ret;
	}

	rc = zpc_aes_key_set_type(aes_key2, type);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_aes_key_set_mkvp(aes_key2, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_aes_key_set_apqns(aes_key2, apqns);
		EXPECT_EQ(rc, 0);
	}
	rc = zpc_aes_key_set_size(aes_key2, size);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_flags(aes_key2, flags);
	EXPECT_EQ(rc, 0);

	if (type != ZPC_AES_KEY_TYPE_PVSECRET) {
		rc = zpc_aes_key_generate(aes_key2);
		EXPECT_EQ(rc, 0);
	} else {
		rc = testlib_set_aes_key_from_pvsecret(aes_key2, size);
		if (rc)
			goto ret;
	}

	rc = zpc_aes_xts_set_key(aes_xts, aes_key1, aes_key2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_set_iv(aes_xts, iv);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_decrypt(aes_xts, m, c, 64);
	EXPECT_EQ(rc, 0);

ret:
	zpc_aes_xts_free(&aes_xts);
	EXPECT_EQ(aes_xts, nullptr);
	zpc_aes_key_free(&aes_key1);
	EXPECT_EQ(aes_key1, nullptr);
	zpc_aes_key_free(&aes_key2);
	EXPECT_EQ(aes_key2, nullptr);
}

TEST(aes_xts, pc)
{
	struct zpc_aes_key *aes_key1, *aes_key2;
	struct zpc_aes_xts *aes_xts1, *aes_xts2;
	const char *mkvp, *apqns[257];
	u8 iv[16], m[96], c[96], key[32], m_bak[96];
	unsigned int flags;
	int rc, size, type;

	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_XTS_HW_CAPS_CHECK();

	size = testlib_env_aes_key_size();
	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	TESTLIB_AES_KERNEL_CAPS_CHECK(type);

	TESTLIB_AES_SW_CAPS_CHECK(type);

	TESTLIB_APQN_CAPS_CHECK(apqns, mkvp, type, size, flags);

	TESTLIB_AES_XTS_KEY_SIZE_CHECK(size);

	memcpy(m_bak, m, 96);

	rc = zpc_aes_key_alloc(&aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_alloc(&aes_key2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_alloc(&aes_xts1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_alloc(&aes_xts2);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_set_size(aes_key1, size);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_type(aes_key1, type);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_aes_key_set_mkvp(aes_key1, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_aes_key_set_apqns(aes_key1, apqns);
		EXPECT_EQ(rc, 0);
	}
	rc = zpc_aes_key_set_flags(aes_key1, flags);
	EXPECT_EQ(rc, 0);

	if (type != ZPC_AES_KEY_TYPE_PVSECRET) {
		rc = zpc_aes_key_import_clear(aes_key1, key);
		EXPECT_EQ(rc, 0);
	} else {
		rc = testlib_set_aes_key_from_pvsecret(aes_key1, size);
		if (rc)
			goto ret;
	}

	rc = zpc_aes_key_set_size(aes_key2, size);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_type(aes_key2, type);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_aes_key_set_mkvp(aes_key2, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_aes_key_set_apqns(aes_key2, apqns);
		EXPECT_EQ(rc, 0);
	}
	rc = zpc_aes_key_set_flags(aes_key2, flags);
	EXPECT_EQ(rc, 0);

	if (type != ZPC_AES_KEY_TYPE_PVSECRET) {
		rc = zpc_aes_key_import_clear(aes_key2, key);
		EXPECT_EQ(rc, 0);
	} else {
		rc = testlib_set_aes_key_from_pvsecret(aes_key2, size);
		if (rc)
			goto ret;
	}

	rc = zpc_aes_xts_set_key(aes_xts1, aes_key1, aes_key2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_set_iv(aes_xts1, iv);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_set_key(aes_xts2, aes_key1, aes_key2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_set_iv(aes_xts2, iv);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_encrypt(aes_xts1, c, m, 96);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_decrypt(aes_xts2, m, c, 96);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(m, m_bak, 96) == 0);
	rc = zpc_aes_xts_encrypt(aes_xts2, c, m, 96);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_decrypt(aes_xts1, m, c, 96);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(m, m_bak, 96) == 0);

	rc = zpc_aes_xts_encrypt(aes_xts2, c,  m, 96);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_decrypt(aes_xts1, m, c, 96);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(m, m_bak, 96) == 0);
	rc = zpc_aes_xts_encrypt(aes_xts1, c, m, 96);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_decrypt(aes_xts2, m, c, 96);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(m, m_bak, 96) == 0);

	/* Random protected key */
	rc = zpc_aes_xts_set_key(aes_xts1, NULL, NULL);   /* Unset key. */
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_set_key(aes_xts2, NULL, NULL);   /* Unset key. */
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_mkvp(aes_key1, NULL);   /* Unset apqns. */
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_mkvp(aes_key2, NULL);   /* Unset apqns. */
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_size(aes_key1, size);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_size(aes_key2, size);
	EXPECT_EQ(rc, 0);

	if (type != ZPC_AES_KEY_TYPE_PVSECRET) {
		rc = zpc_aes_key_generate(aes_key1);
		EXPECT_EQ(rc, 0);
		rc = zpc_aes_key_generate(aes_key2);
		EXPECT_EQ(rc, 0);
	} else {
		rc = testlib_set_aes_key_from_pvsecret(aes_key1, size);
		rc += testlib_set_aes_key_from_pvsecret(aes_key2, size);
		if (rc)
			goto ret;
	}

	rc = zpc_aes_xts_set_key(aes_xts1, aes_key1, aes_key2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_set_iv(aes_xts1, iv);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_set_key(aes_xts2, aes_key1, aes_key2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_set_iv(aes_xts2, iv);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_encrypt(aes_xts1, c, m, 96);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_decrypt(aes_xts2, m, c, 96);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(m, m_bak, 96) == 0);
	rc = zpc_aes_xts_encrypt(aes_xts2, c, m, 96);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_decrypt(aes_xts1, m, c, 96);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(m, m_bak, 96) == 0);

	rc = zpc_aes_xts_encrypt(aes_xts2, c, m, 96);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_decrypt(aes_xts1, m, c, 96);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(m, m_bak, 96) == 0);
	rc = zpc_aes_xts_encrypt(aes_xts1, c, m, 96);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_decrypt(aes_xts2, m, c, 96);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(m, m_bak, 96) == 0);

ret:
	zpc_aes_xts_free(&aes_xts2);
	zpc_aes_xts_free(&aes_xts1);
	zpc_aes_key_free(&aes_key2);
	EXPECT_EQ(aes_key2, nullptr);
	zpc_aes_key_free(&aes_key1);
	EXPECT_EQ(aes_key1, nullptr);
}

TEST(aes_xts, stream_inplace_kat1)
{
	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_XTS_HW_CAPS_CHECK();

	size_t keylen, msglen, ctlen, ivlen;
	unsigned char buf[4096];
	const char *mkvp, *apqns[257];
	struct zpc_aes_key *aes_key1, *aes_key2;
	struct zpc_aes_xts *aes_xts;
	unsigned int flags;
	int type, rc;

	const char *keystr = "88dfd7c83cb121968feb417520555b36c0f63b662570eac12ea96cbe188ad5b1a44db23ac6470316cba0041cadf248f6d9a7713f454e663f3e3987585cebbf96";
	const char *ivstr = "0ee84632b838dd528f1d96c76439805c";
	const char *msgstr = "ec36551c70efcdf85de7a39988978263ad261e83996dad219a0058e02187384f2d0754ff9cfa000bec448fafd2cfa738";
	const char *ctstr = "a55d533c9c5885562b92d4582ea69db8e2ba9c0b967a9f0167700b043525a47bafe7d630774eaf4a1dc9fbcf94a1fda4";

	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	TESTLIB_AES_KERNEL_CAPS_CHECK(type);

	TESTLIB_AES_SW_CAPS_CHECK(type);

	TESTLIB_APQN_CAPS_CHECK(apqns, mkvp, type, 256, flags);

	if (type == ZPC_AES_KEY_TYPE_PVSECRET)
		GTEST_SKIP_("Skipping stream_inplace_kat1 test. KATs cannot be performed with UV secrets.");

	u8 *key1 = testlib_hexstr2buf(keystr, &keylen);
	ASSERT_NE(key1, nullptr);
	keylen /= 2;
	u8 *key2 = key1 + keylen;
	u8 *iv = testlib_hexstr2buf(ivstr, &ivlen);
	ASSERT_NE(iv, nullptr);
	u8 *msg = testlib_hexstr2buf(msgstr, &msglen);
	ASSERT_NE(msg, nullptr);
	u8 *ct = testlib_hexstr2buf(ctstr, &ctlen);
	ASSERT_NE(ct, nullptr);

	rc = zpc_aes_key_alloc(&aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_alloc(&aes_key2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_alloc(&aes_xts);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_set_type(aes_key1, type);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_aes_key_set_mkvp(aes_key1, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_aes_key_set_apqns(aes_key1, apqns);
		EXPECT_EQ(rc, 0);
	}
	rc = zpc_aes_key_set_flags(aes_key1, flags);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_size(aes_key1, keylen * 8);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_import_clear(aes_key1, key1);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_set_type(aes_key2, type);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_aes_key_set_mkvp(aes_key2, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_aes_key_set_apqns(aes_key2, apqns);
		EXPECT_EQ(rc, 0);
	}
	rc = zpc_aes_key_set_flags(aes_key2, flags);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_size(aes_key2, keylen * 8);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_import_clear(aes_key2, key2);
	EXPECT_EQ(rc, 0);

	/* Encrypt */
	memcpy(buf, msg, msglen);

	rc = zpc_aes_xts_set_key(aes_xts, aes_key1, aes_key2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_set_iv(aes_xts, iv);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_encrypt(aes_xts, buf, buf, 16);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_encrypt(aes_xts, buf + 16, buf + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, ct, ctlen) == 0);

	/* Encrypt */
	memcpy(buf, msg, msglen);

	rc = zpc_aes_xts_set_key(aes_xts, aes_key1, aes_key2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_set_iv(aes_xts, iv);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_encrypt(aes_xts, buf, buf, 16);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_encrypt(aes_xts, buf + 16, buf + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, ct, ctlen) == 0);

	/* Decrypt */
	memcpy(buf, ct, ctlen);

	rc = zpc_aes_xts_set_iv(aes_xts, iv);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_decrypt(aes_xts, buf, buf, 16);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_decrypt(aes_xts, buf + 16, buf + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);

	/* Decrypt */
	memcpy(buf, ct, ctlen);

	rc = zpc_aes_xts_set_iv(aes_xts, iv);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_decrypt(aes_xts, buf, buf, 16);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_decrypt(aes_xts, buf + 16, buf + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);

	zpc_aes_xts_free(&aes_xts);
	EXPECT_EQ(aes_xts, nullptr);
	zpc_aes_key_free(&aes_key1);
	EXPECT_EQ(aes_key1, nullptr);
	zpc_aes_key_free(&aes_key2);
	EXPECT_EQ(aes_key2, nullptr);

	free(key1);
	free(iv);
	free(msg);
	free(ct);
}

TEST(aes_xts, stream_inplace_kat2)
{
	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_XTS_HW_CAPS_CHECK();

	size_t keylen, ivlen, msglen, ctlen;
	unsigned char buf[4096];
	const char *mkvp, *apqns[257];
	struct zpc_aes_key *aes_key1, *aes_key2;
	struct zpc_aes_xts *aes_xts;
	unsigned int flags;
	int type, rc;

	const char *keystr = "394c97881abd989d29c703e48a72b397a7acf51b59649eeea9b33274d8541df4";
	const char *ivstr = "4b15c684a152d485fe9937d39b168c29";
	const char *msgstr = "2f3b9dcfbae729583b1d1ffdd16bb6fe2757329435662a78f0";
	const char *ctstr = "f3473802e38a3ffef4d4fb8e6aa266ebde553a64528a06463e";

	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	TESTLIB_AES_KERNEL_CAPS_CHECK(type);

	TESTLIB_AES_SW_CAPS_CHECK(type);

	TESTLIB_APQN_CAPS_CHECK(apqns, mkvp, type, 128, flags);

	if (type == ZPC_AES_KEY_TYPE_PVSECRET)
		GTEST_SKIP_("Skipping stream_inplace_kat2 test. KATs cannot be performed with UV secrets.");

	u8 *key1 = testlib_hexstr2buf(keystr, &keylen);
	ASSERT_NE(key1, nullptr);
	keylen /= 2;
	u8 *key2 = key1 + keylen;
	u8 *iv = testlib_hexstr2buf(ivstr, &ivlen);
	ASSERT_NE(iv, nullptr);
	u8 *msg = testlib_hexstr2buf(msgstr, &msglen);
	ASSERT_NE(msg, nullptr);
	u8 *ct = testlib_hexstr2buf(ctstr, &ctlen);
	ASSERT_NE(ct, nullptr);

	rc = zpc_aes_key_alloc(&aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_alloc(&aes_key2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_alloc(&aes_xts);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_set_type(aes_key1, type);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_aes_key_set_mkvp(aes_key1, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_aes_key_set_apqns(aes_key1, apqns);
		EXPECT_EQ(rc, 0);
	}
	rc = zpc_aes_key_set_flags(aes_key1, flags);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_size(aes_key1, keylen * 8);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_import_clear(aes_key1, key1);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_set_type(aes_key2, type);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_aes_key_set_mkvp(aes_key2, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_aes_key_set_apqns(aes_key2, apqns);
		EXPECT_EQ(rc, 0);
	}
	rc = zpc_aes_key_set_flags(aes_key2, flags);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_size(aes_key2, keylen * 8);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_import_clear(aes_key2, key2);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_set_key(aes_xts, aes_key1, aes_key2);
	EXPECT_EQ(rc, 0);

	/* Encrypt */
	memcpy(buf, msg, msglen);

	rc = zpc_aes_xts_set_iv(aes_xts, iv);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_encrypt(aes_xts, buf, buf, msglen);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, ct, ctlen) == 0);

	/* Decrypt */
	memcpy(buf, ct, ctlen);

	rc = zpc_aes_xts_set_iv(aes_xts, iv);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_decrypt(aes_xts, buf, buf, ctlen);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);

	zpc_aes_xts_free(&aes_xts);
	EXPECT_EQ(aes_xts, nullptr);
	zpc_aes_key_free(&aes_key1);
	EXPECT_EQ(aes_key1, nullptr);
	zpc_aes_key_free(&aes_key2);
	EXPECT_EQ(aes_key2, nullptr);

	free(key1);
	free(iv);
	free(msg);
	free(ct);
}

TEST(aes_xts, stream_inplace_kat3)
{
	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_XTS_HW_CAPS_CHECK();

	size_t keylen, ivlen, msglen, ctlen;
	unsigned char buf[4096], iv2[16];
	const char *mkvp, *apqns[257];
	struct zpc_aes_key *aes_key1, *aes_key2;
	struct zpc_aes_xts *aes_xts1, *aes_xts2;
	unsigned int flags;
	int type, rc, size, i;

	const char *keystr[] = {
		"63f36e9c397c6523c99f1644ecb1a5d9bc0f2f55fbe324444c390fae752ad4d7",
		"88dfd7c83cb121968feb417520555b36c0f63b662570eac12ea96cbe188ad5b1a44db23ac6470316cba0041cadf248f6d9a7713f454e663f3e3987585cebbf96",
	};
	const char *ivstr[] = {
		"cdb1bd3486f353cc160a840beadf0329",
		"0ee84632b838dd528f1d96c76439805c",
	};
	const char *msgstr[] = {
		"9a0149888bf76160a81428bc9140eccd26ed18368e24d49b9cc512929a88ad1e66c763f4f56b63bb9dd9508c5d4df465",
		"ec36551c70efcdf85de7a39988978263ad261e83996dad219a0058e02187384f2d0754ff9cfa000bec448fafd2cfa738",
	};
	const char *ctstr[] = {
		"0eeef28ca159b805f5c215610551678ab772f279374fb140ab550768db42cf6cb73637641934195ffc08cf5a9188b82b",
		"a55d533c9c5885562b92d4582ea69db8e2ba9c0b967a9f0167700b043525a47bafe7d630774eaf4a1dc9fbcf94a1fda4",
	};

	size = testlib_env_aes_key_size();
	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	TESTLIB_AES_KERNEL_CAPS_CHECK(type);

	TESTLIB_AES_SW_CAPS_CHECK(type);

	TESTLIB_APQN_CAPS_CHECK(apqns, mkvp, type, 256, flags);

	TESTLIB_AES_XTS_KEY_SIZE_CHECK(size);

	if (type == ZPC_AES_KEY_TYPE_PVSECRET)
		GTEST_SKIP_("Skipping stream_inplace_kat3 test. KATs cannot be performed with UV secrets.");

	i = size == 128 ? 0 : 1;

	u8 *key1 = testlib_hexstr2buf(keystr[i], &keylen);
	ASSERT_NE(key1, nullptr);
	keylen /= 2;
	u8 *key2 = key1 + keylen;
	u8 *iv = testlib_hexstr2buf(ivstr[i], &ivlen);
	ASSERT_NE(iv, nullptr);
	u8 *msg = testlib_hexstr2buf(msgstr[i], &msglen);
	ASSERT_NE(msg, nullptr);
	u8 *ct = testlib_hexstr2buf(ctstr[i], &ctlen);
	ASSERT_NE(ct, nullptr);

	rc = zpc_aes_key_alloc(&aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_alloc(&aes_key2);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_alloc(&aes_xts1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_alloc(&aes_xts2);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_set_type(aes_key1, type);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_aes_key_set_mkvp(aes_key1, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_aes_key_set_apqns(aes_key1, apqns);
		EXPECT_EQ(rc, 0);
	}
	rc = zpc_aes_key_set_flags(aes_key1, flags);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_size(aes_key1, keylen * 8);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_import_clear(aes_key1, key1);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_set_type(aes_key2, type);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_aes_key_set_mkvp(aes_key2, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_aes_key_set_apqns(aes_key2, apqns);
		EXPECT_EQ(rc, 0);
	}
	rc = zpc_aes_key_set_flags(aes_key2, flags);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_size(aes_key2, keylen * 8);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_import_clear(aes_key2, key2);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_set_key(aes_xts1, aes_key1, aes_key2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_set_key(aes_xts2, aes_key1, aes_key2);
	EXPECT_EQ(rc, 0);

	/* Encrypt first chunk with first ctx */
	memcpy(buf, msg, msglen);
	rc = zpc_aes_xts_set_iv(aes_xts1, iv);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_encrypt(aes_xts1, buf, buf, 16);
	EXPECT_EQ(rc, 0);

	/* Get intermediate iv from first ctx */
	rc = zpc_aes_xts_get_intermediate_iv(aes_xts1, iv2);
	EXPECT_EQ(rc, 0);

	/* Encrypt a 2nd chunk with 2nd ctx */
	rc = zpc_aes_xts_set_iv(aes_xts2, iv);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_set_intermediate_iv(aes_xts2, iv2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_encrypt(aes_xts2, buf + 16, buf + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, ct, msglen) == 0);

	/* Decrypt first chunk with first ctx */
	memcpy(buf, ct, ctlen);
	rc = zpc_aes_xts_set_iv(aes_xts1, iv);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_decrypt(aes_xts1, buf, buf, 16);
	EXPECT_EQ(rc, 0);

	/* Get intermediate iv from first ctx */
	rc = zpc_aes_xts_get_intermediate_iv(aes_xts1, iv2);
	EXPECT_EQ(rc, 0);

	/* Decrypt remaining chunk with 2nd ctx */
	rc = zpc_aes_xts_set_iv(aes_xts2, iv);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_set_intermediate_iv(aes_xts2, iv2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_decrypt(aes_xts2, buf + 16, buf + 16, msglen - 16);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);

	zpc_aes_xts_free(&aes_xts1);
	EXPECT_EQ(aes_xts1, nullptr);
	zpc_aes_xts_free(&aes_xts2);
	EXPECT_EQ(aes_xts2, nullptr);
	zpc_aes_key_free(&aes_key1);
	EXPECT_EQ(aes_key1, nullptr);
	zpc_aes_key_free(&aes_key2);
	EXPECT_EQ(aes_key2, nullptr);

	free(key1);
	free(iv);
	free(msg);
	free(ct);
}

TEST(aes_xts, nist_kat)
{
	int type;

	type = testlib_env_aes_key_type();

	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_XTS_HW_CAPS_CHECK();

	TESTLIB_AES_KERNEL_CAPS_CHECK(type);

	TESTLIB_AES_SW_CAPS_CHECK(type);

	if (type == ZPC_AES_KEY_TYPE_PVSECRET)
		GTEST_SKIP_("Skipping nist_kat test. KATs cannot be performed with UV secrets.");

	__run_json("nist_aes_xts.json");
}

static void __run_json(const char *json)
{
	const char *tv = json, *str;
	const char *mkvp, *apqns[257];
	struct zpc_aes_key *aes_key1, *aes_key2;
	struct zpc_aes_xts *aes_xts;
	unsigned int flags;
	u8 *key1 = NULL, *key2 = NULL, *iv = NULL;
	u8 *pt = NULL, *pt_out = NULL, *ct = NULL, *ct_out = NULL;
	int rc, keysize = 0;
	size_t ptlen, ctlen, i, j, max;
	json_object *jkey, *jiv, *jmsg, *jct, *jtmp, *jtestgroups, *jfile, *jkeysize, *jtests;
	json_bool b;
	int type;

	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	TESTLIB_AES_SW_CAPS_CHECK(type);

	TESTLIB_APQN_CAPS_CHECK(apqns, mkvp, type, 256, flags);

	rc = zpc_aes_key_alloc(&aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_alloc(&aes_key2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_alloc(&aes_xts);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_set_type(aes_key1, type);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_aes_key_set_mkvp(aes_key1, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_aes_key_set_apqns(aes_key1, apqns);
		EXPECT_EQ(rc, 0);
	}
	rc = zpc_aes_key_set_flags(aes_key1, flags);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_set_type(aes_key2, type);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_aes_key_set_mkvp(aes_key2, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_aes_key_set_apqns(aes_key2, apqns);
		EXPECT_EQ(rc, 0);
	}
	rc = zpc_aes_key_set_flags(aes_key2, flags);
	EXPECT_EQ(rc, 0);

	jfile = json_object_from_file(tv);
	ASSERT_NE(jfile, nullptr);

	b = json_object_object_get_ex(jfile, "testGroups", &jtestgroups);
	ASSERT_TRUE(b);

	for (i = 0; i < (size_t)json_object_array_length(jtestgroups); i++) {
		jtmp = json_object_array_get_idx(jtestgroups, i);
		ASSERT_NE(jtmp, nullptr);

		b = json_object_object_get_ex(jtmp, "keySize", &jkeysize);
		ASSERT_TRUE(b);
		b = json_object_object_get_ex(jtmp, "tests", &jtests);
		ASSERT_TRUE(b);

		keysize = json_object_get_int(jkeysize);

		rc = zpc_aes_key_set_size(aes_key1, keysize);
		EXPECT_EQ(rc, 0);
		rc = zpc_aes_key_set_size(aes_key2, keysize);
		EXPECT_EQ(rc, 0);

		for (j = 0; j < (size_t)json_object_array_length(jtests); j++) {
			jtmp = json_object_array_get_idx(jtests, j);
			ASSERT_NE(jtmp, nullptr);

			b = json_object_object_get_ex(jtmp, "key", &jkey);
			ASSERT_TRUE(b);
			b = json_object_object_get_ex(jtmp, "iv", &jiv);
			ASSERT_TRUE(b);
			b = json_object_object_get_ex(jtmp, "msg", &jmsg);
			ASSERT_TRUE(b);
			b = json_object_object_get_ex(jtmp, "ct", &jct);
			ASSERT_TRUE(b);

			str = json_object_get_string(jkey);
			ASSERT_NE(str, nullptr);
			key1 = testlib_hexstr2buf(str, NULL);
			ASSERT_NE(key1, nullptr);
			key2 = key1 + (keysize / 8);
			str = json_object_get_string(jiv);
			ASSERT_NE(str, nullptr);
			iv = testlib_hexstr2buf(str, NULL);
			str = json_object_get_string(jmsg);
			ASSERT_NE(str, nullptr);
			pt = testlib_hexstr2buf(str, &ptlen);
			str = json_object_get_string(jct);
			ASSERT_NE(str, nullptr);
			ct = testlib_hexstr2buf(str, &ctlen);

			max = ptlen > ctlen ? ptlen : ctlen;

			pt_out = NULL;
			ct_out = NULL;
			if (max > 0) {
				pt_out = (unsigned char *)calloc(1, max);
				ASSERT_NE(pt_out, nullptr);
				ct_out = (unsigned char *)calloc(1, max);
				ASSERT_NE(ct_out, nullptr);
			}

			rc = zpc_aes_key_import_clear(aes_key1, key1);
			EXPECT_EQ(rc, 0);
			rc = zpc_aes_key_import_clear(aes_key2, key2);
			EXPECT_EQ(rc, 0);

			rc = zpc_aes_xts_set_key(aes_xts, aes_key1, aes_key2);
			EXPECT_EQ(rc, 0);

			rc = zpc_aes_xts_set_iv(aes_xts, iv);
			EXPECT_EQ(rc, 0);
			rc = zpc_aes_xts_encrypt(aes_xts, ct_out, pt, ptlen);
			EXPECT_EQ(rc, 0);
			EXPECT_TRUE(memcmp(ct_out, ct, ctlen) == 0);

			rc = zpc_aes_xts_set_iv(aes_xts, iv);
			EXPECT_EQ(rc, 0);
			rc = zpc_aes_xts_decrypt(aes_xts, pt_out, ct, ctlen);
			EXPECT_EQ(rc, 0);
			EXPECT_TRUE(memcmp(pt_out, pt, ptlen) == 0);

			/* Unset key. */
			rc = zpc_aes_xts_set_key(aes_xts, NULL, NULL);
			EXPECT_EQ(rc, 0);

			free(key1); key1 = NULL;
			free(iv); iv = NULL;
			free(pt); pt = NULL;
			free(pt_out); pt_out = NULL;
			free(ct); ct = NULL;
			free(ct_out); ct_out = NULL;
		}
	}
	zpc_aes_xts_free(&aes_xts);
	EXPECT_EQ(aes_xts, nullptr);
	zpc_aes_key_free(&aes_key1);
	EXPECT_EQ(aes_key1, nullptr);
	zpc_aes_key_free(&aes_key2);
	EXPECT_EQ(aes_key2, nullptr);
}

TEST(aes_xts, rederive_protected_key1)
{
	struct zpc_aes_key *aes_key1, *aes_key2;
	struct zpc_aes_xts *aes_xts1, *aes_xts2, *aes_xts3;
	u8 iv[16], m[96], c[96];
	int rc, size, type;

	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_XTS_HW_CAPS_CHECK();

	size = testlib_env_aes_key_size();
	type = testlib_env_aes_key_type();

	TESTLIB_AES_KERNEL_CAPS_CHECK(type);

	TESTLIB_AES_XTS_KEY_SIZE_CHECK(size);

	rc = zpc_aes_key_alloc(&aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_alloc(&aes_key2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_alloc(&aes_xts1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_alloc(&aes_xts2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_alloc(&aes_xts3);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_set_key(aes_xts1, NULL, NULL);   /* Unset key. */
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_set_key(aes_xts2, NULL, NULL);   /* Unset key. */
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_set_key(aes_xts3, NULL, NULL);   /* Unset key. */
	EXPECT_EQ(rc, 0);

	/* Random protected keys cannot be re-derived. */

	rc = zpc_aes_key_set_mkvp(aes_key1, NULL);   /* Unset apqns. */
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_size(aes_key1, size);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_generate(aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_mkvp(aes_key2, NULL);   /* Unset apqns. */
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_size(aes_key2, size);
	EXPECT_EQ(rc, 0);
	/*
	 * This key obj has no type set. Therefore the generate will work also
	 * for tests with ZPC_TEST_AES_KEY_TYPE = ZPC_AES_KEY_TYPE_PVSECRET.
	 * The generated protected key has no dependency on any secure key or
	 * pvsecret.
	 */
	rc = zpc_aes_key_generate(aes_key2);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_set_key(aes_xts1, aes_key1, aes_key2);
	EXPECT_EQ(rc, 0);
	memset(aes_xts1->param_pcc, 0, AES_XTS_PROTKEYLEN(aes_xts1->aes_key2->keysize));
	rc = zpc_aes_xts_set_iv(aes_xts1, iv);
	EXPECT_EQ(rc, ZPC_ERROR_PROTKEYONLY);

	rc = zpc_aes_xts_set_key(aes_xts2, aes_key2, aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_set_iv(aes_xts2, iv);
	EXPECT_EQ(rc, 0);
	memset(aes_xts2->param_km, 0, AES_XTS_PROTKEYLEN(aes_xts2->aes_key1->keysize));
	rc = zpc_aes_xts_encrypt(aes_xts2, c, m, 96);
	EXPECT_EQ(rc, ZPC_ERROR_PROTKEYONLY);

	rc = zpc_aes_xts_set_key(aes_xts3, aes_key2, aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_set_iv(aes_xts3, iv);
	EXPECT_EQ(rc, 0);
	memset(aes_xts3->param_km, 0, AES_XTS_PROTKEYLEN(aes_xts3->aes_key1->keysize));
	rc = zpc_aes_xts_decrypt(aes_xts3, m, c, 96);
	EXPECT_EQ(rc, ZPC_ERROR_PROTKEYONLY);

	zpc_aes_xts_free(&aes_xts3);
	zpc_aes_xts_free(&aes_xts2);
	zpc_aes_xts_free(&aes_xts1);
	zpc_aes_key_free(&aes_key2);
	zpc_aes_key_free(&aes_key1);
	EXPECT_EQ(aes_xts3, nullptr);
	EXPECT_EQ(aes_xts2, nullptr);
	EXPECT_EQ(aes_xts1, nullptr);
	EXPECT_EQ(aes_key2, nullptr);
	EXPECT_EQ(aes_key1, nullptr);
}

TEST(aes_xts, rederive_protected_key2)
{
	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_XTS_HW_CAPS_CHECK();

	size_t keylen, msglen, ctlen, ivlen;
	unsigned char buf[4096];
	const char *mkvp, *apqns[257];
	struct zpc_aes_key *aes_key1, *aes_key2;
	struct zpc_aes_xts *aes_xts;
	unsigned int flags;
	int type, rc;

	const char *keystr = "394c97881abd989d29c703e48a72b397a7acf51b59649eeea9b33274d8541df4";
	const char *ivstr = "4b15c684a152d485fe9937d39b168c29";
	const char *msgstr = "2f3b9dcfbae729583b1d1ffdd16bb6fe2757329435662a78f0";
	const char *ctstr = "f3473802e38a3ffef4d4fb8e6aa266ebde553a64528a06463e";

	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	TESTLIB_AES_KERNEL_CAPS_CHECK(type);

	TESTLIB_AES_SW_CAPS_CHECK(type);

	TESTLIB_APQN_CAPS_CHECK(apqns, mkvp, type, 128, flags);

	u8 *key1 = testlib_hexstr2buf(keystr, &keylen);
	ASSERT_NE(key1, nullptr);
	keylen /= 2;
	u8 *key2 = key1 + keylen;
	u8 *iv = testlib_hexstr2buf(ivstr, &ivlen);
	ASSERT_NE(iv, nullptr);
	u8 *msg = testlib_hexstr2buf(msgstr, &msglen);
	ASSERT_NE(msg, nullptr);
	u8 *ct = testlib_hexstr2buf(ctstr, &ctlen);
	ASSERT_NE(ct, nullptr);

	rc = zpc_aes_key_alloc(&aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_alloc(&aes_key2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_alloc(&aes_xts);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_set_type(aes_key1, type);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_aes_key_set_mkvp(aes_key1, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_aes_key_set_apqns(aes_key1, apqns);
		EXPECT_EQ(rc, 0);
	}
	rc = zpc_aes_key_set_flags(aes_key1, flags);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_set_size(aes_key1, keylen * 8);
	EXPECT_EQ(rc, 0);

	if (type != ZPC_AES_KEY_TYPE_PVSECRET) {
		rc = zpc_aes_key_import_clear(aes_key1, key1);
		EXPECT_EQ(rc, 0);
	} else {
		rc = testlib_set_aes_key_from_pvsecret(aes_key1, keylen * 8);
		if (rc)
			goto ret;
	}

	rc = zpc_aes_key_set_type(aes_key2, type);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_aes_key_set_mkvp(aes_key2, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_aes_key_set_apqns(aes_key2, apqns);
		EXPECT_EQ(rc, 0);
	}
	rc = zpc_aes_key_set_flags(aes_key2, flags);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_set_size(aes_key2, keylen * 8);
	EXPECT_EQ(rc, 0);

	if (type != ZPC_AES_KEY_TYPE_PVSECRET) {
		rc = zpc_aes_key_import_clear(aes_key2, key2);
		EXPECT_EQ(rc, 0);
	} else {
		rc = testlib_set_aes_key_from_pvsecret(aes_key2, keylen * 8);
		if (rc)
			goto ret;
	}

	/* Encrypt */
	memcpy(buf, msg, msglen);

	rc = zpc_aes_xts_set_key(aes_xts, aes_key1, aes_key2);
	EXPECT_EQ(rc, 0);
	memset(aes_xts->param_pcc, 0, AES_XTS_PROTKEYLEN(aes_xts->aes_key2->keysize));    /* force WKaVP mismatch */
	rc = zpc_aes_xts_set_iv(aes_xts, iv);
	EXPECT_EQ(rc, 0);

	memset(aes_xts->param_km, 0, AES_XTS_PROTKEYLEN(aes_xts->aes_key1->keysize));    /* force WKaVP mismatch */
	rc = zpc_aes_xts_encrypt(aes_xts, buf, buf, msglen);
	EXPECT_EQ(rc, 0);

	if (type != ZPC_AES_KEY_TYPE_PVSECRET) {
		EXPECT_TRUE(memcmp(buf, ct, ctlen) == 0);
	}

	/* Encrypt */
	memcpy(buf, msg, msglen);

	rc = zpc_aes_xts_set_key(aes_xts, aes_key1, aes_key2);
	EXPECT_EQ(rc, 0);
	memset(aes_xts->param_pcc, 0, AES_XTS_PROTKEYLEN(aes_xts->aes_key2->keysize));    /* force WKaVP mismatch */
	rc = zpc_aes_xts_set_iv(aes_xts, iv);
	EXPECT_EQ(rc, 0);

	memset(aes_xts->param_km, 0, AES_XTS_PROTKEYLEN(aes_xts->aes_key1->keysize));    /* force WKaVP mismatch */
	rc = zpc_aes_xts_encrypt(aes_xts, buf, buf, msglen);
	EXPECT_EQ(rc, 0);

	if (type != ZPC_AES_KEY_TYPE_PVSECRET) {
		EXPECT_TRUE(memcmp(buf, ct, ctlen) == 0);
	}

	/* Decrypt */
	memcpy(buf, ct, ctlen);

	memset(aes_xts->param_pcc, 0, AES_XTS_PROTKEYLEN(aes_xts->aes_key2->keysize));    /* force WKaVP mismatch */
	rc = zpc_aes_xts_set_iv(aes_xts, iv);
	EXPECT_EQ(rc, 0);

	memset(aes_xts->param_km, 0, AES_XTS_PROTKEYLEN(aes_xts->aes_key1->keysize));    /* force WKaVP mismatch */
	rc = zpc_aes_xts_decrypt(aes_xts, buf, buf,  msglen);
	EXPECT_EQ(rc, 0);

	if (type != ZPC_AES_KEY_TYPE_PVSECRET) {
		EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);
	}

	/* Decrypt */
	memcpy(buf, ct, ctlen);

	memset(aes_xts->param_pcc, 0, AES_XTS_PROTKEYLEN(aes_xts->aes_key2->keysize));    /* force WKaVP mismatch */
	rc = zpc_aes_xts_set_iv(aes_xts, iv);
	EXPECT_EQ(rc, 0);

	memset(aes_xts->param_km, 0, AES_XTS_PROTKEYLEN(aes_xts->aes_key1->keysize));    /* force WKaVP mismatch */
	rc = zpc_aes_xts_decrypt(aes_xts, buf, buf, msglen);
	EXPECT_EQ(rc, 0);

	if (type != ZPC_AES_KEY_TYPE_PVSECRET) {
		EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);
	}

ret:
	zpc_aes_xts_free(&aes_xts);
	EXPECT_EQ(aes_xts, nullptr);
	zpc_aes_key_free(&aes_key1);
	EXPECT_EQ(aes_key1, nullptr);
	zpc_aes_key_free(&aes_key2);
	EXPECT_EQ(aes_key2, nullptr);

	free(key1);
	free(iv);
	free(msg);
	free(ct);
}

TEST(aes_xts, reencipher)
{
	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_XTS_HW_CAPS_CHECK();

	size_t keylen, msglen, ctlen, ivlen;
	unsigned char buf[4096];
	const char *mkvp, *apqns[257];
	struct zpc_aes_key *aes_key1, *aes_key2;
	struct zpc_aes_xts *aes_xts;
	unsigned int flags;
	int type, rc;

	const char *keystr = "394c97881abd989d29c703e48a72b397a7acf51b59649eeea9b33274d8541df4";
	const char *ivstr = "4b15c684a152d485fe9937d39b168c29";
	const char *msgstr = "2f3b9dcfbae729583b1d1ffdd16bb6fe2757329435662a78f0";
	const char *ctstr = "f3473802e38a3ffef4d4fb8e6aa266ebde553a64528a06463e";

	u8 *key1 = testlib_hexstr2buf(keystr, &keylen);
	ASSERT_NE(key1, nullptr);
	keylen /= 2;
	u8 *key2 = key1 + keylen;
	u8 *iv = testlib_hexstr2buf(ivstr, &ivlen);
	ASSERT_NE(iv, nullptr);
	u8 *msg = testlib_hexstr2buf(msgstr, &msglen);
	ASSERT_NE(msg, nullptr);
	u8 *ct = testlib_hexstr2buf(ctstr, &ctlen);
	ASSERT_NE(ct, nullptr);

	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	TESTLIB_AES_KERNEL_CAPS_CHECK(type);

	TESTLIB_AES_SW_CAPS_CHECK(type);

	TESTLIB_APQN_CAPS_CHECK(apqns, mkvp, type, 128, flags);

	TESTLIB_AES_NEW_MK_CHECK(type, mkvp, apqns);

	if (type == ZPC_AES_KEY_TYPE_PVSECRET)
		GTEST_SKIP_("Skipping reencipher test. Not applicable for UV secrets.");

	rc = zpc_aes_key_alloc(&aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_alloc(&aes_key2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_alloc(&aes_xts);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_set_type(aes_key1, type);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_aes_key_set_mkvp(aes_key1, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_aes_key_set_apqns(aes_key1, apqns);
		EXPECT_EQ(rc, 0);
	}
	rc = zpc_aes_key_set_flags(aes_key1, flags);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_set_size(aes_key1, keylen * 8);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_import_clear(aes_key1, key1);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_set_type(aes_key2, type);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_aes_key_set_mkvp(aes_key2, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_aes_key_set_apqns(aes_key2, apqns);
		EXPECT_EQ(rc, 0);
	}
	rc = zpc_aes_key_set_flags(aes_key2, flags);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_set_size(aes_key2, keylen * 8);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_import_clear(aes_key2, key2);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_reencipher(aes_key1, ZPC_AES_KEY_REENCIPHER_CURRENT_TO_NEW);
	EXPECT_EQ(rc, 0);
	memset(&aes_key1->cur, 0, sizeof(aes_key1->cur));     /* destroy current secure key */

	rc = zpc_aes_key_reencipher(aes_key2, ZPC_AES_KEY_REENCIPHER_CURRENT_TO_NEW);
	EXPECT_EQ(rc, 0);
	memset(&aes_key2->cur, 0, sizeof(aes_key2->cur));     /* destroy current secure key */

	/* Encrypt */
	memcpy(buf, msg, msglen);

	rc = zpc_aes_xts_set_key(aes_xts, aes_key1, aes_key2);
	EXPECT_EQ(rc, 0);
	memset(&aes_key1->prot, 0, sizeof(aes_key1->prot));    /* destroy cached protected key */
	memset(&aes_key2->prot, 0, sizeof(aes_key2->prot));    /* destroy cached protected key */
	memset(aes_xts->param_pcc, 0, AES_XTS_PROTKEYLEN(aes_xts->aes_key2->keysize));    /* force WKaVP mismatch */
	rc = zpc_aes_xts_set_iv(aes_xts, iv);
	EXPECT_EQ(rc, 0);

	memset(&aes_key1->prot, 0, sizeof(aes_key1->prot));    /* destroy cached protected key */
	memset(&aes_key2->prot, 0, sizeof(aes_key2->prot));    /* destroy cached protected key */
	memset(aes_xts->param_km, 0, AES_XTS_PROTKEYLEN(aes_xts->aes_key1->keysize));    /* force WKaVP mismatch */
	rc = zpc_aes_xts_encrypt(aes_xts, buf, buf, msglen);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, ct, ctlen) == 0);

	/* Encrypt */
	memcpy(buf, msg, msglen);

	rc = zpc_aes_xts_set_key(aes_xts, aes_key1, aes_key2);
	EXPECT_EQ(rc, 0);
	memset(&aes_key1->prot, 0, sizeof(aes_key1->prot));    /* destroy cached protected key */
	memset(&aes_key2->prot, 0, sizeof(aes_key2->prot));    /* destroy cached protected key */
	memset(aes_xts->param_pcc, 0, AES_XTS_PROTKEYLEN(aes_xts->aes_key2->keysize));    /* force WKaVP mismatch */
	rc = zpc_aes_xts_set_iv(aes_xts, iv);
	EXPECT_EQ(rc, 0);

	memset(&aes_key1->prot, 0, sizeof(aes_key1->prot));    /* destroy cached protected key */
	memset(&aes_key2->prot, 0, sizeof(aes_key2->prot));    /* destroy cached protected key */
	memset(aes_xts->param_km, 0, AES_XTS_PROTKEYLEN(aes_xts->aes_key1->keysize));    /* force WKaVP mismatch */
	rc = zpc_aes_xts_encrypt(aes_xts, buf, buf, msglen);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, ct, ctlen) == 0);

	/* Decrypt */
	memcpy(buf, ct, ctlen);

	memset(&aes_key1->prot, 0, sizeof(aes_key1->prot));    /* destroy cached protected key */
	memset(&aes_key2->prot, 0, sizeof(aes_key2->prot));    /* destroy cached protected key */
	memset(aes_xts->param_pcc, 0, AES_XTS_PROTKEYLEN(aes_xts->aes_key2->keysize));    /* force WKaVP mismatch */
	rc = zpc_aes_xts_set_iv(aes_xts, iv);
	EXPECT_EQ(rc, 0);

	memset(&aes_key1->prot, 0, sizeof(aes_key1->prot));    /* destroy cached protected key */
	memset(&aes_key2->prot, 0, sizeof(aes_key2->prot));    /* destroy cached protected key */
	memset(aes_xts->param_km, 0, AES_XTS_PROTKEYLEN(aes_xts->aes_key1->keysize));    /* force WKaVP mismatch */
	rc = zpc_aes_xts_decrypt(aes_xts, buf, buf, msglen);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);

	/* Decrypt */
	memcpy(buf, ct, ctlen);

	memset(&aes_key1->prot, 0, sizeof(aes_key1->prot));    /* destroy cached protected key */
	memset(&aes_key2->prot, 0, sizeof(aes_key2->prot));    /* destroy cached protected key */
	memset(aes_xts->param_pcc, 0, AES_XTS_PROTKEYLEN(aes_xts->aes_key2->keysize));    /* force WKaVP mismatch */
	rc = zpc_aes_xts_set_iv(aes_xts, iv);
	EXPECT_EQ(rc, 0);

	memset(&aes_key1->prot, 0, sizeof(aes_key1->prot));    /* destroy cached protected key */
	memset(&aes_key2->prot, 0, sizeof(aes_key2->prot));    /* destroy cached protected key */
	memset(aes_xts->param_km, 0, AES_XTS_PROTKEYLEN(aes_xts->aes_key1->keysize));    /* force WKaVP mismatch */
	rc = zpc_aes_xts_decrypt(aes_xts, buf, buf, msglen);
	EXPECT_EQ(rc, 0);

	EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);

	zpc_aes_xts_free(&aes_xts);
	EXPECT_EQ(aes_xts, nullptr);
	zpc_aes_key_free(&aes_key1);
	EXPECT_EQ(aes_key1, nullptr);
	zpc_aes_key_free(&aes_key2);
	EXPECT_EQ(aes_key2, nullptr);

	free(key1);
	free(iv);
	free(msg);
	free(ct);
}

/*
 * This test assumes that the tester manually added the clear AES key
 * to the pvsecret list file, for example:
 *
 * 2 AES-128-KEY:
 * 0x8cf9659cd ...   <- secret ID
 * 0x5e511208c7d50...  <- clear key value
 *  ...
 *
 * The test creates two pvsecret-type AES keys and two CCA or EP11 type
 * single AES keys with the given clear key material to compare results.
 * The specified APQN(s) decide if the single keys are CCA or EP11.
 */
TEST(aes_xts, pvsecret_kat)
{
	struct zpc_aes_key *aes_key1, *aes_key2, *aes_key3, *aes_key4;
	struct zpc_aes_xts *ctx1, *ctx2;
	u8 iv[16], m[96], c[96], m_bak[96], c_bak[96];
	const char *mkvp, *apqns[257];
	unsigned int flags;
	int type, type2, rc, size;

	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_XTS_HW_CAPS_CHECK();

	size = testlib_env_aes_key_size();
	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	if (type != ZPC_AES_KEY_TYPE_PVSECRET)
		GTEST_SKIP_("Skipping pvsecret_kat test. Only applicable for UV secrets.");

	TESTLIB_AES_KERNEL_CAPS_CHECK(type);

	TESTLIB_AES_SW_CAPS_CHECK(type);

	TESTLIB_APQN_CAPS_CHECK(apqns, mkvp, type, size, flags);

	TESTLIB_AES_XTS_KEY_SIZE_CHECK(size);

	TESTLIB_AES_SW_CAPS_CHECK(type);

	TESTLIB_AES_KERNEL_CAPS_CHECK(type);

	rc = zpc_aes_key_alloc(&aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_alloc(&aes_key2);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_alloc(&aes_key3);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_alloc(&aes_key4);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_alloc(&ctx1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_alloc(&ctx2);
	EXPECT_EQ(rc, 0);

	/*
	 * key1 and key2 are created from pvsecret for ctx1.
	 */
	rc = zpc_aes_key_set_type(aes_key1, type);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_type(aes_key2, type);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_aes_key_set_mkvp(aes_key1, mkvp);
		EXPECT_EQ(rc, 0);
		rc = zpc_aes_key_set_mkvp(aes_key2, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_aes_key_set_apqns(aes_key1, apqns);
		EXPECT_EQ(rc, 0);
		rc = zpc_aes_key_set_apqns(aes_key2, apqns);
		EXPECT_EQ(rc, 0);
	}

	rc = zpc_aes_key_set_flags(aes_key1, flags);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_flags(aes_key2, flags);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_size(aes_key1, size);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_set_size(aes_key2, size);
	EXPECT_EQ(rc, 0);

	rc = testlib_set_aes_key_from_pvsecret(aes_key1, size);
	if (rc)
		goto ret;

	rc = testlib_set_aes_key_from_pvsecret(aes_key2, size);
	if (rc)
		goto ret;

	rc = zpc_aes_xts_set_key(ctx1, aes_key1, aes_key2);
	EXPECT_EQ(rc, 0);

	/*
	 * key3 and key4 are normal AES keys and contain clear key material from
	 * list file. We first try to create a CCA type key with the given APQN(s),
	 * if this fails we retry with EP11.
	 */
	type2 = ZPC_AES_KEY_TYPE_CCA_DATA;
	while (1) {
		rc = zpc_aes_key_set_type(aes_key3, type2);
		EXPECT_EQ(rc, 0);
		rc = zpc_aes_key_set_type(aes_key4, type2);
		EXPECT_EQ(rc, 0);
		if (mkvp != NULL) {
			rc = zpc_aes_key_set_mkvp(aes_key3, mkvp);
			rc += zpc_aes_key_set_mkvp(aes_key4, mkvp);
			if (type2 == ZPC_AES_KEY_TYPE_CCA_DATA && rc != 0) {
				type2 = ZPC_AES_KEY_TYPE_EP11;
				continue;
			}
			if (rc)
				goto ret;
		} else {
			rc = zpc_aes_key_set_apqns(aes_key3, apqns);
			EXPECT_EQ(rc, 0);
			rc = zpc_aes_key_set_apqns(aes_key4, apqns);
			EXPECT_EQ(rc, 0);
		}

		rc = zpc_aes_key_set_flags(aes_key3, flags);
		EXPECT_EQ(rc, 0);
		rc = zpc_aes_key_set_flags(aes_key4, flags);
		EXPECT_EQ(rc, 0);

		rc = zpc_aes_key_set_size(aes_key3, size);
		EXPECT_EQ(rc, 0);
		rc = zpc_aes_key_set_size(aes_key4, size);
		EXPECT_EQ(rc, 0);

		rc = testlib_set_aes_key_from_file(aes_key3, type2, size, 0, 1);
		rc += testlib_set_aes_key_from_file(aes_key4, type2, size, 0, 2);
		if (type2 == ZPC_AES_KEY_TYPE_CCA_DATA && rc != 0) {
			type2 = ZPC_AES_KEY_TYPE_EP11;
			continue;
		}
		if (rc)
			goto ret;
		else
			break;
	}

	rc = zpc_aes_xts_set_key(ctx2, aes_key3, aes_key4);
	EXPECT_EQ(rc, 0);

	memcpy(m_bak, m, 96);

	/* Now encrypt with both ctx and compare result */
	rc = zpc_aes_xts_set_iv(ctx1, iv);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_encrypt(ctx1, c, m, 96);
	EXPECT_EQ(rc, 0);
	memcpy(c_bak, c, 96);
	rc = zpc_aes_xts_set_iv(ctx2, iv);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_encrypt(ctx2, c, m, 96);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(c, c_bak, 96) == 0);

	/* Now encrypt with ctx1 and decrypt with ctx2 */
	rc = zpc_aes_xts_set_iv(ctx1, iv);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_encrypt(ctx1, c, m, 96);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_set_iv(ctx2, iv);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_xts_decrypt(ctx2, m, c, 96);
	EXPECT_EQ(rc, 0);
	EXPECT_TRUE(memcmp(m, m_bak, 96) == 0);

ret:
	zpc_aes_xts_free(&ctx1);
	EXPECT_EQ(ctx1, nullptr);
	zpc_aes_xts_free(&ctx2);
	EXPECT_EQ(ctx2, nullptr);
	zpc_aes_key_free(&aes_key1);
	EXPECT_EQ(aes_key1, nullptr);
	zpc_aes_key_free(&aes_key2);
	EXPECT_EQ(aes_key2, nullptr);
	zpc_aes_key_free(&aes_key3);
	EXPECT_EQ(aes_key3, nullptr);
	zpc_aes_key_free(&aes_key4);
	EXPECT_EQ(aes_key3, nullptr);
}

static void
__task(struct zpc_aes_key *aes_key1, struct zpc_aes_key *aes_key2)
{
	struct zpc_aes_xts *aes_xts;
	unsigned char buf[4096];
	size_t ivlen, msglen, ctlen;
	int rc, i;

	const char *ivstr = "4b15c684a152d485fe9937d39b168c29";
	const char *msgstr = "2f3b9dcfbae729583b1d1ffdd16bb6fe2757329435662a78f0";
	const char *ctstr = "f3473802e38a3ffef4d4fb8e6aa266ebde553a64528a06463e";

	u8 *iv = testlib_hexstr2buf(ivstr, &ivlen);
	ASSERT_NE(iv, nullptr);
	u8 *msg = testlib_hexstr2buf(msgstr, &msglen);
	ASSERT_NE(msg, nullptr);
	u8 *ct = testlib_hexstr2buf(ctstr, &ctlen);
	ASSERT_NE(ct, nullptr);

	rc = zpc_aes_xts_alloc(&aes_xts);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_xts_set_key(aes_xts, aes_key1, aes_key2);
	EXPECT_EQ(rc, 0);

	for (i = 0; i < 1000; i++) {
		/* Encrypt */
		memcpy(buf, msg, msglen);

		memset(aes_xts->param_pcc, 0, AES_XTS_PROTKEYLEN(aes_xts->aes_key2->keysize));    /* force WKaVP mismatch */
		rc = zpc_aes_xts_set_iv(aes_xts, iv);
		EXPECT_EQ(rc, 0);

		memset(aes_xts->param_km, 0, AES_XTS_PROTKEYLEN(aes_xts->aes_key1->keysize));    /* force WKaVP mismatch */
		rc = zpc_aes_xts_encrypt(aes_xts, buf, buf, ctlen);
		EXPECT_EQ(rc, 0);

		if (aes_key1->type != ZPC_AES_KEY_TYPE_PVSECRET) {
			EXPECT_TRUE(memcmp(buf, ct, ctlen) == 0);
		}

		/* Decrypt */
		if (aes_key1->type != ZPC_AES_KEY_TYPE_PVSECRET) {
			memcpy(buf, ct, ctlen);
		}

		memset(aes_xts->param_pcc, 0, AES_XTS_PROTKEYLEN(aes_xts->aes_key2->keysize));    /* force WKaVP mismatch */
		rc = zpc_aes_xts_set_iv(aes_xts, iv);
		EXPECT_EQ(rc, 0);

		memset(aes_xts->param_km, 0, AES_XTS_PROTKEYLEN(aes_xts->aes_key1->keysize));    /* force WKaVP mismatch */
		rc = zpc_aes_xts_decrypt(aes_xts, buf, buf, msglen);
		EXPECT_EQ(rc, 0);

		EXPECT_TRUE(memcmp(buf, msg, msglen) == 0);
	}

	zpc_aes_xts_free(&aes_xts);
	EXPECT_EQ(aes_xts, nullptr);

	free(iv);
	free(msg);
	free(ct);
}

TEST(aes_xts, threads)
{
	TESTLIB_ENV_AES_KEY_CHECK();

	TESTLIB_AES_XTS_HW_CAPS_CHECK();

	size_t keylen;
	const char *mkvp, *apqns[257];
	struct zpc_aes_key *aes_key1, *aes_key2;
	unsigned int flags;
	int type, rc, i;
	std::thread *t[500];

	const char *keystr = "394c97881abd989d29c703e48a72b397a7acf51b59649eeea9b33274d8541df4";

	type = testlib_env_aes_key_type();
	flags = testlib_env_aes_key_flags();
	mkvp = testlib_env_aes_key_mkvp();
	(void)testlib_env_aes_key_apqns(apqns);

	TESTLIB_AES_KERNEL_CAPS_CHECK(type);

	TESTLIB_AES_SW_CAPS_CHECK(type);

	TESTLIB_APQN_CAPS_CHECK(apqns, mkvp, type, 128, flags);

	TESTLIB_AES_NEW_MK_CHECK(type, mkvp, apqns);

	u8 *key1 = testlib_hexstr2buf(keystr, &keylen);
	keylen /= 2;
	u8 *key2 = key1 + keylen;

	rc = zpc_aes_key_alloc(&aes_key1);
	EXPECT_EQ(rc, 0);
	rc = zpc_aes_key_alloc(&aes_key2);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_set_type(aes_key1, type);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_aes_key_set_mkvp(aes_key1, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_aes_key_set_apqns(aes_key1, apqns);
		EXPECT_EQ(rc, 0);
	}
	rc = zpc_aes_key_set_flags(aes_key1, flags);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_set_size(aes_key1, keylen * 8);
	EXPECT_EQ(rc, 0);

	if (type != ZPC_AES_KEY_TYPE_PVSECRET) {
		rc = zpc_aes_key_import_clear(aes_key1, key1);
		EXPECT_EQ(rc, 0);
	} else {
		rc = testlib_set_aes_key_from_pvsecret(aes_key1, keylen * 8);
		if (rc)
			goto ret;
	}

	rc = zpc_aes_key_set_type(aes_key2, type);
	EXPECT_EQ(rc, 0);
	if (mkvp != NULL) {
		rc = zpc_aes_key_set_mkvp(aes_key2, mkvp);
		EXPECT_EQ(rc, 0);
	} else {
		rc = zpc_aes_key_set_apqns(aes_key2, apqns);
		EXPECT_EQ(rc, 0);
	}
	rc = zpc_aes_key_set_flags(aes_key2, flags);
	EXPECT_EQ(rc, 0);

	rc = zpc_aes_key_set_size(aes_key2, keylen * 8);
	EXPECT_EQ(rc, 0);

	if (type != ZPC_AES_KEY_TYPE_PVSECRET) {
		rc = zpc_aes_key_import_clear(aes_key2, key2);
		EXPECT_EQ(rc, 0);
	} else {
		rc = testlib_set_aes_key_from_pvsecret(aes_key2, keylen * 8);
		if (rc)
			goto ret;
	}

	for (i = 0; i < 500; i++) {
		t[i] = new std::thread(__task, aes_key1, aes_key2);
	}

	/* Do something with key object while threads are working with it. */
	if (type != ZPC_AES_KEY_TYPE_PVSECRET) {
		rc = zpc_aes_key_reencipher(aes_key1, ZPC_AES_KEY_REENCIPHER_CURRENT_TO_NEW);
		EXPECT_EQ(rc, 0);
		memset(&aes_key1->cur, 0, sizeof(aes_key1->cur));     /* destroy current secure key */
		rc = zpc_aes_key_reencipher(aes_key2, ZPC_AES_KEY_REENCIPHER_CURRENT_TO_NEW);
		EXPECT_EQ(rc, 0);
		memset(&aes_key2->cur, 0, sizeof(aes_key2->cur));     /* destroy current secure key */
	}
 
	for (i = 0; i < 500; i++) {
		memset(&aes_key1->prot, 0, sizeof(aes_key1->prot));    /* destroy cached protected key */
		usleep(1);
		memset(&aes_key2->prot, 0, sizeof(aes_key2->prot));    /* destroy cached protected key */
	}

	for (i = 0; i < 500; i++) {
		t[i]->join();
		delete t[i];
	}

ret:
	zpc_aes_key_free(&aes_key1);
	EXPECT_EQ(aes_key1, nullptr);
	zpc_aes_key_free(&aes_key2);
	EXPECT_EQ(aes_key2, nullptr);

	free(key1);
}
