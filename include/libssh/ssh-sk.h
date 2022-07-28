/* $OpenBSD: ssh-sk.h,v 1.11 2021/10/28 02:54:18 djm Exp $ */
/*
 * Copyright (c) 2019 Google LLC
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _SSH_SK_H
#define _SSH_SK_H 1

struct ssh_buffer_struct;
struct ssh_key_struct;
struct sk_option;

/* Version of protocol expected from ssh-sk-helper */
#define SSH_SK_HELPER_VERSION		5

/* ssh-sk-helper messages */
#define SSH_SK_HELPER_ERROR		0	/* Only valid H->C */
#define SSH_SK_HELPER_SIGN		1
#define SSH_SK_HELPER_ENROLL		2
#define SSH_SK_HELPER_LOAD_RESIDENT	3

struct sshsk_resident_key {
	struct ssh_key_struct *key;
	uint8_t *user_id;
	size_t user_id_len;
};

/*
 * Enroll (generate) a new security-key hosted private key of given type
 * via the specified provider middleware.
 * If challenge_buf is NULL then a random 256 bit challenge will be used.
 *
 * Returns 0 on success or a ssherr.h error code on failure.
 *
 * If successful and the attest_data buffer is not NULL then attestation
 * information is placed there.
 */
int sshsk_enroll(int type, const char *provider_path, const char *device,
    const char *application, const char *userid, uint8_t flags,
    const char *pin, struct ssh_buffer_struct *challenge_buf,
    struct ssh_key_struct **keyp, struct ssh_buffer_struct *attest);

/*
 * Calculate an ECDSA_SK or ED25519_SK signature using the specified key
 * and provider middleware.
 *
 * Returns 0 on success or a ssherr.h error code on failure.
 */
int sshsk_sign(const char *provider_path, struct ssh_key_struct *key,
    u_char **sigp, size_t *lenp, const u_char *data, size_t datalen,
    u_int compat, const char *pin);

/*
 * Enumerates and loads all SSH-compatible resident keys from a security
 * key.
 *
 * Returns 0 on success or a ssherr.h error code on failure.
 */
int sshsk_load_resident(const char *provider_path, const char *device,
    const char *pin, u_int flags, struct sshsk_resident_key ***srksp,
    size_t *nsrksp);

/* Free an array of sshsk_resident_key (as returned from sshsk_load_resident) */
void sshsk_free_resident_keys(struct sshsk_resident_key **srks, size_t nsrks);

#endif /* _SSH_SK_H */

//extra additions from ssherr.h
#define SSH_ERR_SUCCESS				0
#define SSH_ERR_INTERNAL_ERROR			-1
#define SSH_ERR_ALLOC_FAIL			-2
#define SSH_ERR_MESSAGE_INCOMPLETE		-3
#define SSH_ERR_INVALID_FORMAT			-4
#define SSH_ERR_BIGNUM_IS_NEGATIVE		-5
#define SSH_ERR_STRING_TOO_LARGE		-6
#define SSH_ERR_BIGNUM_TOO_LARGE		-7
#define SSH_ERR_ECPOINT_TOO_LARGE		-8
#define SSH_ERR_NO_BUFFER_SPACE			-9
#define SSH_ERR_INVALID_ARGUMENT		-10
#define SSH_ERR_KEY_BITS_MISMATCH		-11
#define SSH_ERR_EC_CURVE_INVALID		-12
#define SSH_ERR_KEY_TYPE_MISMATCH		-13
#define SSH_ERR_KEY_TYPE_UNKNOWN		-14 /* XXX UNSUPPORTED? */
#define SSH_ERR_EC_CURVE_MISMATCH		-15
#define SSH_ERR_EXPECTED_CERT			-16
#define SSH_ERR_KEY_LACKS_CERTBLOB		-17
#define SSH_ERR_KEY_CERT_UNKNOWN_TYPE		-18
#define SSH_ERR_KEY_CERT_INVALID_SIGN_KEY	-19
#define SSH_ERR_KEY_INVALID_EC_VALUE		-20
#define SSH_ERR_SIGNATURE_INVALID		-21
#define SSH_ERR_LIBCRYPTO_ERROR			-22
#define SSH_ERR_UNEXPECTED_TRAILING_DATA	-23
#define SSH_ERR_SYSTEM_ERROR			-24
#define SSH_ERR_KEY_CERT_INVALID		-25
#define SSH_ERR_AGENT_COMMUNICATION		-26
#define SSH_ERR_AGENT_FAILURE			-27
#define SSH_ERR_DH_GEX_OUT_OF_RANGE		-28
#define SSH_ERR_DISCONNECTED			-29
#define SSH_ERR_MAC_INVALID			-30
#define SSH_ERR_NO_CIPHER_ALG_MATCH		-31
#define SSH_ERR_NO_MAC_ALG_MATCH		-32
#define SSH_ERR_NO_COMPRESS_ALG_MATCH		-33
#define SSH_ERR_NO_KEX_ALG_MATCH		-34
#define SSH_ERR_NO_HOSTKEY_ALG_MATCH		-35
#define SSH_ERR_NO_HOSTKEY_LOADED		-36
#define SSH_ERR_PROTOCOL_MISMATCH		-37
#define SSH_ERR_NO_PROTOCOL_VERSION		-38
#define SSH_ERR_NEED_REKEY			-39
#define SSH_ERR_PASSPHRASE_TOO_SHORT		-40
#define SSH_ERR_FILE_CHANGED			-41
#define SSH_ERR_KEY_UNKNOWN_CIPHER		-42
#define SSH_ERR_KEY_WRONG_PASSPHRASE		-43
#define SSH_ERR_KEY_BAD_PERMISSIONS		-44
#define SSH_ERR_KEY_CERT_MISMATCH		-45
#define SSH_ERR_KEY_NOT_FOUND			-46
#define SSH_ERR_AGENT_NOT_PRESENT		-47
#define SSH_ERR_AGENT_NO_IDENTITIES		-48
#define SSH_ERR_BUFFER_READ_ONLY		-49
#define SSH_ERR_KRL_BAD_MAGIC			-50
#define SSH_ERR_KEY_REVOKED			-51
#define SSH_ERR_CONN_CLOSED			-52
#define SSH_ERR_CONN_TIMEOUT			-53
#define SSH_ERR_CONN_CORRUPT			-54
#define SSH_ERR_PROTOCOL_ERROR			-55
#define SSH_ERR_KEY_LENGTH			-56
#define SSH_ERR_NUMBER_TOO_LARGE		-57
#define SSH_ERR_SIGN_ALG_UNSUPPORTED		-58
#define SSH_ERR_FEATURE_UNSUPPORTED		-59
#define SSH_ERR_DEVICE_NOT_FOUND		-60
//