/* $OpenBSD: ssh-sk.c,v 1.38 2022/01/14 03:35:10 djm Exp $ */
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

/* #define DEBUG_SK 1 */

#include "config.h"
#ifdef WITH_FIDO
#include <dlfcn.h>
#include <stddef.h>
#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif
#include <string.h>
#include <stdio.h>

#if defined(HAVE_OPENSSL) && defined(HAVE_OPENSSL_ECC)
#include <openssl/objects.h>
#include <openssl/ec.h>
#endif /* HAVE_OPENSSL && HAVE_OPENSSL_ECC */


#include "libssh/pki.h"
#include "libssh/buffer.h"

#include "libssh/libssh.h"

#include "libssh/priv.h"
#include "libssh/ssh-sk.h"
#include "libssh/sk-api.h"

/*
 * Almost every use of OpenSSL in this file is for ECDSA-NISTP256.
 * This is strictly a larger hammer than necessary, but it reduces changes
 * with upstream.
 */
#ifndef HAVE_OPENSSL_ECC
# undef HAVE_OPENSSL
#endif

struct sshsk_provider {
	char *path;
	void *dlhandle;

	/* Return the version of the middleware API */
	uint32_t (*sk_api_version)(void);

	/* Enroll a U2F key (private key generation) */
	int (*sk_enroll)(int alg, const uint8_t *challenge,
	    size_t challenge_len, const char *application, uint8_t flags,
	    const char *pin, struct sk_option **opts,
	    struct sk_enroll_response **enroll_response);

	/* Sign a challenge */
	int (*sk_sign)(int alg, const uint8_t *message, size_t message_len,
	    const char *application,
	    const uint8_t *key_handle, size_t key_handle_len,
	    uint8_t flags, const char *pin, struct sk_option **opts,
	    struct sk_sign_response **sign_response);

	/* Enumerate resident keys */
	int (*sk_load_resident_keys)(const char *pin, struct sk_option **opts,
	    struct sk_resident_key ***rks, size_t *nrks);
};

/* Built-in version */
int ssh_sk_enroll(int alg, const uint8_t *challenge,
    size_t challenge_len, const char *application, uint8_t flags,
    const char *pin, struct sk_option **opts,
    struct sk_enroll_response **enroll_response);
int ssh_sk_sign(int alg, const uint8_t *message, size_t message_len,
    const char *application,
    const uint8_t *key_handle, size_t key_handle_len,
    uint8_t flags, const char *pin, struct sk_option **opts,
    struct sk_sign_response **sign_response);
int ssh_sk_load_resident_keys(const char *pin, struct sk_option **opts,
    struct sk_resident_key ***rks, size_t *nrks);

static void
sshsk_free(struct sshsk_provider *p)
{
	if (p == NULL)
		return;
	free(p->path);
	if (p->dlhandle != NULL)
		dlclose(p->dlhandle);
	free(p);
}

static struct sshsk_provider *
sshsk_open(const char *path)
{
	struct sshsk_provider *ret = NULL;
	uint32_t version;

	if (path == NULL || *path == '\0') {
		SSH_LOG(SSH_LOG_WARNING, "No FIDO SecurityKeyProvider specified");
		return NULL;
	}
	if ((ret = calloc(1, sizeof(*ret))) == NULL) {
		SSH_LOG(SSH_LOG_WARNING, "calloc failed");
		return NULL;
	}
	if ((ret->path = strdup(path)) == NULL) {
		SSH_LOG(SSH_LOG_WARNING, "strdup failed");
		goto fail;
	}
	/* Skip the rest if we're using the linked in middleware */
	if (strcasecmp(ret->path, "internal") == 0) {
// #ifdef ENABLE_SK_INTERNAL
		ret->sk_enroll = ssh_sk_enroll;
		ret->sk_sign = ssh_sk_sign;
		ret->sk_load_resident_keys = ssh_sk_load_resident_keys;
		return ret;
// #else
		SSH_LOG(SSH_LOG_WARNING, "internal security key support not enabled");
		goto fail;
// #endif
	}
	if ((ret->dlhandle = dlopen(path, RTLD_NOW)) == NULL) {
		SSH_LOG(SSH_LOG_WARNING, "Provider \"%s\" dlopen failed: %s", path, dlerror());
		goto fail;
	}
	if ((ret->sk_api_version =dlsym(ret->dlhandle,
	    "sk_api_version")) == NULL) {
		SSH_LOG(SSH_LOG_WARNING, "Provider \"%s\" dlsym(sk_api_version) failed: %s",
		    path, dlerror());
		goto fail;
	}
	version = ret->sk_api_version();
	SSH_LOG(SSH_LOG_DEBUG,"provider %s implements version 0x%08lx", ret->path,
	    (u_long)version);
	if ((version & SSH_SK_VERSION_MAJOR_MASK) != SSH_SK_VERSION_MAJOR) {
		SSH_LOG(SSH_LOG_WARNING, "Provider \"%s\" implements unsupported "
		    "version 0x%08lx (supported: 0x%08lx)",
		    path, (u_long)version, (u_long)SSH_SK_VERSION_MAJOR);
		goto fail;
	}
	if ((ret->sk_enroll = dlsym(ret->dlhandle, "sk_enroll")) == NULL) {
		SSH_LOG(SSH_LOG_WARNING, "Provider %s dlsym(sk_enroll) failed: %s",
		    path, dlerror());
		goto fail;
	}
	if ((ret->sk_sign = dlsym(ret->dlhandle, "sk_sign")) == NULL) {
		SSH_LOG(SSH_LOG_WARNING, "Provider \"%s\" dlsym(sk_sign) failed: %s",
		    path, dlerror());
		goto fail;
	}
	if ((ret->sk_load_resident_keys = dlsym(ret->dlhandle,
	    "sk_load_resident_keys")) == NULL) {
		SSH_LOG(SSH_LOG_WARNING, "Provider \"%s\" dlsym(sk_load_resident_keys) "
		    "failed: %s", path, dlerror()); //checkthisout
		goto fail;
	}
	/* success */
	return ret;
fail:
	sshsk_free(ret);
	return NULL;
}

static void
sshsk_free_enroll_response(struct sk_enroll_response *r)
{
	if (r == NULL)
		return;
	SAFE_FREE(r->key_handle);//, r->key_handle_len);
	SAFE_FREE(r->public_key);//, r->public_key_len);
	SAFE_FREE(r->signature);//, r->signature_len);
	SAFE_FREE(r->attestation_cert);//, r->attestation_cert_len);
	SAFE_FREE(r->authdata);//, r->authdata_len);
	SAFE_FREE(r);//, sizeof(*r));
}

static void
sshsk_free_sign_response(struct sk_sign_response *r)
{
	if (r == NULL)
		return;
	SAFE_FREE(r->sig_r); //, r->sig_r_len);
	SAFE_FREE(r->sig_s); //, r->sig_s_len);
	SAFE_FREE(r); //, sizeof(*r));
}

#ifdef HAVE_OPENSSL
/* Assemble key from response */
static int
sshsk_ecdsa_assemble(struct sk_enroll_response *resp, struct ssh_key_struct **keyp)
{
	struct ssh_key_struct *key = NULL;
	struct ssh_buffer_struct *b = NULL;
	EC_POINT *q = NULL;
	int r;

	*keyp = NULL;
	if (key->type == SSH_KEYTYPE_SK_ECDSA && key == NULL) {
		SSH_LOG(SSH_LOG_WARN, "ssh_key_new failed");
		r = -2;
		goto out;
	}
	key->ecdsa_nid = NID_X9_62_prime256v1;
	if ((key->ecdsa = EC_KEY_new_by_curve_name(key->ecdsa_nid)) == NULL ||
	    (q = EC_POINT_new(EC_KEY_get0_group(key->ecdsa))) == NULL ||
	    (b = ssh_buffer_new()) == NULL) {
		SSH_LOG(SSH_LOG_WARN, "allocation failed");
		r = -2;
		goto out;
	}
	if ((r = ssh_buffer_add_data(b,
	    resp->public_key, resp->public_key_len)) != 0) {
		SSH_LOG(SSH_LOG_WARNING, "sshbuf_put_string");
		goto out;
	}
	if ((r = sshbuf_get_ec(b, q, EC_KEY_get0_group(key->ecdsa))) != 0) {
		SSH_LOG(SSH_LOG_WARNING, "parse");
		r = -4;
		goto out;
	}
	if (sshkey_ec_validate_public(EC_KEY_get0_group(key->ecdsa), q) != 0) {
		SSH_LOG(SSH_LOG_WARNING, "Authenticator returned invalid ECDSA key");
		r = -20;
		goto out;
	}
	if (EC_KEY_set_public_key(key->ecdsa, q) != 1) {
		/* XXX assume it is a allocation error */
		SSH_LOG(SSH_LOG_WARN, "allocation failed");
		r = -2;
		goto out;
	}
	/* success */
	*keyp = key;
	key = NULL; /* transferred */
	r = 0;
 out:
	EC_POINT_free(q);
	ssh_key_free(key);
	ssh_buffer_free(b);
	return r;
}
#endif /* HAVE_OPENSSL */

static int
sshsk_ed25519_assemble(struct sk_enroll_response *resp, struct ssh_key_struct **keyp)
{
	struct ssh_key_struct *key = NULL;
	int r;

	*keyp = NULL;
	if (resp->public_key_len != ED25519_KEY_LEN) { //checkthisout
		SSH_LOG(SSH_LOG_WARNING, "invalid size: %zu", resp->public_key_len);
		r = -4;
		goto out;
	}
	if (key->type == SSH_KEYTYPE_SK_ED25519  && key == NULL) {
		SSH_LOG(SSH_LOG_WARN,"sshkey_new failed");
		r = -2;
		goto out;
	}
	if ((key->ed25519_pubkey = malloc(ED25519_KEY_LEN)) == NULL) {
		SSH_LOG(SSH_LOG_WARN, "malloc failed");
		r = -2;
		goto out;
	}
	memcpy(key->ed25519_pubkey, resp->public_key, ED25519_KEY_LEN);
	/* success */
	*keyp = key;
	key = NULL; /* transferred */
	r = 0;
 out:
	ssh_key_free(key);
	return r;
}

static int
sshsk_key_from_response(int alg, const char *application, uint8_t flags,
    struct sk_enroll_response *resp, struct ssh_key_struct **keyp)
{
	struct ssh_key_struct *key = NULL;
	int r = -1;

	*keyp = NULL;

	/* Check response validity */
	if (resp->public_key == NULL || resp->key_handle == NULL) {
		SSH_LOG(SSH_LOG_WARNING, "sk_enroll response invalid");
		r = -4;
		goto out;
	}
	switch (alg) {
#ifdef HAVE_OPENSSL
	case SSH_SK_ECDSA:
		if ((r = sshsk_ecdsa_assemble(resp, &key)) != 0)
			goto out;
		break;
#endif /* HAVE_OPENSSL */
	case SSH_SK_ED25519:
		if ((r = sshsk_ed25519_assemble(resp, &key)) != 0)
			goto out;
		break;
	default:
		SSH_LOG(SSH_LOG_WARNING, "unsupported algorithm %d", alg);
		r = -10;
		goto out;
	}
	key->sk_flags = flags;
	if ((key->sk_key_handle = ssh_buffer_new()) == NULL ||
	    (key->sk_reserved = ssh_buffer_new()) == NULL) {
		SSH_LOG(SSH_LOG_WARNING, "allocation failed");
		r = -2;
		goto out;
	}
	if ((key->sk_application = strdup(application)) == NULL) {
		SSH_LOG(SSH_LOG_WARNING, "strdup application failed");
		r = -2;
		goto out;
	}
	if ((r = ssh_buffer_add_data(key->sk_key_handle, resp->key_handle,
	    resp->key_handle_len)) != 0) {
		//SSH_LOG(SSH_LOG_WARNING, "put key handle");
		SSH_LOG(SSH_LOG_WARNING,"put key handle");
		goto out;
	}
	/* success */
	r = 0;
	*keyp = key;
	key = NULL;
 out:
	ssh_key_free(key);
	return r;
}

static int
skerr_to_ssherr(int skerr)
{
	switch (skerr) {
	case SSH_SK_ERR_UNSUPPORTED:
		return -59;
	case SSH_SK_ERR_PIN_REQUIRED:
		return -43;
	case SSH_SK_ERR_DEVICE_NOT_FOUND:
		return -60;
	case SSH_SK_ERR_GENERAL:
	default:
		return -4;
	}
}

static void
sshsk_free_options(struct sk_option **opts)
{
	size_t i;

	if (opts == NULL)
		return;
	for (i = 0; opts[i] != NULL; i++) {
		free(opts[i]->name);
		free(opts[i]->value);
		free(opts[i]);
	}
	free(opts);
}

static int
sshsk_add_option(struct sk_option ***optsp, size_t *noptsp,
    const char *name, const char *value, uint8_t required)
{
	struct sk_option **opts = *optsp;
	size_t nopts = *noptsp;

	if ((opts = realloc(opts,/* nopts,*/ nopts + 2)) == NULL) { /* extra for NULL */
	    //sizeof(*opts))) == NULL) {
		SSH_LOG(SSH_LOG_WARNING, "array alloc failed");
		return -2;
	}
	*optsp = opts;
	*noptsp = nopts + 1;
	if ((opts[nopts] = calloc(1, sizeof(**opts))) == NULL) {
		SSH_LOG(SSH_LOG_WARNING, "alloc failed");
		return -2;
	}
	if ((opts[nopts]->name = strdup(name)) == NULL ||
	    (opts[nopts]->value = strdup(value)) == NULL) {
		SSH_LOG(SSH_LOG_WARNING, "alloc failed");
		return -2;
	}
	opts[nopts]->required = required;
	return 0;
}

static int
make_options(const char *device, const char *user_id,
    struct sk_option ***optsp)
{
	struct sk_option **opts = NULL;
	size_t nopts = 0;
	int r, ret = -1;

	if (device != NULL &&
	    (r = sshsk_add_option(&opts, &nopts, "device", device, 0)) != 0) {
		ret = r;
		goto out;
	}
	if (user_id != NULL &&
	    (r = sshsk_add_option(&opts, &nopts, "user", user_id, 0)) != 0) {
		ret = r;
		goto out;
	}
	/* success */
	*optsp = opts;
	opts = NULL;
	nopts = 0;
	ret = 0;
 out:
	sshsk_free_options(opts);
	return ret;
}


static int
fill_attestation_blob(const struct sk_enroll_response *resp,
    struct ssh_buffer_struct *attest)
{
	int r;

	if (attest == NULL)
		return 0; /* nothing to do */
	if ((r = ssh_buffer_add_data(attest, "ssh-sk-attest-v01", strlen("ssh-sk-attest-v01"))) != 0 ||
	    (r = ssh_buffer_add_data(attest,
	    resp->attestation_cert, resp->attestation_cert_len)) != 0 ||
	    (r = ssh_buffer_add_data(attest,
	    resp->signature, resp->signature_len)) != 0 ||
	    (r = ssh_buffer_add_data(attest,
	    resp->authdata, resp->authdata_len)) != 0 ||
	    (r = ssh_buffer_add_data(attest, 0, sizeof(uint32_t))) != 0 || /* resvd flags */
	    (r = ssh_buffer_add_data(attest, NULL, 0)) != 0 /* resvd */) {
		SSH_LOG(SSH_LOG_WARNING, "compose");
		return r;
	}
	/* success */
	return 0;
}

int
sshsk_enroll(int type, const char *provider_path, const char *device,
    const char *application, const char *userid, uint8_t flags,
    const char *pin, struct ssh_buffer_struct *challenge_buf,
    struct ssh_key_struct **keyp, struct ssh_buffer_struct *attest)
{
	struct sshsk_provider *skp = NULL;
	struct ssh_key_struct *key = NULL;
	u_char randchall[32];
	const u_char *challenge;
	size_t challenge_len;
	struct sk_enroll_response *resp = NULL;
	struct sk_option **opts = NULL;
	int r = -1;
	int alg;

	SSH_LOG(SSH_LOG_DEBUG,"provider \"%s\", device \"%s\", application \"%s\", "
	    "userid \"%s\", flags 0x%02x, challenge len %zu%s",
	    provider_path, device, application, userid, flags,
	    challenge_buf == NULL ? 0 : (size_t) ssh_buffer_get_len(challenge_buf),
	    (pin != NULL && *pin != '\0') ? " with-pin" : "");

	*keyp = NULL;
	if (attest)
		ssh_buffer_reinit(attest);

	if ((r = make_options(device, userid, &opts)) != 0)
		goto out;

	switch (type) {
#ifdef HAVE_OPENSSL
	case KEY_ECDSA_SK:
		alg = SSH_SK_ECDSA;
		break;
#endif /* HAVE_OPENSSL */
	case SSH_KEYTYPE_SK_ED25519: //checkthisout
		alg = SSH_SK_ED25519;
		break;
	default:
		SSH_LOG(SSH_LOG_WARNING, "unsupported key type");
		r = -10;
		goto out;
	}
	if (provider_path == NULL) {
		SSH_LOG(SSH_LOG_WARNING, "missing provider");
		r = -10;
		goto out;
	}
	if (application == NULL || *application == '\0') {
		SSH_LOG(SSH_LOG_WARNING, "missing application");
		r = -10;
		goto out;
	}
	if (challenge_buf == NULL) {
		SSH_LOG(SSH_LOG_DEBUG,"using random challenge");
		ssh_get_random(randchall, sizeof(randchall), 1);
		challenge = randchall;
		challenge_len = sizeof(randchall);
	} else if (ssh_buffer_get_len(challenge_buf) == 0) {
		SSH_LOG(SSH_LOG_WARNING, "Missing enrollment challenge");
		r = -10;
		goto out;
	} else {
		challenge = ssh_buffer_get(challenge_buf);
		challenge_len = ssh_buffer_get_len(challenge_buf);
		SSH_LOG(SSH_LOG_DEBUG, "using explicit challenge len=%zd", challenge_len);
	}
	if ((skp = sshsk_open(provider_path)) == NULL) {
		r = -4; /* XXX sshsk_open return code? */
		goto out;
	}
	/* XXX validate flags? */
	/* enroll key */
	if ((r = skp->sk_enroll(alg, challenge, challenge_len, application,
	    flags, pin, opts, &resp)) != 0) {
		SSH_LOG(SSH_LOG_DEBUG,"provider \"%s\" failure %d", provider_path, r);
		r = skerr_to_ssherr(r);
		goto out;
	}

	if ((r = sshsk_key_from_response(alg, application, resp->flags,
	    resp, &key)) != 0)
		goto out;

	/* Optionally fill in the attestation information */
	if ((r = fill_attestation_blob(resp, attest)) != 0)
		goto out;

	/* success */
	*keyp = key;
	key = NULL; /* transferred */
	r = 0;
 out:
	sshsk_free_options(opts);
	sshsk_free(skp);
	ssh_key_free(key);
	sshsk_free_enroll_response(resp);
	explicit_bzero(randchall, sizeof(randchall)); //checkthisout
	return r;
}

#ifdef HAVE_OPENSSL
static int
sshsk_ecdsa_sig(struct sk_sign_response *resp, struct ssh_buffer_struct *sig)
{
	struct ssh_buffer_struct *inner_sig = NULL;
	int r = -1;

	/* Check response validity */
	if (resp->sig_r == NULL || resp->sig_s == NULL) {
		SSH_LOG(SSH_LOG_WARNING, "sk_sign response invalid");
		r = -4;
		goto out;
	}
	if ((inner_sig = ssh_buffer_new()) == NULL) {
		r = -2;
		goto out;
	}
	/* Prepare and append inner signature object */
	if ((r = sshbuf_put_bignum2_bytes(inner_sig,
	    resp->sig_r, resp->sig_r_len)) != 0 ||
	    (r = sshbuf_put_bignum2_bytes(inner_sig,
	    resp->sig_s, resp->sig_s_len)) != 0) {
		SSH_LOG(SSH_LOG_WARNING, "compose inner");
		goto out;
	}
	if ((r = ssh_buffer_add_buffer(sig, inner_sig)) != 0 ||
	    (r = ssh_buffer_add_u8(sig, resp->flags)) != 0 ||
	    (r = ssh_buffer_add_u32(sig, resp->counter)) != 0) {
		SSH_LOG(SSH_LOG_WARNING, "compose");
		goto out;
	}
#ifdef DEBUG_SK
	SSH_LOG(SSH_LOG_WARNING, "%s: sig_r:\n", __func__);
	sshbuf_dump_data(resp->sig_r, resp->sig_r_len, stderr);
	SSH_LOG(SSH_LOG_WARNING, "%s: sig_s:\n", __func__);
	sshbuf_dump_data(resp->sig_s, resp->sig_s_len, stderr);
	SSH_LOG(SSH_LOG_WARNING, "%s: inner:\n", __func__);
	sshbuf_dump(inner_sig, stderr);
#endif
	r = 0;
 out:
	ssh_buffer_free(inner_sig);
	return r;
}
#endif /* HAVE_OPENSSL */

static int
sshsk_ed25519_sig(struct sk_sign_response *resp, struct ssh_buffer_struct *sig)
{
	int r = -1;

	/* Check response validity */
	if (resp->sig_r == NULL) {
		SSH_LOG(SSH_LOG_WARNING, "sk_sign response invalid");
		r = -4;
		goto out;
	}
	if ((r = ssh_buffer_add_data(sig,
	    resp->sig_r, resp->sig_r_len)) != 0 ||
	    (r = ssh_buffer_add_u8(sig, resp->flags)) != 0 ||
	    (r = ssh_buffer_add_u32(sig, resp->counter)) != 0) {
		SSH_LOG(SSH_LOG_WARNING, "compose");
		goto out;
	}
#ifdef DEBUG_SK
	SSH_LOG(SSH_LOG_WARNING, "%s: sig_r:\n", __func__);
	sshbuf_dump_data(resp->sig_r, resp->sig_r_len, stderr);
#endif
	r = 0;
 out:
	return r;
}

int
sshsk_sign(const char *provider_path, struct ssh_key_struct *key,
    u_char **sigp, size_t *lenp, const u_char *data, size_t datalen,
    u_int compat, const char *pin)
{
	struct sshsk_provider *skp = NULL;
	int r = -1;
	int type, alg;
	struct sk_sign_response *resp = NULL;
	struct ssh_buffer_struct *inner_sig = NULL, *sig = NULL;
	struct sk_option **opts = NULL;

	SSH_LOG(SSH_LOG_DEBUG,"provider \"%s\", key %s, flags 0x%02x%s",
	    provider_path, ssh_key_type_to_char(key->type), key->sk_flags,
	    (pin != NULL && *pin != '\0') ? " with-pin" : "");

	if (sigp != NULL)
		*sigp = NULL;
	if (lenp != NULL)
		*lenp = 0;
	type = ssh_key_type(key);
	switch (type) {
#ifdef HAVE_OPENSSL
	case KEY_ECDSA_SK:
		alg = SSH_SK_ECDSA;
		break;
#endif /* HAVE_OPENSSL */
	case SSH_KEYTYPE_SK_ED25519:
		alg = SSH_SK_ED25519;
		break;
	default:
		return -10;
	}
	if (provider_path == NULL ||
	    key->sk_key_handle == NULL ||
	    key->sk_application == NULL || *key->sk_application == '\0') {
		r = -10;
		goto out;
	}
	if ((skp = sshsk_open(provider_path)) == NULL) {
		r = -4; /* XXX sshsk_open return code? */
		goto out;
	}
#ifdef DEBUG_SK
	SSH_LOG(SSH_LOG_WARNING, "%s: sk_flags = 0x%02x, sk_application = \"%s\"\n",
	    __func__, key->sk_flags, key->sk_application);
	SSH_LOG(SSH_LOG_WARNING, "%s: sk_key_handle:\n", __func__);
	sshbuf_dump(key->sk_key_handle, stderr);
#endif
	if ((r = skp->sk_sign(alg, data, datalen, key->sk_application,
	    ssh_buffer_get(key->sk_key_handle), ssh_buffer_get_len(key->sk_key_handle),
	    key->sk_flags, pin, opts, &resp)) != 0) {
		SSH_LOG(SSH_LOG_DEBUG,"sk_sign failed with code %d", r);
		r = skerr_to_ssherr(r);
		goto out;
	}
	/* Assemble signature */
	if ((sig = ssh_buffer_new()) == NULL) {
		r = -2;
		goto out;
	}
	if ((r = ssh_buffer_add_data(sig, ssh_pki_key_ecdsa_name(key),strlen(ssh_pki_key_ecdsa_name(key)))) != 0) {
		SSH_LOG(SSH_LOG_WARNING, "compose outer");
		goto out;
	}
	switch (type) {
#ifdef HAVE_OPENSSL
	case KEY_ECDSA_SK:
		if ((r = sshsk_ecdsa_sig(resp, sig)) != 0)
			goto out;
		break;
#endif /* HAVE_OPENSSL */
	case SSH_KEYTYPE_SK_ED25519:
		if ((r = sshsk_ed25519_sig(resp, sig)) != 0)
			goto out;
		break;
	}
#ifdef DEBUG_SK
	SSH_LOG(SSH_LOG_WARNING, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, resp->flags, resp->counter);
	SSH_LOG(SSH_LOG_WARNING, "%s: data to sign:\n", __func__);
	sshbuf_dump_data(data, datalen, stderr);
	SSH_LOG(SSH_LOG_WARNING, "%s: sigbuf:\n", __func__);
	sshbuf_dump(sig, stderr);
#endif
	if (sigp != NULL) {
		if ((*sigp = malloc(ssh_buffer_get_len(sig))) == NULL) {
			r = -2;
			goto out;
		}
		memcpy(*sigp, ssh_buffer_get(sig), ssh_buffer_get_len(sig));
	}
	if (lenp != NULL)
		*lenp = ssh_buffer_get_len(sig);
	/* success */
	r = 0;
 out:
	sshsk_free_options(opts); //checkthisout
	sshsk_free(skp);
	sshsk_free_sign_response(resp);
	ssh_buffer_free(sig);
	ssh_buffer_free(inner_sig);
	return r;
}

static void
sshsk_free_sk_resident_keys(struct sk_resident_key **rks, size_t nrks)
{
	size_t i;

	if (nrks == 0 || rks == NULL)
		return;
	for (i = 0; i < nrks; i++) {
		free(rks[i]->application);
		SAFE_FREE(rks[i]->user_id); //, rks[i]->user_id_len);
		SAFE_FREE(rks[i]->key.key_handle); //, rks[i]->key.key_handle_len);
		SAFE_FREE(rks[i]->key.public_key); //, rks[i]->key.public_key_len);
		SAFE_FREE(rks[i]->key.signature); //, rks[i]->key.signature_len);
		SAFE_FREE(rks[i]->key.attestation_cert); //,
		    //rks[i]->key.attestation_cert_len);
		SAFE_FREE(rks[i]); //, sizeof(**rks));
	}
	free(rks);
}

static void
sshsk_free_resident_key(struct sshsk_resident_key *srk)
{
	if (srk == NULL)
		return;
	ssh_key_free(srk->key);
	SAFE_FREE(srk->user_id); //, srk->user_id_len);
	free(srk);
}


void
sshsk_free_resident_keys(struct sshsk_resident_key **srks, size_t nsrks)
{
	size_t i;

	if (srks == NULL || nsrks == 0)
		return;

	for (i = 0; i < nsrks; i++)
		sshsk_free_resident_key(srks[i]);
	free(srks);
}

int
sshsk_load_resident(const char *provider_path, const char *device,
    const char *pin, u_int flags, struct sshsk_resident_key ***srksp,
    size_t *nsrksp)
{
	struct sshsk_provider *skp = NULL;
	int r = -1;
	struct sk_resident_key **rks = NULL;
	size_t i, nrks = 0, nsrks = 0;
	struct ssh_key_struct *key = NULL;
	struct sshsk_resident_key *srk = NULL, **srks = NULL, **tmp;
	uint8_t sk_flags;
	struct sk_option **opts = NULL;

	SSH_LOG(SSH_LOG_DEBUG,"provider \"%s\"%s", provider_path,
	    (pin != NULL && *pin != '\0') ? ", have-pin": "");

	if (srksp == NULL || nsrksp == NULL)
		return -10;
	*srksp = NULL;
	*nsrksp = 0;

	if ((r = make_options(device, NULL, &opts)) != 0)
		goto out;
	if ((skp = sshsk_open(provider_path)) == NULL) {
		r = -4; /* XXX sshsk_open return code? */
		goto out;
	}
	if ((r = skp->sk_load_resident_keys(pin, opts, &rks, &nrks)) != 0) {
		SSH_LOG(SSH_LOG_WARNING, "Provider \"%s\" returned failure %d", provider_path, r);
		r = skerr_to_ssherr(r);
		goto out;
	}
	for (i = 0; i < nrks; i++) {
		SSH_LOG(SSH_LOG_DEBUG,"rk %zu: slot %zu, alg %d, app \"%s\", uidlen %zu",
		    i, rks[i]->slot, rks[i]->alg, rks[i]->application,
		    rks[i]->user_id_len);
		/* XXX need better filter here */
		if (strncmp(rks[i]->application, "ssh:", 4) != 0)
			continue;
		switch (rks[i]->alg) {
		case SSH_SK_ECDSA:
		case SSH_SK_ED25519:
			break;
		default:
			continue;
		}
		sk_flags = SSH_SK_USER_PRESENCE_REQD|SSH_SK_RESIDENT_KEY;
		if ((rks[i]->flags & SSH_SK_USER_VERIFICATION_REQD))
			sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
		if ((r = sshsk_key_from_response(rks[i]->alg,
		    rks[i]->application, sk_flags, &rks[i]->key, &key)) != 0)
			goto out;
		if ((srk = calloc(1, sizeof(*srk))) == NULL) {
			SSH_LOG(SSH_LOG_WARNING, "calloc failed");
			r = -2;
			goto out;
		}
		srk->key = key;
		key = NULL; /* transferred */
		if ((srk->user_id = calloc(1, rks[i]->user_id_len)) == NULL) {
			SSH_LOG(SSH_LOG_WARNING, "calloc failed");
			r = -2;
			goto out;
		}
		memcpy(srk->user_id, rks[i]->user_id, rks[i]->user_id_len);
		srk->user_id_len = rks[i]->user_id_len;
		if ((tmp = realloc(srks, nsrks + 1))== NULL) {
			SSH_LOG(SSH_LOG_WARNING, "recallocarray failed");
			r = -2;
			goto out;
		}
		srks = tmp;
		srks[nsrks++] = srk;
		srk = NULL;
		/* XXX synthesise comment */
	}
	/* success */
	*srksp = srks;
	*nsrksp = nsrks;
	srks = NULL;
	nsrks = 0;
	r = 0;
 out:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshsk_free_sk_resident_keys(rks, nrks);
	ssh_key_free(key);
	sshsk_free_resident_key(srk);
	sshsk_free_resident_keys(srks, nsrks);
	return r;
}

#endif /* ENABLE_SK */

