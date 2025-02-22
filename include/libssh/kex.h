/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2009 by Aris Adamantiadis
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef KEX_H_
#define KEX_H_

#include "libssh/priv.h"
#include "libssh/callbacks.h"
#include "libssh/curve25519.h"
#include "libssh/sntrup761.h"

#ifdef HAVE_BLOWFISH
# define BLOWFISH ",blowfish-cbc"
#else
# define BLOWFISH ""
#endif

#ifdef HAVE_LIBGCRYPT
# define AES "aes256-gcm@openssh.com,aes128-gcm@openssh.com," \
             "aes256-ctr,aes192-ctr,aes128-ctr"
# define AES_CBC ",aes256-cbc,aes192-cbc,aes128-cbc"
# define DES_SUPPORTED ",3des-cbc"

#elif defined(HAVE_LIBMBEDCRYPTO)
# ifdef MBEDTLS_GCM_C
#  define GCM "aes256-gcm@openssh.com,aes128-gcm@openssh.com,"
# else
#  define GCM ""
# endif /* MBEDTLS_GCM_C */
# define AES GCM "aes256-ctr,aes192-ctr,aes128-ctr"
# define AES_CBC ",aes256-cbc,aes192-cbc,aes128-cbc"
# define DES_SUPPORTED ",3des-cbc"

#elif defined(HAVE_LIBCRYPTO)
# ifdef HAVE_OPENSSL_AES_H
#  define GCM "aes256-gcm@openssh.com,aes128-gcm@openssh.com,"
#  define AES GCM "aes256-ctr,aes192-ctr,aes128-ctr"
#  define AES_CBC ",aes256-cbc,aes192-cbc,aes128-cbc"
# else /* HAVE_OPENSSL_AES_H */
#  define AES ""
#  define AES_CBC ""
# endif /* HAVE_OPENSSL_AES_H */

# define DES_SUPPORTED ",3des-cbc"
#endif /* HAVE_LIBCRYPTO */

#ifdef WITH_ZLIB
#define ZLIB "none,zlib@openssh.com,zlib"
#define ZLIB_DEFAULT "none,zlib@openssh.com"
#else
#define ZLIB "none"
#define ZLIB_DEFAULT "none"
#endif /* WITH_ZLIB */

#ifdef HAVE_CURVE25519
#define CURVE25519 "curve25519-sha256,curve25519-sha256@libssh.org,"
#else
#define CURVE25519 ""
#endif /* HAVE_CURVE25519 */

#ifdef HAVE_SNTRUP761
#define SNTRUP761X25519 "sntrup761x25519-sha512@openssh.com,"
#else
#define SNTRUP761X25519 ""
#endif /* HAVE_SNTRUP761 */

#ifdef HAVE_ECC
#define ECDH "ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,"
#define EC_HOSTKEYS "ecdsa-sha2-nistp521," \
                    "ecdsa-sha2-nistp384," \
                    "ecdsa-sha2-nistp256,"
#define EC_SK_HOSTKEYS "sk-ecdsa-sha2-nistp256@openssh.com,"
#define EC_FIPS_PUBLIC_KEY_ALGOS "ecdsa-sha2-nistp521-cert-v01@openssh.com," \
                                 "ecdsa-sha2-nistp384-cert-v01@openssh.com," \
                                 "ecdsa-sha2-nistp256-cert-v01@openssh.com,"
#define EC_PUBLIC_KEY_ALGORITHMS EC_FIPS_PUBLIC_KEY_ALGOS \
                                 "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,"
#else
#define ECDH ""
#define EC_HOSTKEYS ""
#define EC_SK_HOSTKEYS ""
#define EC_FIPS_PUBLIC_KEY_ALGOS ""
#define EC_PUBLIC_KEY_ALGORITHMS ""
#endif /* HAVE_ECC */

#ifdef WITH_INSECURE_NONE
#define NONE ",none"
#else
#define NONE
#endif /* WITH_INSECURE_NONE */

#define HOSTKEY_SIGNATURE_ALGOS "ssh-ed25519," \
                                EC_HOSTKEYS \
                                "sk-ssh-ed25519@openssh.com," \
                                EC_SK_HOSTKEYS \
                                "rsa-sha2-512," \
                                "rsa-sha2-256," \
                                "ssh-rsa"
#define DEFAULT_HOSTKEY_SIGNATURE_ALGOS "ssh-ed25519," \
                                        EC_HOSTKEYS \
                                        "sk-ssh-ed25519@openssh.com," \
                                        EC_SK_HOSTKEYS \
                                        "rsa-sha2-512," \
                                        "rsa-sha2-256"
#define HOSTKEY_TYPES "ssh-ed25519," \
                      EC_HOSTKEYS \
                      "sk-ssh-ed25519@openssh.com," \
                      EC_SK_HOSTKEYS \
                      "ssh-rsa"

#define PUBLIC_KEY_ALGORITHMS "ssh-ed25519-cert-v01@openssh.com," \
                              "sk-ssh-ed25519-cert-v01@openssh.com," \
                              EC_PUBLIC_KEY_ALGORITHMS \
                              "rsa-sha2-512-cert-v01@openssh.com," \
                              "rsa-sha2-256-cert-v01@openssh.com," \
                              "ssh-rsa-cert-v01@openssh.com," \
                              HOSTKEY_SIGNATURE_ALGOS
#define DEFAULT_PUBLIC_KEY_ALGORITHMS "ssh-ed25519-cert-v01@openssh.com," \
                                      EC_PUBLIC_KEY_ALGORITHMS \
                                      "rsa-sha2-512-cert-v01@openssh.com," \
                                      "rsa-sha2-256-cert-v01@openssh.com," \
                                      DEFAULT_HOSTKEY_SIGNATURE_ALGOS

#ifdef WITH_GEX
#define GEX_SHA256 "diffie-hellman-group-exchange-sha256,"
#define GEX_SHA1 "diffie-hellman-group-exchange-sha1,"
#else
#define GEX_SHA256
#define GEX_SHA1
#endif /* WITH_GEX */

#define CHACHA20 "chacha20-poly1305@openssh.com,"

#define DEFAULT_KEY_EXCHANGE \
    CURVE25519 \
    SNTRUP761X25519 \
    ECDH \
    "diffie-hellman-group18-sha512,diffie-hellman-group16-sha512," \
    GEX_SHA256 \
    "diffie-hellman-group14-sha256" \

#define KEY_EXCHANGE_SUPPORTED \
    GEX_SHA1 \
    DEFAULT_KEY_EXCHANGE \
    ",diffie-hellman-group14-sha1,diffie-hellman-group1-sha1"

/* RFC 8308 */
#define KEX_EXTENSION_CLIENT "ext-info-c"
/* Strict kex mitigation against CVE-2023-48795 */
#define KEX_STRICT_CLIENT "kex-strict-c-v00@openssh.com"
#define KEX_STRICT_SERVER "kex-strict-s-v00@openssh.com"

/* Allowed algorithms in FIPS mode */
#define FIPS_ALLOWED_CIPHERS "aes256-gcm@openssh.com,"\
                             "aes256-ctr,"\
                             "aes256-cbc,"\
                             "aes128-gcm@openssh.com,"\
                             "aes128-ctr,"\
                             "aes128-cbc"

#define FIPS_ALLOWED_HOSTKEY_SIGNATURE_ALGOS EC_HOSTKEYS \
                                             "rsa-sha2-512," \
                                             "rsa-sha2-256"

#define FIPS_ALLOWED_PUBLIC_KEY_ALGORITHMS EC_FIPS_PUBLIC_KEY_ALGOS \
                                           "rsa-sha2-512-cert-v01@openssh.com," \
                                           "rsa-sha2-256-cert-v01@openssh.com," \
                                           FIPS_ALLOWED_HOSTKEY_SIGNATURE_ALGOS

#define FIPS_ALLOWED_KEX "ecdh-sha2-nistp256,"\
                         "ecdh-sha2-nistp384,"\
                         "ecdh-sha2-nistp521,"\
                         "diffie-hellman-group-exchange-sha256,"\
                         "diffie-hellman-group14-sha256,"\
                         "diffie-hellman-group16-sha512,"\
                         "diffie-hellman-group18-sha512"

#define FIPS_ALLOWED_MACS "hmac-sha2-256-etm@openssh.com,"\
                          "hmac-sha1-etm@openssh.com,"\
                          "hmac-sha2-512-etm@openssh.com,"\
                          "hmac-sha2-256,"\
                          "hmac-sha1,"\
                          "hmac-sha2-512"

#define SSH_KEX_METHODS 10

struct ssh_kex_struct {
    unsigned char cookie[16];
    char *methods[SSH_KEX_METHODS];
};

#ifdef __cplusplus
extern "C" {
#endif

SSH_PACKET_CALLBACK(ssh_packet_kexinit);

int ssh_send_kex(ssh_session session);
void ssh_list_kex(struct ssh_kex_struct *kex);
int ssh_set_client_kex(ssh_session session);
int ssh_kex_append_extensions(ssh_session session, struct ssh_kex_struct *pkex);
int ssh_kex_select_methods(ssh_session session);
int ssh_verify_existing_algo(enum ssh_kex_types_e algo, const char *name);
char *ssh_keep_known_algos(enum ssh_kex_types_e algo, const char *list);
char *ssh_keep_fips_algos(enum ssh_kex_types_e algo, const char *list);
char *ssh_add_to_default_algos(enum ssh_kex_types_e algo, const char *list);
char *ssh_remove_from_default_algos(enum ssh_kex_types_e algo,
                                    const char *list);
char *ssh_prefix_default_algos(enum ssh_kex_types_e algo, const char *list);
char **ssh_space_tokenize(const char *chain);
int ssh_get_kex1(ssh_session session);
char *ssh_find_matching(const char *in_d, const char *what_d);
const char *ssh_kex_get_supported_method(uint32_t algo);
const char *ssh_kex_get_default_methods(uint32_t algo);
const char *ssh_kex_get_fips_methods(uint32_t algo);
const char *ssh_kex_get_description(uint32_t algo);
char *ssh_client_select_hostkeys(ssh_session session);
int ssh_send_rekex(ssh_session session);
int server_set_kex(ssh_session session);
int ssh_make_sessionid(ssh_session session);
/* add data for the final cookie */
int ssh_hashbufin_add_cookie(ssh_session session, unsigned char *cookie);
int ssh_hashbufout_add_cookie(ssh_session session);
int ssh_generate_session_keys(ssh_session session);

#ifdef __cplusplus
}
#endif

#endif /* KEX_H_ */
