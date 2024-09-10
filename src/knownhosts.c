/*
 * known_hosts: Host and public key verification.
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2009 by Aris Adamantiadis
 * Copyright (c) 2009-2017 by Andreas Schneider <asn@cryptomilk.org>
 *
 * The SSH Library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 *
 * The SSH Library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the SSH Library; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#include "config.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

#include "libssh/priv.h"
#include "libssh/dh.h"
#include "libssh/session.h"
#include "libssh/options.h"
#include "libssh/misc.h"
#include "libssh/pki.h"
#include "libssh/dh.h"
#include "libssh/knownhosts.h"
#include "libssh/token.h"

#ifndef MAX_LINE_SIZE
#define MAX_LINE_SIZE 8192
#endif

/**
 * @addtogroup libssh_session
 *
 * @{
 */

static int hash_hostname(const char *name,
                         unsigned char *salt,
                         unsigned int salt_size,
                         unsigned char **hash,
                         size_t *hash_size)
{
    int rc;
    HMACCTX mac_ctx;

    mac_ctx = hmac_init(salt, salt_size, SSH_HMAC_SHA1);
    if (mac_ctx == NULL) {
        return SSH_ERROR;
    }

    rc = hmac_update(mac_ctx, name, strlen(name));
    if (rc != 1)
        return SSH_ERROR;

    rc = hmac_final(mac_ctx, *hash, hash_size);
    if (rc != 1)
        return SSH_ERROR;

    return SSH_OK;
}

static int match_hashed_hostname(const char *host, const char *hashed_host)
{
    char *hashed;
    char *b64_hash;
    ssh_buffer salt = NULL;
    ssh_buffer hash = NULL;
    unsigned char hashed_buf[256] = {0};
    unsigned char *hashed_buf_ptr = hashed_buf;
    size_t hashed_buf_size = sizeof(hashed_buf);
    int cmp;
    int rc;
    int match = 0;

    cmp = strncmp(hashed_host, "|1|", 3);
    if (cmp != 0) {
        return 0;
    }

    hashed = strdup(hashed_host + 3);
    if (hashed == NULL) {
        return 0;
    }

    b64_hash = strchr(hashed, '|');
    if (b64_hash == NULL) {
        goto error;
    }
    *b64_hash = '\0';
    b64_hash++;

    salt = base64_to_bin(hashed);
    if (salt == NULL) {
        goto error;
    }

    hash = base64_to_bin(b64_hash);
    if (hash == NULL) {
        goto error;
    }

    rc = hash_hostname(host,
                       ssh_buffer_get(salt),
                       ssh_buffer_get_len(salt),
                       &hashed_buf_ptr,
                       &hashed_buf_size);
    if (rc != SSH_OK) {
        goto error;
    }

    if (hashed_buf_size != ssh_buffer_get_len(hash)) {
        goto error;
    }

    cmp = memcmp(hashed_buf, ssh_buffer_get(hash), hashed_buf_size);
    if (cmp == 0) {
        match = 1;
    }

error:
    free(hashed);
    SSH_BUFFER_FREE(salt);
    SSH_BUFFER_FREE(hash);

    return match;
}

/**
 * @brief Free an allocated ssh_knownhosts_entry.
 *
 * Use SSH_KNOWNHOSTS_ENTRY_FREE() to set the pointer to NULL.
 *
 * @param[in]  entry     The entry to free.
 */
void ssh_knownhosts_entry_free(struct ssh_knownhosts_entry *entry)
{
    if (entry == NULL) {
        return;
    }

    SAFE_FREE(entry->hostname);
    SAFE_FREE(entry->unparsed);
    ssh_key_free(entry->publickey);
    SAFE_FREE(entry->comment);
    SAFE_FREE(entry);
}

static int known_hosts_read_line(FILE *fp,
                                 char *buf,
                                 size_t buf_size,
                                 size_t *buf_len,
                                 size_t *lineno)
{
    while (fgets(buf, (int)buf_size, fp) != NULL) {
        size_t len;
        if (buf[0] == '\0') {
            continue;
        }

        *lineno += 1;
        len = strlen(buf);
        if (buf_len != NULL) {
            *buf_len = len;
        }
        if (buf[len - 1] == '\n' || feof(fp)) {
            return 0;
        } else {
            errno = E2BIG;
            return -1;
        }
    }

    return -1;
}

static int
ssh_known_hosts_entries_compare(struct ssh_knownhosts_entry *k1,
                                struct ssh_knownhosts_entry *k2)
{
    int cmp;

    if (k1 == NULL || k2 == NULL) {
        return 1;
    }

    cmp = strcmp(k1->hostname, k2->hostname);
    if (cmp != 0) {
        return cmp;
    }

    cmp = ssh_key_cmp(k1->publickey, k2->publickey, SSH_KEY_CMP_PUBLIC);
    if (cmp != 0) {
        return cmp;
    }

    cmp = k1->marker != k2->marker;
    if (cmp != 0) {
        return cmp;
    }

    return 0;
}

/* This method reads the known_hosts file referenced by the path
 * in  filename  argument, and entries matching the  match  argument
 * will be added to the list in  entries  argument.
 * If the  entries  list is NULL, it will allocate a new list. Caller
 * is responsible to free it even if an error occurs.
 */
static int ssh_known_hosts_read_entries(const char *match,
                                        const char *filename,
                                        struct ssh_list **entries)
{
    char line[MAX_LINE_SIZE];
    size_t lineno = 0;
    size_t len = 0;
    FILE *fp;
    int rc;

    fp = fopen(filename, "r");
    if (fp == NULL) {
        char err_msg[SSH_ERRNO_MSG_MAX] = {0};
        SSH_LOG(SSH_LOG_TRACE, "Failed to open the known_hosts file '%s': %s",
                filename, ssh_strerror(errno, err_msg, SSH_ERRNO_MSG_MAX));
        /* The missing file is not an error here */
        return SSH_OK;
    }

    if (*entries == NULL) {
        *entries = ssh_list_new();
        if (*entries == NULL) {
            fclose(fp);
            return SSH_ERROR;
        }
    }

    for (rc = known_hosts_read_line(fp, line, sizeof(line), &len, &lineno);
         rc == 0;
         rc = known_hosts_read_line(fp, line, sizeof(line), &len, &lineno)) {
        struct ssh_knownhosts_entry *entry = NULL;
        struct ssh_iterator *it = NULL;
        char *p = NULL;

        if (line[len] != '\n') {
            len = strcspn(line, "\n");
        }
        line[len] = '\0';

        /* Skip leading spaces */
        for (p = line; isspace((int)p[0]); p++);

        /* Skip comments and empty lines */
        if (p[0] == '\0' || p[0] == '#') {
            continue;
        }

        rc = ssh_known_hosts_parse_line(match,
                                        line,
                                        &entry);
        if (rc == SSH_AGAIN) {
            continue;
        } else if (rc != SSH_OK) {
            goto error;
        }

        /* Check for duplicates */
        for (it = ssh_list_get_iterator(*entries);
             it != NULL;
             it = it->next) {
            struct ssh_knownhosts_entry *entry2;
            int cmp;
            entry2 = ssh_iterator_value(struct ssh_knownhosts_entry *, it);
            cmp = ssh_known_hosts_entries_compare(entry, entry2);
            if (cmp == 0) {
                ssh_knownhosts_entry_free(entry);
                entry = NULL;
                break;
            }
        }
        if (entry != NULL) {
            ssh_list_append(*entries, entry);
        }
    }

    fclose(fp);
    return SSH_OK;
error:
    fclose(fp);
    return SSH_ERROR;
}

static char *ssh_session_get_host_port(ssh_session session)
{
    char *host_port;
    char *host;

    if (session->opts.host == NULL) {
        ssh_set_error(session,
                      SSH_FATAL,
                      "Can't verify server in known hosts if the host we "
                      "should connect to has not been set");

        return NULL;
    }

    host = ssh_lowercase(session->opts.host);
    if (host == NULL) {
        ssh_set_error_oom(session);
        return NULL;
    }

    if (session->opts.port == 0 || session->opts.port == 22) {
        host_port = host;
    } else {
        host_port = ssh_hostport(host, session->opts.port);
        SAFE_FREE(host);
        if (host_port == NULL) {
            ssh_set_error_oom(session);
            return NULL;
        }
    }

    return host_port;
}

/**
 * @internal
 * @brief Check which host keys should be preferred for the session.
 *
 * This checks the known_hosts file to find out which algorithms should be
 * preferred for the connection we are going to establish.
 *
 * @param[in]  session  The ssh session to use.
 *
 * @return A list of supported key types, NULL on error.
 */
struct ssh_list *ssh_known_hosts_get_algorithms(ssh_session session)
{
    struct ssh_list *entry_list = NULL;
    struct ssh_iterator *it = NULL;
    char *host_port = NULL;
    size_t count;
    struct ssh_list *list = NULL;
    int list_error = 0;
    int rc;

    if (session->opts.knownhosts == NULL ||
        session->opts.global_knownhosts == NULL) {
        if (ssh_options_apply(session) < 0) {
            ssh_set_error(session,
                          SSH_REQUEST_DENIED,
                          "Can't find a known_hosts file");

            return NULL;
        }
    }

    host_port = ssh_session_get_host_port(session);
    if (host_port == NULL) {
        return NULL;
    }

    list = ssh_list_new();
    if (list == NULL) {
        ssh_set_error_oom(session);
        SAFE_FREE(host_port);
        return NULL;
    }

    rc = ssh_known_hosts_read_entries(host_port,
                                      session->opts.knownhosts,
                                      &entry_list);
    if (rc != 0) {
        ssh_list_free(entry_list);
        ssh_list_free(list);
        return NULL;
    }

    rc = ssh_known_hosts_read_entries(host_port,
                                      session->opts.global_knownhosts,
                                      &entry_list);
    SAFE_FREE(host_port);
    if (rc != 0) {
        ssh_list_free(entry_list);
        ssh_list_free(list);
        return NULL;
    }

    if (entry_list == NULL) {
        ssh_list_free(list);
        return NULL;
    }

    count = ssh_list_count(entry_list);
    if (count == 0) {
        ssh_list_free(list);
        ssh_list_free(entry_list);
        return NULL;
    }

    for (it = ssh_list_get_iterator(entry_list);
         it != NULL;
         it = ssh_list_get_iterator(entry_list)) {
        struct ssh_iterator *it2 = NULL;
        struct ssh_knownhosts_entry *entry = NULL;
        const char *algo = NULL;
        bool present = false;

        entry = ssh_iterator_value(struct ssh_knownhosts_entry *, it);
        algo = entry->publickey->type_c;

        /* Check for duplicates */
        for (it2 = ssh_list_get_iterator(list);
             it2 != NULL;
             it2 = it2->next) {
            char *alg2 = ssh_iterator_value(char *, it2);
            int cmp = strcmp(alg2, algo);
            if (cmp == 0) {
                present = true;
                break;
            }
        }

        /* Add to the new list only if it is unique */
        if (!present) {
            rc = ssh_list_append(list, algo);
            if (rc != SSH_OK) {
               list_error = 1;
            }
        }

        ssh_knownhosts_entry_free(entry);
        ssh_list_remove(entry_list, it);
    }
    ssh_list_free(entry_list);
    if (list_error) {
        goto error;
    }

    return list;
error:
    ssh_list_free(list);
    return NULL;
}

/**
 * @internal
 *
 * @brief   Returns a static string containing a list of the signature types the
 * given key type can generate.
 *
 * @returns A static cstring containing the signature types the key is able to
 * generate separated by commas; NULL in case of error
 */
static const char *ssh_known_host_sigs_from_hostkey_type(enum ssh_keytypes_e type)
{
    switch (type) {
    case SSH_KEYTYPE_RSA:
        return "rsa-sha2-512,rsa-sha2-256,ssh-rsa";
    case SSH_KEYTYPE_ED25519:
        return "ssh-ed25519";
    case SSH_KEYTYPE_SK_ED25519:
        return "sk-ssh-ed25519@openssh.com";
#ifdef HAVE_ECC
    case SSH_KEYTYPE_ECDSA_P256:
        return "ecdsa-sha2-nistp256";
    case SSH_KEYTYPE_ECDSA_P384:
        return "ecdsa-sha2-nistp384";
    case SSH_KEYTYPE_ECDSA_P521:
        return "ecdsa-sha2-nistp521";
    case SSH_KEYTYPE_SK_ECDSA:
        return "sk-ecdsa-sha2-nistp256@openssh.com";
#else
    case SSH_KEYTYPE_ECDSA_P256:
    case SSH_KEYTYPE_ECDSA_P384:
    case SSH_KEYTYPE_ECDSA_P521:
        SSH_LOG(SSH_LOG_WARN, "ECDSA keys are not supported by this build");
        break;
#endif
    case SSH_KEYTYPE_UNKNOWN:
    default:
        SSH_LOG(SSH_LOG_TRACE,
                "The given type %d is not a base private key type "
                "or is unsupported",
                type);
    }

    return NULL;
}

/**
 * @internal
 * @brief Get the host keys algorithms identifiers from the known_hosts files
 *
 * This expands the signatures types that can be generated from the keys types
 * present in the known_hosts files
 *
 * @param[in]  session  The ssh session to use.
 *
 * @return A newly allocated cstring containing a list of signature algorithms
 * that can be generated by the host using the keys listed in the known_hosts
 * files, NULL on error.
 */
char *ssh_known_hosts_get_algorithms_names(ssh_session session)
{
    char methods_buffer[256 + 1] = {0};
    struct ssh_list *entry_list = NULL;
    struct ssh_iterator *it = NULL;
    char *host_port = NULL;
    size_t count;
    bool needcomma = false;
    char *names;

    int rc;

    if (session->opts.knownhosts == NULL ||
        session->opts.global_knownhosts == NULL) {
        if (ssh_options_apply(session) < 0) {
            ssh_set_error(session,
                          SSH_REQUEST_DENIED,
                          "Can't find a known_hosts file");

            return NULL;
        }
    }

    host_port = ssh_session_get_host_port(session);
    if (host_port == NULL) {
        return NULL;
    }

    rc = ssh_known_hosts_read_entries(host_port,
                                      session->opts.knownhosts,
                                      &entry_list);
    if (rc != 0) {
        SAFE_FREE(host_port);
        ssh_list_free(entry_list);
        return NULL;
    }

    rc = ssh_known_hosts_read_entries(host_port,
                                      session->opts.global_knownhosts,
                                      &entry_list);
    SAFE_FREE(host_port);
    if (rc != 0) {
        ssh_list_free(entry_list);
        return NULL;
    }

    if (entry_list == NULL) {
        return NULL;
    }

    count = ssh_list_count(entry_list);
    if (count == 0) {
        ssh_list_free(entry_list);
        return NULL;
    }

    for (it = ssh_list_get_iterator(entry_list);
         it != NULL;
         it = ssh_list_get_iterator(entry_list))
    {
        struct ssh_knownhosts_entry *entry = NULL;
        const char *algo = NULL;

        entry = ssh_iterator_value(struct ssh_knownhosts_entry *, it);

        /*
         * Skip keys algorithm with CA marker since any CA key type can sign
         * certificates. There are no preferred algorithms for certificates
         * when encountering a CA signing key in the known_hosts file.
         */
        if (entry->marker == MARK_CA) {
            SSH_LOG(SSH_LOG_TRACE, "CA key found. Skipping key algorithm "
                                   "for host key algorithms negotiation");
            ssh_knownhosts_entry_free(entry);
            ssh_list_remove(entry_list, it);
            continue;
        } else if (entry->marker == MARK_REVOKED) {
            SSH_LOG(SSH_LOG_TRACE, "Revoked key found. Skipping key algorithm "
                                   "for host key algorithms negotiation");
            ssh_knownhosts_entry_free(entry);
            ssh_list_remove(entry_list, it);
            continue;
        }

        algo = ssh_known_host_sigs_from_hostkey_type(entry->publickey->type);
        if (algo == NULL) {
            ssh_knownhosts_entry_free(entry);
            ssh_list_remove(entry_list, it);
            continue;
        }

        if (needcomma) {
            strncat(methods_buffer,
                    ",",
                    sizeof(methods_buffer) - strlen(methods_buffer) - 1);
        }

        strncat(methods_buffer,
                algo,
                sizeof(methods_buffer) - strlen(methods_buffer) - 1);
        needcomma = true;

        ssh_knownhosts_entry_free(entry);
        ssh_list_remove(entry_list, it);
    }

    ssh_list_free(entry_list);

    names = ssh_remove_duplicates(methods_buffer);

    return names;
}

/**
 * @brief Get the enum type of a marker given a C string.
 *
 * @param[in]  marker    The string containing the marker name.
 *
 * @return the enum type of the marker on success.
 * @eturn -1 if the marker argument is NULL.
 */
static int
ssh_known_hosts_marker_from_name(const char *marker)
{
    if (marker == NULL) {
        return -1;
    }

    if (strcmp(marker, "@cert-authority") == 0) {
        return MARK_CA;
    } else if (strcmp(marker, "@revoked") == 0) {
        return MARK_REVOKED;
    } else {
        return MARK_UNKNOWN;
    }
}

/**
 * @brief Parse a line from a known_hosts entry into a structure
 *
 * This parses a known_hosts entry into a structure with the key in a libssh
 * consumeable form. You can use the PKI key function to further work with it.
 *
 * @param[in]  hostname     The hostname to match the line to
 *
 * @param[in]  line         The line to compare and parse if we have a hostname
 *                          match.
 *
 * @param[in]  entry        A pointer to store the allocated known_hosts
 *                          entry structure. The user needs to free the memory
 *                          using SSH_KNOWNHOSTS_ENTRY_FREE().
 *
 * @return SSH_OK on success, SSH_AGAIN if the hostname does not match the line,
 * SSH_ERROR otherwise.
 */
int ssh_known_hosts_parse_line(const char *hostname,
                               const char *line,
                               struct ssh_knownhosts_entry **entry)
{
    struct ssh_knownhosts_entry *e = NULL;
    char *keyword = NULL;
    char *p = NULL;
    char *save_tok = NULL, *save_tok2 = NULL;
    char *host_list = NULL;
    enum ssh_keytypes_e key_type;
    int match = 0;
    int rc = SSH_OK;

    keyword = strdup(line);
    if (keyword == NULL) {
        return SSH_ERROR;
    }

    /* Check for marker */
    p = strtok_r(keyword, " ", &save_tok);
    if (p == NULL ) {
        SAFE_FREE(keyword);
        return SSH_ERROR;
    }

    e = calloc(1, sizeof(struct ssh_knownhosts_entry));
    if (e == NULL) {
        SSH_LOG(SSH_LOG_WARN, "Memory allocation failure");
        SAFE_FREE(keyword);
        return SSH_ERROR;
    }

    if (p[0] == '@') {
        rc = ssh_known_hosts_marker_from_name(p);
        /* rc should never be -1 because p can't be NULL at this point */
        if (rc == MARK_UNKNOWN) {
            SSH_LOG(SSH_LOG_WARN, "Unknown marker: %s", p);
            rc = SSH_ERROR;
            goto out;
        }
        e->marker = rc;

        /* Move the pointer and get the next tok */
        p = strtok_r(NULL, " ", &save_tok);
        if (p == NULL) {
            rc = SSH_ERROR;
            goto out;
        }
    }

    host_list = strdup(p);
    if (host_list == NULL) {
        SSH_LOG(SSH_LOG_WARN, "Memory allocation failure");
        rc = SSH_ERROR;
        goto out;
    }

    if (hostname != NULL) {
        char *host_port = NULL;
        char *q = NULL;

        /* Hashed */
        if (p[0] == '|') {
            match = match_hashed_hostname(hostname, p);
        }

        for (q = strtok_r(p, ",", &save_tok2);
             q != NULL;
             q = strtok_r(NULL, ",", &save_tok2)) {
            int cmp;

            if (q[0] == '[' && hostname[0] != '[') {
                /* Corner case: We have standard port so we do not have
                 * hostname in square braces. But the pattern is enclosed
                 * in braces with, possibly standard or wildcard, port.
                 * We need to test against [host]:port pair here.
                 */
                if (host_port == NULL) {
                    host_port = ssh_hostport(hostname, 22);
                    if (host_port == NULL) {
                        SAFE_FREE(host_list);
                        rc = SSH_ERROR;
                        goto out;
                    }
                }

                cmp = match_hostname(host_port, q, strlen(q));
            } else {
                cmp = match_hostname(hostname, q, strlen(q));
            }
            if (cmp == 1) {
                match = 1;
                break;
            }
        }
        SAFE_FREE(host_port);

        if (match == 0) {
            SAFE_FREE(host_list);
            rc = SSH_AGAIN;
            goto out;
        }

        e->hostname = strdup(hostname);
        if (e->hostname == NULL) {
            SSH_LOG(SSH_LOG_WARN, "Memory allocation failure");
            SAFE_FREE(host_list);
            rc = SSH_ERROR;
            goto out;
        }
    }

    e->unparsed = host_list;

    /* pubkey type */
    p = strtok_r(NULL, " ", &save_tok);
    if (p == NULL) {
        rc = SSH_ERROR;
        goto out;
    }

    key_type = ssh_key_type_from_name(p);
    if (key_type == SSH_KEYTYPE_UNKNOWN) {
        SSH_LOG(SSH_LOG_TRACE, "key type '%s' unknown!", p);
        rc = SSH_ERROR;
        goto out;
    }

    /* public key */
    p = strtok_r(NULL, " ", &save_tok);
    if (p == NULL) {
        rc = SSH_ERROR;
        goto out;
    }

    rc = ssh_pki_import_pubkey_base64(p,
                                      key_type,
                                      &e->publickey);
    if (rc != SSH_OK) {
        SSH_LOG(SSH_LOG_TRACE,
                "Failed to parse %s key for entry: %s!",
                ssh_key_type_to_char(key_type),
                e->unparsed);
        rc = SSH_ERROR;
        goto out;
    }

    /* comment */
    p = strtok_r(NULL, " ", &save_tok);
    if (p != NULL) {
        p = strstr(line, p);
        if (p != NULL) {
            e->comment = strdup(p);
            if (e->comment == NULL) {
                SSH_LOG(SSH_LOG_WARN, "Memory allocation failure");
                rc = SSH_ERROR;
                goto out;
            }
        }
    }

    *entry = e;

    SAFE_FREE(keyword);
    return SSH_OK;
out:
    SAFE_FREE(keyword);
    SSH_KNOWNHOSTS_ENTRY_FREE(e);
    return rc;
}

/**
 * @brief Check if the set hostname and port match an entry in known_hosts.
 *
 * This check if the set hostname and port have an entry in the known_hosts file.
 * You need to set at least the hostname using ssh_options_set().
 *
 * @param[in]  session  The session with the values set to check.
 *
 * @return A ssh_known_hosts_e return value.
 */
enum ssh_known_hosts_e ssh_session_has_known_hosts_entry(ssh_session session)
{
    struct ssh_list *entry_list = NULL;
    struct ssh_iterator *it = NULL;
    char *host_port = NULL;
    bool global_known_hosts_found = false;
    bool known_hosts_found = false;
    int rc;

    if (session->opts.knownhosts == NULL) {
        if (ssh_options_apply(session) < 0) {
            ssh_set_error(session,
                          SSH_REQUEST_DENIED,
                          "Cannot find a known_hosts file");

            return SSH_KNOWN_HOSTS_NOT_FOUND;
        }
    }

    if (session->opts.knownhosts == NULL &&
        session->opts.global_knownhosts == NULL) {
            ssh_set_error(session,
                          SSH_REQUEST_DENIED,
                          "No path set for a known_hosts file");

            return SSH_KNOWN_HOSTS_NOT_FOUND;
    }

    if (session->opts.knownhosts != NULL) {
        known_hosts_found = ssh_file_readaccess_ok(session->opts.knownhosts);
        if (!known_hosts_found) {
            SSH_LOG(SSH_LOG_TRACE, "Cannot access file %s",
                    session->opts.knownhosts);
        }
    }

    if (session->opts.global_knownhosts != NULL) {
        global_known_hosts_found =
                ssh_file_readaccess_ok(session->opts.global_knownhosts);
        if (!global_known_hosts_found) {
            SSH_LOG(SSH_LOG_TRACE, "Cannot access file %s",
                    session->opts.global_knownhosts);
        }
    }

    if ((!known_hosts_found) && (!global_known_hosts_found)) {
        ssh_set_error(session,
                      SSH_REQUEST_DENIED,
                      "Cannot find a known_hosts file");

        return SSH_KNOWN_HOSTS_NOT_FOUND;
    }

    host_port = ssh_session_get_host_port(session);
    if (host_port == NULL) {
        return SSH_KNOWN_HOSTS_ERROR;
    }

    if (known_hosts_found) {
        rc = ssh_known_hosts_read_entries(host_port,
                                          session->opts.knownhosts,
                                          &entry_list);
        if (rc != 0) {
            SAFE_FREE(host_port);
            ssh_list_free(entry_list);
            return SSH_KNOWN_HOSTS_ERROR;
        }
    }

    if (global_known_hosts_found) {
        rc = ssh_known_hosts_read_entries(host_port,
                                          session->opts.global_knownhosts,
                                          &entry_list);
        if (rc != 0) {
            SAFE_FREE(host_port);
            ssh_list_free(entry_list);
            return SSH_KNOWN_HOSTS_ERROR;
        }
    }

    SAFE_FREE(host_port);

    if (ssh_list_count(entry_list) == 0) {
        ssh_list_free(entry_list);
        return SSH_KNOWN_HOSTS_UNKNOWN;
    }

    for (it = ssh_list_get_iterator(entry_list);
         it != NULL;
         it = ssh_list_get_iterator(entry_list)) {
        struct ssh_knownhosts_entry *entry = NULL;

        entry = ssh_iterator_value(struct ssh_knownhosts_entry *, it);
        ssh_knownhosts_entry_free(entry);
        ssh_list_remove(entry_list, it);
    }
    ssh_list_free(entry_list);

    return SSH_KNOWN_HOSTS_OK;
}

/**
 * @brief Export the current session information to a known_hosts string.
 *
 * This exports the current information of a session which is connected so a
 * ssh server into an entry line which can be added to a known_hosts file.
 *
 * @param[in]  session  The session with information to export.
 *
 * @param[in]  pentry_string A pointer to a string to store the allocated
 *                           line of the entry. The user must free it using
 *                           ssh_string_free_char().
 *
 * @return SSH_OK on success, SSH_ERROR otherwise.
 */
int ssh_session_export_known_hosts_entry(ssh_session session,
                                         char **pentry_string)
{
    ssh_key server_pubkey = NULL;
    char *host = NULL;
    char entry_buf[MAX_LINE_SIZE] = {0};
    char *b64_key = NULL;
    int rc;

    if (pentry_string == NULL) {
        ssh_set_error_invalid(session);
        return SSH_ERROR;
    }

    if (session->opts.host == NULL) {
        ssh_set_error(session, SSH_FATAL,
                      "Can't create known_hosts entry - hostname unknown");
        return SSH_ERROR;
    }

    host = ssh_session_get_host_port(session);
    if (host == NULL) {
        return SSH_ERROR;
    }

    if (session->current_crypto == NULL) {
        ssh_set_error(session, SSH_FATAL,
                      "No current crypto context, please connect first");
        SAFE_FREE(host);
        return SSH_ERROR;
    }

    server_pubkey = ssh_dh_get_current_server_publickey(session);
    if (server_pubkey == NULL){
        ssh_set_error(session, SSH_FATAL, "No public key present");
        SAFE_FREE(host);
        return SSH_ERROR;
    }

    rc = ssh_pki_export_pubkey_base64(server_pubkey, &b64_key);
    if (rc < 0) {
        SAFE_FREE(host);
        return SSH_ERROR;
    }

    snprintf(entry_buf, sizeof(entry_buf),
                "%s %s %s\n",
                host,
                server_pubkey->type_c,
                b64_key);

    SAFE_FREE(host);
    SAFE_FREE(b64_key);

    *pentry_string = strdup(entry_buf);
    if (*pentry_string == NULL) {
        return SSH_ERROR;
    }

    return SSH_OK;
}

/**
 * @brief Adds the currently connected server to the user known_hosts file.
 *
 * This adds the currently connected server to the known_hosts file by
 * appending a new line at the end. The global known_hosts file is considered
 * read-only so it is not touched by this function.
 *
 * @param[in]  session  The session to use to write the entry.
 *
 * @return SSH_OK on success, SSH_ERROR otherwise.
 */
int ssh_session_update_known_hosts(ssh_session session)
{
    FILE *fp = NULL;
    char *entry = NULL;
    char *dir = NULL;
    size_t nwritten;
    size_t len;
    int rc;
    char err_msg[SSH_ERRNO_MSG_MAX] = {0};

    if (session->opts.knownhosts == NULL) {
        rc = ssh_options_apply(session);
        if (rc != SSH_OK) {
            ssh_set_error(session, SSH_FATAL, "Can't find a known_hosts file");
            return SSH_ERROR;
        }
    }

    errno = 0;
    fp = fopen(session->opts.knownhosts, "a");
    if (fp == NULL) {
        if (errno == ENOENT) {
            dir = ssh_dirname(session->opts.knownhosts);
            if (dir == NULL) {
                ssh_set_error(session, SSH_FATAL, "%s",
                              ssh_strerror(errno, err_msg, SSH_ERRNO_MSG_MAX));
                return SSH_ERROR;
            }

            rc = ssh_mkdirs(dir, 0700);
            if (rc < 0) {
                ssh_set_error(session, SSH_FATAL,
                              "Cannot create %s directory: %s",
                              dir,
                              ssh_strerror(errno, err_msg, SSH_ERRNO_MSG_MAX));
                SAFE_FREE(dir);
                return SSH_ERROR;
            }
            SAFE_FREE(dir);

            errno = 0;
            fp = fopen(session->opts.knownhosts, "a");
            if (fp == NULL) {
                ssh_set_error(session, SSH_FATAL,
                              "Couldn't open known_hosts file %s"
                              " for appending: %s",
                              session->opts.knownhosts,
                              ssh_strerror(errno, err_msg, SSH_ERRNO_MSG_MAX));
                return SSH_ERROR;
            }
        } else {
            ssh_set_error(session, SSH_FATAL,
                          "Couldn't open known_hosts file %s for appending: %s",
                          session->opts.knownhosts, strerror(errno));
            return SSH_ERROR;
        }
    }

    rc = ssh_session_export_known_hosts_entry(session, &entry);
    if (rc != SSH_OK) {
        fclose(fp);
        return rc;
    }

    len = strlen(entry);
    nwritten = fwrite(entry, sizeof(char), len, fp);
    SAFE_FREE(entry);
    if (nwritten != len || ferror(fp)) {
        ssh_set_error(session, SSH_FATAL,
                      "Couldn't append to known_hosts file %s: %s",
                      session->opts.knownhosts,
                      ssh_strerror(errno, err_msg, SSH_ERRNO_MSG_MAX));
        fclose(fp);
        return SSH_ERROR;
    }

    fclose(fp);
    return SSH_OK;
}

static enum ssh_known_hosts_e
ssh_known_hosts_check_server_key(const char *hosts_entry,
                                 const char *filename,
                                 ssh_key server_key,
                                 struct ssh_knownhosts_entry **pentry)
{
    struct ssh_list *entry_list = NULL;
    struct ssh_iterator *it = NULL;
    enum ssh_known_hosts_e found = SSH_KNOWN_HOSTS_UNKNOWN;
    struct ssh_knownhosts_entry *initial_entry = NULL;
    int rc, with_marker;
    bool check_revoked;

    /*
     * Save the initial value of *pentry. If a revoked entry is found after
     * setting a prior valid entry to *pentry, we will revert *pentry back
     * to this initial value.
     */
    if (pentry != NULL) {
        initial_entry = *pentry;
    }

    rc = ssh_known_hosts_read_entries(hosts_entry,
                                      filename,
                                      &entry_list);
    if (rc != 0) {
        ssh_list_free(entry_list);
        return SSH_KNOWN_HOSTS_UNKNOWN;
    }

    it = ssh_list_get_iterator(entry_list);
    if (it == NULL) {
        ssh_list_free(entry_list);
        return SSH_KNOWN_HOSTS_UNKNOWN;
    }

    /*
     * If the server key is a certificate then the following loop should
     * check only @cert-authority marked keys.
     */
    with_marker = is_cert_type(server_key->type) ? MARK_CA : MARK_NONE;

    for (;it != NULL; it = it->next) {
        struct ssh_knownhosts_entry *entry = NULL;
        int cmp;

        entry = ssh_iterator_value(struct ssh_knownhosts_entry *, it);
        check_revoked = (entry->marker == MARK_REVOKED);

        /*
         * Skip the entry if the marker is not required, except for the @revoked
         * marker. When @revoked is encountered, proceed with the comparison
         * to verify that the server key is not revoked.
         */
        if (!check_revoked && entry->marker != with_marker) {
            continue;
        }

        if (is_cert_type(server_key->type)) {
            /* with certificates check the signature key */
            cmp = ssh_key_cmp(server_key->cert_data->signature_key,
                              entry->publickey,
                              SSH_KEY_CMP_PUBLIC);
        } else {
            /* plain keys */
            cmp = ssh_key_cmp(server_key, entry->publickey, SSH_KEY_CMP_PUBLIC);
        }

        /*
         * Don't break even if a match is found in order to check the remaining
         * entries that could revoke a valid key.
         * Without breaking here we don't need to traverse again the entries
         * list searching for revoking matches.
         */
        if (cmp == 0) {
            found = check_revoked ?
                                  SSH_KNOWN_HOSTS_REVOKED : SSH_KNOWN_HOSTS_OK;
            if (pentry != NULL) {
                *pentry = entry;
            }

            /*
             * Only if the key is revoked we break. If the key is revoked
             * then *pentry should be set to the initial value overriding
             * previous assigned entry since it is not valid anymore.
             */
            if (found == SSH_KNOWN_HOSTS_REVOKED) {
                if (pentry != NULL) {
                    *pentry = initial_entry;
                }
                break;
            }
        }

        if (ssh_key_type(server_key) == ssh_key_type(entry->publickey)
            && found != SSH_KNOWN_HOSTS_OK) {
            found = SSH_KNOWN_HOSTS_CHANGED;
            continue;
        }

        if (found != SSH_KNOWN_HOSTS_CHANGED && found != SSH_KNOWN_HOSTS_OK) {
            found = SSH_KNOWN_HOSTS_OTHER;
        }
    }

    for (it = ssh_list_get_iterator(entry_list);
         it != NULL;
         it = ssh_list_get_iterator(entry_list)) {
        struct ssh_knownhosts_entry *entry = NULL;

        entry = ssh_iterator_value(struct ssh_knownhosts_entry *, it);
        ssh_knownhosts_entry_free(entry);
        ssh_list_remove(entry_list, it);
    }
    ssh_list_free(entry_list);

    return found;
}

/**
 * @brief Get the known_hosts entry for the currently connected session.
 *
 * @param[in]  session  The session to validate.
 *
 * @param[in]  pentry   A pointer to store the allocated known hosts entry.
 *
 * @returns SSH_KNOWN_HOSTS_OK:        The server is known and has not changed.\n
 *          SSH_KNOWN_HOSTS_CHANGED:   The server key has changed. Either you
 *                                     are under attack or the administrator
 *                                     changed the key. You HAVE to warn the
 *                                     user about a possible attack.\n
 *          SSH_KNOWN_HOSTS_OTHER:     The server gave use a key of a type while
 *                                     we had an other type recorded. It is a
 *                                     possible attack.\n
 *          SSH_KNOWN_HOSTS_UNKNOWN:   The server is unknown. User should
 *                                     confirm the public key hash is correct.\n
 *          SSH_KNOWN_HOSTS_NOT_FOUND: The known host file does not exist. The
 *                                     host is thus unknown. File will be
 *                                     created if host key is accepted.\n
 *          SSH_KNOWN_HOSTS_REVOKED:   The server key is revoked and not valid
 *                                     anymore. A revoked key may indicate that
 *                                     a stolen key is being used to impersonate
 *                                     the host. Always WARN the user about a
 *                                     possible attack.\n
 *          SSH_KNOWN_HOSTS_ERROR:     There had been an error checking the host.
 *
 * @see ssh_knownhosts_entry_free()
 */
enum ssh_known_hosts_e
ssh_session_get_known_hosts_entry(ssh_session session,
                                  struct ssh_knownhosts_entry **pentry)
{
    enum ssh_known_hosts_e old_rv, rv = SSH_KNOWN_HOSTS_UNKNOWN;

    if (session->opts.knownhosts == NULL) {
        if (ssh_options_apply(session) < 0) {
            ssh_set_error(session,
                          SSH_REQUEST_DENIED,
                          "Can't find a known_hosts file");

            return SSH_KNOWN_HOSTS_NOT_FOUND;
        }
    }

    rv = ssh_session_get_known_hosts_entry_file(session,
                                                session->opts.knownhosts,
                                                pentry);
    if (rv == SSH_KNOWN_HOSTS_OK) {
        /* We already found a match in the first file: return */
        return rv;
    }

    old_rv = rv;
    rv = ssh_session_get_known_hosts_entry_file(session,
                                                session->opts.global_knownhosts,
                                                pentry);

    /* If we did not find any match at all:  we report the previous result */
    if (rv == SSH_KNOWN_HOSTS_UNKNOWN) {
        if (session->opts.StrictHostKeyChecking == 0) {
            return SSH_KNOWN_HOSTS_OK;
        }
        return old_rv;
    }

    /* We found some match: return it */
    return rv;

}

/**
 * @brief Get the known_hosts entry for the current connected session
 *        from the given known_hosts file.
 *
 * @param[in]  session  The session to validate.
 *
 * @param[in]  filename The filename to parse.
 *
 * @param[in]  pentry   A pointer to store the allocated known hosts entry.
 *
 * @returns SSH_KNOWN_HOSTS_OK:        The server is known and has not changed.\n
 *          SSH_KNOWN_HOSTS_CHANGED:   The server key has changed. Either you
 *                                     are under attack or the administrator
 *                                     changed the key. You HAVE to warn the
 *                                     user about a possible attack.\n
 *          SSH_KNOWN_HOSTS_OTHER:     The server gave use a key of a type while
 *                                     we had an other type recorded. It is a
 *                                     possible attack.\n
 *          SSH_KNOWN_HOSTS_UNKNOWN:   The server is unknown. User should
 *                                     confirm the public key hash is correct.\n
 *          SSH_KNOWN_HOSTS_NOT_FOUND: The known host file does not exist. The
 *                                     host is thus unknown. File will be
 *                                     created if host key is accepted.\n
 *          SSH_KNOWN_HOSTS_REVOKED:   The server key is revoked and not valid
 *                                     anymore. A revoked key may indicate that
 *                                     a stolen key is being used to impersonate
 *                                     the host. Always WARN the user about a
 *                                     possible attack.\n
 *          SSH_KNOWN_HOSTS_ERROR:     There had been an error checking the host.
 *
 * @see ssh_knownhosts_entry_free()
 */
enum ssh_known_hosts_e
ssh_session_get_known_hosts_entry_file(ssh_session session,
                                       const char *filename,
                                       struct ssh_knownhosts_entry **pentry)
{
    ssh_key server_pubkey = NULL;
    char *host_port = NULL;
    enum ssh_known_hosts_e found = SSH_KNOWN_HOSTS_UNKNOWN;

    server_pubkey = ssh_dh_get_current_server_publickey(session);
    if (server_pubkey == NULL) {
        ssh_set_error(session,
                      SSH_FATAL,
                      "ssh_session_is_known_host called without a "
                      "server_key!");

        return SSH_KNOWN_HOSTS_ERROR;
    }

    host_port = ssh_session_get_host_port(session);
    if (host_port == NULL) {
        return SSH_KNOWN_HOSTS_ERROR;
    }

    found = ssh_known_hosts_check_server_key(host_port,
                                             filename,
                                             server_pubkey,
                                             pentry);
    SAFE_FREE(host_port);

    return found;
}

/**
 * @brief Check if the servers public key for the connected session is known.
 *
 * This checks if we already know the public key of the server we want to
 * connect to. It checks also if the server public key is not revoked. If it is
 * a certificate then it checks its validity based on the CA that signed it and
 * on its specifications. This allows to detect if there is a MITM attack going
 * on or if there have been changes on the server we don't know about.
 *
 * @param[in]  session  The SSH to validate.
 *
 * @returns SSH_KNOWN_HOSTS_OK:        The server is known and has not changed.\n
 *          SSH_KNOWN_HOSTS_CHANGED:   The server key has changed. Either you
 *                                     are under attack or the administrator
 *                                     changed the key. You HAVE to warn the
 *                                     user about a possible attack.\n
 *          SSH_KNOWN_HOSTS_OTHER:     The server gave use a key of a type while
 *                                     we had an other type recorded. It is a
 *                                     possible attack.\n
 *          SSH_KNOWN_HOSTS_UNKNOWN:   The server is unknown. User should
 *                                     confirm the public key hash is correct.\n
 *          SSH_KNOWN_HOSTS_NOT_FOUND: The known host file does not exist. The
 *                                     host is thus unknown. File will be
 *                                     created if host key is accepted.\n
 *          SSH_KNOWN_HOSTS_REVOKED:   The server key is revoked and not valid
 *                                     anymore. A revoked key may indicate that
 *                                     a stolen key is being used to impersonate
 *                                     the host. Always WARN the user about a
 *                                     possible attack.\n
 *          SSH_KNOWN_HOSTS_ERROR:     There had been an error checking the host.
 */
enum ssh_known_hosts_e ssh_session_is_known_server(ssh_session session)
{
    ssh_key server_pubkey = NULL;
    char *host_port = NULL, *server_fp = NULL, *ca_fp = NULL;
    int known_host_status, with_cert, rc;
    unsigned int i;

    server_pubkey = ssh_dh_get_current_server_publickey(session);
    if (server_pubkey == NULL) {
        ssh_set_error(session,
                      SSH_FATAL,
                      "ssh_session_is_known_host called without a "
                      "server_key!");
        known_host_status = SSH_KNOWN_HOSTS_ERROR;
        goto out;
    }
    with_cert = is_cert_type(server_pubkey->type);

    host_port = ssh_session_get_host_port(session);
    if (host_port == NULL) {
        known_host_status = SSH_KNOWN_HOSTS_ERROR;
        goto out;
    }

    /* Verbose logging of the server public key info */
    server_fp  = ssh_pki_get_pubkey_fingerprint(server_pubkey,
                                               SSH_PUBLICKEY_HASH_SHA256);
    if (server_fp == NULL) {
        SSH_LOG(SSH_LOG_TRACE, "Error while retrieving host key fingerprint");
        known_host_status = SSH_KNOWN_HOSTS_ERROR;
        goto out;
    }

    if (with_cert) {
        ca_fp =
            ssh_pki_get_pubkey_fingerprint(server_pubkey->cert_data->signature_key,
                                           SSH_PUBLICKEY_HASH_SHA256);
        if (ca_fp == NULL) {
            SSH_LOG(SSH_LOG_TRACE, "Error while retrieving CA key fingerprint");
            known_host_status = SSH_KNOWN_HOSTS_ERROR;
            goto out;
        }

        SSH_LOG(SSH_LOG_DEBUG,
                "Server host certificate: %s %s, serial %"PRIu64", "
                "ID \"%s\", CA %s %s",
                server_pubkey->type_c,
                server_fp,
                server_pubkey->cert_data->serial,
                server_pubkey->cert_data->key_id,
                server_pubkey->cert_data->signature_key->type_c,
                ca_fp);
        for (i = 0; i < server_pubkey->cert_data->n_principals; i++) {
            SSH_LOG(SSH_LOG_DEBUG,
                    "Server host certificate principal: %s",
                    server_pubkey->cert_data->principals[i]);
        }
    } else {
        SSH_LOG(SSH_LOG_DEBUG,
                "Server host public key: %s %s",
                server_pubkey->type_c,
                server_fp);
    }

    /*
     * Check if the host key is revoked by RevokedHostKeys file, if defined.
     * If the key is revoked we immediately refuse it before even checking if
     * it is known by the known_hosts file.
     */
    if (session->opts.revoked_host_keys != NULL) {
        rc = ssh_pki_key_is_revoked(server_pubkey,
                                    session->opts.revoked_host_keys);
        if (rc) {
            SSH_LOG(SSH_LOG_TRACE,
                    "Rejecting host key: %s %s. The key is revoked by file %s",
                    server_pubkey->type_c,
                    server_fp,
                    session->opts.revoked_host_keys);
            known_host_status = SSH_KNOWN_HOSTS_REVOKED;
            goto out;
        } else if (rc == -1) {
            SSH_LOG(SSH_LOG_TRACE,
                    "Error while checking host key %s %s "
                    "in revoked keys file %s",
                    server_pubkey->type_c,
                    server_fp,
                    session->opts.revoked_host_keys);
            known_host_status = SSH_KNOWN_HOSTS_ERROR;
            goto out;
        }
    }

    /* Check if the server public key is known by the known_hosts file */
    known_host_status = ssh_session_get_known_hosts_entry(session, NULL);

    /*
     * If the server pubkey is a certificate and its certification authority
     * known, then it must be validated for the current time and its
     * specifications.
     */
    if (with_cert && known_host_status == SSH_KNOWN_HOSTS_OK) {
        rc = pki_cert_validate(server_pubkey,
                               SSH_CERT_TYPE_HOST,
                               host_port,
                               session->opts.ca_signature_algorithms);
        if (rc == SSH_ERROR) {
            SSH_LOG(SSH_LOG_TRACE,
                    "The host certificate is invalid and has been refused");
            known_host_status = SSH_KNOWN_HOSTS_ERROR;
        }
    }

out:
    SAFE_FREE(host_port);
    SAFE_FREE(server_fp);
    SAFE_FREE(ca_fp);
    return known_host_status;
}

/**
 * @brief Check if the server host name and port for a session match an entry
 * with a specific marker in the known_hosts file.
 *
 * @note You need to set at least the hostname using ssh_options_set().
 *
 * @param[in] session The ssh_session containing known hosts information.
 *
 * @param[in] marker  The marker type to search for.
 *
 * @returns 1 if at least one entry with the specified marker is found.
 * @returns 0 if no such entry is found.
 * @returns SSH_ERROR if an error occurs.
 */
int
ssh_session_find_known_hosts_marker(ssh_session session,
                                    enum ssh_known_hosts_marker_e marker)
{
    struct ssh_list *entry_list = NULL;
    struct ssh_iterator *it = NULL;
    struct ssh_knownhosts_entry *entry = NULL;
    char *host_port = NULL;
    size_t count;
    int rc, rv = 0;

    if (session->opts.knownhosts == NULL ||
        session->opts.global_knownhosts == NULL) {
        if (ssh_options_apply(session) < 0) {
            ssh_set_error(session,
                          SSH_REQUEST_DENIED,
                          "Can't find a known_hosts file");
            return SSH_ERROR;
        }
    }

    host_port = ssh_session_get_host_port(session);
    if (host_port == NULL) {
        return SSH_ERROR;
    }

    rc = ssh_known_hosts_read_entries(host_port,
                                      session->opts.knownhosts,
                                      &entry_list);
    if (rc != 0) {
        ssh_set_error(session,
                      SSH_REQUEST_DENIED,
                      "Error while reading known_hosts entries from %s",
                      session->opts.knownhosts);
        SAFE_FREE(host_port);
        SSH_LIST_FREE(entry_list);
        return SSH_ERROR;
    }

    rc = ssh_known_hosts_read_entries(host_port,
                                      session->opts.global_knownhosts,
                                      &entry_list);
    if (rc != 0) {
        ssh_set_error(session,
                      SSH_REQUEST_DENIED,
                      "Error while reading known_hosts entries from %s",
                      session->opts.global_knownhosts);
        SSH_LIST_FREE(entry_list);
        SAFE_FREE(host_port);
        return SSH_ERROR;
    }

    if (entry_list == NULL) {
        ssh_set_error(session,
                      SSH_REQUEST_DENIED,
                      "known_hosts entry list for %s is NULL",
                      host_port);
        SAFE_FREE(host_port);
        return SSH_ERROR;
    }

    count = ssh_list_count(entry_list);
    if (count == 0) {
        ssh_set_error(session,
                      SSH_REQUEST_DENIED,
                      "known_hosts entry list for %s is empty",
                      host_port);
        SAFE_FREE(host_port);
        SSH_LIST_FREE(entry_list);
        return SSH_ERROR;
    }

    SAFE_FREE(host_port);
    for (it = ssh_list_get_iterator(entry_list);
         it != NULL;
         it = ssh_list_get_iterator(entry_list))
    {
        entry = ssh_iterator_value(struct ssh_knownhosts_entry *, it);

        if (entry->marker == (int)marker) {
            rv = 1;
            /*
             * Don't break here even if the marker has been found.
             * All the remaining list entries need to be freed.
             */
        }

        ssh_knownhosts_entry_free(entry);
        ssh_list_remove(entry_list, it);
    }
    SSH_LIST_FREE(entry_list);

    return rv;
}

/** @} */
