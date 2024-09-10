/*
 * auth_file.c
 * This file is part of the SSH Library
 *
 * Copyright (c) 2024 by Francesco Rollo <eferollo@gmail.com>
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
#include <time.h>

#include "libssh/auth_file.h"
#include "libssh/misc.h"
#include "libssh/token.h"

#define MAX_LINE_SIZE 8192

/**
 * @brief Authorize a remote peer based on the "from" option list.
 *
 * The list format can contain explicit IP addresses, hostnames or a CIDR list.
 * This function tries to match either an IP address or a hostname against the
 * given list.
 *
 * @param[in] list            A comma-separated list of authorized hosts.
 *
 * @param[in] remote_peer_ip  The IP address of the remote peer.
 *
 * @param[in] remote_peer_hostname The hostname of the remote peer.
 *
 * @returns SSH_OK if the peer is authorized.
 * @returns SSH_ERROR otherwise.
 */
static int
authorize_from_option(char *list,
                      const char *remote_peer_ip,
                      const char *remote_peer_hostname)
{
    struct ssh_tokens_st *tokens = NULL;
    char *entry = NULL;
    int i, rc;
    size_t len;

    if (list == NULL || remote_peer_ip == NULL) {
        SSH_LOG(SSH_LOG_TRACE, "Bad arguments");
        return SSH_ERROR;
    }

    len = strlen(list);
    /* First try to find a match against explicit IP addresses */
    rc = match_pattern_list(remote_peer_ip, list, len, 0);
    if (rc) {
        return SSH_OK;
    }

    /*
     * If failed, try a match against explicit hostname.
     * Since hostname and ip address might be the same then perform additional
     * check only if they differ.
     */
    rc = strcmp(remote_peer_ip, remote_peer_hostname);
    if (rc != 0) {
        rc = match_pattern_list(remote_peer_hostname, list, len, 0);
        if (rc) {
            return SSH_OK;
        }
    }

#ifdef _WIN32
    SSH_LOG(SSH_LOG_TRACE,
            "\"from\" option is not supported on Windows. "
            "A match against a CIDR list cannot be verified. Skipping.");
#else

    /*
     * If both matching attempts fail, then try against a CIDR list. Since we
     * don't know if the input list contains only a CIDR list or not, tokenize
     * it and verify the match against each entry, hoping for a CIDR pattern.
     */
    tokens = ssh_tokenize(list, ',');
    if (tokens == NULL) {
        SSH_LOG(SSH_LOG_TRACE, "Error while tokenizing \"from\" option list");
        return SSH_ERROR;
    }

    for (i = 0; tokens->tokens[i] != NULL; i++) {
        entry = tokens->tokens[i];

        /* We don't know the address. Let's derive it with sa_family = -1 */
        rc = match_cidr_address_list(remote_peer_ip, entry, -1);

        if (rc == 1) {
            SSH_LOG(SSH_LOG_TRACE,
                    "%s address matches %s CIDR list entry",
                    remote_peer_ip,
                    entry);
            ssh_tokens_free(tokens);
            return SSH_OK;
        }
    }
    ssh_tokens_free(tokens);
#endif

    return SSH_ERROR;
}

/**
 * @brief Authorize a remote peer based on SSH authentication options.
 *
 * This function verifies if the key or certificate is valid and not expired,
 * and checks the "from" option and "source-address" option if specified.
 *
 * @note When processing an authorized principals line, the authentication
 * options list should NOT include the "cert-authority" option. To prevent
 * this undesired option, pass `false` as the `ca_opt_allowed` argument.
 *
 * @param[in] auth_opts            The ssh_auth_opts to be checked.
 *
 * @param[in] remote_peer_ip       The IP address of the remote peer.
 *
 * @param[in] remote_peer_hostname The hostname of the remote peer.
 *
 * @param[in] with_cert            A boolean indicating whether the peer
 *                                 is using a certificate.
 *
 * @returns SSH_OK if the peer is authorized.
 * @returns SSH_ERROR otherwise.
 */
int
ssh_authorize_authkey_options(struct ssh_auth_options *auth_opts,
                              const char *remote_peer_ip,
                              const char *remote_peer_hostname,
                              bool with_cert)
{
    time_t time_now;
    char datetime[64], err_msg[SSH_ERRNO_MSG_MAX] = {0};
    const char *key_name = with_cert ? "certificate" : "key";
    int rc;

    time_now = time(NULL);
    if (time_now == (time_t)-1) {
        SSH_LOG(SSH_LOG_WARN,
                "Error while retrieving current time: %s",
                ssh_strerror(errno, err_msg, SSH_ERRNO_MSG_MAX));
        return SSH_ERROR;
    }

    /* First check if the key is expired */
    if ((uint64_t)time_now > auth_opts->valid_before) {
        ssh_format_time_to_string(auth_opts->valid_before,
                                  datetime,
                                  sizeof(datetime));
        SSH_LOG(SSH_LOG_WARN,
                "The %s is expired. Valid before: %s",
                key_name,
                datetime);
        return SSH_ERROR;
    }

    /*
     * Check "from" option. No need to log errors (authorize_from_option is
     * already verbose logging them).
     */
    if (auth_opts->authkey_from_addr_host != NULL) {
        rc = authorize_from_option(auth_opts->authkey_from_addr_host,
                                   remote_peer_ip,
                                   remote_peer_hostname);
        if (rc == SSH_ERROR) {
            SSH_LOG(SSH_LOG_WARN,
                    "The %s is valid but the host is not authorized. "
                    "Host: %s, IP: %s refused by option <from=\"%.100s\">",
                    key_name,
                    remote_peer_hostname,
                    remote_peer_ip,
                    auth_opts->authkey_from_addr_host);
            return SSH_ERROR;
        }
    }

    /*
     * Check source-address option. With plain keys this check will never
     * be performed. No need to log errors (match_cidr_address_list is
     * already verbose logging them).
     */
#ifdef _WIN32
    SSH_LOG(SSH_LOG_TRACE,
            "\"source-address\" option is not supported on Windows. "
            "A match against a CIDR list cannot be verified. Skipping.");
    return SSH_ERROR;
#else
    if (auth_opts->cert_source_address != NULL) {
        rc = match_cidr_address_list(remote_peer_ip,
                                     auth_opts->cert_source_address,
                                     -1);
        if (!rc) {
            SSH_LOG(SSH_LOG_WARN,
                    "The certificate is valid but the host is not authorized. "
                    "Host: %s, IP: %s refused by certificate source-address "
                    "option \"%.100s\".",
                    remote_peer_hostname,
                    remote_peer_ip,
                    auth_opts->authkey_from_addr_host);
            return SSH_ERROR;
        }
    }
#endif

    return SSH_OK;
}

/**
 * @brief Checks if any principal in the given certificate matches
 * any entry in the ssh_auth_opts principals.
 *
 * @param[in] cert  The certificate containing principals to be matched.
 *
 * @param[in] opts  The ssh_auth_opts containing principals against which
 *                  the match is performed.
 *
 * @returns 1 if a match is found.
 * @returns 0 otherwise.
 */
static int
match_principals_entries(ssh_cert cert, struct ssh_auth_options *opts)
{
    unsigned int i, j;

    if (cert == NULL || opts == NULL) {
        return 0;
    }

    /* Max 256x256 */
    for (i = 0; i < cert->n_principals; i++) {
        for (j = 0; j < opts->n_cert_principals; j++) {
            if (strcmp(cert->principals[i], opts->cert_principals[j]) == 0) {
                return 1;
            }
        }
    }

    return 0;
}

/**
 * @brief Checks a single line of an authorized keys file for a matching
 * SSH key or certificate.
 *
 * @note If a match is found, it performs further validation based on
 * in-line authentication options and certificate options.
 *
 * @param[in] key The ssh_key to match against.
 *
 * @param[in] cp  The current line from the authorized keys file.
 *
 * @param[in] count The line number in the file, for logging purposes.
 *
 * @param[in] user The username of the user that is trying to authenticate.
 *                 Used for validating certificate principals if applicable
 *
 * @param[out] auth_opts A pointer to store the resulting ssh_auth_opts.
 *
 * @param[in] remote_peer_ip The IP address of the remote peer.
 *
 * @param[in] remote_peer_hostname The hostname of the remote peer.
 *
 * @returns 1 if a matching key is found and authorized.
 * @returns 0 if no match is found or the key is not authorized.
 * @returns -1 on errors.
 */
static int
ssh_authorized_keys_check_line(ssh_key key,
                               char *cp,
                               unsigned int count,
                               const char *user,
                               struct ssh_auth_options **auth_opts,
                               const char *remote_peer_ip,
                               const char *remote_peer_hostname)
{
    int r, cmp = -1, rc = 0, i;
    struct ssh_tokens_st *auth_line_tokens = NULL;
    char *token = NULL, *b64_key = NULL, *authkey_fp = NULL, *key_fp = NULL;
    const char *auth_opts_list = "", *name = NULL;
    struct ssh_auth_options *authkey_opts = NULL, *merged_auth_opts = NULL;
    enum ssh_keytypes_e key_type;
    ssh_key authorized_key = NULL;
    bool with_cert = is_cert_type(key->type);
    bool auth_opts_parsed = false;

    /*
     * Tokenize authorized key line with auth options included. This is needed
     * since there could be options like "command=" option that allow spaces
     * within quotes. Each element on the line is delimited by white space.
     */
    auth_line_tokens = ssh_tokenize_with_auth_options(cp, ' ');
    if (auth_line_tokens == NULL) {
        SSH_LOG(SSH_LOG_TRACE,
                "Error while tokenizing authorized key line %d",
                count);
        return -1;
    }

    /*
     * We are interested to the first two tokens. The first token can be either
     * an auth options list or a key type.
     *
     * - If the first token is an auth options list then the second token should
     * be a key type. In this case we don't break from the loop and check for a
     * known key type. The base64 encoded key will be the tokens[i + 1] value.
     *
     * - If the first token is a known key type then the second token should be
     * a base64 encoded key. In this case we break from the loop and check
     * tokens[i + 1] for the key.
     *
     * Note: proper checking on missing/invalid base64 encoded key is mandatory.
     */
    for (i = 0; i < 2; i++) {
        token = auth_line_tokens->tokens[i];

        key_type = ssh_key_type_from_name(token);
        if (!auth_opts_parsed && key_type == SSH_KEYTYPE_UNKNOWN) {
            /* Don't return now since there could be leading auth options */
            auth_opts_list = token;
            auth_opts_parsed = true;
            continue;
        } else if (key_type == SSH_KEYTYPE_UNKNOWN) {
            SSH_LOG(SSH_LOG_TRACE, "Key type '%s' unknown!", token);
            rc = -1;
            goto out;
        }
        break;
    }

    /* Import the base64 encoded key */
    b64_key = auth_line_tokens->tokens[i + 1];
    if (b64_key == NULL) {
        SSH_LOG(SSH_LOG_TRACE, "Missing base64 encoded key at line %d", count);
        rc = -1;
        goto out;
    }

    r = ssh_pki_import_pubkey_base64(b64_key, key_type, &authorized_key);
    if (r != SSH_OK) {
        SSH_LOG(SSH_LOG_TRACE,
                "Failed to parse %s key, line %d",
                ssh_key_type_to_char(key_type),
                count);
        rc = -1;
        goto out;
    }

    /* Parsing an empty list will return a zero-initialized structure */
    authkey_opts = ssh_auth_options_list_parse(auth_opts_list);
    if (authkey_opts == NULL) {
        SSH_LOG(SSH_LOG_TRACE,
                "Failed while parsing authentication options %s at line %d",
                auth_opts_list,
                count);
        rc = -1;
        goto out;
    }

    if (with_cert && (authkey_opts->opt_flags & CERT_AUTHORITY_OPT)) {
        /* With certificates make sure the auth key is a CA key */
        cmp = ssh_key_cmp(key->cert_data->signature_key,
                          authorized_key,
                          SSH_KEY_CMP_PUBLIC);
    } else if (!(authkey_opts->opt_flags & CERT_AUTHORITY_OPT)) {
        /* With plain keys make sure the auth key is not a CA key */
        cmp = ssh_key_cmp(key, authorized_key, SSH_KEY_CMP_PUBLIC);
    }

    if (cmp == 0) {
        /* Get authkey fingerprint */
        authkey_fp = ssh_pki_get_pubkey_fingerprint(authorized_key,
                                                    SSH_PUBLICKEY_HASH_SHA256);
        if (authkey_fp == NULL) {
            SSH_LOG(SSH_LOG_TRACE,
                    "Error while retrieving authorized key fingerprint");
            SSH_AUTH_OPTS_FREE(authkey_opts);
            rc = -1;
            goto out;
        }

        SSH_LOG(SSH_LOG_DEBUG,
                "line %d: matching %s key found: %s",
                count,
                is_cert_type(key->type) ? "CA" : "",
                authkey_fp);

        /* Get input key fingerprint */
        key_fp = ssh_pki_get_pubkey_fingerprint(key,
                                                SSH_PUBLICKEY_HASH_SHA256);
        if (key_fp == NULL) {
            SSH_LOG(SSH_LOG_TRACE,
                    "Error while retrieving input key fingerprint");
            SSH_AUTH_OPTS_FREE(authkey_opts);
            rc = -1;
            goto out;
        }

        /* If processing a plain key return now */
        if (!with_cert) {
            /* Authorize authentication options before returning */
            rc = ssh_authorize_authkey_options(authkey_opts,
                                               remote_peer_ip,
                                               remote_peer_hostname,
                                               with_cert);
            if (rc != SSH_OK) {
                /* Already verbose logging the reason */
                SSH_LOG(SSH_LOG_TRACE, "Key refused by authentication options");
                SSH_AUTH_OPTS_FREE(authkey_opts);
                rc = 0;
                goto out;
            }

            /* Save auth options */
            *auth_opts = authkey_opts;
            SSH_LOG(SSH_LOG_TRACE, "Accepted key %s %s", key->type_c, key_fp);
            rc = 1;
            goto out;
        }

        /* If processing a certificate merge auth opts, if any */
        merged_auth_opts = ssh_auth_options_merge_cert_opts(key, authkey_opts);
        SSH_AUTH_OPTS_FREE(authkey_opts);
        if (merged_auth_opts == NULL) {
            SSH_LOG(SSH_LOG_TRACE,
                    "Error while merging authentication options between "
                    "option list (line %d) and certificate options",
                    count);
            rc = -1;
            goto out;
        }

        /* Authorize authentication options now */
        rc = ssh_authorize_authkey_options(merged_auth_opts,
                                           remote_peer_ip,
                                           remote_peer_hostname,
                                           with_cert);
        if (rc != SSH_OK) {
            /* Already verbose logging the reason */
            SSH_LOG(SSH_LOG_TRACE,
                    "Certificate refused by authentication options");
            SSH_AUTH_OPTS_FREE(merged_auth_opts);
            rc = 0;
            goto out;
        }

        /*
         * Always prefer user specified principals. If there is no certificate
         * principal matching at least one of the user specified principals
         * then fail immediately.
         */
        if (merged_auth_opts->cert_principals != NULL &&
            !match_principals_entries(key->cert_data, merged_auth_opts)) {
            SSH_LOG(SSH_LOG_TRACE,
                    "No certificate principal matches user specified "
                    "principals at line %d",
                    count);
            SSH_AUTH_OPTS_FREE(merged_auth_opts);
            rc = 0;
            goto out;
        }

        /*
         * Set name to requested user only if the previous principal check did
         * not take place, otherwise leave it to NULL.
         */
        if (merged_auth_opts->cert_principals == NULL) {
            name = user;
        }

        /*
         * Passing a NULL name as argument will skip the principal check since
         * it took place at previous step against the user specified principals.
         */
        rc = pki_cert_check_validity(key, false, name, NULL);
        if (rc != SSH_OK) {
            /* Already verbose logging the reason */
            SSH_AUTH_OPTS_FREE(merged_auth_opts);
            rc = 0;
            goto out;
        }

        SSH_LOG(SSH_LOG_TRACE,
                "Accepted user certificate: %s %s, serial %"PRIu64", "
                "ID \"%s\", CA %s %s",
                key->type_c,
                key_fp,
                key->cert_data->serial,
                key->cert_data->key_id,
                key->cert_data->signature_key->type_c,
                authkey_fp);

        *auth_opts = merged_auth_opts;
        rc = 1;
        goto out;
    }
    SSH_AUTH_OPTS_FREE(authkey_opts);

out:
    ssh_tokens_free(auth_line_tokens);
    SSH_KEY_FREE(authorized_key);
    SAFE_FREE(key_fp);
    SAFE_FREE(authkey_fp);
    return rc;
}

/**
 * @brief Checks a file of authorized keys for a match with a given SSH key.
 *
 * This function reads through a specified authorized_keys file line by line,
 * attempting to match each line against a provided SSH key or certificate.
 * If a matching key is found, the corresponding authentication options are
 * authorized and set.
 *
 * @param[in] key The ssh_key to match against entries in the file.
 *
 * @param[in] filename The path to the authorized keys file.
 *
 * @param[in] user The username of the user that is trying to authenticate.
 *                 Used for validating certificate principals if applicable.
 *
 * @param[out] auth_opts A pointer to store the resulting ssh_auth_opts.
 *
 * @param[in] remote_peer_ip The IP address of the remote peer.
 *
 * @param[in] remote_peer_hostname The hostname of the remote peer.
 *
 * @returns 1 if a matching key is found and authorized.
 * @returns 0 if no match is found or the key is not authorized.
 * @returns -1 on errors.
 */
int
ssh_authorized_keys_check_file(ssh_key key,
                               const char *filename,
                               const char *user,
                               struct ssh_auth_options **auth_opts,
                               const char *remote_peer_ip,
                               const char *remote_peer_hostname)
{
    char line[MAX_LINE_SIZE] = {0};
    unsigned int count = 0;
    FILE *fp = NULL;
    char *cp = NULL;
    int found = 0;

    if (key == NULL || filename == NULL || user == NULL || auth_opts == NULL ||
        remote_peer_ip == NULL || remote_peer_hostname == NULL) {
        SSH_LOG(SSH_LOG_TRACE, "Bad arguments");
        return -1;
    }

    fp = fopen(filename, "r");
    if (fp == NULL) {
        SSH_LOG(SSH_LOG_TRACE,
                "Error while opening authorized keys file %s, %s\n",
                filename,
                strerror(errno));
        return -1;
    }

    SSH_LOG(SSH_LOG_PACKET, "Reading authorized keys file from %s", filename);

    while (fgets(line, sizeof(line), fp) && !found) {
        count++;

        for (cp = line; *cp != '\0'; cp++) {
            if (!isspace(*cp)) {
                break;
            }
        }

        switch (*cp) {
        case '#':
        case '\0':
            continue;
        }

        found = ssh_authorized_keys_check_line(key,
                                               cp,
                                               count,
                                               user,
                                               auth_opts,
                                               remote_peer_ip,
                                               remote_peer_hostname);
        if (found < 0) {
            fclose(fp);
            return -1;
        }
    }

    if (ferror(fp)) {
        SSH_LOG(SSH_LOG_TRACE, "Error while reading file at line %d", count);
        return -1;
    }

    fclose(fp);
    return found;
}

/**
 * @brief Checks a single line of an authorized principals file for
 * a matching certificate principal.
 *
 * @note If a match is found, it performs further validation based on
 * in-line authentication options and certificate options.
 *
 * @param[in] cert The ssh_key certificate containing principals to be checked.
 *
 * @param[in] cp The current line from the authorized principals file.
 *
 * @param[in] count The line number in the file, for logging purposes.
 *
 * @param[out] auth_opts A pointer to store the resulting ssh_auth_opts.
 *
 * @param[in] remote_peer_ip The IP address of the remote peer.
 *
 * @param[in] remote_peer_hostname The hostname of the remote peer.
 *
 * @returns 1 if a matching principal is found and authorized.
 * @returns 0 if no match is found or the principal is not authorized.
 * @returns -1 on error.
 */
static int
ssh_authorized_principals_check_line(ssh_key cert,
                                     char *cp,
                                     unsigned char count,
                                     struct ssh_auth_options **auth_opts,
                                     const char *remote_peer_ip,
                                     const char *remote_peer_hostname)
{
    struct ssh_auth_options *principal_opts = NULL, *final_opts = NULL;
    char *p = NULL, *save_tok = NULL;
    int found = 0, rc;
    unsigned int i;

    /*
     * At this point, the line starts without leading space.
     * Try to parse auth opts.
     */
    p = strtok_r(cp, " ", &save_tok);
    if (p == NULL) {
        SSH_LOG(SSH_LOG_TRACE, "Error while parsing line %d", count);
        return -1;
    }

    /*
     * If there are no leading auth opts (e.g. a principal) then the
     * function will return a NULL pointer. If NULL suppose that the tok is a
     * principal, otherwise continue parsing the line searching for a
     * principal name.
     */
    principal_opts = ssh_auth_options_list_parse(p);
    if (principal_opts != NULL) {
        /* Try to parse the principal name */
        p = strtok_r(NULL, " ", &save_tok);
        if (p == NULL) {
            SSH_LOG(SSH_LOG_TRACE,
                    "Principal name is missing at line %d",
                    count);
            return -1;
        }
    }

    /*
     * First check that cert-authority flag is not present. When processing
     * authorized principals file, cert-authority option is not allowed.
     */
    if (principal_opts != NULL &&
        (principal_opts->opt_flags & CERT_AUTHORITY_OPT)) {
        SSH_LOG(SSH_LOG_TRACE,
                "\"cert-authority\" option is not allowed in authorized "
                "principals file");
        /*
         * "principals=" option can be set only if cert-authority option has
         * been previously set. If set, log to the user the invalid reason.
         */
        if (principal_opts->cert_principals != NULL) {
            SSH_LOG(SSH_LOG_TRACE,
                    "\"principals\" option is not allowed in authorized "
                    "principals file");
        }
        SSH_AUTH_OPTS_FREE(principal_opts);
        return SSH_ERROR;
    }

    /* Now *p should be a principal with or without auth opts */
    for (i = 0; i < cert->cert_data->n_principals; i++) {
        if (strcmp(p, cert->cert_data->principals[i]) == 0) {
            SSH_LOG(SSH_LOG_TRACE,
                    "Matching principal %s found at line %d",
                    cert->cert_data->principals[i],
                    count);
            found = 1;
            break;
        }
    }

    if (found) {
        if (principal_opts != NULL) {
            final_opts = ssh_auth_options_merge_cert_opts(cert,
                                                          principal_opts);
            SSH_AUTH_OPTS_FREE(principal_opts);

            if (final_opts == NULL) {
                SSH_LOG(SSH_LOG_TRACE,
                        "Error while merging authentication options between "
                        "option list (line %d) and certificate options",
                        count);
                return -1;
            }
        } else {
            final_opts = ssh_auth_options_from_cert(cert);
            if (final_opts == NULL) {
                SSH_LOG(SSH_LOG_TRACE,
                        "Error while importing certificate authentication "
                        "options");
                return -1;
            }
        }

        rc = ssh_authorize_authkey_options(final_opts,
                                           remote_peer_ip,
                                           remote_peer_hostname,
                                           true);
        if (rc != SSH_OK) {
            /* Already verbose logging the reason */
            SSH_LOG(SSH_LOG_TRACE,
                    "Certificate refused by authentication options");
            SSH_AUTH_OPTS_FREE(final_opts);
            return -1;
        }

        /*
         * There is no need to pass a principal name at this point, as the
         * authorized principals file has already verified it.
         */
        rc = pki_cert_check_validity(cert, false, NULL, NULL);
        if (rc != SSH_OK) {
            /* Already verbose logging the reason */
            SSH_AUTH_OPTS_FREE(final_opts);
            return -1;
        }

        *auth_opts = final_opts;
        return 1;
    }

    /* No match found */
    SSH_AUTH_OPTS_FREE(principal_opts);
    return 0;
}

/**
 * @brief Checks a file of authorized principals for a match with a given
 * SSH certificate.
 *
 * This function reads through a specified authorized principals file
 * line by line, attempting to match each line against the principals listed
 * in a given SSH certificate. If a matching principal is found,
 * the corresponding authentication options are authorized and set.
 *
 * @param[in] cert The ssh_key certificate containing principals to be checked.
 *
 * @param[in] filename The path to the authorized principals file.
 *
 * @param[out] auth_opts A pointer to store the resulting authentication
 *                       options.
 *
 * @param[in] remote_peer_ip The IP address of the remote peer.
 *
 * @param[in] remote_peer_hostname The hostname of the remote peer.
 *
 * @returns 1 if a matching principal is found and authorized.
 * @returns 0 if no match is found or the principal is not authorized.
 * @returns -1 on error.
 */
int
ssh_authorized_principals_check_file(ssh_key cert,
                                     const char *filename,
                                     struct ssh_auth_options **auth_opts,
                                     const char *remote_peer_ip,
                                     const char *remote_peer_hostname)
{
    char line[MAX_LINE_SIZE] = {0};
    unsigned int count = 0;
    FILE *fp = NULL;
    char *cp = NULL;
    int found = 0;
    size_t len;

    if (cert == NULL || filename == NULL || auth_opts == NULL ||
        remote_peer_ip == NULL || remote_peer_hostname == NULL) {
        SSH_LOG(SSH_LOG_TRACE, "Bad arguments");
        return -1;
    }

    if (!is_cert_type(cert->type)) {
        SSH_LOG(SSH_LOG_TRACE,
                "Invalid key. The input key must be a certificate");
        return -1;
    }

    fp = fopen(filename, "r");
    if (fp == NULL) {
        SSH_LOG(SSH_LOG_TRACE,
                "Error while opening authorized principals file %s, %s\n",
                filename,
                strerror(errno));
        return -1;
    }

    SSH_LOG(SSH_LOG_PACKET,
            "Reading authorized principals file from %s",
            filename);

    while (fgets(line, sizeof(line), fp) && !found) {
        count++;

        for (cp = line; *cp != '\0'; cp++) {
            if (!isspace(*cp)) {
                break;
            }
        }

        switch (*cp) {
        case '#':
        case '\0':
            continue;
        }

        /* Remove trailing space */
        len = strlen(cp);
        if (isspace(cp[len - 1])) {
            cp[len - 1] = '\0';
        }

        found = ssh_authorized_principals_check_line(cert,
                                                     cp,
                                                     count,
                                                     auth_opts,
                                                     remote_peer_ip,
                                                     remote_peer_hostname);
        if (found < 0) {
            fclose(fp);
            return -1;
        }
    }

    if (ferror(fp)) {
        SSH_LOG(SSH_LOG_TRACE, "Error while reading file at line %d", count);
        return -1;
    }

    fclose(fp);
    return found;
}
