/*
 * auth_options.c
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

#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <stdint.h>
#include "config.h"

#include "libssh/libssh.h"
#include "libssh/priv.h"
#include "libssh/pki.h"
#include "libssh/pki_priv.h"
#include "libssh/misc.h"
#include "libssh/auth_options.h"
#include "libssh/token.h"

#define SSH_AUTH_OPT_MAX_PRINCIPALS 256
#define SSH_AUTH_OPT_MAX_ENVS 1024
#define SSH_AUTH_OPT_MAX_PERMIT 4096
#define SSH_AUTH_OPT_MAX_TUN_INTERFACE 0x7ffffffe

/**
 * @brief Allocates and initializes a new ssh_auth_options structure.
 *
 * @returns A pointer to the newly allocated ssh_auth_options structure.
 * @returns NULL if allocation failed.
 */
struct ssh_auth_options *
ssh_auth_option_new(void)
{
    struct ssh_auth_options *x = calloc(1, sizeof(struct ssh_auth_options));
    if (x == NULL) {
        return NULL;
    }

    /* 0 is a valid tun device. Set to -1 instead. */
    x->tun_device = -1;
    /* Set expiry time to "infinite" */
    x->valid_before = 0xffffffffffffffffULL;
    return x;
}

/**
 * @brief Cleans up the ssh_auth_options structure, freeing any allocated
 * memory.
 *
 * @param[in] auth_opts A pointer to the ssh_auth_options structure to clean.
 */
static void
ssh_auth_options_clean(struct ssh_auth_options *auth_opts)
{
    unsigned int i;

    if (auth_opts == NULL) {
        return;
    }

    SAFE_FREE(auth_opts->force_command);
    SAFE_FREE(auth_opts->authkey_from_addr_host);
    SAFE_FREE(auth_opts->cert_source_address);

    if (auth_opts->envs != NULL) {
        for (i = 0; i < auth_opts->n_envs; i++) {
            SAFE_FREE(auth_opts->envs[i]);
        }
        SAFE_FREE(auth_opts->envs);
    }

    if (auth_opts->permit_listen != NULL) {
        for (i = 0; i < auth_opts->n_permit_listen; i++) {
            SAFE_FREE(auth_opts->permit_listen[i]);
        }
        SAFE_FREE(auth_opts->permit_listen);
    }

    if (auth_opts->permit_open != NULL) {
        for (i = 0; i < auth_opts->n_permit_open; i++) {
            SAFE_FREE(auth_opts->permit_open[i]);
        }
        SAFE_FREE(auth_opts->permit_open);
    }

    if (auth_opts->cert_principals != NULL) {
        for (i = 0; i < auth_opts->n_cert_principals; i++) {
            SAFE_FREE(auth_opts->cert_principals[i]);
        }
        SAFE_FREE(auth_opts->cert_principals);
    }

    ZERO_STRUCTP(auth_opts);
}

/**
 * @brief Deallocates an ssh_auth_options structure and its contents.
 *
 * @param auth_opts  A pointer to the ssh_auth_options structure to deallocate.
 */
void
ssh_auth_options_free(struct ssh_auth_options *auth_opts)
{
    if (auth_opts != NULL) {
        ssh_auth_options_clean(auth_opts);
        SAFE_FREE(auth_opts);
    }
}

/**
 * @brief Tokenizes a given string based on a specified delimiter, with special
 * handling for quoted strings. This function treats quoted substrings as single
 * tokens, ignoring delimiters that appear within quotes, thereby preventing
 * them from splitting the string.
 *
 * This function is a modified version of ssh_tokenize() that tokenizes
 * following the authentication options format. Delimiter within quotes is
 * skipped.
 *
 * @see ssh_tokenize()
 *
 * @param[in]  chain     The input string to tokenize.
 *
 * @param[in]  delimiter The character used as a delimiter for tokenization.
 *
 * @returns A pointer to a ssh_tokens_st structure containing the tokens.
 * @returns NULL on error.
 */
struct ssh_tokens_st *
ssh_tokenize_with_auth_options(const char *chain, char delimiter)
{
    struct ssh_tokens_st *tokens = NULL;
    int num_tokens = 0, n_allocated = 0;
    char **temp = NULL;
    size_t len, token_start = 0, i;
    bool in_quotes = false;

    if (chain == NULL) {
        SSH_LOG(SSH_LOG_TRACE, "Bad arguments");
        return NULL;
    }

    tokens = calloc(1, sizeof(struct ssh_tokens_st));
    if (tokens == NULL) {
        SSH_LOG(SSH_LOG_TRACE, "Error while allocating space for tokens");
        return NULL;
    }

    tokens->buffer = strdup(chain);
    if (tokens->buffer == NULL) {
        SSH_LOG(SSH_LOG_TRACE,
                "Error while allocating space for tokens buffer");
        goto fail;
    }

    len = strlen(chain);
    for (i = 0; i <= len; i++) {
        if (tokens->buffer[i] == '\"') {
            in_quotes = !in_quotes;
        } else if ((tokens->buffer[i] == delimiter && !in_quotes)
                   || tokens->buffer[i] == '\0') {
            tokens->buffer[i] = '\0';

            /*
             * Re-allocate in chunks. Starting with size 4 and doubling each
             * time more space is needed.
             */
            if (num_tokens >= n_allocated) {
                n_allocated = n_allocated == 0 ? 4 : n_allocated * 2;
                temp = realloc(tokens->tokens, n_allocated * sizeof(char *));
                if (temp == NULL) {
                    SSH_LOG(SSH_LOG_TRACE, "realloc() failed");
                    goto fail;
                }
                tokens->tokens = temp;
            }

            tokens->tokens[num_tokens] = &tokens->buffer[token_start];
            num_tokens += 1;
            token_start = i + 1;
        }
    }

    /* NULL terminate the tokens array if necessary */
    if (num_tokens >= n_allocated) {
        temp = realloc(tokens->tokens, (num_tokens + 1) * sizeof(char *));
        if (temp == NULL) {
            SSH_LOG(SSH_LOG_TRACE, "final realloc() failed");
            goto fail;
        }
        tokens->tokens = temp;
    }
    tokens->tokens[num_tokens] = NULL;

    return tokens;

fail:
    ssh_tokens_free(tokens);
    return NULL;
}

/**
 * @brief Processes a comma-separated list of options, storing them in an array.
 *
 * The options array is reallocated as needed to accommodate new options at
 * every new call to this function.
 *
 * @param[in]   option_list  The comma-separated list of options as a string.
 *
 * @param[out]  option       A pointer to the array of options. The caller is
 *                           responsible for freeing the memory
 *
 * @param[out]  n_options    A pointer to the number of options.
 *
 * @returns 0 on success.
 * @returns -1 on failure.
 */
static int
auth_options_process_comma_list(const char *option_list,
                                char ***option,
                                unsigned int *n_options)
{
    unsigned int i, n_parsed = 0, n_allocated = 0, empty;
    struct ssh_tokens_st *p_tokens = NULL;
    char **temp = NULL, **ret = NULL, *token = NULL;

    if (option_list == NULL || *option_list == '\0') {
        SSH_LOG(SSH_LOG_TRACE, "Bad arguments");
        return -1;
    }

    p_tokens = ssh_tokenize(option_list, ',');
    if (p_tokens == NULL) {
        SSH_LOG(SSH_LOG_TRACE,
                "Error while tokenizing option list \"%s\"",
                option_list);
        return -1;
    }

    if (*n_options > 0) {
        empty = *n_options % 4;
        n_allocated = empty == 0 ? *n_options : *n_options + (4 - empty);
        n_parsed = *n_options;
        ret = *option;
    }

    /*
     * Re-allocate in chunks. Starting with size 4 and doubling each time
     * more space is needed.
     */
    for (i = 0; p_tokens->tokens[i] != NULL; i++) {
        token = p_tokens->tokens[i];

        if (n_parsed >= n_allocated) {
            n_allocated = n_allocated == 0 ? 4 : n_allocated * 2;
            temp = realloc(ret, n_allocated * sizeof(char *));
            if (temp == NULL) {
                SSH_LOG(SSH_LOG_TRACE, "realloc() failed");
                goto fail;
            }
            ret = temp;
        }

        ret[n_parsed] = strdup(token);
        if (ret[n_parsed] == NULL) {
            SSH_LOG(SSH_LOG_TRACE, "Error while duplicating token");
            goto fail;
        }
        n_parsed += 1;
    }

    *n_options = n_parsed;
    *option = ret;

    ssh_tokens_free(p_tokens);
    return 0;

fail:
    for (i = 0; i < n_parsed; i++) {
        SAFE_FREE(ret[i]);
    }
    SAFE_FREE(ret);
    ssh_tokens_free(p_tokens);
    return -1;
}

/**
 * @brief Validates a list of environment variable settings.
 *
 * @param[in]  envs    Array of environment variable strings to validate.
 *
 * @param[in]  n_envs  Number of environment variables in the array.
 *
 * @returns 1 if all environment variables are valid.
 * @returns 0 if one or more environments are invalid.
 * @returns -1 on error.
 */
static int
auth_options_valid_envs(char **envs, unsigned int n_envs)
{
    unsigned int i;
    char *equal_sign_ptr = NULL, *name = NULL, *env_copy = NULL, *cp = NULL;

    if (envs == NULL) {
        SSH_LOG(SSH_LOG_TRACE, "Bad argument");
        return -1;
    }

    if (n_envs > SSH_AUTH_OPT_MAX_ENVS) {
        SSH_LOG(SSH_LOG_TRACE,
                "The number of environment variables specified exceeds "
                "the maximum allowed (%d)",
                SSH_AUTH_OPT_MAX_ENVS);
        return 0;
    }

    for (i = 0; i < n_envs; i++) {
        env_copy = strdup(envs[i]);
        if (env_copy == NULL) {
            SSH_LOG(SSH_LOG_TRACE, "Error while duplicating environment");
            return -1;
        }
        equal_sign_ptr = strchr(env_copy, '=');

        if (equal_sign_ptr == NULL) {
            SSH_LOG(SSH_LOG_TRACE,
                    "Bad environment format %s. "
                    "Usage: environment=\"NAME=value\"",
                    envs[i]);
            SAFE_FREE(env_copy);
            return 0;
        }

        *equal_sign_ptr = '\0';
        name = env_copy;

        /* Validate env name */
        if (name[0] == '\0') {
            SAFE_FREE(env_copy);
            return 0;
        }

        for (cp = name; *cp != '\0'; cp++) {
            if (!isalnum(*cp) && *cp != '_') {
                SAFE_FREE(env_copy);
                return 0;
            }
        }
        SAFE_FREE(env_copy);
    }

    return 1;
}

/**
 * @brief Validates the permit-listen and permit-open options.
 *
 * This function checks the validity of a list of permit options for either
 * listening or opening connections. It ensures that the options are formatted
 * correctly and within allowed limits.
 *
 * @param[in]  permit    Array of permit options (permit-listen or permit-open).
 *
 * @param[in]  n_permits Number of permit options in the array.
 *
 * @param[in]  permit_listen Boolean indicating whether the options are for
*                            permit-listen (true) or permit-open (false).
 *
 * @returns 1 if all permit options are valid.
 * @returns 0 if one or more permit options are invalid.
 * @returns -1 on error.
 */
static int
auth_options_valid_permit_opts(char **permit_opts,
                               unsigned int n_permit,
                               bool permit_listen)
{
    int rc;
    long port;
    unsigned int i;
    char *colon_ptr = NULL, *host = NULL, *c_port = NULL, *permit_entry = NULL,
         *pentry = NULL, *endptr = NULL;

    if (permit_opts == NULL) {
        SSH_LOG(SSH_LOG_TRACE, "Bad argument");
        return -1;
    }

    if (n_permit > SSH_AUTH_OPT_MAX_PERMIT) {
        SSH_LOG(SSH_LOG_TRACE,
                "The number of permit%s options exceeds the maximum "
                "allowed (%d)",
                permit_listen ? "listen" : "open",
                SSH_AUTH_OPT_MAX_PERMIT);
        return 0;
    }

    for (i = 0; i < n_permit; i++) {
        permit_entry = strdup(permit_opts[i]);
        if (permit_entry == NULL) {
            SSH_LOG(SSH_LOG_TRACE, "Error while duplicating permit option");
            return -1;
        }

        if (permit_entry[0] == '[') {
            /* Handle IPv6 address with square brackets */
            pentry = strchr(permit_entry, ']');
            if (pentry == NULL) {
                SSH_LOG(SSH_LOG_TRACE, "%s is missing a closing bracket",
                        permit_opts[i]);
                SAFE_FREE(permit_entry);
                return 0;
            }
            colon_ptr = strchr(pentry, ':');
        } else {
            colon_ptr = strchr(permit_entry, ':');
        }

        if (!permit_listen &&
            (colon_ptr == permit_entry || colon_ptr == NULL)) {
            /* With permitopen option the host:port format is mandatory */
            SSH_LOG(SSH_LOG_TRACE,
                    "%s is an invalid permitopen option "
                    "(host:port format is mandatory)",
                    permit_opts[i]);
            SAFE_FREE(permit_entry);
            return 0;
        }

        if (colon_ptr != NULL && colon_ptr != permit_entry) {
            *colon_ptr = '\0';
            host = permit_entry;
            c_port = colon_ptr + 1;
        } else {
            /* Validate only the port (permitlisten case) */
            host = NULL;
            c_port = permit_entry;
        }

        if (host != NULL) {
            ssh_remove_square_brackets(host);
            if (strcmp(host, "localhost") == 0) {
                goto port;
            }

            rc = ssh_is_ipaddr(host);
            if (rc == SSH_ERROR) {
                SSH_LOG(SSH_LOG_TRACE,
                        "%s does not contain a valid hostname",
                        permit_opts[i]);
                SAFE_FREE(permit_entry);
                return 0;
            }
        }

    port:
        if (strcmp(c_port, "*") == 0) {
            continue;
        }

        errno = 0;
        port = strtol(c_port, &endptr, 10);

        if (*endptr != '\0') {
            SSH_LOG(SSH_LOG_TRACE,
                    "Port conversion error: %s",
                    strerror(errno));
            SAFE_FREE(permit_entry);
            return 0;
        }

        if (port < 0 || port > 65535) {
            SSH_LOG(SSH_LOG_TRACE,
                    "%s does not contain a valid port: %s",
                    permit_opts[i],
                    strerror(errno));
            SAFE_FREE(permit_entry);
            return 0;
        }
        SAFE_FREE(permit_entry);
    }

    return 1;
}

/**
 * @brief Set a specific authentication flag ON or OFF.
 *
 * @param[out] auth_opts Pointer to the ssh_auth_options structure.
 *
 * @param[in]  flag      The flag to set.
 *
 * @param[in]  negate    If true, the flag is cleared.\n
 *                       If false, the flag is set.
 */
static void
auth_options_set_flag(struct ssh_auth_options *auth_opts,
                         enum ssh_auth_opts_flags flag,
                         bool negate)
{
    if (auth_opts == NULL) {
        return;
    }

    if (negate) {
        auth_opts->opt_flags &= ~flag;
    } else {
        auth_opts->opt_flags |= flag;
    }
}

/**
 * @brief Enables restricted mode for authentication options. It clears the
 * following auth_opts flags:
 *
 * - PERMIT_PORT_FORWARDING_OPT\n
 * - PERMIT_AGENT_FORWARDING_OPT\n
 * - PERMIT_X11_FORWARDING_OPT\n
 * - PERMIT_PTY_OPT\n
 * - PERMIT_USER_RC_OPT\n
 *
 * @param[out] auth_opts Pointer to the ssh_auth_options structure.
 */
static void
auth_options_toggle_restrict_mode(struct ssh_auth_options *auth_opts)
{
    if (auth_opts == NULL) {
        return;
    }

    auth_opts->opt_flags |= RESTRICTED_OPT;
    auth_opts->opt_flags &= ~PERMIT_PORT_FORWARDING_OPT;
    auth_opts->opt_flags &= ~PERMIT_AGENT_FORWARDING_OPT;
    auth_opts->opt_flags &= ~PERMIT_X11_FORWARDING_OPT;
    auth_opts->opt_flags &= ~PERMIT_PTY_OPT;
    auth_opts->opt_flags &= ~PERMIT_USER_RC_OPT;
}

/**
 * @brief Parses and validates a tunnel device ID from a string.
 *
 * This function converts a string representation of a tunnel device ID into
 * an integer, validating that it falls within the allowed range.
 *
 * @param[in] tun_device  The string representation of the tunnel device ID.
 *
 * @returns The converted tunnel device ID on success.
 * @returns -1 on error (e.g., invalid device ID or out of range).
 */
static int
auth_options_parse_tun_device(const char *tun_device)
{
    long tun;
    char *endptr = NULL;

    if (tun_device == NULL || *tun_device == '\0') {
        SSH_LOG(SSH_LOG_TRACE, "Bad argument");
        return -1;
    }

    errno = 0;
    tun = strtol(tun_device, &endptr, 10);

    if (*endptr != '\0') {
        SSH_LOG(SSH_LOG_TRACE,
                "Tunnel ID conversion error: %s",
                strerror(errno));
        return -1;
    }

    if (tun < 0 || tun > SSH_AUTH_OPT_MAX_TUN_INTERFACE) {
        SSH_LOG(SSH_LOG_TRACE,
                "Tunnel ID %d is not valid: %s",
                (int)tun,
                strerror(errno));
        return -1;
    }

    return (int)tun;
}

/**
 * @brief Parses a list of SSH authentication options.
 *
 * This function processes a comma-separated list of SSH authentication options,
 * extracting key-value pairs or single-word options and updating the given
 * authentication options structure accordingly.
 *
 * @param[in] list  The comma-separated list of authentication options.
 *
 * @returns A pointer to a new ssh_auth_options structure on success.
 * @returns NULL on failure.
 *
 * @note The caller is responsible for freeing the memory.
 */
struct ssh_auth_options *
ssh_auth_options_list_parse(const char *list)
{
    int rc, i;
    struct ssh_auth_options *auth_opts = NULL;
    struct ssh_tokens_st *opt_tokens = NULL;
    char *token = NULL, *key = NULL, *value = NULL, *equal_sign_ptr = NULL,
         *value_q = NULL;
    uint64_t timestamp;
    bool negate = false;

    if (list == NULL) {
        SSH_LOG(SSH_LOG_TRACE,
                "Bad arguments. Authentication options list is NULL");
        return NULL;
    }

    auth_opts = ssh_auth_option_new();
    if (auth_opts == NULL) {
        SSH_LOG(SSH_LOG_TRACE,
                "Error while initializing authentication options");
        return NULL;
    }

    if (*list == '\0') {
        return auth_opts;
    }

    opt_tokens = ssh_tokenize_with_auth_options(list, ',');
    if (opt_tokens == NULL) {
        SSH_LOG(SSH_LOG_TRACE, "Error while tokenizing auth-opts list");
        SSH_AUTH_OPTS_FREE(auth_opts);
        return NULL;
    }

    for (i = 0; opt_tokens->tokens[i] != NULL; i++) {
        token = opt_tokens->tokens[i];

        /* Handle key="value" auth options */
        equal_sign_ptr = strchr(token, '=');
        if (equal_sign_ptr != NULL) {
            *equal_sign_ptr = '\0';
            key = token;
            value_q = equal_sign_ptr + 1;

            /* Remove quotes from option value */
            value = ssh_dequote(value_q);
            if (value == NULL || memcmp(value, value_q, strlen(value_q)) == 0) {
                /* Already verbose logging the reason */
                SSH_LOG(SSH_LOG_TRACE, "Invalid option format");
                goto fail;
            }

            if (strcasecmp(key, "command") == 0) {
                if (auth_opts->force_command != NULL) {
                    SSH_LOG(SSH_LOG_TRACE,
                            "Multiple \"command\" options are not allowed");
                    goto fail;
                }

                auth_opts->force_command = strdup(value);
                if (auth_opts->force_command == NULL) {
                    SSH_LOG(SSH_LOG_TRACE,
                            "Error while allocating space for force-command"
                            " option");
                    goto fail;
                }
            } else if (strcasecmp(key, "from") == 0) {
                if (auth_opts->authkey_from_addr_host != NULL) {
                    SSH_LOG(SSH_LOG_TRACE,
                            "Multiple \"from\" options are not allowed");
                    goto fail;
                }

                auth_opts->authkey_from_addr_host = strdup(value);
                if (auth_opts->authkey_from_addr_host == NULL) {
                    SSH_LOG(SSH_LOG_TRACE,
                            "Error while allocating space for \"from\""
                            " option");
                    goto fail;
                }
            } else if (strcasecmp(key, "principals") == 0) {
                if (!(auth_opts->opt_flags & CERT_AUTHORITY_OPT)) {
                    SSH_LOG(SSH_LOG_TRACE,
                            "Principals list is ignored for keys not marked as "
                            "trusted certificate signers: "
                            "prior \"cert-authority\" option missing");
                    continue;
                }

                rc = auth_options_process_comma_list(
                    value,
                    &auth_opts->cert_principals,
                    &auth_opts->n_cert_principals);
                if (rc < 0) {
                    SSH_LOG(SSH_LOG_TRACE,
                            "Error while parsing \"principals\" option");
                    goto fail;
                }

                if (auth_opts->n_cert_principals > SSH_AUTH_OPT_MAX_PRINCIPALS)
                {
                    SSH_LOG(SSH_LOG_TRACE,
                            "The number of principals specified exceeds "
                            "the maximum allowed (%d)",
                            SSH_AUTH_OPT_MAX_PRINCIPALS);
                    goto fail;
                }
            } else if (strcasecmp(key, "expiry-time") == 0) {
                rc = ssh_convert_datetime_format_to_timestamp(value,
                                                              &timestamp);
                if (rc == -1) {
                    SSH_LOG(SSH_LOG_TRACE,
                            "%s is not valid expiry time",
                            value);
                    goto fail;
                }

                /* Override expiry time only if less than the current one */
                if (timestamp < auth_opts->valid_before) {
                    auth_opts->valid_before = timestamp;
                }
            } else if (strcasecmp(key, "environment") == 0) {
                rc = auth_options_process_comma_list(value,
                                                     &auth_opts->envs,
                                                     &auth_opts->n_envs);
                if (rc < 0) {
                    SSH_LOG(SSH_LOG_TRACE,
                            "Error while parsing \"environment\" option");
                    goto fail;
                }

                rc = auth_options_valid_envs(auth_opts->envs,
                                             auth_opts->n_envs);
                if (rc <= 0) {
                    /* Already verbose logging the output */
                    goto fail;
                }
            } else if (strcasecmp(key, "permitlisten") == 0) {
                rc = auth_options_process_comma_list(
                    value,
                    &auth_opts->permit_listen,
                    &auth_opts->n_permit_listen);
                if (rc < 0) {
                    SSH_LOG(SSH_LOG_TRACE,
                            "Error while parsing \"permitlisten\" option");
                    goto fail;
                }

                rc = auth_options_valid_permit_opts(
                    auth_opts->permit_listen,
                    auth_opts->n_permit_listen,
                    true);
                if (rc <= 0) {
                    /* Already verbose logging the output */
                    goto fail;
                }
            } else if (strcasecmp(key, "permitopen") == 0) {
                rc = auth_options_process_comma_list(value,
                                                     &auth_opts->permit_open,
                                                     &auth_opts->n_permit_open);
                if (rc < 0) {
                    SSH_LOG(SSH_LOG_TRACE,
                            "Error while parsing \"permitopen\" option");
                    goto fail;
                }

                rc = auth_options_valid_permit_opts(auth_opts->permit_open,
                                                    auth_opts->n_permit_open,
                                                    false);
                if (rc <= 0) {
                    /* Already verbose logging the output */
                    goto fail;
                }
            } else if (strcasecmp(key, "tunnel") == 0) {
                auth_opts->tun_device = auth_options_parse_tun_device(value);
                if (auth_opts->tun_device == -1) {
                    /* Already verbose logging the output */
                    goto fail;
                }
            } else {
                SSH_LOG(SSH_LOG_TRACE, "Option \"%s\" not supported", key);
                goto fail;
            }
            SAFE_FREE(value);
        } else {
            /* Advance of 3 positions if "no-" prefix is present */
            if (strncasecmp(token, "no-", 3) == 0) {
                negate = true;
                token += 3;
            }

            if (strcasecmp(token, "cert-authority") == 0) {
                if (negate) {
                    SSH_LOG(SSH_LOG_TRACE,
                            "\"no-cert-authority\" option is not recognized");
                    goto fail;
                }
                auth_opts->opt_flags |= CERT_AUTHORITY_OPT;
            } else if (strcasecmp(token, "touch-required") == 0) {
                auth_options_set_flag(auth_opts,
                                      NO_TOUCH_REQUIRED_OPT,
                                      !negate);
            } else if (strcasecmp(token, "x11-forwarding") == 0) {
                auth_options_set_flag(auth_opts,
                                      PERMIT_X11_FORWARDING_OPT,
                                      negate);
            } else if (strcasecmp(token, "agent-forwarding") == 0) {
                auth_options_set_flag(auth_opts,
                                      PERMIT_AGENT_FORWARDING_OPT,
                                      negate);
            } else if (strcasecmp(token, "port-forwarding") == 0) {
                auth_options_set_flag(auth_opts,
                                      PERMIT_PORT_FORWARDING_OPT,
                                      negate);
            } else if (strcasecmp(token, "pty") == 0) {
                auth_options_set_flag(auth_opts,
                                      PERMIT_PTY_OPT,
                                      negate);
            } else if (strcasecmp(token, "user-rc") == 0) {
                auth_options_set_flag(auth_opts,
                                      PERMIT_USER_RC_OPT,
                                      negate);
            } else if (strcasecmp(token, "verify-required") == 0) {
                auth_options_set_flag(auth_opts,
                                      VERIFY_REQUIRED_OPT,
                                      negate);
            } else if (strcasecmp(token, "restrict") == 0) {
                if (negate) {
                    SSH_LOG(SSH_LOG_TRACE,
                            "\"no-restrict\" option is not recognized");
                    goto fail;
                }
                auth_options_toggle_restrict_mode(auth_opts);
            } else {
                SSH_LOG(SSH_LOG_TRACE, "Option \"%s\" not supported", key);
                goto fail;
            }
            negate = false;
        }
    }

    ssh_tokens_free(opt_tokens);
    return auth_opts;

fail:
    SAFE_FREE(value);
    ssh_tokens_free(opt_tokens);
    SSH_AUTH_OPTS_FREE(auth_opts);
    return NULL;
}

/**
 * @brief Copies an array of authentication options.
 *
 * @param[out]  dest    Pointer to the destination array where the options
 *                      will be copied.
 *
 * @param[in]  options  Array of string options to be copied.
 *
 * @param[in]  n_opts   The number of options to be copied.
 *
 * @returns 0 on success.
 * @returns -1 on failure.
 */
static int
auth_options_opt_array_copy(char ***dest,
                            char **options,
                            unsigned int n_opts)
{
    char **new = NULL;
    unsigned int i, j;

    if (dest == NULL || *options == NULL) {
        SSH_LOG(SSH_LOG_TRACE, "Nothing to copy from/to");
        return -1;
    }

    new = calloc(n_opts, sizeof(char *));
    if (new == NULL) {
        SSH_LOG(SSH_LOG_TRACE, "Memory allocation error");
        return -1;
    }

    for (i = 0; i < n_opts; i++) {
        new[i] = strdup(options[i]);
        if (new[i] == NULL) {
            SSH_LOG(SSH_LOG_TRACE, "Error while duplicating option");
            goto fail;
        }
    }

    *dest = new;
    return 0;

fail:
    for(j = 0; j < i;  j++) {
        SAFE_FREE(new[j]);
    }
    SAFE_FREE(new);
    return -1;
}

/**
 * @brief Merges authentication options from a certificate and a source
 * ssh_auth_options structure.
 *
 * This function combines authentication options from a certificate key
 * and a source ssh_auth_opts structure into a new authentication options
 * structure. Currently it only supports user certificate options.
 *
 * @param[in] certkey  The certificate key containing auth options to merge.
 *
 * @param[in] src_opts The source ssh_auth_opts to merge with the certificate.
 *
 * @returns A newly allocated ssh_auth_options structure on success.
 * @returns NULL on failure.
 *
 * @note The caller is responsible for freeing the memory.
 */
struct ssh_auth_options *
ssh_auth_options_merge_cert_opts(ssh_key certkey,
                                 struct ssh_auth_options *src_opts)
{
    struct ssh_auth_options *ret = NULL;
    ssh_cert cert_data = NULL;
    int r;

    if (certkey == NULL || src_opts == NULL || !is_cert_type(certkey->type) ||
        certkey->cert_data->type != SSH_CERT_TYPE_USER) {
        SSH_LOG(SSH_LOG_TRACE, "Bad arguments");
        return NULL;
    }

    ret = ssh_auth_option_new();
    if (ret == NULL) {
        SSH_LOG(SSH_LOG_TRACE,
                "Error while initializing authentication options");
        return NULL;
    }

    cert_data = certkey->cert_data;

    /*
     * Merge flags. Flags common to ssh_auth_opts and ssh_cert follow
     * the same enumeration. Clear cert-authority as it's not needed anymore
     * */
    ret->opt_flags |= cert_data->extensions.ext;
    ret->opt_flags |= src_opts->opt_flags;
    ret->opt_flags &= ~CERT_AUTHORITY_OPT;

    /* Merge verify-required option */
    if (cert_data->critical_options->verify_required) {
        ret->opt_flags |= VERIFY_REQUIRED_OPT;
    }

    /* Merge force-command option */
    if (cert_data->critical_options->force_command != NULL &&
        src_opts->force_command != NULL) {
        r = strcmp(cert_data->critical_options->force_command,
                   src_opts->force_command);
        if (r == 0) {
            ret->force_command = strdup(src_opts->force_command);
            if (ret->force_command == NULL) {
                SSH_LOG(SSH_LOG_TRACE,
                        "Error while duplicating \"force-command\" option");
                goto fail;
            }
        } else {
            SSH_LOG(SSH_LOG_TRACE,
                    "Error: \"force-command\" options must be the same");
            goto fail;
        }
    } else if (cert_data->critical_options->force_command != NULL) {
        ret->force_command =
            strdup(cert_data->critical_options->force_command);
        if (ret->force_command == NULL) {
            SSH_LOG(SSH_LOG_TRACE,
                    "Error while duplicating \"force-command\" option");
            goto fail;
        }
    } else if (src_opts->force_command != NULL) {
        ret->force_command = strdup(src_opts->force_command);
        if (ret->force_command == NULL) {
            SSH_LOG(SSH_LOG_TRACE,
                    "Error while duplicating \"force-command\" option");
            goto fail;
        }
    }

    /* Merge expiry-date */
    if (cert_data->valid_before < src_opts->valid_before) {
        ret->valid_before = cert_data->valid_before;
    } else {
        ret->valid_before = src_opts->valid_before;
    }

    /* Merge envs */
    if (src_opts->envs != NULL) {
        ret->n_envs = src_opts->n_envs;
        r = auth_options_opt_array_copy(&ret->envs,
                                        src_opts->envs,
                                        src_opts->n_envs);
        if (r == -1) {
            goto fail;
        }
    }

    /* Merge permitlisten */
    if (src_opts->permit_listen != NULL) {
        ret->n_permit_listen = src_opts->n_permit_listen;
        r = auth_options_opt_array_copy(&ret->permit_listen,
                                        src_opts->permit_listen,
                                        src_opts->n_permit_listen);
        if (r == -1) {
            goto fail;
        }
    }

    /* Merge permitopen */
    if (src_opts->permit_open != NULL) {
        ret->n_permit_open = src_opts->n_permit_open;
        r = auth_options_opt_array_copy(&ret->permit_open,
                                        src_opts->permit_open,
                                        src_opts->n_permit_open);
        if (r == -1) {
            goto fail;
        }
    }

    /* Merge tunnel device */
    ret->tun_device = src_opts->tun_device;

    /* Merge "from" option */
    if (src_opts->authkey_from_addr_host != NULL) {
        ret->authkey_from_addr_host = strdup(src_opts->authkey_from_addr_host);
        if (ret->authkey_from_addr_host == NULL) {
            SSH_LOG(SSH_LOG_TRACE,
                    "Error while duplicating \"from\" option");
            goto fail;
        }
    }

    /* Merge source-address option from certificate */
    if (cert_data->critical_options->source_address != NULL) {
        ret->cert_source_address =
            strdup(cert_data->critical_options->source_address);
        if (ret->cert_source_address == NULL) {
            SSH_LOG(SSH_LOG_TRACE,
                    "Error while duplicating \"source-address\" option");
            goto fail;
        }
    }

    /*
     * Copy the principals list specified by the user, if any. The principals
     * list specified by the user as in-line option always override certificate
     * principals. If there are no principals specified by the user then copy
     * the certificate principals, if any.
     */
    if (src_opts->cert_principals != NULL) {
        ret->n_cert_principals = src_opts->n_cert_principals;
        r = auth_options_opt_array_copy(&ret->cert_principals,
                                        src_opts->cert_principals,
                                        src_opts->n_cert_principals);
        if (r == -1) {
            goto fail;
        }
    }

    if (ret->n_cert_principals == 0 && cert_data->principals != NULL) {
        ret->n_cert_principals = cert_data->n_principals;
        r = auth_options_opt_array_copy(&ret->cert_principals,
                                        cert_data->principals,
                                        cert_data->n_principals);
        if (r == -1) {
            goto fail;
        }
    }

    return ret;

fail:
    SSH_AUTH_OPTS_FREE(ret);
    return NULL;
}

/**
 * @brief Imports authentication options from a certificate key into a new
 * ssh_auth_options structure. Currently it only supports user certificate
 * options.
 *
 * @param[in] certkey  The certificate key from which authentication options
 *                     are imported.
 *
 * @returns A newly allocated ssh_auth_options structure on success.
 * @returns NULL on failure.
 *
 * @note The caller is responsible for freeing the memory.
 */
struct ssh_auth_options *
ssh_auth_options_from_cert(ssh_key certkey)
{
    struct ssh_auth_options *ret = NULL;
    ssh_cert cert_data = NULL;
    int r;

    if (certkey == NULL || !is_cert_type(certkey->type) ||
        certkey->cert_data->type != SSH_CERT_TYPE_USER) {
        SSH_LOG(SSH_LOG_TRACE, "Bad arguments");
        return NULL;
    }

    ret = ssh_auth_option_new();
    if (ret == NULL) {
        SSH_LOG(SSH_LOG_TRACE,
                "Error while initializing authentication options");
        return NULL;
    }

    cert_data = certkey->cert_data;

    /* Import extension flags */
    ret->opt_flags |= cert_data->extensions.ext;

    /* Import verify-required flag from critical options */
    if (cert_data->critical_options->verify_required) {
        ret->opt_flags |= VERIFY_REQUIRED_OPT;
    }

    ret->valid_before = cert_data->valid_before;

    /* Import force-command option */
    if (cert_data->critical_options->force_command != NULL) {
        ret->force_command = strdup(cert_data->critical_options->force_command);
        if (ret->force_command == NULL) {
            SSH_LOG(SSH_LOG_TRACE,
                    "Error while duplicating \"force-command\" option");
            goto fail;
        }
    }

    /* Import source-address option from certificate */
    if (cert_data->critical_options->source_address != NULL) {
        ret->cert_source_address =
            strdup(cert_data->critical_options->source_address);
        if (ret->cert_source_address == NULL) {
            SSH_LOG(SSH_LOG_TRACE,
                    "Error while duplicating \"source-address\" option");
            goto fail;
        }
    }

    /* Import principals from certificate */
    if (cert_data->principals != NULL) {
        ret->n_cert_principals = cert_data->n_principals;
        r = auth_options_opt_array_copy(&ret->cert_principals,
                                        cert_data->principals,
                                        cert_data->n_principals);
        if (r == -1) {
            goto fail;
        }
    }

    return ret;

fail:
    SSH_AUTH_OPTS_FREE(ret);
    return NULL;
}
