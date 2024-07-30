/*
* pki_cert.c
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

#include <stdint.h>
#include <stdio.h>

#include "libssh/libssh.h"
#include "libssh/priv.h"
#include "libssh/pki.h"
#include "libssh/buffer.h"
#include "libssh/misc.h"
#include <time.h>
#include <errno.h>

#define SSH_CERT_MAX_PRINCIPALS 256
#define SSH_CERT_PARSE_CRITICAL_OPTIONS 1
#define SSH_CERT_PARSE_EXTENSIONS 2

/**
 * @brief creates a new empty SSH certificate.
 *
 * @returns an empty ssh_cert handle, or NULL on error.
 */
ssh_cert
ssh_cert_new(void)
{
    ssh_cert ptr = calloc(1, sizeof(struct ssh_key_cert_struct));
    if (ptr == NULL) {
        return NULL;
    }

    ptr->critical_options = calloc(1, sizeof(struct ssh_key_cert_opts));
    if (ptr->critical_options == NULL) {
        SAFE_FREE(ptr);
        return NULL;
    }

    return ptr;
}

/**
 * @brief clean up the certificate and deallocate existing keys and signatures
 * @param[in] cert ssh_cert to clean
 */
static void
ssh_cert_clean(ssh_cert cert)
{
    unsigned int i;

    if (cert == NULL) {
        return;
    }

    /* Clean nonce */
    SSH_STRING_FREE(cert->nonce);

    /* Clean key id */
    SAFE_FREE(cert->key_id);

    /* Clean critical options */
    if (cert->critical_options != NULL) {
        SAFE_FREE(cert->critical_options->force_command);
        SAFE_FREE(cert->critical_options->source_address);
        ZERO_STRUCTP(cert->critical_options);
        SAFE_FREE(cert->critical_options);
    }

    /* Clean principals */
    if (cert->principals != NULL) {
        for (i = 0; i < cert->n_principals; i++) {
            SAFE_FREE(cert->principals[i]);
        }
        SAFE_FREE(cert->principals);
    }

    /* Clean signature key and signature */
    SSH_KEY_FREE(cert->signature_key);
    SSH_SIGNATURE_FREE(cert->signature);

    /* Clean all the remaining fields */
    ZERO_STRUCTP(cert);
}

/**
 * @brief deallocate a SSH cert
 * @param[in] cert ssh_cert handle to free
 */
void
ssh_cert_free(ssh_cert cert)
{
    if (cert != NULL) {
        ssh_cert_clean(cert);
        SAFE_FREE(cert);
    }
}

/**
 * @brief Duplicate a certificate.
 *
 * @param[in] src_cert  ssh_cert certificate to copy.
 *
 * @return Newly allocated copy of the certificate.
 * @return NULL on error.
 */
ssh_cert
ssh_cert_dup(const ssh_cert src_cert)
{
    unsigned int i;
    ssh_cert dest_cert = NULL;

    if (src_cert == NULL) {
        goto fail;
    }

    dest_cert = ssh_cert_new();
    if (dest_cert == NULL) {
        goto fail;
    }

    /* Copy the nonce */
    if (src_cert->nonce != NULL) {
        dest_cert->nonce = ssh_string_copy(src_cert->nonce);
        if (dest_cert->nonce == NULL) {
            SSH_LOG(SSH_LOG_TRACE, "Error while getting the option value payload");
            goto fail;
        }
    }

    /* Copy the type and the serial */
    dest_cert->type = src_cert->type;
    dest_cert->serial = src_cert->serial;

    if (src_cert->key_id != NULL) {
        dest_cert->key_id = strdup(src_cert->key_id);
        if (dest_cert->key_id == NULL) {
            SSH_LOG(SSH_LOG_TRACE, "Error while allocating space for key id");
            goto fail;
        }
    }

    /* Copy the principals */
    if (src_cert->n_principals > 0) {
        dest_cert->n_principals = src_cert->n_principals;
        dest_cert->principals = calloc(1, sizeof(char *));

        if (dest_cert->principals == NULL) {
            SSH_LOG(SSH_LOG_TRACE,
                    "Error while allocating space for cert principals "
                    "during certificate copy");
            goto fail;
        }

        for (i = 0; i < src_cert->n_principals; i++) {
            dest_cert->principals[i] = strdup(src_cert->principals[i]);
            if (dest_cert->principals[i] == NULL) {
                SSH_LOG(SSH_LOG_TRACE,
                        "Error while copying cert principals "
                        "during certificate copy");
                goto fail;
            }
        }
    }

    /* Copy the validity dates */
    dest_cert->valid_after = src_cert->valid_after;
    dest_cert->valid_before = src_cert->valid_before;

    /* Copy the critical options */
    if (src_cert->critical_options->force_command != NULL) {
        dest_cert->critical_options->force_command =
            strdup(src_cert->critical_options->force_command);
        if (dest_cert->critical_options->force_command == NULL) {
            SSH_LOG(SSH_LOG_TRACE,
                    "Error while allocating space for force-command option "
                    "during certificate copy");
            goto fail;
        }
    }

    if (src_cert->critical_options->source_address != NULL) {
        dest_cert->critical_options->source_address =
            strdup(src_cert->critical_options->source_address);
        if (dest_cert->critical_options->source_address == NULL) {
            SSH_LOG(SSH_LOG_TRACE,
                    "Error while allocating space for source-address option "
                    "during certificate copy");
            goto fail;
        }
    }

    dest_cert->critical_options->verify_required =
        src_cert->critical_options->verify_required;

    /* Copy the extensions */
    dest_cert->extensions.ext = src_cert->extensions.ext;

    /* Copy the signature key */
    if (src_cert->signature_key != NULL) {
        dest_cert->signature_key = ssh_key_dup(src_cert->signature_key);
        if (dest_cert->signature_key == NULL) {
            SSH_LOG(SSH_LOG_TRACE,
                    "Error while duplicating the signature key "
                    "during certificate copy");
            goto fail;
        }
    }

    /* Copy the signature */
    if (src_cert->signature != NULL) {
        dest_cert->signature = ssh_signature_dup(src_cert->signature);
        if (dest_cert->signature == NULL) {
            SSH_LOG(SSH_LOG_TRACE,
                    "Error while duplicating the signature "
                    "during certificate copy");
            goto fail;
        }
    }

    return dest_cert;

fail:
    SSH_CERT_FREE(dest_cert);
    return NULL;
}

/**
 * @brief Validate and parse the ssh_string data of an authentication option
 * (critical or not) containing the value associated to the name of the option.
 *
 * @param [in]   data   The ssh_string containing the option value.
 *
 * @param [out]  value  The C string null-terminated being updated with the
 *                      content of the data argument.
 *
 * @return 0 and the value updated on success.
 * @return -1 on error.
 */
static int
pki_process_auth_option(ssh_string data, char **value)
{
    ssh_string inner_data = NULL;
    size_t data_size = 0, inner_data_size = 0;
    char *val = NULL;
    int rc = 0;

    data_size = ssh_string_len(data);
    /*
     * If the data size is 0 then the option is a flag,
     * otherwise it is of type key=value
     */
    if (data_size == 0) {
        goto out;
    }

    inner_data = ssh_string_data(data);
    if (inner_data == NULL) {
        SSH_LOG(SSH_LOG_TRACE, "Error while getting the option value payload");
        rc = -1;
        goto out;
    }

    inner_data_size = ssh_string_len(inner_data);
    if ((data_size - inner_data_size) != sizeof(uint32_t)) {
        SSH_LOG(SSH_LOG_TRACE, "Corrupted size of the option value");
        rc = -1;
        goto out;
    }

    val = ssh_string_to_char(inner_data);
    if (val == NULL) {
        SSH_LOG(SSH_LOG_TRACE,
                "Error while unpacking the option value "
                "to a C string");
        rc = -1;
        goto out;
    }
    *value = val;

out:
    return rc;
}

/**
 * @brief Parse certificate authentication options packed strings (e.g. critical
 * options or extensions).
 *
 * @warning Before calling this function the certificate type must be properly
 * initialized to a valid type (SSH_CERT_TYPE_USER or SSH_CERT_TYPE_HOST).
 *
 * @param[out]  cert   The certificate structure being updated.
 *
 * @param[in]   field  The authentication options field where the packed strings
 *                     are located.
 *
 * @param[in]   what   The target option (e.g. SSH_CERT_PARSE_CRITICAL_OPTIONS
 *                                        or SSH_CERT_PARSE_EXTENSIONS).
 *
 * @return  0 on parsing success or empty field.
 * @return  -1 on failure.
 */
static int
pki_cert_unpack_auth_options(ssh_cert cert, ssh_string field, int what)
{
    ssh_buffer buffer = NULL;
    char *name = NULL, *value = NULL;
    ssh_string data = NULL;
    int rc;

    buffer = ssh_buffer_new();
    if (buffer == NULL) {
        SSH_LOG(SSH_LOG_TRACE, "Buffer initialization failed");
        rc = -1;
        goto out;
    }

    rc = ssh_buffer_add_data(buffer,
                             ssh_string_data(field),
                             ssh_string_len(field));
    if (rc < 0) {
        SSH_LOG(SSH_LOG_TRACE, "Error while adding data to the buffer");
        goto out;
    }

    switch (what) {
    case SSH_CERT_PARSE_CRITICAL_OPTIONS:
        while (ssh_buffer_get_len(buffer) != 0) {
            rc = ssh_buffer_unpack(buffer, "sS", &name, &data);
            if (rc != SSH_OK) {
                SSH_LOG(SSH_LOG_TRACE, "Unpack critical option error");
                break;
            }

            rc = pki_process_auth_option(data, &value);
            if (rc == -1) {
                SSH_LOG(SSH_LOG_TRACE,
                        "Error while processing %s option",
                        name);
                break;
            }

            if (strcmp(name, "force-command") == 0 && value != NULL) {
                if (cert->type == SSH_CERT_TYPE_HOST) {
                    SSH_LOG(SSH_LOG_TRACE,
                            "Critical options for Host Certificates "
                            "are not defined - Invalid option: %s",
                            name);
                    rc = -1;
                    break;
                }

                if (cert->critical_options->force_command != NULL) {
                    SSH_LOG(SSH_LOG_TRACE,
                            "Certificate contains multiple"
                            "force-command options");
                    rc = -1;
                    break;
                }

                cert->critical_options->force_command = strdup(value);
                if (cert->critical_options->force_command == NULL) {
                    SSH_LOG(SSH_LOG_TRACE,
                            "Error while allocating space for "
                            "force-command option");
                    rc = -1;
                    break;
                }
            } else if (strcmp(name, "source-address") == 0 && value != NULL) {
                if (cert->type == SSH_CERT_TYPE_HOST) {
                    SSH_LOG(SSH_LOG_TRACE,
                            "Critical options for Host Certificates "
                            "are not defined - Invalid option: %s",
                            name);
                    rc = -1;
                    break;
                }

#ifdef _WIN32
                /*
                 * Unsupported source-address option on Windows is just stored
                 * without any check on its validity and later discarded during
                 * the actual use and validation of the certificate
                 */
                SSH_LOG(SSH_LOG_TRACE,
                        "Critical option source-address is not"
                        "supported on Windows");
#endif

                if (cert->critical_options->source_address != NULL) {
                    SSH_LOG(SSH_LOG_TRACE,
                            "Certificate contains multiple"
                            "source-address options");
                    rc = -1;
                    break;
                }

#ifndef _WIN32
                rc = match_cidr_address_list(NULL, value, -1);
                if (rc == -1) {
                    SSH_LOG(SSH_LOG_TRACE,
                            "Validation of CIDR list \"%.100s\" failed",
                            value);
                    break;
                }
#endif
                cert->critical_options->source_address = strdup(value);
                if (cert->critical_options->source_address == NULL) {
                    SSH_LOG(SSH_LOG_TRACE,
                            "Error while allocating space for "
                            "source-address option");
                    rc = -1;
                    break;
                }
            } else if (strcmp(name, "verify-required") == 0) {
                if (cert->type == SSH_CERT_TYPE_HOST) {
                    SSH_LOG(SSH_LOG_TRACE,
                            "Critical options for Host Certificates "
                            "are not defined - Invalid option: %s",
                            name);
                    rc = -1;
                    break;
                }

                if (cert->critical_options->verify_required && value == NULL) {
                    SSH_LOG(SSH_LOG_TRACE,
                            "Certificate contains multiple"
                            "verify-required options");
                    rc = -1;
                    break;
                }

                cert->critical_options->verify_required = true;
            } else {
                SSH_LOG(SSH_LOG_TRACE,
                        "Critical option \"%s\" not supported",
                        name);
                rc = -1;
                break;
            }

            SAFE_FREE(name);
            SAFE_FREE(value);
            SSH_STRING_FREE(data);
        }
        break;
    case SSH_CERT_PARSE_EXTENSIONS:
        while (ssh_buffer_get_len(buffer) != 0) {
            rc = ssh_buffer_unpack(buffer, "sS", &name, &data);
            if (rc != SSH_OK) {
                SSH_LOG(SSH_LOG_TRACE, "Unpack extension error");
                break;
            }

            if (cert->type == SSH_CERT_TYPE_HOST) {
                SSH_LOG(SSH_LOG_TRACE,
                        "Extensions for Host Certificates "
                        "are not defined - Invalid extension: %s",
                        name);
                SAFE_FREE(name);
                SAFE_FREE(data);
                continue;
            }

            rc = pki_process_auth_option(data, &value);
            if (rc == -1) {
                SSH_LOG(SSH_LOG_TRACE,
                        "Error while processing %s option",
                        name);
                break;
            }

            if (strcmp(name, "no-touch-required") == 0) {
                if ((cert->extensions.ext & NO_TOUCH_REQUIRED) != 0) {
                    SSH_LOG(SSH_LOG_TRACE,
                            "Certificate contains multiple %s extensions",
                            name);
                    rc = -1;
                    break;
                }
                cert->extensions.ext |= NO_TOUCH_REQUIRED;
            } else if (strcmp(name, "permit-X11-forwarding") == 0) {
                if ((cert->extensions.ext & PERMIT_X11_FORWARDING) != 0) {
                    SSH_LOG(SSH_LOG_TRACE,
                            "Certificate contains multiple %s extensions",
                            name);
                    rc = -1;
                    break;
                }
                cert->extensions.ext |= PERMIT_X11_FORWARDING;
            } else if (strcmp(name, "permit-agent-forwarding") == 0) {
                if ((cert->extensions.ext & PERMIT_AGENT_FORWARDING) != 0) {
                    SSH_LOG(SSH_LOG_TRACE,
                            "Certificate contains multiple %s extensions",
                            name);
                    rc = -1;
                    break;
                }
                cert->extensions.ext |= PERMIT_AGENT_FORWARDING;
            } else if (strcmp(name, "permit-port-forwarding") == 0) {
                if ((cert->extensions.ext & PERMIT_PORT_FORWARDING) != 0) {
                    SSH_LOG(SSH_LOG_TRACE,
                            "Certificate contains multiple %s extensions",
                            name);
                    rc = -1;
                    break;
                }
                cert->extensions.ext |= PERMIT_PORT_FORWARDING;
            } else if (strcmp(name, "permit-pty") == 0) {
                if ((cert->extensions.ext & PERMIT_PTY) != 0) {
                    SSH_LOG(SSH_LOG_TRACE,
                            "Certificate contains multiple %s extensions",
                            name);
                    rc = -1;
                    break;
                }
                cert->extensions.ext |= PERMIT_PTY;
            } else if (strcmp(name, "permit-user-rc") == 0) {
                if ((cert->extensions.ext & PERMIT_USER_RC) != 0) {
                    SSH_LOG(SSH_LOG_TRACE,
                            "Certificate contains multiple %s extensions",
                            name);
                    rc = -1;
                    break;
                }
                cert->extensions.ext |= PERMIT_USER_RC;
            } else {
                SSH_LOG(SSH_LOG_TRACE, "Extension \"%s\" not supported", name);
            }
            SAFE_FREE(name);
            SAFE_FREE(value);
            SSH_STRING_FREE(data);
        }
        break;
    default:
        SSH_LOG(SSH_LOG_TRACE, "Target option not valid");
        rc = -1;
        break;
    }

out:
    SSH_BUFFER_FREE(buffer);
    SAFE_FREE(name);
    SAFE_FREE(value);
    SSH_STRING_FREE(data);
    return rc;
}

/**
 * @brief Parse certificate principals packed strings. If no entries are found,
 * the number of principals is set to 0 and the principals list is set to NULL.
 *
 * @param[out] cert   The certificate structure being updated.
 *
 * @param[in]  field  The principals field where the packed strings are located.
 *
 * @return  0 on success.
 * @return  -1 on failure.
 *
 */
static int
pki_cert_unpack_principals(ssh_cert cert, ssh_string field)
{
    ssh_buffer buffer = NULL;
    char *tmp_s = NULL, **temp = NULL, **ret = NULL;
    int rc, n_entries = 0, alloc_entries = 0, i;

    buffer = ssh_buffer_new();
    if (buffer == NULL) {
        SSH_LOG(SSH_LOG_TRACE, "Buffer initialization failed");
        goto fail;
    }

    rc = ssh_buffer_add_data(buffer,
                             ssh_string_data(field),
                             ssh_string_len(field));
    if (rc < 0) {
        SSH_LOG(SSH_LOG_TRACE, "Error while adding data to the buffer");
        goto fail;
    }

    while (ssh_buffer_get_len(buffer) != 0) {
        rc = ssh_buffer_unpack(buffer, "s", &tmp_s);
        if (rc != SSH_OK) {
            SSH_LOG(SSH_LOG_TRACE, "Unpack principal error");
            goto fail;
        }

        /*
         * Re-allocate in chunks. Starting with size 4 and doubling each time
         * more space is needed.
         */
        if (n_entries >= alloc_entries) {
            alloc_entries = alloc_entries == 0 ? 4 : alloc_entries * 2;
            temp = realloc(ret, alloc_entries * sizeof(char *));
            if (temp == NULL) {
                SSH_LOG(SSH_LOG_TRACE, "realloc() failed");
                goto fail;
            }
            ret = temp;
        }

        ret[n_entries] = tmp_s;
        tmp_s = NULL;

        n_entries += 1;

        if (n_entries > SSH_CERT_MAX_PRINCIPALS) {
            SSH_LOG(SSH_LOG_TRACE,
                    "The number of principals in the certificate"
                    " exceeds the maximum allowed (256) ");
            goto fail;
        }
    }

    cert->n_principals = n_entries;
    cert->principals = ret;

    SSH_BUFFER_FREE(buffer);
    SAFE_FREE(tmp_s);
    return 0;

fail:
    cert->n_principals = 0;
    cert->principals = NULL;
    SSH_BUFFER_FREE(buffer);
    SAFE_FREE(tmp_s);
    for (i = 0; i < n_entries; i++) {
        SAFE_FREE(ret[i]);
    }
    SAFE_FREE(ret);
    return -1;
}

/**
 * @brief Parse remaining certificate fields from serial up to the signature.
 *
 * @param[in]  buffer   The buffer holding certificate fields.
 *
 * @param[out] pkey     A pointer where the allocated key can be stored.
 *
 * @return  SSH_OK on success.
 * @return  SSH_ERROR on error.
 *
 */
int
pki_parse_cert_data(ssh_buffer buffer, ssh_cert cert)
{
    ssh_key signature_key = NULL;
    ssh_signature signature = NULL;
    ssh_string principals = NULL, ext = NULL, c_opts = NULL, sign_key = NULL,
               sign = NULL, reserved = NULL;
    int rc;

    if (cert == NULL) {
        goto fail;
    }

    /* Parse serial, type, key_id, principals */
    rc = ssh_buffer_unpack(buffer,
                           "qdsS",
                           &cert->serial,
                           &cert->type,
                           &cert->key_id,
                           &principals);

    if (rc != SSH_OK) {
        SSH_LOG(SSH_LOG_TRACE,
                "Unpack of serial, type, key_id and principals failed");
        goto fail;
    }

    if (cert->type != SSH_CERT_TYPE_HOST && cert->type != SSH_CERT_TYPE_USER) {
        SSH_LOG(SSH_LOG_TRACE,
                "Unsupported certificate type. It is neither a host certificate"
                " nor a user certificate");
        goto fail;
    }

    rc = pki_cert_unpack_principals(cert, principals);
    if (rc == -1) {
        SSH_LOG(SSH_LOG_TRACE, "Principals unpack failed");
        goto fail;
    }
    if (cert->principals == NULL && cert->n_principals == 0) {
        SSH_LOG(SSH_LOG_TRACE,
                "Principals field is empty - "
                "The certificate is valid for any principals");
    }
    SSH_STRING_FREE(principals);

    /*
     * Parse validity dates, critical options and extensions.
     * Reserved field can be skipped
     */
    rc = ssh_buffer_unpack(buffer,
                           "qqSSS",
                           &cert->valid_after,
                           &cert->valid_before,
                           &c_opts,
                           &ext,
                           &reserved);

    if (rc != SSH_OK) {
        SSH_LOG(SSH_LOG_TRACE,
                "Unpack of validity dates, critical options, extensions and "
                "reserved field failed");
        goto fail;
    }

    rc = pki_cert_unpack_auth_options(cert,
                                      c_opts,
                                      SSH_CERT_PARSE_CRITICAL_OPTIONS);
    if (rc == -1) {
        SSH_LOG(SSH_LOG_TRACE, "Critical options unpack failed");
        goto fail;
    }
    rc = pki_cert_unpack_auth_options(cert, ext, SSH_CERT_PARSE_EXTENSIONS);
    if (rc == -1) {
        SSH_LOG(SSH_LOG_TRACE, "Extensions unpack failed");
        goto fail;
    }

    SSH_STRING_FREE(c_opts);
    SSH_STRING_FREE(ext);
    SSH_STRING_FREE(reserved);

    /* Parse signature key and signature */
    rc = ssh_buffer_unpack(buffer, "SS", &sign_key, &sign);
    if (rc != SSH_OK) {
        SSH_LOG(SSH_LOG_TRACE, "Unpack of signature key and signature failed");
        goto fail;
    }

    /* Key extraction */
    rc = ssh_pki_import_pubkey_blob(sign_key, &signature_key);
    if (rc != SSH_OK) {
        goto fail;
    }
    cert->signature_key = signature_key;
    SSH_STRING_FREE(sign_key);

    /* Signature extraction */
    rc = ssh_pki_import_signature_blob(sign, signature_key, &signature);
    if (rc != SSH_OK) {
        goto fail;
    }
    cert->signature = signature;
    SSH_STRING_FREE(sign);

    return SSH_OK;

fail:
    SSH_SIGNATURE_FREE(signature);
    SSH_KEY_FREE(signature_key);
    SSH_STRING_FREE(principals);
    SSH_STRING_FREE(ext);
    SSH_STRING_FREE(c_opts);
    SSH_STRING_FREE(sign_key);
    SSH_STRING_FREE(sign);
    SSH_STRING_FREE(reserved);
    return SSH_ERROR;
}

/**
 * @brief Verify the current validity of a certificate. The certificate
 * is checked based on the type, validity dates, valid principals and allowed
 * CA signature algorithms.
 *
 * @param[in] key        The ssh_key public key of a certificate.
 *
 * @param[in] host_type  A boolean indicating if the function is called during
 *                       server host authentication requiring, then, a host cert
 *                       type.
 *
 * @param[in] name       The hostname or username to be checked against the
 *                       allowed principal names in the certificate
 *                       for host or user authentication.
 *
 * @param[in] allowed_ca_sign_algos The list of allowed CA signature algorithms.
 *
 * @returns SSH_OK if the certificate is valid.
 * @returns SSH_ERROR if the certificate is NOT valid.
 */
int
pki_cert_check_validity(ssh_key key,
                        bool host_type,
                        const char *name,
                        const char *allowed_ca_sign_algos)
{
    time_t time_now;
    int rc, valid_principal = 0;
    char datetime[64], err_msg[SSH_ERRNO_MSG_MAX] = {0};
    unsigned int i;

    if (!is_cert_type(key->type)) {
        SSH_LOG(SSH_LOG_WARN, "The key is not a certificate");
        return SSH_ERROR;
    }

    /*
     * Check if the certificate signature type is allowed by default or custom
     * CASignatureAlgorithms.
     */
    if (allowed_ca_sign_algos != NULL) {
        rc = match_pattern_list(key->cert_data->signature->type_c,
                                allowed_ca_sign_algos,
                                strlen(allowed_ca_sign_algos),
                                0);
        if (rc == 0) {
            SSH_LOG(SSH_LOG_WARN, "Invalid certificate. The certificate is "
                                  "signed with non-allowed signature type");
            return SSH_ERROR;
        }
    }

    /*
     * Check if the certificate type is correct based on whether the
     * function has been called during host or user authentication
     */
    if (host_type) {
        if (key->cert_data->type != SSH_CERT_TYPE_HOST) {
            SSH_LOG(SSH_LOG_WARN,
                    "Invalid certificate: not a host certificate");
            return SSH_ERROR;
        }
    } else {
        if (key->cert_data->type != SSH_CERT_TYPE_USER) {
            SSH_LOG(SSH_LOG_WARN,
                    "Invalid certificate: not a user certificate");
            return SSH_ERROR;
        }
    }

    time_now = time(NULL);
    if (time_now == (time_t) - 1) {
        SSH_LOG(SSH_LOG_WARN,
                "Error while retrieving current time: %s",
                ssh_strerror(errno, err_msg, SSH_ERRNO_MSG_MAX));
        return SSH_ERROR;
    }

    /* Check the certificate validity dates */
    if ((uint64_t)time_now < key->cert_data->valid_after) {
        ssh_format_time_to_string(key->cert_data->valid_after,
                                  datetime,
                                  sizeof(datetime));
        SSH_LOG(SSH_LOG_WARN,
                "Invalid certificate. The certificate is not valid yet. "
                "Valid after: %s",
                datetime);
        return SSH_ERROR;
    }

    if ((uint64_t)time_now > key->cert_data->valid_before) {
        ssh_format_time_to_string(key->cert_data->valid_before,
                                  datetime,
                                  sizeof(datetime));
        SSH_LOG(SSH_LOG_WARN,
                "Invalid certificate. The certificate is expired. "
                "Valid before: %s",
                datetime);
        return SSH_ERROR;
    }

    /* Check if there are any valid principals */
    if (key->cert_data->n_principals == 0) {
        /* Certificate is valid for any principals */
        SSH_LOG(SSH_LOG_TRACE,
                "Certificate serial %"PRIu64" ID: %s is valid for "
                "any principal",
                key->cert_data->serial,
                key->cert_data->key_id);
    } else if (name != NULL) {
        for (i = 0; i < key->cert_data->n_principals; i++) {
            if (strcmp(name, key->cert_data->principals[i]) == 0) {
                valid_principal = 1;
                break;
            }
        }
        if (!valid_principal) {
            SSH_LOG(SSH_LOG_WARN,
                    "Invalid certificate: %s is not a valid principal",
                    name);
            return SSH_ERROR;
        }
    }

    return SSH_OK;
}
