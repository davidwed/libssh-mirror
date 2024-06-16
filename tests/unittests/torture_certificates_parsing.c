#include "libssh/libssh.h"
#include "pki.c"
#include "pki_cert.c"
#include "torture.h"

#define CERT_DIR SOURCEDIR "/tests/keys/certs"

/* Base input for computing a signature. Only for test purpose. */
const unsigned char BASE_INPUT[] = "1234567890123456789012345678901234567890"
                                   "123456789012345678901234";

/**
 * @brief helper function for generating a list of principals in the form
 * "user%d" given the number of the required principals
 * (e.g. n=3 -> user1,user2,user3 )
 */
static int
generate_n_principals(char ***principals, int n)
{
    int i = 0, j;
    char **tmp = NULL, buffer[32];

    tmp = calloc(1, n * sizeof(char *));
    if (tmp == NULL) {
        goto fail;
    }

    for (i = 0; i < n; i++) {
        snprintf(buffer, sizeof(buffer), "user%d", i + 1);
        tmp[i] = strdup(buffer);
        if (tmp[i] == NULL) {
            goto fail;
        }
    }

    *principals = tmp;
    return 0;

fail:
    for (j = 0; j < i; j++) {
        SAFE_FREE(tmp[j]);
    }
    SAFE_FREE(tmp);
    return -1;
}

/**
 * @brief helper function for freeing certificate principals list
 */
static void
free_principals(ssh_cert cert)
{
    unsigned int i;

    if (cert->principals != NULL) {
        for (i = 0; i < cert->n_principals; i++) {
            SAFE_FREE(cert->principals[i]);
        }
        SAFE_FREE(cert->principals);
    }
}

/**
 * @brief helper function for setting up the default extensions in the bitmap.
 * (see OpenSSH PROTOCOL.certkeys for the default extensions)
 */
static void
make_default_extensions(struct ssh_key_cert_exts *a)
{
    if (a == NULL) {
        return;
    }

    a->ext = 0;

    a->ext |= PERMIT_X11_FORWARDING;
    a->ext |= PERMIT_AGENT_FORWARDING;
    a->ext |= PERMIT_PORT_FORWARDING;
    a->ext |= PERMIT_PTY;
    a->ext |= PERMIT_USER_RC;
}

/**
 * @brief helper function for comparing two lists of critical options
 */
static void
assert_copts_equal(cert_opt a, cert_opt b)
{
    assert_int_equal(a->verify_required, b->verify_required);

    if (a->force_command != NULL && b->force_command != NULL) {
        assert_string_equal(a->force_command, b->force_command);
    } else {
        assert_null(a->force_command);
        assert_null(b->force_command);
    }

    if (a->source_address != NULL && b->source_address != NULL) {
        assert_string_equal(a->source_address, b->source_address);
    } else {
        assert_null(a->source_address);
        assert_null(b->source_address);
    }
}

/**
 * @brief setup a default certificate in the form:
 *   Type:            USER
 *   Serial:          0
 *   Key_ID:          test\@libssh.com
 *   Principals:      user1
 *   Validity:        after->19990101 before->19991231
 *   Critical opts:   (none)
 *   Extensions:      permit-X11-forwarding, permit-agent-forwarding
 *                    permit-port-forwarding, permit-pty, permit-user-rc
 *   Signature key    /tests/cert/user_ca.pub
 *
 * The signature is omitted and not checked during the tests that require this
 * setup function since we miss the fields prior to the serial (e,n,nonce).
 *
 */
static int
setup_default_cert(void **state)
{
    ssh_cert cert = NULL;
    int rc;

    cert = ssh_cert_new();
    if (cert == NULL) {
        goto fail;
    }

    cert->type = SSH_CERT_TYPE_USER;
    cert->serial = 0;

    cert->key_id = strdup("test@libssh.com");
    if (cert->key_id == NULL) {
        goto fail;
    }

    cert->n_principals = 1;
    cert->principals = calloc(1, sizeof(char *));
    if (cert->principals == NULL) {
        goto fail;
    }

    generate_n_principals(&cert->principals, 1);
    cert->valid_after = 915145200;
    cert->valid_before = 946594800;

    make_default_extensions(&cert->extensions);
    rc = ssh_pki_import_pubkey_file(CERT_DIR "/user_ca.pub",
                                    &cert->signature_key);
    if (rc != SSH_OK) {
        goto fail;
    }

    *state = cert;
    return 0;

fail:
    SSH_CERT_FREE(cert);
    return -1;
}

static int
teardown_default_cert(void **state)
{
    SSH_CERT_FREE(*state);

    return 0;
}

/**
 * @brief helper function that compares a certificate loaded from the CERT_DIR
 * against a default certificate modified to match the expected fields of
 * the test certificate loaded.
 */
static void
torture_pki_parse_cert_data(void **state, const char *filename)
{
    int rc;
    unsigned int i;
    ssh_key cert = NULL;
    ssh_cert expected_cert = *state, test_cert = NULL;
    enum ssh_keytypes_e key_type;

    rc = ssh_pki_import_cert_file(filename, &cert);
    assert_return_code(rc, errno);
    if (cert == NULL) {
        goto fail;
    }

    /* The CERT_DIR contains only RSA certificates type */
    key_type = ssh_key_type(cert);
    assert_int_equal(key_type, SSH_KEYTYPE_RSA_CERT01);

    rc = ssh_key_is_public(cert);
    assert_int_equal(rc, 1);

    test_cert = cert->cert_data;

    assert_int_equal(test_cert->type, expected_cert->type);
    assert_int_equal(test_cert->serial, expected_cert->serial);
    assert_string_equal(test_cert->key_id, expected_cert->key_id);
    assert_int_equal(test_cert->n_principals, expected_cert->n_principals);

    for (i = 0; i < test_cert->n_principals; i++) {
        if (test_cert->principals[i] != NULL &&
            expected_cert->principals[i] != NULL) {
            assert_string_equal(test_cert->principals[i],
                                expected_cert->principals[i]);
        } else {
            goto fail;
        }
    }

    assert_int_equal(test_cert->valid_before, expected_cert->valid_before);
    assert_int_equal(test_cert->valid_after, expected_cert->valid_after);

    assert_copts_equal(test_cert->critical_options,
                       expected_cert->critical_options);

    assert_int_equal(test_cert->extensions.ext, expected_cert->extensions.ext);

    rc = ssh_key_cmp(test_cert->signature_key,
                     expected_cert->signature_key,
                     SSH_KEY_CMP_PUBLIC);
    assert_int_equal(rc, 0);

    SSH_KEY_FREE(cert);
    return;

fail:
    SSH_KEY_FREE(cert);
    fail();
}

static void
torture_cert_default_extensions(void **state)
{
    /*
     * Type:            USER
     * Serial:          0
     * Key_ID:          test@libssh.com
     * Principals:      user1
     * Validity:        after->19990101 before->19991231
     * Critical opts:   (none)
     * Extensions:      permit-X11-forwarding, permit-agent-forwarding
     *                  permit-port-forwarding, permit-pty, permit-user-rc
     * Signature key    /tests/cert/user_ca.pub
     */
    torture_pki_parse_cert_data(state, CERT_DIR "/default_exts.cert");
}

static void
torture_cert_all_exts(void **state)
{
    /*
     * Type:            USER
     * Serial:          1
     * Key_ID:          test@libssh.com
     * Principals:      user1
     * Validity:        after->19990101 before->19991231
     * Critical opts:   (none)
     * Extensions:      permit-X11-forwarding, permit-agent-forwarding
     *                  permit-port-forwarding, permit-pty, permit-user-rc
     *                  no-touch-required
     * Signature key    /tests/cert/user_ca.pub
     */
    ssh_cert cert = *state;

    cert->serial = 1;
    cert->extensions.ext |= NO_TOUCH_REQUIRED;

    torture_pki_parse_cert_data(state, CERT_DIR "/all_exts.cert");
}

static void
torture_cert_no_exts(void **state)
{
    /*
     * Type:            USER
     * Serial:          2
     * Key_ID:          test@libssh.com
     * Principals:      user1,user2,user3,user4,user5,user6
     * Validity:        after->19990101 before->19991231
     * Critical opts:   (none)
     * Extensions:      (none)
     * Signature key    /tests/cert/user_ca.pub
     */
    ssh_cert cert = *state;
    int rc;

    cert->serial = 2;
    cert->extensions.ext = 0;

    free_principals(cert);
    cert->n_principals = 6;
    rc = generate_n_principals(&cert->principals, 6);
    assert_int_equal(rc, 0);

    torture_pki_parse_cert_data(state, CERT_DIR "/no_exts.cert");
}

static void
torture_cert_force_command(void **state)
{
    /*
     * Type:            USER
     * Serial:          3
     * Key_ID:          test@libssh.com
     * Principals:      user1
     * Validity:        after->19990101 before->19991231
     * Critical opts:   force-command=/path/to/run.sh
     * Extensions:      permit-X11-forwarding, permit-agent-forwarding
     *                  permit-port-forwarding, permit-pty, permit-user-rc
     *                  (default)
     * Signature key    /tests/cert/user_ca.pub
     */
    ssh_cert cert = *state;
    char *option = NULL;

    cert->serial = 3;
    option = strdup("/path/to/run.sh");
    assert_non_null(option);

    cert->critical_options->force_command = option;
    torture_pki_parse_cert_data(state, CERT_DIR "/force_command.cert");
}

static void
torture_cert_source_address(void **state)
{
    /*
     * Type:            USER
     * Serial:          4
     * Key_ID:          test@libssh.com
     * Principals:      user1,user2,user3,user4
     * Validity:        after->19990101 before->19991231
     * Critical opts:   source-address=127.0.0.1/32,::1/128
     * Extensions:      permit-X11-forwarding, permit-agent-forwarding
     *                  permit-port-forwarding, permit-pty, permit-user-rc
     *                  (default)
     * Signature key    /tests/cert/user_ca.pub
     */
    ssh_cert cert = *state;
    char *option = NULL;
    int rc;

    cert->serial = 4;

    free_principals(cert);
    cert->n_principals = 4;
    rc = generate_n_principals(&cert->principals, 4);
    assert_int_equal(rc, 0);

#ifdef _WIN32
    cert->critical_options->source_address = NULL;
#else
    option = strdup("127.0.0.1/32,::1/128");
    assert_non_null(option);
    cert->critical_options->source_address = option;
#endif

    torture_pki_parse_cert_data(state, CERT_DIR "/source_address.cert");
}

static void
torture_cert_verify_required(void **state)
{
    /*
     * Type:            USER
     * Serial:          5
     * Key_ID:          test@libssh.com
     * Principals:      user1,user2,user3,user4,user5,user6,user7,user8,user9
     * Validity:        after->19990101 before->19991231
     * Critical opts:   verify-required
     * Extensions:      permit-X11-forwarding, permit-agent-forwarding
     *                  permit-port-forwarding, permit-pty, permit-user-rc
     *                  (default)
     * Signature key    /tests/cert/user_ca.pub
     */
    ssh_cert cert = *state;
    int rc;

    cert->serial = 5;

    free_principals(cert);
    cert->n_principals = 9;
    rc = generate_n_principals(&cert->principals, 9);
    assert_int_equal(rc, 0);

    cert->critical_options->verify_required = true;

    torture_pki_parse_cert_data(state, CERT_DIR "/verify_required.cert");
}

static void
torture_cert_all_options(void **state)
{
    /*
     * Type:            USER
     * Serial:          6
     * Key_ID:          test@libssh.com
     * Principals:      user1
     * Validity:        after->19990101 before->19991231
     * Critical opts:   force-command=/path/to/run.sh
     *                  source-address=127.0.0.1/32,::1/128
     *                  verify-required
     * Extensions:      permit-X11-forwarding, permit-agent-forwarding
     *                  permit-port-forwarding, permit-pty, permit-user-rc
     *                  no-touch-required
     * Signature key    /tests/cert/user_ca.pub
     */
    ssh_cert cert = *state;
    char *option_a = NULL, *option_b = NULL;

    cert->serial = 6;

    option_a = strdup("/path/to/run.sh");
    assert_non_null(option_a);
    cert->critical_options->force_command = option_a;

#ifdef _WIN32
    cert->critical_options->source_address = NULL;
#else
    option_b = strdup("127.0.0.1/32,::1/128");
    assert_non_null(option_b);
    cert->critical_options->source_address = option_b;
#endif

    cert->critical_options->verify_required = true;
    cert->extensions.ext |= NO_TOUCH_REQUIRED;

    torture_pki_parse_cert_data(state, CERT_DIR "/all_options.cert");
}

static void
torture_cert_no_all(void **state)
{
    /*
     * Type:            USER
     * Serial:          7
     * Key_ID:          test@libssh.com
     * Principals:      (none)
     * Validity:        (forever)
     * Critical opts:   (none)
     * Extensions:      (none)
     * Signature key    /tests/cert/user_ca.pub
     */
    ssh_cert cert = *state;

    cert->serial = 7;

    free_principals(cert);
    cert->n_principals = 0;

    cert->valid_after = 0;
    cert->valid_before = 0xffffffffffffffffULL;

    cert->extensions.ext = 0;

    torture_pki_parse_cert_data(state, CERT_DIR "/no_all.cert");
}

static void
torture_cert_host(void **state)
{
    /*
     * Type:            HOST
     * Serial:          8
     * Key_ID:          test@libssh.com
     * Principals:      hostname
     * Validity:        after->19990101 before->19991231
     * Critical opts:   (none)
     * Extensions:      (none)
     * Signature key    /tests/cert/user_ca.pub
     */
    ssh_cert cert = *state;

    cert->type = SSH_CERT_TYPE_HOST;
    cert->serial = 8;

    SAFE_FREE(cert->principals[0]);
    cert->principals[0] = strdup("hostname");
    assert_non_null(cert->principals[0]);

    cert->extensions.ext = 0;

    torture_pki_parse_cert_data(state, CERT_DIR "/host.cert");
}

/**
 * @brief helper function that converts a list of principals into a ssh_string,
 * given then number of the principals. If n=0, it returns an empty ssh_string.
 */
static ssh_string
make_principals(const char **principal, int n)
{
    ssh_buffer buffer = NULL;
    ssh_string principals = NULL;
    int rc, i;
    size_t buf_len;
    void *data = NULL;

    if (n == 0) {
        principals = ssh_string_new(0);
        goto out;
    }

    buffer = ssh_buffer_new();
    if (buffer == NULL) {
        goto fail;
    }

    for (i = 0; i < n; i++) {
        rc = ssh_buffer_pack(buffer, "s", principal[i]);
        if (rc != SSH_OK) {
            goto fail;
        }
    }

    buf_len = ssh_buffer_get_len(buffer);
    data = ssh_buffer_get(buffer);

    principals = ssh_string_new(buf_len);
    rc = ssh_string_fill(principals, data, buf_len);
    if (rc == -1) {
        goto fail;
    }

    SSH_BUFFER_FREE(buffer);

out:
    return principals;

fail:
    SSH_BUFFER_FREE(buffer);
    SSH_STRING_FREE(principals);
    return NULL;
}

/**
 * @brief helper function that converts a list of extensions (critical or not)
 * into a ssh_string, given then number of the extensions. If n=0, it returns an
 * empty ssh_string.
 *
 * @usage (e.g. "key=value" or only "key" (as a flag))
 */
static ssh_string
make_extensions(const char **options, int n)
{
    ssh_buffer buffer = NULL, b = NULL;
    ssh_string critical_options = NULL, value_s = NULL;

    int rc, i;
    size_t buf_len;
    void *data = NULL;
    char *tmp = NULL, *sp = NULL, *key = NULL, *value = NULL;


    if (n == 0) {
        critical_options = ssh_string_new(0);
        goto out;
    }

    buffer = ssh_buffer_new();
    if (buffer == NULL) {
        goto fail;
    }

    for (i = 0; i < n; i++) {
        b = ssh_buffer_new();
        if (b == NULL) {
            goto fail;
        }

        tmp = strdup(options[i]);
        if (tmp == NULL) {
            goto fail;
        }
        sp = strchr(tmp, '=');

        if (sp == NULL) {
            key = strdup(tmp);
            if (key == NULL) {
                goto fail;
            }

            value_s = ssh_string_new(0);
            if (value_s == NULL) {
                goto fail;
            }

            rc = ssh_buffer_pack(buffer, "sS", key, value_s);
        } else {
            *sp = '\0';
            key = strdup(tmp);
            value = strdup(sp + 1);
            if (key == NULL || value == NULL) {
                goto fail;
            }

            rc = ssh_buffer_pack(b, "s", value);
            if (rc != SSH_OK) {
                goto fail;
            }

            value_s = ssh_string_new(ssh_buffer_get_len(b));
            if (value_s == NULL) {
                goto fail;
            }

            rc = ssh_string_fill(value_s,
                                 ssh_buffer_get(b),
                                 ssh_buffer_get_len(b));
            if (rc < 0) {
                goto fail;
            }
            rc = ssh_buffer_pack(buffer, "sS", key, value_s);
        }

        if (rc != SSH_OK) {
            goto fail;
        }
        SAFE_FREE(key);
        SAFE_FREE(value);
        SAFE_FREE(tmp);
        SSH_STRING_FREE(value_s);
        SSH_BUFFER_FREE(b);
    }

    buf_len = ssh_buffer_get_len(buffer);
    data = ssh_buffer_get(buffer);

    critical_options = ssh_string_new(buf_len);
    rc = ssh_string_fill(critical_options, data, buf_len);
    if (rc == -1) {
        goto fail;
    }

    SSH_BUFFER_FREE(buffer);

out:
    return critical_options;

fail:
    SAFE_FREE(tmp);
    SAFE_FREE(key);
    SAFE_FREE(value);
    SSH_BUFFER_FREE(buffer);
    SSH_BUFFER_FREE(b);
    SSH_STRING_FREE(critical_options);
    return NULL;
}

/**
 * @brief helper function that serialize the certificate input fields into a
 * buffer. Used for testing pki_parse_cert_data.
 */
static ssh_buffer
setup_cert_buffer(uint64_t serial,
                  unsigned int type,
                  const char *key_id,
                  int n_princ,
                  const char **principals,
                  uint64_t valid_after,
                  uint64_t valid_before,
                  int n_crit,
                  const char **critical_options,
                  int n_exts,
                  const char **extensions)
{
    ssh_buffer cert_data = NULL, ret = NULL;
    ssh_string principals_s = NULL, critical_options_s = NULL,
               extensions_s = NULL, sign_key_s = NULL, signature_s = NULL,
               reserved = NULL;
    ssh_key sign_key_public = NULL, sign_key_private = NULL;
    ssh_signature signature = NULL;
    int rc;

    /* Initialize certificate buffer */
    cert_data = ssh_buffer_new();
    if (cert_data == NULL) {
        goto out;
    }

    /* Serialize and convert principals to a blob */
    principals_s = make_principals(principals, n_princ);
    if (principals_s == NULL) {
        goto out;
    }

    /* Create an empty ssh_string for the reserved field */
    reserved = ssh_string_new(0);
    if (reserved == NULL) {
        goto out;
    }

    /* Serialize and convert critical options to a blob */
    critical_options_s = make_extensions(critical_options, n_crit);
    if (critical_options_s == NULL) {
        goto out;
    }

    /* Serialize and convert extensions to a blob */
    extensions_s = make_extensions(extensions, n_exts);
    if (extensions_s == NULL) {
        goto out;
    }

    /* Import the CA public key as the signature key of the certificate */
    rc = ssh_pki_import_pubkey_file(CERT_DIR "/user_ca.pub", &sign_key_public);
    assert_return_code(rc, errno);
    if (rc != SSH_OK) {
        goto out;
    }

    /* Convert the CA public key to a blob */
    sign_key_s = pki_key_to_blob(sign_key_public, SSH_KEY_PUBLIC);
    if (sign_key_s == NULL) {
        goto out;
    }

    /*
     * Compute a signature for the certificate. The signature is not the actual
     * signature of the certificate because we miss the other fields prior to
     * the serial field (e,n,nonce). The signature is computed over a default
     * value just for filling the signature field. This is required for the test
     * to not fail when reaching pki_parse_cert_data function
     */

    /* Import the private key of the signer */
    rc = ssh_pki_import_privkey_file(CERT_DIR "/user_ca",
                                     NULL,
                                     NULL,
                                     NULL,
                                     &sign_key_private);
    assert_return_code(rc, errno);
    if (rc != SSH_OK) {
        goto out;
    }

    signature = pki_sign_data(sign_key_private,
                              SSH_DIGEST_SHA512,
                              BASE_INPUT,
                              sizeof(BASE_INPUT));
    if (signature == NULL) {
        goto out;
    }

    /* Convert the signature to a blob */
    rc = ssh_pki_export_signature_blob(signature, &signature_s);
    assert_return_code(rc, errno);
    if (rc != SSH_OK) {
        goto out;
    }

    /* Pack all the certificate fields into the buffer */
    rc = ssh_buffer_pack(cert_data,
                         "qdsSqqSSSSS",
                         serial,
                         type,
                         key_id,
                         principals_s,
                         valid_after,
                         valid_before,
                         critical_options_s,
                         extensions_s,
                         reserved,
                         sign_key_s,
                         signature_s);
    assert_return_code(rc, errno);
    if (rc != SSH_OK) {
        goto out;
    }

    ret = cert_data;
    cert_data = NULL;

out:
    SSH_STRING_FREE(principals_s);
    SSH_STRING_FREE(critical_options_s);
    SSH_STRING_FREE(extensions_s);
    SSH_STRING_FREE(sign_key_s);
    SSH_STRING_FREE(signature_s);
    SSH_STRING_FREE(reserved);
    SSH_KEY_FREE(sign_key_private);
    SSH_KEY_FREE(sign_key_public);
    SSH_SIGNATURE_FREE(signature);
    SSH_BUFFER_FREE(cert_data);
    return ret;
}

static void
torture_parse_cert_data_valid(void **state)
{
    ssh_buffer cert_data = NULL;
    ssh_cert cert = NULL;
    int rc, n_princ, n_exts, n_crit;

    const char *principals[] = {"user", "test", "root"};
    const char *exts[] = {"permit-x11-forwarding",
                          "no-touch-required",
                          "permit-user-rc",
                          "permit-agent-forwarding"};
    const char *c_opts[] = {"force-command=foo", "source-address=127.0.0.1/32"};

    (void)state;

    n_princ = sizeof(principals) / sizeof(principals[0]);
    n_crit = sizeof(c_opts) / sizeof(c_opts[0]);
    n_exts = sizeof(exts) / sizeof(exts[0]);

    cert_data = setup_cert_buffer(1,
                                  SSH_CERT_TYPE_USER,
                                  "test@libssh.com",
                                  n_princ,
                                  principals,
                                  1704067261,
                                  1735689599,
                                  n_crit,
                                  c_opts,
                                  n_exts,
                                  exts);
    assert_non_null(cert_data);

    cert = ssh_cert_new();
    assert_non_null(cert);

    rc = pki_parse_cert_data(cert_data, cert);
    assert_int_equal(rc, SSH_OK);

    SSH_BUFFER_FREE(cert_data);
    SSH_CERT_FREE(cert);
}

static void
torture_parse_cert_data_invalid_crit_opt(void **state)
{
    ssh_buffer cert_data = NULL;
    ssh_cert cert = NULL;
    int rc, n_princ, n_exts, n_crit;

    const char *principals[] = {"user", "alice", "bob"};
    const char *exts[] = {"permit-x11-forwarding",
                          "no-touch-required",
                          "permit-agent-forwarding"};
    const char *c_opts[] = {"force-command=foo",
                            "source-address=127.0.0.1/32",
                            "fake-option"};

    (void)state;

    n_princ = sizeof(principals) / sizeof(principals[0]);
    n_crit = sizeof(c_opts) / sizeof(c_opts[0]);
    n_exts = sizeof(exts) / sizeof(exts[0]);

    cert_data = setup_cert_buffer(1,
                                  SSH_CERT_TYPE_USER,
                                  "test@libssh.com",
                                  n_princ,
                                  principals,
                                  1704067261,
                                  1735689599,
                                  n_crit,
                                  c_opts,
                                  n_exts,
                                  exts);
    assert_non_null(cert_data);

    cert = ssh_cert_new();
    assert_non_null(cert);

    rc = pki_parse_cert_data(cert_data, cert);
    assert_int_equal(rc, SSH_ERROR);

    SSH_BUFFER_FREE(cert_data);
    SSH_CERT_FREE(cert);
}

static void
torture_parse_cert_data_invalid_exts(void **state)
{
    ssh_buffer cert_data = NULL;
    ssh_cert cert = NULL;
    int rc, n_princ, n_exts, n_crit;

    const char *principals[] = {"user123"};
    const char *exts[] = {"permit-x11-forwarding",
                          "no-touch-required",
                          "permit-user-rc",
                          "permit-agent-forwarding",
                          "fake-extension"};
    const char *c_opts[] = {"force-command=/usr/bin/run.sh",
                            "source-address=::1/128"};

    (void)state;

    n_princ = sizeof(principals) / sizeof(principals[0]);
    n_crit = sizeof(c_opts) / sizeof(c_opts[0]);
    n_exts = sizeof(exts) / sizeof(exts[0]);

    cert_data = setup_cert_buffer(1,
                                  SSH_CERT_TYPE_USER,
                                  "test@libssh.com",
                                  n_princ,
                                  principals,
                                  1704067261,
                                  1735689599,
                                  n_crit,
                                  c_opts,
                                  n_exts,
                                  exts);
    assert_non_null(cert_data);

    cert = ssh_cert_new();
    assert_non_null(cert);

    /* It should ignore the unrecognized extension -> rc = SSH_OK */
    rc = pki_parse_cert_data(cert_data, cert);
    assert_int_equal(rc, SSH_OK);

    SSH_BUFFER_FREE(cert_data);
    SSH_CERT_FREE(cert);
}

static void
torture_parse_cert_data_invalid_double_opts(void **state)
{
    ssh_buffer cert_data = NULL;
    ssh_cert cert = NULL;
    int rc, n_exts, n_crit;

    const char *exts[] = {"permit-x11-forwarding",
                          "no-touch-required",
                          "permit-user-rc",
                          "permit-agent-forwarding"};
    const char *c_opts[] = {"force-command=/usr/bin/run.sh",
                            "force-command=foo"};

    (void)state;

    n_crit = sizeof(c_opts) / sizeof(c_opts[0]);
    n_exts = sizeof(exts) / sizeof(exts[0]);

    /* Just for test, no principals are defined (cert valid to everyone) */
    cert_data = setup_cert_buffer(1,
                                  SSH_CERT_TYPE_USER,
                                  "test@libssh.com",
                                  0,
                                  NULL,
                                  1704067261,
                                  1735689599,
                                  n_crit,
                                  c_opts,
                                  n_exts,
                                  exts);
    assert_non_null(cert_data);

    cert = ssh_cert_new();
    assert_non_null(cert);

    rc = pki_parse_cert_data(cert_data, cert);
    assert_int_equal(rc, SSH_ERROR);

    SSH_BUFFER_FREE(cert_data);
    SSH_CERT_FREE(cert);
}

static void
torture_parse_cert_data_invalid_double_exts(void **state)
{
    ssh_buffer cert_data = NULL;
    ssh_cert cert = NULL;
    int rc, n_exts, n_crit;

    const char *exts[] = {"permit-x11-forwarding",
                          "no-touch-required",
                          "permit-user-rc",
                          "permit-user-rc",
                          "permit-pty"};
    const char *c_opts[] = {"force-command=/usr/bin/run.sh"};

    (void)state;

    n_crit = sizeof(c_opts) / sizeof(c_opts[0]);
    n_exts = sizeof(exts) / sizeof(exts[0]);

    /* Just for test, no principals are defined (cert valid to everyone) */
    cert_data = setup_cert_buffer(1,
                                  SSH_CERT_TYPE_USER,
                                  "test@libssh.com",
                                  0,
                                  NULL,
                                  1704067261,
                                  1735689599,
                                  n_crit,
                                  c_opts,
                                  n_exts,
                                  exts);
    assert_non_null(cert_data);

    cert = ssh_cert_new();
    assert_non_null(cert);

    rc = pki_parse_cert_data(cert_data, cert);
    assert_int_equal(rc, SSH_ERROR);

    SSH_BUFFER_FREE(cert_data);
    SSH_CERT_FREE(cert);
}

/**
 * @brief helper function for negative tests on pki_cert_unpack_auth_options
 */
static int
torture_pki_cert_unpack_auth_options(int what,
                                     int n_copts,
                                     const char **c_opts,
                                     int n_exts,
                                     const char **exts,
                                     int type)
{
    ssh_string critical_options = NULL, extensions = NULL;
    ssh_cert cert = NULL;
    int rc;

    cert = ssh_cert_new();
    if (cert == NULL) {
        goto fail;
    }

    cert->type = type;

    switch (what) {
    case SSH_CERT_PARSE_CRITICAL_OPTIONS:
        critical_options = make_extensions(c_opts, n_copts);
        if (critical_options == NULL) {
            goto fail;
        }

        rc = pki_cert_unpack_auth_options(cert, critical_options, what);
        if (rc == -1) {
            goto fail;
        }
        break;
    case SSH_CERT_PARSE_EXTENSIONS:
        extensions = make_extensions(exts, n_exts);
        if (extensions == NULL) {
            goto fail;
        }

        rc = pki_cert_unpack_auth_options(cert, extensions, what);
        if (rc == -1) {
            goto fail;
        }
        break;
    default:
        goto fail;
    }

    SSH_CERT_FREE(cert);
    SSH_STRING_FREE(critical_options);
    SSH_STRING_FREE(extensions);
    return 0;

fail:
    SSH_CERT_FREE(cert);
    SSH_STRING_FREE(critical_options);
    SSH_STRING_FREE(extensions);
    return -1;
}

static void
torture_pki_cert_unpack_invalid_copts(void **state)
{
    const char *c_opts[] = {"force-command=foo",
                            "verify-required",
                            "source-address=::1/128, fe80::/64"};
    int rc, n_crit;

    (void)state;

    n_crit = sizeof(c_opts) / sizeof(c_opts[0]);
    rc = torture_pki_cert_unpack_auth_options(SSH_CERT_PARSE_CRITICAL_OPTIONS,
                                              n_crit,
                                              c_opts,
                                              0,
                                              NULL,
                                              SSH_CERT_TYPE_USER);

#ifdef _WIN32
    /* When running on Windows, unsupported critical options are skipped */
    assert_int_equal(rc, 0);
#else
    assert_int_equal(rc, -1);
#endif
}

static void
torture_pki_cert_unpack_invalid_copts_host(void **state)
{
    /* Critical options are correct but not valid for host certificate */
    const char *c_opts[] = {"force-command=foo",
                            "verify-required",
                            "source-address=::1/128,fe80::/64"};
    int rc, n_crit;

    (void)state;

    n_crit = sizeof(c_opts) / sizeof(c_opts[0]);
    rc = torture_pki_cert_unpack_auth_options(SSH_CERT_PARSE_CRITICAL_OPTIONS,
                                              n_crit,
                                              c_opts,
                                              0,
                                              NULL,
                                              SSH_CERT_TYPE_HOST);

    assert_int_equal(rc, -1);
}

static void
torture_pki_cert_unpack_invalid_exts(void **state)
{
    const char *exts[] = {"permit-x11-forwarding",
                          "permit-agent-forwarding",
                          "permit-user-rc",
                          "no-touch-required",
                          "fake-option"};
    int rc, n_exts;

    (void)state;

    n_exts = sizeof(exts) / sizeof(exts[0]);
    rc = torture_pki_cert_unpack_auth_options(SSH_CERT_PARSE_EXTENSIONS,
                                              0,
                                              NULL,
                                              n_exts,
                                              exts,
                                              SSH_CERT_TYPE_USER);

    assert_int_equal(rc, 0);
}

static void
torture_pki_cert_unpack_invalid_exts_host(void **state)
{
    /*
     * Extensions are correct but not valid for host certificate.
     * The test should not fail since invalid extensions are ignored
     */
    const char *exts[] = {"permit-x11-forwarding",
                          "permit-agent-forwarding",
                          "permit-user-rc",
                          "permit-pty"};
    int rc, n_exts;

    (void)state;

    n_exts = sizeof(exts) / sizeof(exts[0]);
    rc = torture_pki_cert_unpack_auth_options(SSH_CERT_PARSE_EXTENSIONS,
                                              0,
                                              NULL,
                                              n_exts,
                                              exts,
                                              SSH_CERT_TYPE_HOST);

    assert_int_equal(rc, 0);
}

static void
torture_pki_cert_unpack_principals(void **state)
{
    char **princs = NULL;
    ssh_cert cert = NULL;
    ssh_string principals = NULL;
    int rc, n_princs = 300, i;

    (void)state;

    rc = generate_n_principals(&princs, n_princs);
    assert_int_equal(rc, 0);
    if (princs == NULL) {
        goto fail;
    }

    principals = make_principals((const char **)princs, n_princs);
    if (principals == NULL) {
        goto fail;
    }

    cert = ssh_cert_new();
    if (cert == NULL) {
        goto fail;
    }

    /*
     * In this test we are passing to pki_cert_unpack_principals a number of
     * principals (300) that exceeds the maximum allowed (256).
     */
    rc = pki_cert_unpack_principals(cert, principals);
    assert_int_equal(rc, -1);

    assert_int_equal(cert->n_principals, 0);
    assert_null(cert->principals);

    free_principals(cert);
    SSH_STRING_FREE(principals);
    SSH_CERT_FREE(cert);
    return;

fail:
    if (princs != NULL) {
        for (i = 0; i < n_princs; i++) {
            SAFE_FREE(princs[i]);
        }
        SAFE_FREE(princs);
    }
    SSH_STRING_FREE(principals);
    SSH_CERT_FREE(cert);
    fail();
}

static void
torture_pki_cert_unpack_principals_invalid_format(void **state)
{
    ssh_cert cert = NULL;
    ssh_string principals = NULL;
    ssh_buffer buffer = NULL;
    const char *princs[] = {"user1", "user2"};
    int rc, n_princs, i;
    size_t buf_len;
    void *data = NULL;

    (void)state;

    cert = ssh_cert_new();
    assert_non_null(cert);

    buffer = ssh_buffer_new();
    assert_non_null(buffer);

    /*
     * In this test we are packing some junk (integer values) on purpose. The
     * pki_cert_unpack_principals fails only if there are errors while
     * allocating memory or errors while unpacking data from the buffer.
     * Packing the principals with junk integers before them will make
     * pki_cert_unpack_principals fail.
     */
    n_princs = sizeof(princs) / sizeof(princs[0]);
    for (i = 0; i < n_princs; i++) {
        rc = ssh_buffer_pack(buffer, "w", i);
        assert_int_equal(rc, SSH_OK);
    }
    for (i = 0; i < n_princs; i++) {
        rc = ssh_buffer_pack(buffer, "s", princs[i]);
        assert_int_equal(rc, SSH_OK);
    }

    buf_len = ssh_buffer_get_len(buffer);
    data = ssh_buffer_get(buffer);

    principals = ssh_string_new(buf_len);
    rc = ssh_string_fill(principals, data, buf_len);
    assert_int_equal(rc, 0);

    rc = pki_cert_unpack_principals(cert, principals);
    assert_int_equal(rc, -1);

    assert_int_equal(cert->n_principals, 0);
    assert_null(cert->principals);

    SSH_STRING_FREE(principals);
    SSH_BUFFER_FREE(buffer);
    SSH_CERT_FREE(cert);
}

int
torture_run_tests(void)
{
    int rc;

    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_cert_default_extensions,
                                        setup_default_cert,
                                        teardown_default_cert),
        cmocka_unit_test_setup_teardown(torture_cert_all_exts,
                                        setup_default_cert,
                                        teardown_default_cert),
        cmocka_unit_test_setup_teardown(torture_cert_no_exts,
                                        setup_default_cert,
                                        teardown_default_cert),
        cmocka_unit_test_setup_teardown(torture_cert_force_command,
                                        setup_default_cert,
                                        teardown_default_cert),
        cmocka_unit_test_setup_teardown(torture_cert_source_address,
                                        setup_default_cert,
                                        teardown_default_cert),
        cmocka_unit_test_setup_teardown(torture_cert_verify_required,
                                        setup_default_cert,
                                        teardown_default_cert),
        cmocka_unit_test_setup_teardown(torture_cert_all_options,
                                        setup_default_cert,
                                        teardown_default_cert),
        cmocka_unit_test_setup_teardown(torture_cert_no_all,
                                        setup_default_cert,
                                        teardown_default_cert),
        cmocka_unit_test_setup_teardown(torture_cert_host,
                                        setup_default_cert,
                                        teardown_default_cert),
        cmocka_unit_test(torture_parse_cert_data_valid),
        cmocka_unit_test(torture_parse_cert_data_invalid_crit_opt),
        cmocka_unit_test(torture_parse_cert_data_invalid_exts),
        cmocka_unit_test(torture_parse_cert_data_invalid_double_opts),
        cmocka_unit_test(torture_parse_cert_data_invalid_double_exts),
        cmocka_unit_test(torture_pki_cert_unpack_invalid_copts),
        cmocka_unit_test(torture_pki_cert_unpack_invalid_copts_host),
        cmocka_unit_test(torture_pki_cert_unpack_invalid_exts),
        cmocka_unit_test(torture_pki_cert_unpack_invalid_exts_host),
        cmocka_unit_test(torture_pki_cert_unpack_principals),
        cmocka_unit_test(torture_pki_cert_unpack_principals_invalid_format),
    };

    ssh_init();
    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests,
                                setup_default_cert,
                                teardown_default_cert);
    ssh_finalize();
    return rc;
}
