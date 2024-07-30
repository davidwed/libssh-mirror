#include "config.h"
#include "libssh/libssh.h"
#include "pki.c"
#include "torture.h"
#include "torture_pki.h"

#define RSA_KEY_1 "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDLpnWky+5bodU+C1R5VPBfWS7y33TEnVaE7apWszJD1Qjm9DC4+921HrWpJF+xo2qH09uVcAm+9N5cgiXWtjQ/aXFX0YUBTEfn8apWKzbhrtUEfiEMaBnuc3Aos3EZjj+L5wrzgqdwg/FLU3/Yt/9Mx+3S5SNgrgg2DFFgo8UYbXCC9BLr9sSjO+i7cDmRdRDYl8O5cCltQn7f6t87UGB7iz2wnC/HyBCRqbpevlQF/kaQuN2Dl+F7cEbRE38LYB6Y7f+EVZR4u2L51lXvBRLHC81zLy+JN1+TKodfCcyaeISELLDV/++H+ssk2I36qk7IBkfPZTMZujJTzpPPH7Ih rsa1@libssh"
#define RSA_KEY_2 "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCqq4Rl043RloSljr6L5wFbMkIF3EqdOnTkIs6sVQQNv55pmlCPZsKiyxqKCvfoXG3c8lcZ4QYBUXvc4mcIdqzgB/pPRn2YGL9WrVLDzGLhkQj1wSkWwflaSwCrnVCZYcSrkaQkb4QmaOReaZWPERVDP9+luYkprfq+lzipy5oxRsB410AlC7QpfBlDna2EfrOn+Djrxdr03TtQnTxbxM3Mlyai/q6R4kZz1R2R26o1LWh0KI+st/+s6hGHY0s9GMcDtFXgzkMRDQwIabqjWHBoPMkF2b/Laim3yt5HjqUvFBhKh7HG0FfHW7tr1AwtKtb9a7sv8zBIyxlihh1g5uBH rsa2@libssh"
#define RSA_KEY_3 "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCzI+I55QhTY9U7tUvjLr2ECGW/HHSTNiBVeWKOSvpIUkgVr4zaI15QUO5YwdPx6BqIwFgDWATgEfSQRNeiggL0TZgrDUFyrBNnbPe0jlFgUZ6plEiuvimsONkadZy7ItVMSQqtgb3yoKb11Tv8Sc+RsdRus7EgNTTGfaxdIVRmdzbbRoZa/RDIY92modLJkeJzbutxwqNBS6LMSrdl3cn5fKL2l3VaneVzAF6lIFCBg1Wn/S+gui7w6hKAF81MwlipAq7pH7R1AJzXDnuWPoco0eFyijSBWvfhIcQfBMr7ZV20HDUnc4gFkIJFUkM36Qs2MoarOHse83gEu0Yct6xmuY0qkdSjoQBzElmxBcMdCk0uiSsOvdVjtbAf+dgZ26Ck6h16hxksKIZuFL7cXLZhTPh9OC1Xbw1oMUe/BXTa8/WzV4bh3oyLBlUwYDqxQ9jkuV9zaVlLtWnMK99ZwVr60TqbPI7fkkcKY5m4cTvbzCsla5nUNFEYO3pnkgXd0d0= rsa3@libssh"
#define ECDSA_KEY_1 "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBI3mfaZxZKz6wAU7+gLsrh61KepUDHFN0EeIIO3xlAcwDx/bGX2vLFbcXg4N789ni5tFeACoO9yxgzvDDHqTd/M= ecdsa1@libssh"
#define ECDSA_KEY_2 "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBFcasZJwq+BFtCj4YjFestz/t3oKE3cwRGgHCxCWyRnKe8VpUtn7IRSbQnGaD1dyZLRqb3NtagCdWJ+yypA2a8jwiyeUk92ihstVKOnJFLr7Ca1Oa5DfS7IksZqhrx/sXg== ecdsa2@libssh"
#define ECDSA_KEY_3 "ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAGPdbJkevkJEue3r9sfXo2h66IyrHkFVs2713qkcRQGpxfOSO+KzMvxJwZ2GcFAYPJnligC3CSrg7KVZTiK9fYEbQBXEz0fec6jlD+8dLT1bWchoa8m7SQd5pUl8QNXzMbgm28YkOr6OvBsLFOtaSKPBIr1N0KhNyUZEiKg0H5JbW8IBg== ecdsa3@libssh"
#define ED25519_KEY_1 "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILbD4Ffc7cz1wlyWuClJFx657YTxkNQFQ9W00d5t6GGR ed25519_1@libssh"
#define ED25519_KEY_2 "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIElrtkXlvao4ArJaTkeVfUYkHQWz6v3j3z/IUKvQ5QDR ed25519_2@libssh"
#define ED25519_KEY_3 "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEKY7r4PdiWX1hE2mFWifhSKE0reZXCHKB0zNoRNPSdU ed25519_3@libssh"
#define COMMENT_LINE "#ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJqorQg9rMvLpt0WeHhedtzIuLgPI4VY8mDMQ+GWsr6R ed25519_4@libssh"
#define RSA_CA_KEY "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDbKq/vimmeicklwuURq9G8Svw+xOnaDxdmxKgHYchjSB7eclVh9VGtiUaccJb2D9/Piwex66gA7t2sKj1gADabGLpdg3JdYJAHQ9I8DlckM5nLFTFu2wOG3Sp+YUb7n18q4K9tERmQWNk00FzvXgLHC+2qqYMc1VqXRtKL6HpQdjapx3LVUSrZ9FIcgECiXVyaqU//Vpm0HHXWVNeFvH2km15ysiV0GTIBwevoToA20QXDXzBmLZWIW4mknxGcvGSqbRGqf0VRuVj//ft39jApYZW7YmJbRIsWAv7Cq/J2Z3nLDreI+D5QU6vmqJhw0/i01DKop1RT1NhvHhubHXukywAvy/hCX6SGRKMNvqXTl7nvUUE/RVVlvtGWuBwXqS/ImPxap1klmFNkpOq3EB5PI/5uKpgo34IWM8EpqSUHfXEwNwgvDmbhiYGZSB8L/+ybbfuDYO+PXoQLL0W0I/znOKHSzvQfHIt0aFtQ18Jo5+QbLgq26D3t0geUTORJmaOjLnHkrrGBcmRgh62haz7yWUH6KBfFlaHQxOoiIUYFEsDXrpFvq2M1kcYjPyVX7MK0LdXbOP2WL/JKCkWtzQcZHnKg4gHAUT70r7DixyLeS/BgE2Xbr+LfyvSHwdcxZO0HlnQvj6dOXpClP2t/JcvJp/3CkCQs3WyYSaDp0aIj0Q== user_ca"
#define RSA_CERT "ssh-rsa-cert-v01@openssh.com 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 user@libssh"
#define ECDSA_CERT "ecdsa-sha2-nistp521-cert-v01@openssh.com AAAAKGVjZHNhLXNoYTItbmlzdHA1MjEtY2VydC12MDFAb3BlbnNzaC5jb20AAAAg1rTC0v7H/wOkrcoDdG/YpqX2lhylcZgTujjUU5k5s10AAAAIbmlzdHA1MjEAAACFBADx4gCL8NBid+atKQFWrw4tguPuQtWsbjh8GFw/jh/ol+L8WxG2YHNB+HfvBsMMbgwBQlU/w+F9iBLmxSFsTbuMuwE9kvvfUedZoAMQNHPjp7wEOcTANwPfeznfxQPfy+Wqfg2vM8coVybdjfkppOlIHP70+xRpOwDPfGQ5UEZvZzEH3gAAAAAAAAAAAAAAAgAAAAoxMjcuMC4wLjEwAAAAAAAAAAAAAAAA//////////8AAAAAAAAAAAAAAAAAAAEXAAAAB3NzaC1yc2EAAAADAQABAAABAQDczUbRv4vt7rJzVQ8PhILO3gIwYvl/MGz3aEocCWiRFPg31RSRCoDCWhjY/+JhKNNimNaOKLtD76NYU023NfPSagIwm1sH9dyTMv+xpyu/IxsCP23DIpEicFhFLXgWVJ+oL+X1izzBWT+/eYl8+JKri9mwsl3QkGnqvrTDxOlBBw6MGCH9vb0Yjp2yFHtp6LKSJyJLsa7ZEEbtR1/vR6voMxhnAdVeMjoU/T6EJb5E5zpnWNDyjw+J+09aqYJjealjr77hvECY3gt9PpPUFxW2uAMhyjF4MHUnqUBTIYOBWCzGI8J2lgUE1oIhZYmzLiXryv8tlxHCbVKJk8dhyrhFAAABFAAAAAxyc2Etc2hhMi01MTIAAAEAiV2x+Fhi/gpePveU8gAzqTOkSHUO1CTYdqJUwdC+ONFPU2hP5c7p2IVpyyW/bj4dtaFpHuV+hemiRC17Q2XS7gf9XwsEcN8pn4732DQK2cy2cUabu08n171ydtSfCl31kNKCFr+onlF3rEtzNk16xbmBB1Qws9j69vs+B8Tj6AzpLyqYD595p8s+7K5kMi+R0v4W9j/FFolcYfYMOgLvLvIKZQwPalWzN8Ad4A/T2WomK7FzvsCG0/q1qsCD5mq6l5KjnALs/gxA/OJ0UQds/vMGU2T4G3LOTqOw/Tz+NqPVvi+gYONqkr0ns2ogjnpg40wsM7EpsygExFIJPjwwUA== host@libssh"

static const char *REVOKED_KEYS[] = {RSA_KEY_1,
                                     RSA_KEY_2,
                                     ECDSA_KEY_1,
                                     ECDSA_KEY_2,
                                     ED25519_KEY_1,
                                     ED25519_KEY_2,
                                     RSA_CA_KEY};

#define TMP_FILE_NAME "/tmp/revoked_keys_XXXXXX"

/**
 * @brief Setup file containing a flat list of revoked keys.
 */
static int
setup_revoked_keys_file(const char **keys, int n_keys, void **state)
{
    char *tmp_file = NULL;
    FILE *fp = NULL;
    int ret, i;

    tmp_file = torture_create_temp_file(TMP_FILE_NAME);
    assert_non_null(tmp_file);

    *state = tmp_file;

    fp = fopen(tmp_file, "w");
    assert_non_null(fp);

    for (i = 0; i < n_keys; i++) {
        ret = fprintf(fp, "%s\n", keys[i]);
        if (ret < 0) {
            fail();
        }
    }

    ret = fprintf(fp, "%s\n", COMMENT_LINE);
    if (ret < 0) {
        fail();
    }

    fclose(fp);
    return 0;
}

static int
teardown_revoked_file(void **state)
{
    char *tmp_file = *state;
    int rc;

    if (tmp_file == NULL) {
        return -1;
    }

    rc = unlink(tmp_file);
    assert_int_equal(rc, 0);
    SAFE_FREE(tmp_file);

    return 0;
}

static int
setup_revoked_keys_file_flat_list(void **state)
{
    int n_keys = sizeof(REVOKED_KEYS) / sizeof(REVOKED_KEYS[0]);
    return setup_revoked_keys_file(REVOKED_KEYS, n_keys, state);
}

/**
 * @brief Helper function for retrieving the ssh_key from the globally defined
 * key string format.
 */
static ssh_key
import_key_from_string_format(const char *entry)
{
    int rc;
    ssh_key key = NULL;
    char *str = NULL, *type_c = NULL, *key_b64 = NULL, *save_tok = NULL;
    enum ssh_keytypes_e key_type;

    str = strdup(entry);
    if (str == NULL) {
        return NULL;
    }

    type_c = strtok_r(str, " ", &save_tok);
    key_type = ssh_key_type_from_name(type_c);

    key_b64 = strtok_r(NULL, " ", &save_tok);
    rc = ssh_pki_import_pubkey_base64(key_b64, key_type, &key);

    SAFE_FREE(str);
    if (rc == SSH_ERROR) {
        return NULL;
    }

    return key;
}

/**
 * @brief Helper function for asserting the revocation status of a key.
 * The final assert is left to the caller.
 */
static int
key_is_revoked(const char *entry, char *revoked_keys_file)
{
    ssh_key key = NULL;
    int rc;

    key = import_key_from_string_format(entry);
    assert_non_null(key);
    rc = ssh_pki_key_is_revoked(key, revoked_keys_file);
    SSH_KEY_FREE(key);
    return rc;
}

static void
torture_revoked_keys_flat_list(void **state)
{
    /*
     * Revoked keys are:
     * RSA_KEY_1, RSA_KEY_2, ECDSA_KEY_1, ECDSA_KEY_2, ED25519_KEY_1,
     * ED25519_KEY_2, RSA_CA_KEY
     */
    char *revoked_keys_file = *state;
    int rc;

    /* Test revoked keys */
    /* RSA 1 */
    rc = key_is_revoked(RSA_KEY_1, revoked_keys_file);
    assert_int_equal(rc, 1);

    /* RSA 2 */
    rc = key_is_revoked(RSA_KEY_2, revoked_keys_file);
    assert_int_equal(rc, 1);

    /* ECDSA 1 */
    rc = key_is_revoked(ECDSA_KEY_1, revoked_keys_file);
    assert_int_equal(rc, 1);

    /* ECDSA 2 */
    rc = key_is_revoked(ECDSA_KEY_2, revoked_keys_file);
    assert_int_equal(rc, 1);

    /* ED25519 1 */
    rc = key_is_revoked(ED25519_KEY_1, revoked_keys_file);
    assert_int_equal(rc, 1);

    /* ED25519 2 */
    rc = key_is_revoked(ED25519_KEY_2, revoked_keys_file);
    assert_int_equal(rc, 1);

    /* RSA_CERT should be revoked by the revoked RSA_CA_KEY */
    rc = key_is_revoked(RSA_CERT, revoked_keys_file);
    assert_int_equal(rc, 1);

    /* Test not revoked keys */
    /* RSA 3 */
    rc = key_is_revoked(RSA_KEY_3, revoked_keys_file);
    assert_int_equal(rc, 0);

    /* ECDSA 3 */
    rc = key_is_revoked(ECDSA_KEY_3, revoked_keys_file);
    assert_int_equal(rc, 0);

    /* ED25519 3 */
    rc = key_is_revoked(ED25519_KEY_3, revoked_keys_file);
    assert_int_equal(rc, 0);

    /* ECDSA CERT */
    rc = key_is_revoked(ECDSA_CERT, revoked_keys_file);
    assert_int_equal(rc, 0);
}

int torture_run_tests(void) {
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(torture_revoked_keys_flat_list,
                                        setup_revoked_keys_file_flat_list,
                                        teardown_revoked_file),
    };

    ssh_init();
    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, NULL, NULL);
    ssh_finalize();
    return rc;
}
