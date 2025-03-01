/*Tests for ssh_get_kex_algo()*/
#include "config.h"
#include "libssh/libssh.h"
#include <libssh/pki.h>
#define LIBSSH_STATIC
#include <libssh/priv.h>
#include <libssh/session.h>
#include "torture.h"

static void torture_ssh_get_kex_algo(void **state)
{
    ssh_session session;
    const char *kex_algo;

    (void)state; /* to avoid unused warning */

    session = ssh_new();
    assert_non_null(session);

    session->current_crypto = calloc(1, sizeof(struct ssh_crypto_struct)); // Use calloc to avoid uninitialized memory
    assert_non_null(session->current_crypto);

    session->current_crypto->kex_type = SSH_KEX_DH_GROUP14_SHA1;
    kex_algo = ssh_get_kex_algo(session);
    assert_non_null(kex_algo);
    assert_string_equal(kex_algo, "diffie-hellman-group14-sha1");

    session->current_crypto->kex_type = SSH_KEX_CURVE25519_SHA256;
    kex_algo = ssh_get_kex_algo(session);
    assert_non_null(kex_algo);
    assert_string_equal(kex_algo, "curve25519-sha256");

    session->current_crypto->kex_type = 9999;
    kex_algo = ssh_get_kex_algo(session);
    assert_null(kex_algo);

    free(session->current_crypto);
    session->current_crypto = NULL; // Prevent double free
    ssh_free(session);
}

int torture_run_tests(void)
{
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test(torture_ssh_get_kex_algo),
    };

    ssh_init();
    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, NULL, NULL);
    ssh_finalize();

    return rc;
}

