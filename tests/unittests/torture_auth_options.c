#include "libssh/libssh.h"
#include "libssh/auth_options.h"
#include "auth_options.c"
#include "torture.h"

#define PERMIT_FLAGS "x11-forwarding,agent-forwarding,port-forwarding,pty," \
                     "user-rc,touch-required"
#define DENY_FLAGS "no-x11-forwarding,no-agent-forwarding,no-port-forwarding," \
                   "no-pty,no-user-rc,no-touch-required"
#define CERT_DIR SOURCEDIR "/tests/keys/certs"

static void
torture_ssh_auth_options_list_parse_all(void **state)
{
    struct ssh_auth_options *x = NULL;
    const char *list = PERMIT_FLAGS ",cert-authority,"
                                    "principals=\"user1,user2,user3,user4\","
                                    "permitlisten=\"localhost:8080\","
                                    "permitopen=\"192.0.2.2:25\","
                                    "expiry-time=\"20250901Z\","
                                    "tunnel=\"0\","
                                    "command=\"sh /etc/netstart tun0\","
                                    "from=\"10.0.0.0/24,fe80::/64\","
                                    "environment="
                                    "\"LD_PRELOAD=/path/to/randlib.so\"";
    uint32_t flags = PERMIT_X11_FORWARDING_OPT | PERMIT_AGENT_FORWARDING_OPT |
                     PERMIT_PORT_FORWARDING_OPT | PERMIT_PTY_OPT |
                     PERMIT_USER_RC_OPT | CERT_AUTHORITY_OPT;

    (void)state;

    x = ssh_auth_options_list_parse(list);
    assert_non_null(x);

    /* Assert bitmap flags */
    assert_int_equal(x->opt_flags, flags);

    /* Assert principals= */
    assert_int_equal(x->n_cert_principals, 4);
    assert_string_equal(x->cert_principals[0], "user1");
    assert_string_equal(x->cert_principals[1], "user2");
    assert_string_equal(x->cert_principals[2], "user3");
    assert_string_equal(x->cert_principals[3], "user4");

    /* Assert permitlisten= */
    assert_int_equal(x->n_permit_listen, 1);
    assert_string_equal(x->permit_listen[0], "localhost:8080");

    /* Assert permitopen= */
    assert_int_equal(x->n_permit_open, 1);
    assert_string_equal(x->permit_open[0], "192.0.2.2:25");

    /* Assert expiry-date= */
    assert_int_equal(x->valid_before, 1756684800ULL);

    /* Assert tunnel= */
    assert_int_equal(x->tun_device, 0);

    /* Assert command= */
    assert_string_equal(x->force_command, "sh /etc/netstart tun0");

    /* Assert from= */
    assert_string_equal(x->authkey_from_addr_host, "10.0.0.0/24,fe80::/64");

    /* Assert environment= */
    assert_int_equal(x->n_envs, 1);
    assert_string_equal(x->envs[0], "LD_PRELOAD=/path/to/randlib.so");

    SSH_AUTH_OPTS_FREE(x);
}

static void
torture_ssh_auth_options_list_parse_restrict(void **state)
{
    struct ssh_auth_options *x = NULL;
    const char *list = "restrict";
    uint32_t flags = RESTRICTED_OPT;

    (void)state;

    /* Test default restrict mode */
    x = ssh_auth_options_list_parse(list);
    assert_non_null(x);
    assert_int_equal(x->opt_flags, flags);
    ssh_auth_options_free(x);

    /* Test restrict option defined later in the list */
    list = PERMIT_FLAGS",restrict";
    x = ssh_auth_options_list_parse(list);
    assert_non_null(x);
    assert_int_equal(x->opt_flags, flags);
    SSH_AUTH_OPTS_FREE(x);
}

static void
torture_ssh_auth_options_list_deny_flags(void **state)
{
    struct ssh_auth_options *x = NULL;
    const char *list = DENY_FLAGS;
    uint32_t flags = NO_TOUCH_REQUIRED_OPT;

    (void)state;

    /* Make sure that no-touch-required has been set */
    x = ssh_auth_options_list_parse(list);
    assert_non_null(x);
    assert_int_equal(x->opt_flags, flags);
    SSH_AUTH_OPTS_FREE(x);
}

static void
torture_ssh_auth_options_list_multiple_opts(void **state)
{
    struct ssh_auth_options *x = NULL;
    const char *list = "permitopen=\"192.0.2.1:80\","
                       "permitopen=\"192.0.2.2:25\","
                       "permitlisten=\"localhost:8080\","
                       "permitlisten=\"[::1]:22000\","
                       "environment=\"LD_PRELOAD=/path/to/randlib.so\","
                       "environment=\"LC_TIME=it_IT.utf8\","
                       "environment=\"PATH=/usr/local/sbin\","
                       "environment=\"HOME=/home/user\","
                       "environment=\"LANG=en_US.UTF-8\","
                       "expiry-time=\"203010010000Z\","
                       "expiry-time=\"203009302230Z\"";
    (void)state;

    x = ssh_auth_options_list_parse(list);
    assert_non_null(x);
    assert_int_equal(x->opt_flags, 0);

    /* Assert double permitopen= */
    assert_int_equal(x->n_permit_open, 2);
    assert_non_null(x->permit_open);
    assert_string_equal(x->permit_open[0], "192.0.2.1:80");
    assert_string_equal(x->permit_open[1], "192.0.2.2:25");

    /* Assert double permitlisten= */
    assert_int_equal(x->n_permit_listen, 2);
    assert_non_null(x->permit_listen);
    assert_string_equal(x->permit_listen[0], "localhost:8080");
    assert_string_equal(x->permit_listen[1], "[::1]:22000");

    /* Assert multiple environments= */
    assert_int_equal(x->n_envs, 5);
    assert_non_null(x->envs);
    assert_string_equal(x->envs[0], "LD_PRELOAD=/path/to/randlib.so");
    assert_string_equal(x->envs[1], "LC_TIME=it_IT.utf8");
    assert_string_equal(x->envs[2], "PATH=/usr/local/sbin");
    assert_string_equal(x->envs[3], "HOME=/home/user");
    assert_string_equal(x->envs[4], "LANG=en_US.UTF-8");

    /*
     * Assert multiple expiry-time= options. The second datetime should
     * override the previous one. From 2030/10/01 00:00 to 2030/09/30 22:30.
     */
    assert_int_equal(x->valid_before, 1917037800ULL);

    SSH_AUTH_OPTS_FREE(x);
}

/** @brief Test multiple non-consecutive options of the same type */
static void
torture_ssh_auth_options_list_multiple_nc_opts(void **state)
{
    struct ssh_auth_options *x = NULL;
    const char *list = "environment=\"HOME=/home/user\","
                       "expiry-time=\"203009302230Z\","
                       "permitlisten=\"localhost:8080\","
                       "permitopen=\"192.0.2.2:25\","
                       "environment=\"PATH=/usr/local/sbin\","
                       "permitopen=\"192.0.2.1:80\","
                       "expiry-time=\"203010010000Z\","
                       "environment=\"LC_TIME=it_IT.utf8\","
                       "environment=\"LD_PRELOAD=/path/to/randlib.so\","
                       "environment=\"LANG=en_US.UTF-8\","
                       "permitlisten=\"[::1]:22000\","
                       "permitlisten=\"24\"";
    (void)state;

    x = ssh_auth_options_list_parse(list);
    assert_non_null(x);
    assert_int_equal(x->opt_flags, 0);

    /* Assert double permitopen= */
    assert_int_equal(x->n_permit_open, 2);
    assert_non_null(x->permit_open);
    assert_string_equal(x->permit_open[0], "192.0.2.2:25");
    assert_string_equal(x->permit_open[1], "192.0.2.1:80");

    /* Assert triple permitlisten= */
    assert_int_equal(x->n_permit_listen, 3);
    assert_non_null(x->permit_listen);
    assert_string_equal(x->permit_listen[0], "localhost:8080");
    assert_string_equal(x->permit_listen[1], "[::1]:22000");
    assert_string_equal(x->permit_listen[2], "24");

    /* Assert multiple environments= */
    assert_int_equal(x->n_envs, 5);
    assert_non_null(x->envs);
    assert_string_equal(x->envs[0], "HOME=/home/user");
    assert_string_equal(x->envs[1], "PATH=/usr/local/sbin");
    assert_string_equal(x->envs[2], "LC_TIME=it_IT.utf8");
    assert_string_equal(x->envs[3], "LD_PRELOAD=/path/to/randlib.so");
    assert_string_equal(x->envs[4], "LANG=en_US.UTF-8");

    /*
     * Assert multiple expiry-date. The second datetime should NOT
     * override the previous one. It's not possible to override
     * 2030/10/01 00:00 with 2030/09/30 22:30
     */
    assert_int_equal(x->valid_before, 1917037800ULL);

    SSH_AUTH_OPTS_FREE(x);
}


/** @brief Test multiple options comma-separated in the same key="value" */
static void
torture_ssh_auth_options_list_multiple_opts_in_value(void **state)
{
    struct ssh_auth_options *x = NULL;
    const char *list = "permitopen=\"192.0.2.1:80,192.0.2.2:25\","
                       "permitlisten=\"localhost:8080,[::1]:22000\","
                       "environment=\"LC_TIME=it_IT.utf8,PATH=/usr/local/sbin\","
                       "environment=\"HOME=/home/user\"";
    (void)state;

    x = ssh_auth_options_list_parse(list);
    assert_non_null(x);
    assert_int_equal(x->opt_flags, 0);

    /* Assert double permitopen= */
    assert_int_equal(x->n_permit_open, 2);
    assert_non_null(x->permit_open);
    assert_string_equal(x->permit_open[0], "192.0.2.1:80");
    assert_string_equal(x->permit_open[1], "192.0.2.2:25");

    /* Assert double permitlisten= */
    assert_int_equal(x->n_permit_listen, 2);
    assert_non_null(x->permit_listen);
    assert_string_equal(x->permit_listen[0], "localhost:8080");
    assert_string_equal(x->permit_listen[1], "[::1]:22000");

    /* Assert multiple environments= */
    assert_int_equal(x->n_envs, 3);
    assert_non_null(x->envs);
    assert_string_equal(x->envs[0], "LC_TIME=it_IT.utf8");
    assert_string_equal(x->envs[1], "PATH=/usr/local/sbin");
    assert_string_equal(x->envs[2], "HOME=/home/user");

    SSH_AUTH_OPTS_FREE(x);
}

static void
torture_ssh_auth_options_list_valid_flags(void **state)
{
    struct ssh_auth_options *x = NULL;
    const char *list = "x11-forwarding,no-user-rc,pty,no-x11-forwarding,"
                       "cert-authority,cert-authority,port-forwarding";
    uint32_t flags = PERMIT_PTY_OPT | CERT_AUTHORITY_OPT |
                     PERMIT_PORT_FORWARDING_OPT;
    (void)state;

    x = ssh_auth_options_list_parse(list);
    assert_non_null(x);
    assert_int_equal(x->opt_flags, flags);
    SSH_AUTH_OPTS_FREE(x);

    list = PERMIT_FLAGS","DENY_FLAGS;
    x = ssh_auth_options_list_parse(list);
    assert_non_null(x);
    assert_int_equal(x->opt_flags, NO_TOUCH_REQUIRED_OPT);
    SSH_AUTH_OPTS_FREE(x);

    list = "CERT-AUTHORITY,Port-Forwarding";
    flags = CERT_AUTHORITY_OPT | PERMIT_PORT_FORWARDING_OPT;
    x = ssh_auth_options_list_parse(list);
    assert_non_null(x);
    assert_int_equal(x->opt_flags, flags);
    SSH_AUTH_OPTS_FREE(x);
}

static void
torture_ssh_auth_options_list_invalid_flags(void **state)
{
    struct ssh_auth_options *x = NULL;
    const char *list[] = {"no-cert-authority", "no-restrict", "unknown"};
    size_t len, i;

    (void)state;

    len = sizeof(list) / sizeof(list[0]);
    for (i = 0; i < len; i++) {
        x = ssh_auth_options_list_parse(list[i]);
        assert_null(x);
    }
}

static void
torture_ssh_auth_options_list_invalid_options(void **state)
{
    struct ssh_auth_options *x = NULL;
    const char *invalid_lists[] = {
        "permitopen=\"192.0.2.1:80",      /* Missing closing quote */
        "environment=LC_TIME=it_IT.utf8", /* Missing quotes around value */
        "from=10.0.0.0/24,fe80::/64",     /* Missing quotes around value */
        "unknownoption=\"value\"",        /* Unknown option */
        "permitopen=\"192.0.2.1:80\",env=\"foo",  /* Valid + invalid option */
        "environment=",                   /* Empty environment value */
        "tunnel=\"not-a-number\"",        /* Invalid value for tunnel option */
        "principals=user1,\"user2",       /* Closing quote position erroneous */
        "permitlisten=localhost:8080",    /* Missing quotes */
        "command=\"foo\",command=\"ls\"", /* Not permitted multiple command */
        "permitopen=\"64\"",              /* Missing mandatory host part */
        "permitlisten=\"::1:128\"",       /* Missing square brackets for IPv6 */
        "permitlisten=\"8000000\"",       /* Invalid port */
        "expiry-time=\"2026-01-25-18:30"  /* Invalid datetime format */
    };

    size_t len, i;
    (void)state;

    len = sizeof(invalid_lists) / sizeof(invalid_lists[0]);
    for (i = 0; i < len; i++) {
        x = ssh_auth_options_list_parse(invalid_lists[i]);
        assert_null(x);  // Expecting parse failure for invalid options
    }
}

static void
torture_ssh_tokenize_auth_options(void **state)
{
    const char *input = "one,two,\"three,four\",five";
    char delimiter = ',';
    struct ssh_tokens_st *tokens = NULL;

    (void)state;

    tokens = ssh_tokenize_with_auth_options(input, delimiter);
    assert_non_null(tokens);
    assert_non_null(tokens->tokens);

    assert_string_equal(tokens->tokens[0], "one");
    assert_string_equal(tokens->tokens[1], "two");
    assert_string_equal(tokens->tokens[2], "\"three,four\"");
    assert_string_equal(tokens->tokens[3], "five");
    assert_null(tokens->tokens[4]);
    ssh_tokens_free(tokens);

    /* NULL list */
    tokens = ssh_tokenize_with_auth_options(NULL, delimiter);
    assert_null(tokens);

    /* Empty list */
    input = "";
    tokens = ssh_tokenize_with_auth_options(input, delimiter);
    assert_non_null(tokens);
    ssh_tokens_free(tokens);

    /* Quoted empty list */
    input = "\"\"";
    tokens = ssh_tokenize_with_auth_options(input, delimiter);
    assert_non_null(tokens);
    assert_non_null(tokens->tokens);
    assert_string_equal(tokens->tokens[0], "\"\"");
    assert_null(tokens->tokens[1]);
    ssh_tokens_free(tokens);
}

static void
torture_auth_options_process_comma_list(void **state)
{
    const char *input = "one,two,three,four";
    const char *to_add = "five";
    char **options = NULL;
    unsigned int n_options = 0, i;
    int rc;

    (void)state;

    /* NULL list */
    rc = auth_options_process_comma_list(NULL, &options, &n_options);
    assert_int_equal(rc, -1);
    assert_null(options);
    assert_int_equal(n_options, 0);

    /* Empty list */
    rc = auth_options_process_comma_list("", &options, &n_options);
    assert_int_equal(rc, -1);
    assert_null(options);
    assert_int_equal(n_options, 0);

    /* Valid input list */
    rc = auth_options_process_comma_list(input, &options, &n_options);
    assert_int_equal(rc, 0);
    assert_non_null(options);
    assert_int_equal(n_options, 4);

    assert_string_equal(options[0], "one");
    assert_string_equal(options[1], "two");
    assert_string_equal(options[2], "three");
    assert_string_equal(options[3], "four");

    /* Call again and add a new option */
    rc = auth_options_process_comma_list(to_add, &options, &n_options);
    assert_int_equal(rc, 0);
    assert_non_null(options);
    assert_int_equal(n_options, 5);

    assert_string_equal(options[0], "one");
    assert_string_equal(options[1], "two");
    assert_string_equal(options[2], "three");
    assert_string_equal(options[3], "four");
    assert_string_equal(options[4], "five");

    for (i = 0; i < n_options; i++) {
        SAFE_FREE(options[i]);
    }
    SAFE_FREE(options);
}

static void
torture_auth_options_valid_envs(void **state)
{
    const char *valid_envs[] = {"VAR1=value1", "VAR2=value2", "VAR_3=value3"};
    const char *invalid_envs_missing[] = {"=value1", "VAR2=value2"};
    const char *invalid_envs_symbol[] = {"VAR1=value1","VAR2@=value2"};
    const char *invalid_envs_sign[] = {"VAR1=value1","VAR2value2"};
    int n_envs, rc;

    (void)state;

    /* NULL envs */
    rc = auth_options_valid_envs(NULL, 0);
    assert_int_equal(rc, -1);

    /* Valid envs */
    n_envs = sizeof(valid_envs) / sizeof(valid_envs[0]);
    rc = auth_options_valid_envs((char **)valid_envs, n_envs);
    assert_int_equal(rc, 1);

    /* Env name missing */
    n_envs = sizeof(invalid_envs_missing) / sizeof(invalid_envs_missing[0]);
    rc = auth_options_valid_envs((char **)invalid_envs_missing, n_envs);
    assert_int_equal(rc, 0);

    /* Invalid symbol */
    n_envs = sizeof(invalid_envs_symbol) / sizeof(invalid_envs_symbol[0]);
    rc = auth_options_valid_envs((char **)invalid_envs_symbol, n_envs);
    assert_int_equal(rc, 0);

    /* Missing equal sign */
    n_envs = sizeof(invalid_envs_sign) / sizeof(invalid_envs_sign[0]);
    rc = auth_options_valid_envs((char **)invalid_envs_sign, n_envs);
    assert_int_equal(rc, 0);
}

static void
torture_auth_options_valid_permit_opts(void **state)
{
    const char *valid_permit_opts[] = {"localhost:8080",
                                       "[2001:db8::1]:80",
                                       "*:443"};
    /* Optional host part is valid only for permitlisten option */
    const char *valid_only_port[] = {"3002"};
    const char *invalid_permit_opts[] = {"localhost443",
                                         "192.168.1.85:65536",
                                         "10.0.0.1",
                                         "[2001:db8::1]:",
                                         ":3002"};
    int n_permit, rc, i;

    (void)state;

    /* NULL permit_opts */
    rc = auth_options_valid_permit_opts(NULL,0,true);
    assert_int_equal(rc, -1);

    /******* permitlisten ********/
    /* Valid options */
    n_permit = sizeof(valid_permit_opts) / sizeof(valid_permit_opts[0]);
    rc = auth_options_valid_permit_opts((char **)valid_permit_opts,
                                        n_permit,
                                        true);
    assert_int_equal(rc, 1);
    rc = auth_options_valid_permit_opts((char **)valid_only_port,
                                        1,
                                        true);
    assert_int_equal(rc, 1);
    /* Invalid options */
    n_permit = sizeof(invalid_permit_opts) / sizeof(invalid_permit_opts[0]);
    for (i = 0; i < n_permit; i++) {
        rc = auth_options_valid_permit_opts((char **)invalid_permit_opts,
                                            1,
                                            true);
        assert_int_equal(rc, 0);
    }

    /******** permitopen ********/
    /* Valid options */
    n_permit = sizeof(valid_permit_opts) / sizeof(valid_permit_opts[0]);
    rc = auth_options_valid_permit_opts((char **)valid_permit_opts,
                                        n_permit,
                                        false);
    assert_int_equal(rc, 1);
    /* Invalid options */
    n_permit = sizeof(invalid_permit_opts) / sizeof(invalid_permit_opts[0]);
    for (i = 0; i < n_permit; i++) {
        rc = auth_options_valid_permit_opts((char **)invalid_permit_opts,
                                            1,
                                            false);
        assert_int_equal(rc, 0);
    }
}

static void
torture_auth_options_opt_array_copy(void **state)
{
    const char *options[] = {"option1", "option2", "option3"};
    char **dest;
    size_t n_opts, i;
    int rc;

    (void)state;

    n_opts = sizeof(options) / sizeof(options[0]);
    rc = auth_options_opt_array_copy(&dest, (char **)options, n_opts);
    assert_int_equal(rc, 0);
    assert_string_equal(dest[0], "option1");
    assert_string_equal(dest[1], "option2");
    assert_string_equal(dest[2], "option3");

    for(i = 0; i < n_opts; i++) {
        SAFE_FREE(dest[i]);
    }
    SAFE_FREE(dest);
}

static void
torture_ssh_auth_options_merge_cert_opts(void **state)
{
    /* CERTIFICATE INFO
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
     */
    int rc;
    ssh_key cert = NULL;
    struct ssh_auth_options *merged = NULL, *src_opts = NULL;
    const char *list = "cert-authority,"
                       "principals=\"user1,user2,user3,user4\","
                       "permitlisten=\"localhost:8080\","
                       "permitopen=\"192.0.2.2:25\","
                       "tunnel=\"0\","
                       "command=\"/path/to/run.sh\","
                       "from=\"10.0.0.0/24,fe80::/64\","
                       "expiry-time=\"19990630Z\","
                       "environment="
                       "\"LD_PRELOAD=/path/to/randlib.so\"";
    uint32_t flags;

    (void)state;

    rc = ssh_pki_import_cert_file(CERT_DIR"/all_options.cert", &cert);
    assert_return_code(rc, errno);
    assert_non_null(cert);

    src_opts = ssh_auth_options_list_parse(list);
    assert_non_null(src_opts);

    merged = ssh_auth_options_merge_cert_opts(cert, src_opts);
    assert_non_null(merged);

    /* cert-authority should be cleared */
    flags = PERMIT_X11_FORWARDING_OPT | PERMIT_AGENT_FORWARDING_OPT |
            PERMIT_PORT_FORWARDING_OPT | PERMIT_PTY_OPT |
            PERMIT_USER_RC_OPT | NO_TOUCH_REQUIRED_OPT | VERIFY_REQUIRED_OPT;

    /* Assert bitmap flags */
    assert_int_equal(merged->opt_flags, flags);

    /* Assert principals= */
    assert_int_equal(merged->n_cert_principals, 4);
    assert_string_equal(merged->cert_principals[0], "user1");
    assert_string_equal(merged->cert_principals[1], "user2");
    assert_string_equal(merged->cert_principals[2], "user3");
    assert_string_equal(merged->cert_principals[3], "user4");

    /* Assert permitlisten= */
    assert_int_equal(merged->n_permit_listen, 1);
    assert_string_equal(merged->permit_listen[0], "localhost:8080");

    /* Assert permitopen= */
    assert_int_equal(merged->n_permit_open, 1);
    assert_string_equal(merged->permit_open[0], "192.0.2.2:25");

    /* Assert tunnel= */
    assert_int_equal(merged->tun_device, 0);

    /* Assert command= */
    assert_string_equal(merged->force_command, "/path/to/run.sh");

    /* Assert from= */
    assert_string_equal(merged->authkey_from_addr_host, "10.0.0.0/24,fe80::/64");

    /* Assert source-address option */
    assert_string_equal(merged->cert_source_address, "127.0.0.1/32,::1/128");

    /* Assert environment= */
    assert_int_equal(merged->n_envs, 1);
    assert_string_equal(merged->envs[0], "LD_PRELOAD=/path/to/randlib.so");

    /* Assert expiry-time= (overrided by auth opts list) */
    assert_int_equal(merged->valid_before, 930700800ULL);

    SSH_KEY_FREE(cert);
    SSH_AUTH_OPTS_FREE(src_opts);
    SSH_AUTH_OPTS_FREE(merged);
}

static void
torture_ssh_auth_options_merge_cert_opts_restrict(void **state)
{
    /* CERTIFICATE INFO
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
     */
    int rc;
    ssh_key cert = NULL;
    struct ssh_auth_options *merged = NULL, *src_opts = NULL;
    const char *list = "cert-authority,restrict,"
                       "principals=\"user1,user2,user3,user4\","
                       "permitlisten=\"localhost:8080\","
                       "permitopen=\"192.0.2.2:25\","
                       "tunnel=\"0\","
                       "command=\"/path/to/run.sh\","
                       "from=\"10.0.0.0/24,fe80::/64\","
                       "expiry-time=\"19990630Z\","
                       "environment="
                       "\"LD_PRELOAD=/path/to/randlib.so\"";
    uint32_t flags;

    (void)state;

    rc = ssh_pki_import_cert_file(CERT_DIR"/all_options.cert", &cert);
    assert_return_code(rc, errno);
    assert_non_null(cert);

    src_opts = ssh_auth_options_list_parse(list);
    assert_non_null(src_opts);

    merged = ssh_auth_options_merge_cert_opts(cert, src_opts);
    assert_non_null(merged);

    /*
     * cert-authority should be cleared and make sure that all certificate
     * permit flags have been cleared.
     */
    flags = RESTRICTED_OPT | NO_TOUCH_REQUIRED_OPT | VERIFY_REQUIRED_OPT;

    /* Assert bitmap flags */
    assert_int_equal(merged->opt_flags, flags);

    /* Assert principals= */
    assert_int_equal(merged->n_cert_principals, 4);
    assert_string_equal(merged->cert_principals[0], "user1");
    assert_string_equal(merged->cert_principals[1], "user2");
    assert_string_equal(merged->cert_principals[2], "user3");
    assert_string_equal(merged->cert_principals[3], "user4");

    /* Assert permitlisten= */
    assert_int_equal(merged->n_permit_listen, 1);
    assert_string_equal(merged->permit_listen[0], "localhost:8080");

    /* Assert permitopen= */
    assert_int_equal(merged->n_permit_open, 1);
    assert_string_equal(merged->permit_open[0], "192.0.2.2:25");

    /* Assert tunnel= */
    assert_int_equal(merged->tun_device, 0);

    /* Assert command= */
    assert_string_equal(merged->force_command, "/path/to/run.sh");

    /* Assert from= */
    assert_string_equal(merged->authkey_from_addr_host, "10.0.0.0/24,fe80::/64");

    /* Assert source-address option */
    assert_string_equal(merged->cert_source_address, "127.0.0.1/32,::1/128");

    /* Assert environment= */
    assert_int_equal(merged->n_envs, 1);
    assert_string_equal(merged->envs[0], "LD_PRELOAD=/path/to/randlib.so");

    /* Assert expiry-time= (overrided by auth opts list) */
    assert_int_equal(merged->valid_before, 930700800ULL);

    SSH_KEY_FREE(cert);
    SSH_AUTH_OPTS_FREE(src_opts);
    SSH_AUTH_OPTS_FREE(merged);
}

static void
torture_ssh_auth_options_from_cert(void **state)
{
    /* CERTIFICATE INFO
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
     */
    int rc;
    ssh_key cert = NULL;
    struct ssh_auth_options *cert_opts = NULL;
    uint32_t flags;

    (void)state;

    rc = ssh_pki_import_cert_file(CERT_DIR"/all_options.cert", &cert);
    assert_return_code(rc, errno);
    assert_non_null(cert);

    cert_opts = ssh_auth_options_from_cert(cert);
    assert_non_null(cert_opts);

    /* cert-authority should be cleared */
    flags = PERMIT_X11_FORWARDING_OPT | PERMIT_AGENT_FORWARDING_OPT |
            PERMIT_PORT_FORWARDING_OPT | PERMIT_PTY_OPT |
            PERMIT_USER_RC_OPT | NO_TOUCH_REQUIRED_OPT | VERIFY_REQUIRED_OPT;

    /* Assert bitmap flags */
    assert_int_equal(cert_opts->opt_flags, flags);

    /* Assert principals= */
    assert_int_equal(cert_opts->n_cert_principals, 1);
    assert_non_null(cert_opts->cert_principals);
    assert_string_equal(cert_opts->cert_principals[0], "user1");

    /* Assert permitlisten= */
    assert_int_equal(cert_opts->n_permit_listen, 0);
    assert_null(cert_opts->permit_listen);

    /* Assert permitopen= */
    assert_int_equal(cert_opts->n_permit_open, 0);
    assert_null(cert_opts->permit_open);

    /* Assert tunnel= */
    assert_int_equal(cert_opts->tun_device, -1);

    /* Assert force-command */
    assert_string_equal(cert_opts->force_command, "/path/to/run.sh");

    /* Assert from= */
    assert_null(cert_opts->authkey_from_addr_host);

    /* Assert source-address option */
    assert_string_equal(cert_opts->cert_source_address, "127.0.0.1/32,::1/128");

    /* Assert environment= */
    assert_int_equal(cert_opts->n_envs, 0);
    assert_null(cert_opts->envs);

    /* Assert expiry date */
    assert_int_equal(cert_opts->valid_before, 946594800);

    SSH_KEY_FREE(cert);
    SSH_AUTH_OPTS_FREE(cert_opts);
}

int
torture_run_tests(void)
{
    int rc;

    struct CMUnitTest tests[] = {
        cmocka_unit_test(torture_ssh_auth_options_list_parse_all),
        cmocka_unit_test(torture_ssh_auth_options_list_parse_restrict),
        cmocka_unit_test(torture_ssh_auth_options_list_deny_flags),
        cmocka_unit_test(torture_ssh_auth_options_list_multiple_opts),
        cmocka_unit_test(torture_ssh_auth_options_list_multiple_nc_opts),
        cmocka_unit_test(torture_ssh_auth_options_list_multiple_opts_in_value),
        cmocka_unit_test(torture_ssh_auth_options_list_valid_flags),
        cmocka_unit_test(torture_ssh_auth_options_list_invalid_flags),
        cmocka_unit_test(torture_ssh_auth_options_list_invalid_options),
        cmocka_unit_test(torture_ssh_tokenize_auth_options),
        cmocka_unit_test(torture_auth_options_process_comma_list),
        cmocka_unit_test(torture_auth_options_valid_envs),
        cmocka_unit_test(torture_auth_options_valid_permit_opts),
        cmocka_unit_test(torture_auth_options_opt_array_copy),
        cmocka_unit_test(torture_ssh_auth_options_merge_cert_opts),
        cmocka_unit_test(torture_ssh_auth_options_merge_cert_opts_restrict),
        cmocka_unit_test(torture_ssh_auth_options_from_cert),
    };

    ssh_init();
    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, NULL, NULL);
    ssh_finalize();
    return rc;
}
