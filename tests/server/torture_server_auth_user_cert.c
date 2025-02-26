#include "config.h"

#define LIBSSH_STATIC

#include <sys/stat.h>
#include <errno.h>

#include "torture.h"
#include "torture_key.h"
#include "libssh/libssh.h"
#include "libssh/session.h"

#include "test_server.h"
#include "default_cb.h"

const char template[] = "temp_dir_XXXXXX";

struct test_server_st {
    struct torture_state *state;
    struct server_state_st *ss;
    struct {
        char *temp_dir;
        char *test_key;
        char *test_key_pub;
        char *test_cert_key;
    } client;
};

/** ------------------ SERVER CODE ------------------ */
static void
assert_auth_options(struct ssh_auth_options *a, struct ssh_auth_options *b)
{
    unsigned int i;

    assert_non_null(a);
    assert_non_null(b);

    assert_int_equal(a->opt_flags, b->opt_flags);

    if (a->force_command != NULL && b->force_command != NULL) {
        assert_string_equal(a->force_command, b->force_command);
    } else {
        assert_null(a->force_command);
        assert_null(b->force_command);
    }

    if (a->authkey_from_addr_host != NULL &&
        b->authkey_from_addr_host != NULL) {
        assert_string_equal(a->authkey_from_addr_host,
                            b->authkey_from_addr_host);
    } else {
        assert_null(a->authkey_from_addr_host);
        assert_null(b->authkey_from_addr_host);
    }

    if (a->cert_source_address != NULL && b->cert_source_address != NULL) {
        assert_string_equal(a->cert_source_address, b->cert_source_address);
    } else {
        assert_null(a->cert_source_address);
        assert_null(b->cert_source_address);
    }

    assert_int_equal(a->valid_before, b->valid_before);

    assert_int_equal(a->n_envs, b->n_envs);
    for (i = 0; i < a->n_envs; i++) {
        assert_string_equal(a->envs[i], b->envs[i]);
    }

    assert_int_equal(a->n_permit_listen, b->n_permit_listen);
    for (i = 0; i < a->n_permit_listen; i++) {
        assert_string_equal(a->permit_listen[i], b->permit_listen[i]);
    }

    assert_int_equal(a->n_permit_open, b->n_permit_open);
    for (i = 0; i < a->n_permit_open; i++) {
        assert_string_equal(a->permit_open[i], b->permit_open[i]);
    }

    assert_int_equal(a->n_cert_principals, b->n_cert_principals);
    for (i = 0; i < a->n_cert_principals; i++) {
        assert_string_equal(a->cert_principals[i], b->cert_principals[i]);
    }

    assert_int_equal(a->tun_device, b->tun_device);
}

static int
custom_auth_pubkey_cb(ssh_session session,
                      const char *user,
                      struct ssh_key_struct *pubkey,
                      char signature_state,
                      void *userdata)
{
    struct session_data_st *sdata;
    struct ssh_auth_options *expected = NULL, *session_auth_opts = NULL;
    struct server_state_st *ss = NULL;
    int rc;

    sdata = (struct session_data_st *)userdata;
    if (sdata == NULL) {
        fprintf(stderr, "Error: NULL userdata\n");
        goto null_userdata;
    }

    printf("Public key authentication of user %s\n", user);

    switch(signature_state) {
    case SSH_PUBLICKEY_STATE_NONE:
    case SSH_PUBLICKEY_STATE_VALID:
        break;
    default:
        goto denied;
    }

    rc = ssh_auth_user_key(session, pubkey, user);
    if (rc != SSH_OK) {
        goto denied;
    }

    assert_non_null(session->auth_opts);
    session_auth_opts = session->auth_opts;

    ss = sdata->server_state;
    expected = ss->expected_auth_opts;
    assert_non_null(expected);

    assert_auth_options(session_auth_opts, expected);

    /* Authenticated */
    printf("Authenticated\n");
    sdata->authenticated = 1;
    sdata->auth_attempts = 0;
    return SSH_AUTH_SUCCESS;

denied:
    sdata->auth_attempts++;
    assert_null(session->auth_opts);
null_userdata:
    return SSH_AUTH_DENIED;
}

static void
free_test_server_state(void **state)
{
    struct test_server_st *tss = *state;

    torture_free_state(tss->state);
    /*
     * Clean also client data. This is needed because when restarting the
     * server they are passed (from the state) to the child process after fork
     */
    SAFE_FREE(tss->client.temp_dir);
    SAFE_FREE(tss->client.test_key);
    SAFE_FREE(tss->client.test_key_pub);
    SAFE_FREE(tss->client.test_cert_key);
    SAFE_FREE(tss);
}

static void
run_test_server_now(void **state)
{
    struct test_server_st *tss = *state;
    struct torture_state *s = NULL;
    struct server_state_st *ss = NULL;
    char pid_str[1024];
    pid_t pid;
    int rc;

    ss = tss->ss;
    assert_non_null(ss);

    s = tss->state;
    assert_non_null(s);

    /* Start the server using the default values */
    pid = fork_run_server(ss, free_test_server_state, &tss);
    if (pid < 0) {
        fail();
    }

    snprintf(pid_str, sizeof(pid_str), "%d", pid);

    torture_write_file(s->srv_pidfile, (const char *)pid_str);

    setenv("SOCKET_WRAPPER_DEFAULT_IFACE", "21", 1);

    /* Wait until the sshd is ready to accept connections */
    rc = torture_wait_for_daemon(3);
    assert_int_equal(rc, 0);
}

static void
setup_server_config_file(void **state,
                         const char *auth_key_line,
                         const char *auth_principals_line,
                         const char *trusted_user_ca_line)
{
    struct test_server_st *tss = *state;
    struct torture_state *s = NULL;
    struct server_state_st *ss = NULL;

    char authorized_keys[1024];
    char authorized_principals[1024];
    char trusted_user_ca_keys[1024];
    FILE *fp = NULL;
    int ret;

    assert_non_null(tss);

    ss = tss->ss;
    assert_non_null(ss);

    s = tss->state;
    assert_non_null(s);

    fp = fopen(s->srv_config, "w");
    assert_non_null(fp);

    if (auth_key_line != NULL) {
        snprintf(authorized_keys,
                 sizeof(authorized_keys),
                 "%s/sshd/authorized_keys",
                 s->socket_dir);
        torture_write_file(authorized_keys, auth_key_line);
        ret = fprintf(fp, "AuthorizedKeysFile %s\n", authorized_keys);
        assert_false(ret < 0);
    }

    if (auth_principals_line != NULL) {
        snprintf(authorized_principals,
                 sizeof(authorized_principals),
                 "%s/sshd/authorized_principals",
                 s->socket_dir);
        torture_write_file(authorized_principals, auth_principals_line);
        ret = fprintf(fp, "AuthorizedPrincipalsFile %s\n", authorized_principals);
        assert_false(ret < 0);
    }

    if (trusted_user_ca_line != NULL) {
        snprintf(trusted_user_ca_keys,
                 sizeof(trusted_user_ca_keys),
                 "%s/sshd/trusted_user_ca",
                 s->socket_dir);
        torture_write_file(trusted_user_ca_keys, trusted_user_ca_line);
        ret = fprintf(fp, "TrustedUserCAKeys %s\n", trusted_user_ca_keys);
        assert_false(ret < 0);
    }

    fclose(fp);
    ss->config_file = strdup(s->srv_config);
    assert_non_null(ss->config_file);
}

static void
update_server_config_file(void **state,
                          const char *auth_key_line,
                          const char *auth_principals_line,
                          const char *trusted_user_ca_line)
{
    struct test_server_st *tss = *state;
    struct torture_state *s = NULL;
    struct server_state_st *ss = NULL;

    char authorized_keys[1024];
    char authorized_principals[1024];
    char trusted_user_ca_keys[1024];

    assert_non_null(tss);

    ss = tss->ss;
    assert_non_null(ss);

    s = tss->state;
    assert_non_null(s);

    assert_non_null(ss->config_file);

    if (auth_key_line != NULL) {
        snprintf(authorized_keys,
                 sizeof(authorized_keys),
                 "%s/sshd/authorized_keys",
                 s->socket_dir);
        torture_write_file(authorized_keys, auth_key_line);
    }

    if (auth_principals_line != NULL) {
        snprintf(authorized_principals,
                 sizeof(authorized_principals),
                 "%s/sshd/authorized_principals",
                 s->socket_dir);
        torture_write_file(authorized_principals, auth_principals_line);
    }

    if (trusted_user_ca_line != NULL) {
        snprintf(trusted_user_ca_keys,
                 sizeof(trusted_user_ca_keys),
                 "%s/sshd/trusted_user_ca",
                 s->socket_dir);
        torture_write_file(trusted_user_ca_keys, trusted_user_ca_line);
    }
}

#ifdef WITH_PCAP
static void
set_pcap(struct session_data_st *sdata,
         ssh_session session,
         char *pcap_file)
{
    int rc = 0;

    if (sdata == NULL) {
        return;
    }

    if (pcap_file == NULL) {
        return;
    }

    sdata->pcap = ssh_pcap_file_new();
    if (sdata->pcap == NULL) {
        return;
    }

    rc = ssh_pcap_file_open(sdata->pcap, pcap_file);
    if (rc == SSH_ERROR) {
        fprintf(stderr, "Error opening pcap file\n");
        ssh_pcap_file_free(sdata->pcap);
        sdata->pcap = NULL;
        return;
    }
    ssh_set_pcap_file(session, sdata->pcap);
}

static void
cleanup_pcap(struct session_data_st *sdata)
{
    if (sdata == NULL) {
        return;
    }

    if (sdata->pcap == NULL) {
        return;
    }

    ssh_pcap_file_free(sdata->pcap);
    sdata->pcap = NULL;
}
#endif

static void
custom_handle_session_cb(ssh_event event,
                         ssh_session session,
                         struct server_state_st *state)
{
    int n;
    int rc = 0;

    /* Our struct holding information about the session. */
    struct session_data_st sdata = {
        .channel = NULL,
        .auth_attempts = 0,
        .authenticated = 0
    };

    struct ssh_server_callbacks_struct *server_cb = NULL;

    if (state == NULL) {
        fprintf(stderr, "NULL server state provided\n");
        goto end;
    }

    /* Set custom callbacks */
    server_cb = calloc(1, sizeof(struct ssh_server_callbacks_struct));
    if (server_cb == NULL) {
        goto end;
    }
    server_cb->auth_pubkey_function = custom_auth_pubkey_cb;

    /* This is a macro, it does not return a value */
    ssh_callbacks_init(server_cb);

    rc = ssh_set_server_callbacks(session, server_cb);
    if (rc) {
        goto end;
    }

    server_cb->userdata = &sdata;
    sdata.server_state = (void *)state;

#ifdef WITH_PCAP
    set_pcap(&sdata, session, state->pcap_file);
#endif

    if (ssh_handle_key_exchange(session) != SSH_OK) {
        fprintf(stderr, "%s\n", ssh_get_error(session));
        goto end;
    }

    /* Set the supported authentication methods */
    ssh_set_auth_methods(session,SSH_AUTH_METHOD_PUBLICKEY);

    ssh_event_add_session(event, session);

    n = 0;
    while (sdata.authenticated == 0 || sdata.channel == NULL) {
        /* If the user has used up all attempts, or if he hasn't been able to
         * authenticate in 10 seconds (n * 100ms), disconnect. */
        if (sdata.auth_attempts >= state->max_tries || n >= 100) {
            goto end;
        }

        if (ssh_event_dopoll(event, 100) == SSH_ERROR) {
            fprintf(stderr, "do_poll error: %s\n", ssh_get_error(session));
            goto end;
        }
        n++;
    }

end:
#ifdef WITH_PCAP
    cleanup_pcap(&sdata);
#endif
    if (server_cb != NULL) {
        free(server_cb);
    }
    return;
}

static int
setup_default_server(void **state)
{
    struct torture_state *s = NULL;
    struct server_state_st *ss = NULL;
    struct test_server_st *tss = NULL;

    char ed25519_hostkey[1024];
    char rsa_hostkey[1024];
    char ecdsa_hostkey[1024];
    char user_ca_key[1024];

    char sshd_path[1024];
    char log_file[1024];

    int rc;

    assert_non_null(state);

    tss = (struct test_server_st*)calloc(1, sizeof(struct test_server_st));
    assert_non_null(tss);

    torture_setup_socket_dir((void **)&s);
    assert_non_null(s->socket_dir);

    /* Set the default interface for the server */
    setenv("SOCKET_WRAPPER_DEFAULT_IFACE", "10", 1);

    snprintf(sshd_path,
             sizeof(sshd_path),
             "%s/sshd",
             s->socket_dir);

    rc = mkdir(sshd_path, 0755);
    assert_return_code(rc, errno);

    snprintf(log_file,
             sizeof(log_file),
             "%s/sshd/log",
             s->socket_dir);

    /* Set up server keys */
    snprintf(ed25519_hostkey,
             sizeof(ed25519_hostkey),
             "%s/sshd/ssh_host_ed25519_key",
             s->socket_dir);
    torture_write_file(ed25519_hostkey,
                       torture_get_openssh_testkey(SSH_KEYTYPE_ED25519, 0));

    snprintf(rsa_hostkey,
             sizeof(rsa_hostkey),
             "%s/sshd/ssh_host_rsa_key",
             s->socket_dir);
    torture_write_file(rsa_hostkey, torture_get_testkey(SSH_KEYTYPE_RSA, 0));

    snprintf(ecdsa_hostkey,
             sizeof(ecdsa_hostkey),
             "%s/sshd/ssh_host_ecdsa_key",
             s->socket_dir);
    torture_write_file(ecdsa_hostkey,
                       torture_get_testkey(SSH_KEYTYPE_ECDSA_P521, 0));

    /* Set up user CA key */
    snprintf(user_ca_key,
             sizeof(user_ca_key),
             "%s/sshd/user_ca.pub",
             s->socket_dir);
    torture_write_file(user_ca_key,
                       torture_get_testkey_user_ca_public());

    /* Create default server state */
    ss = (struct server_state_st *)calloc(1, sizeof(struct server_state_st));
    assert_non_null(ss);

    ss->address = strdup(TORTURE_SSH_SERVER);
    assert_non_null(ss->address);

    ss->port = 22;

    ss->ecdsa_key = strdup(ecdsa_hostkey);
    assert_non_null(ss->ecdsa_key);

    ss->ed25519_key = strdup(ed25519_hostkey);
    assert_non_null(ss->ed25519_key);

    ss->rsa_key = strdup(rsa_hostkey);
    assert_non_null(ss->rsa_key);

    ss->host_key = NULL;

    ss->expected_username = NULL;
    ss->expected_password = NULL;

    /* not to mix up the client and server messages */
    ss->verbosity = 4;
    ss->log_file = strdup(log_file);
    assert_non_null(ss->log_file);

#ifdef WITH_PCAP
    ss->with_pcap = 1;
    ss->pcap_file = strdup(s->pcap_file);
    assert_non_null(ss->pcap_file);
#endif

    ss->max_tries = 3;
    ss->error = 0;

    tss->state = s;
    tss->ss = ss;

    /* Use the custom session handling function */
    ss->handle_session = custom_handle_session_cb;
    assert_non_null(ss->handle_session);

    /* Do not use global configuration */
    ss->parse_global_config = false;

    *state = tss;

    return 0;
}

static int teardown_default_server(void **state)
{
    struct torture_state *s;
    struct server_state_st *ss;
    struct test_server_st *tss;

    tss = *state;
    assert_non_null(tss);

    s = tss->state;
    assert_non_null(s);

    ss = tss->ss;
    assert_non_null(ss);

    torture_teardown_sshd_server((void **)&s);

    free_server_state(tss->ss);
    SAFE_FREE(tss->ss);

    SAFE_FREE(tss->client.temp_dir);
    SAFE_FREE(tss->client.test_key);
    SAFE_FREE(tss->client.test_key_pub);
    SAFE_FREE(tss->client.test_cert_key);

    SAFE_FREE(tss);
    return 0;
}

/** ------------------ CLIENT CODE ------------------ */
static int
session_setup(void **state)
{
    struct test_server_st *tss = *state;
    struct torture_state *s = NULL;
    int verbosity = torture_libssh_verbosity();
    const char *all_keytypes = NULL;
    bool b = false;
    int rc;

    unsetenv("UID_WRAPPER_ROOT");
    assert_non_null(tss);

    s = tss->state;
    assert_non_null(s);

    s->ssh.session = ssh_new();
    assert_non_null(s->ssh.session);

    rc = ssh_options_set(s->ssh.session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
    assert_ssh_return_code(s->ssh.session, rc);
    rc = ssh_options_set(s->ssh.session, SSH_OPTIONS_HOST, TORTURE_SSH_SERVER);
    assert_ssh_return_code(s->ssh.session, rc);
    /* Make sure no other configuration options from system will get used */
    rc = ssh_options_set(s->ssh.session, SSH_OPTIONS_PROCESS_CONFIG, &b);
    assert_ssh_return_code(s->ssh.session, rc);

    /* Enable all hostkeys */
    all_keytypes = ssh_kex_get_supported_method(SSH_HOSTKEYS);
    rc = ssh_options_set(s->ssh.session,
                         SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES,
                         all_keytypes);
    assert_ssh_return_code(s->ssh.session, rc);

    /* Skip user setup now since we need to change it depending on the test */
    return 0;
}

static int
session_teardown(void **state)
{
    struct test_server_st *tss = *state;
    struct torture_state *s = NULL;
    int rc;

    assert_non_null(tss);

    s = tss->state;
    assert_non_null(s);

    rc = torture_rmdirs(tss->client.temp_dir);
    assert_int_equal(rc, 0);

    ssh_disconnect(s->ssh.session);
    ssh_free(s->ssh.session);
    return 0;
}

/** ------------------ TESTS ------------------ */
static void
setup_test_keys(void **state)
{
    struct test_server_st *tss = *state;
    char *temp_dir = NULL;
    char test_key[1024] = {0};
    char test_key_pub[1024] = {0};
    char test_cert_key[2048] = {0};
    char user_ca[1024] = {0};

    assert_non_null(tss);

    /*
     * Create a temporary dir for the user identity. Here will be stored the
     * client key pair plus the certificate to test along with its user CA
     */
    temp_dir = torture_make_temp_dir(template);
    tss->client.temp_dir = temp_dir;
    assert_non_null(tss->client.temp_dir);

    /* Write the RSA private key */
    snprintf(test_key,
             sizeof(test_key),
             "%s/user_key",
             tss->client.temp_dir);
    torture_write_file(test_key, torture_get_testkey(SSH_KEYTYPE_RSA, false));
    tss->client.test_key = strdup(test_key);
    assert_non_null(tss->client.test_key);

    /* Write the RSA public key */
    snprintf(test_key_pub,
             sizeof(test_key_pub),
             "%s/user_key.pub",
             tss->client.temp_dir);
    torture_write_file(test_key_pub, torture_get_testkey_pub(SSH_KEYTYPE_RSA));
    tss->client.test_key_pub = strdup(test_key_pub);
    assert_non_null(tss->client.test_key_pub);

    /* Write a signing user CA. This will be used later for signing certs */
    snprintf(user_ca,
             sizeof(user_ca),
             "%s/user_ca",
             tss->client.temp_dir);
    torture_write_file(user_ca, torture_get_testkey_user_ca_private());

    /* Write the path to the certificate file that will be generated */
    snprintf(test_cert_key,
             sizeof(test_cert_key),
             "%s-cert.pub",
             tss->client.test_key);
    tss->client.test_cert_key = strdup(test_cert_key);
    assert_non_null(tss->client.test_cert_key);
}

static void
torture_cert_auth_only_authorized_keys_no_option(void **state)
{
    struct test_server_st *tss = *state;
    struct ssh_auth_options *expected = NULL;
    ssh_session session = NULL;
    ssh_key cert = NULL;
    ssh_key privkey = NULL;
    char auth_key_line[4096];
    char command[4096];
    int rc;

    assert_non_null(tss);
    assert_non_null(tss->state);
    assert_non_null(tss->ss);

    /**--------------------------------------------------*/
    /* Set up the server config file */
    snprintf(auth_key_line,
             sizeof(auth_key_line),
             "cert-authority %s",
             torture_get_testkey_user_ca_public());
    setup_server_config_file(state, auth_key_line, NULL, NULL);

    /* Update the server state with the expected auth_options struct  */
    expected = ssh_auth_option_new();
    assert_non_null(expected);
    expected->opt_flags = PERMIT_X11_FORWARDING_OPT | PERMIT_USER_RC_OPT |
                          PERMIT_PORT_FORWARDING_OPT | PERMIT_PTY_OPT |
                          PERMIT_AGENT_FORWARDING_OPT;
    expected->n_cert_principals = 1;
    expected->cert_principals = calloc(1, sizeof(char *));
    assert_non_null(expected->cert_principals);
    expected->cert_principals[0] = strdup("libssh");
    assert_non_null(expected->cert_principals[0]);

    tss->ss->expected_auth_opts = expected;

    /* Run server now */
    run_test_server_now(state);
    /**--------------------------------------------------*/

    /* Set up session */
    session_setup(state);
    session = tss->state->ssh.session;

    /* Setup client keys */
    setup_test_keys(state);

    /*
     * CERTIFICATE INFO (ALL CERTS HAVE THE SAME KEY ID, SERIAL AND SIGNING CA)
     * Principals:      libssh
     * Validity:        forever
     * Critical opts:   (none)
     * Extensions:      permit-X11-forwarding, permit-agent-forwarding
     *                  permit-port-forwarding, permit-pty, permit-user-rc
     *                  (default)
     */
    snprintf(command,
             sizeof(command),
             "ssh-keygen -q -s %s/user_ca -I %s -n %s %s %s",
             tss->client.temp_dir,
             TORTURE_SSH_SERVER,
             "libssh",
             "",
             tss->client.test_key_pub);

    rc = system(command);
    assert_return_code(rc, errno);

    /* Try auth now */
    rc = ssh_options_set(session, SSH_OPTIONS_USER, SSHD_DEFAULT_USER);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_connect(session);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_pki_import_privkey_file(tss->client.test_key,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_pki_import_cert_file(tss->client.test_cert_key, &cert);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_pki_copy_cert_to_privkey(cert, privkey);
    assert_int_equal(rc, SSH_OK);

    /* It must succeed since the certificate is valid for the requested user */
    rc = ssh_userauth_publickey(session, NULL, privkey);
    assert_int_equal(rc, SSH_AUTH_SUCCESS);

    SSH_KEY_FREE(cert);
    SSH_KEY_FREE(privkey);

    session_teardown(state);
}

static void
torture_cert_auth_only_authorized_keys_principals_option(void **state)
{
    struct test_server_st *tss = *state;
    struct ssh_auth_options *expected = NULL;
    ssh_session session = NULL;
    ssh_key cert = NULL;
    ssh_key privkey = NULL;
    char auth_key_line[4096];
    char command[4096];
    int rc;

    assert_non_null(tss);
    assert_non_null(tss->state);
    assert_non_null(tss->ss);

    /**--------------------------------------------------*/
    /* Set up the server config file */
    snprintf(auth_key_line,
             sizeof(auth_key_line),
             "cert-authority,principals=\"bob,alice\" %s",
             torture_get_testkey_user_ca_public());
    setup_server_config_file(state, auth_key_line, NULL, NULL);

    /* Expected auth_options not needed since the auth request will be denied */

    /* Run server now */
    run_test_server_now(state);
    /**--------------------------------------------------*/

    /* Set up session */
    session_setup(state);
    session = tss->state->ssh.session;

    /* Setup client keys */
    setup_test_keys(state);

    /*
     * CERTIFICATE INFO (ALL CERTS HAVE THE SAME KEY ID, SERIAL AND SIGNING CA)
     * Principals:      libssh,doe
     * Validity:        forever
     * Critical opts:   (none)
     * Extensions:      permit-X11-forwarding, permit-agent-forwarding
     *                  permit-port-forwarding, permit-pty, permit-user-rc
     *                  (default)
     */
    snprintf(command,
             sizeof(command),
             "ssh-keygen -q -s %s/user_ca -I %s -n %s %s %s",
             tss->client.temp_dir,
             TORTURE_SSH_SERVER,
             "libssh,doe",
             "",
             tss->client.test_key_pub);

    rc = system(command);
    assert_return_code(rc, errno);

    /* Try auth now */
    rc = ssh_options_set(session, SSH_OPTIONS_USER, SSHD_DEFAULT_USER);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_connect(session);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_pki_import_privkey_file(tss->client.test_key,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_pki_import_cert_file(tss->client.test_cert_key, &cert);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_pki_copy_cert_to_privkey(cert, privkey);
    assert_int_equal(rc, SSH_OK);

    /*
     * It must fail since there are no matching principal between certificate
     * principals and in-line option principals: libssh,doe != bob,alice
     * Note: at least one cert principal must match in-line principals.
     */
    rc = ssh_userauth_publickey(session, NULL, privkey);
    assert_int_equal(rc, SSH_AUTH_DENIED);

    SSH_KEY_FREE(cert);
    SSH_KEY_FREE(privkey);

    /* Restart and test a matching principal this time */
    ssh_disconnect(session);
    ssh_free(session);
    torture_terminate_process(tss->state->srv_pidfile);

    /**--------------------------------------------------*/
    /* Set up the server config file */
    snprintf(auth_key_line,
             sizeof(auth_key_line),
             "cert-authority,principals=\"bob,alice,libssh\" %s",
             torture_get_testkey_user_ca_public());
    update_server_config_file(state, auth_key_line, NULL, NULL);

    /* Update the server state with the expected auth_options struct  */
    expected = ssh_auth_option_new();
    assert_non_null(expected);
    expected->opt_flags = PERMIT_X11_FORWARDING_OPT | PERMIT_USER_RC_OPT |
                          PERMIT_PORT_FORWARDING_OPT | PERMIT_PTY_OPT |
                          PERMIT_AGENT_FORWARDING_OPT;
    expected->n_cert_principals = 3;
    expected->cert_principals = calloc(3, sizeof(char *));
    assert_non_null(expected->cert_principals);
    expected->cert_principals[0] = strdup("bob");
    assert_non_null(expected->cert_principals[0]);
    expected->cert_principals[1] = strdup("alice");
    assert_non_null(expected->cert_principals[1]);
    expected->cert_principals[2] = strdup("libssh");
    assert_non_null(expected->cert_principals[2]);

    tss->ss->expected_auth_opts = expected;

    /* Run server now */
    run_test_server_now(state);
    /**--------------------------------------------------*/

    /* Try auth now */
    session_setup(state);
    session = tss->state->ssh.session;
    rc = ssh_options_set(session, SSH_OPTIONS_USER, SSHD_DEFAULT_USER);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_connect(session);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_pki_import_privkey_file(tss->client.test_key,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_pki_import_cert_file(tss->client.test_cert_key, &cert);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_pki_copy_cert_to_privkey(cert, privkey);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_userauth_publickey(session, NULL, privkey);
    assert_int_equal(rc, SSH_AUTH_SUCCESS);

    SSH_KEY_FREE(cert);
    SSH_KEY_FREE(privkey);

    session_teardown(state);
}

static void
torture_cert_auth_only_authorized_keys_match_user(void **state)
{
    struct test_server_st *tss = *state;
    struct ssh_auth_options *expected = NULL;
    ssh_session session = NULL;
    ssh_key cert = NULL;
    ssh_key privkey = NULL;
    char auth_key_line[4096];
    char command[4096];
    int rc;

    assert_non_null(tss);
    assert_non_null(tss->state);
    assert_non_null(tss->ss);

    /**--------------------------------------------------*/
    /* Set up the server config file */
    snprintf(auth_key_line,
             sizeof(auth_key_line),
             "cert-authority %s",
             torture_get_testkey_user_ca_public());
    setup_server_config_file(state, auth_key_line, NULL, NULL);

    /* Expected auth_options not needed since the auth request will be denied */

    /* Run server now */
    run_test_server_now(state);
    /**--------------------------------------------------*/

    /* Set up session */
    session_setup(state);
    session = tss->state->ssh.session;

    /* Setup client keys */
    setup_test_keys(state);

    /*
     * CERTIFICATE INFO (ALL CERTS HAVE THE SAME KEY ID, SERIAL AND SIGNING CA)
     * Principals:      userABCD
     * Validity:        forever
     * Critical opts:   (none)
     * Extensions:      permit-X11-forwarding, permit-agent-forwarding
     *                  permit-port-forwarding, permit-pty, permit-user-rc
     *                  (default)
     */
    snprintf(command,
             sizeof(command),
             "ssh-keygen -q -s %s/user_ca -I %s -n %s %s %s",
             tss->client.temp_dir,
             TORTURE_SSH_SERVER,
             "userABCD",
             "",
             tss->client.test_key_pub);

    rc = system(command);
    assert_return_code(rc, errno);

    /* Try auth now */
    rc = ssh_options_set(session, SSH_OPTIONS_USER, SSHD_DEFAULT_USER);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_connect(session);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_pki_import_privkey_file(tss->client.test_key,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_pki_import_cert_file(tss->client.test_cert_key, &cert);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_pki_copy_cert_to_privkey(cert, privkey);
    assert_int_equal(rc, SSH_OK);

    /*
     * It must fail since the certificate principal does not match the
     * requested user to be authenticated.
     */
    rc = ssh_userauth_publickey(session, NULL, privkey);
    assert_int_equal(rc, SSH_AUTH_DENIED);

    SSH_KEY_FREE(cert);
    SSH_KEY_FREE(privkey);

    /* Restart and test a matching user this time */
    ssh_disconnect(session);
    ssh_free(session);
    torture_terminate_process(tss->state->srv_pidfile);

    /**--------------------------------------------------*/
    /* Update the server state with the expected auth_options struct  */
    expected = ssh_auth_option_new();
    assert_non_null(expected);
    expected->opt_flags = PERMIT_X11_FORWARDING_OPT | PERMIT_USER_RC_OPT |
                          PERMIT_PORT_FORWARDING_OPT | PERMIT_PTY_OPT |
                          PERMIT_AGENT_FORWARDING_OPT;
    expected->n_cert_principals = 1;
    expected->cert_principals = calloc(1, sizeof(char *));
    assert_non_null(expected->cert_principals);
    expected->cert_principals[0] = strdup("userABCD");
    assert_non_null(expected->cert_principals[0]);

    tss->ss->expected_auth_opts = expected;

    /* Run server now */
    run_test_server_now(state);
    /**--------------------------------------------------*/

    /* Try auth now */
    session_setup(state);
    session = tss->state->ssh.session;
    rc = ssh_options_set(session, SSH_OPTIONS_USER, "userABCD");
    assert_int_equal(rc, SSH_OK);

    rc = ssh_connect(session);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_pki_import_privkey_file(tss->client.test_key,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_pki_import_cert_file(tss->client.test_cert_key, &cert);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_pki_copy_cert_to_privkey(cert, privkey);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_userauth_publickey(session, NULL, privkey);
    assert_int_equal(rc, SSH_AUTH_SUCCESS);

    SSH_KEY_FREE(cert);
    SSH_KEY_FREE(privkey);

    session_teardown(state);
}

/** Missing tests with non-expired certificates TODO: fake system datetime */
static void
torture_cert_auth_only_authorized_keys_expiry_time(void **state)
{
    struct test_server_st *tss = *state;
    //struct ssh_auth_options *expected = NULL;
    ssh_session session = NULL;
    ssh_key cert = NULL;
    ssh_key privkey = NULL;
    char auth_key_line[4096];
    char command[4096];
    int rc;

    assert_non_null(tss);
    assert_non_null(tss->state);
    assert_non_null(tss->ss);

    /**--------------------------------------------------*/
    /* Set up the server config file */
    snprintf(auth_key_line,
             sizeof(auth_key_line),
             "cert-authority %s",
             torture_get_testkey_user_ca_public());
    setup_server_config_file(state, auth_key_line, NULL, NULL);

    /* Expected auth_options not needed since the auth request will be denied */

    /* Run server now */
    run_test_server_now(state);
    /**--------------------------------------------------*/

    /* Set up session */
    session_setup(state);
    session = tss->state->ssh.session;

    /* Setup client keys */
    setup_test_keys(state);

    /*
     * CERTIFICATE INFO (ALL CERTS HAVE THE SAME KEY ID, SERIAL AND SIGNING CA)
     * Principals:      libssh
     * Validity:        forever
     * Critical opts:   (none)
     * Extensions:      permit-X11-forwarding, permit-agent-forwarding
     *                  permit-port-forwarding, permit-pty, permit-user-rc
     *                  (default)
     */
    snprintf(command,
             sizeof(command),
             "ssh-keygen -q -s %s/user_ca -I %s -n %s %s %s",
             tss->client.temp_dir,
             TORTURE_SSH_SERVER,
             "libssh",
             "-V 20151001:20201001",
             tss->client.test_key_pub);

    rc = system(command);
    assert_return_code(rc, errno);

    /* Try auth now */
    rc = ssh_options_set(session, SSH_OPTIONS_USER, SSHD_DEFAULT_USER);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_connect(session);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_pki_import_privkey_file(tss->client.test_key,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_pki_import_cert_file(tss->client.test_cert_key, &cert);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_pki_copy_cert_to_privkey(cert, privkey);
    assert_int_equal(rc, SSH_OK);

    /* It must fail because the certificate expired in 2020, January 10th */
    rc = ssh_userauth_publickey(session, NULL, privkey);
    assert_int_equal(rc, SSH_AUTH_DENIED);

    SSH_KEY_FREE(cert);
    SSH_KEY_FREE(privkey);

    session_teardown(state);
}

static void
torture_cert_auth_only_authorized_keys_source_address(void **state)
{
    struct test_server_st *tss = *state;
    struct ssh_auth_options *expected = NULL;
    ssh_session session = NULL;
    ssh_key cert = NULL;
    ssh_key privkey = NULL;
    char auth_key_line[8192];
    char command[4096];
    int rc;

    skip();

    assert_non_null(tss);
    assert_non_null(tss->state);
    assert_non_null(tss->ss);

    /**--------------------------------------------------*/
    /* Set up the server config file */
    snprintf(auth_key_line,
             sizeof(auth_key_line),
             "cert-authority %s",
             torture_get_testkey_user_ca_public());
    setup_server_config_file(state, auth_key_line, NULL, NULL);

    /* Expected auth_options not needed since the auth request will be denied */

    /* Run server now */
    run_test_server_now(state);
    /**--------------------------------------------------*/

    /* Set up session */
    session_setup(state);
    session = tss->state->ssh.session;

    /* Setup client keys */
    setup_test_keys(state);

    /*
     * CERTIFICATE INFO (ALL CERTS HAVE THE SAME KEY ID, SERIAL AND SIGNING CA)
     * Principals:      libssh
     * Validity:        forever
     * Critical opts:   source-address="10.0.1.0/24"
     * Extensions:      permit-X11-forwarding, permit-agent-forwarding
     *                  permit-port-forwarding, permit-pty, permit-user-rc
     *                  (default)
     */
    snprintf(command,
             sizeof(command),
             "ssh-keygen -q -s %s/user_ca -I %s -n %s "
             "-O source-address=\"10.0.1.0/24\" %s %s",
             tss->client.temp_dir,
             TORTURE_SSH_SERVER,
             "libssh",
             "",
             tss->client.test_key_pub);

    rc = system(command);
    assert_return_code(rc, errno);

    /* Try auth now */
    rc = ssh_options_set(session, SSH_OPTIONS_USER, SSHD_DEFAULT_USER);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_connect(session);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_pki_import_privkey_file(tss->client.test_key,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_pki_import_cert_file(tss->client.test_cert_key, &cert);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_pki_copy_cert_to_privkey(cert, privkey);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_userauth_publickey(session, NULL, privkey);
    assert_int_equal(rc, SSH_AUTH_DENIED);

    /* Restart and this time test a matching source address */
    SSH_KEY_FREE(privkey);
    SSH_KEY_FREE(cert);
    ssh_disconnect(session);
    ssh_free(session);
    torture_terminate_process(tss->state->srv_pidfile);

    /**--------------------------------------------------*/
    /* No need to update the server config file */

    /* Update the server state with the expected auth_options struct  */
    expected = ssh_auth_option_new();
    assert_non_null(expected);
    expected->opt_flags = PERMIT_X11_FORWARDING_OPT | PERMIT_USER_RC_OPT |
                          PERMIT_PORT_FORWARDING_OPT | PERMIT_PTY_OPT |
                          PERMIT_AGENT_FORWARDING_OPT;
    expected->cert_source_address = strdup("127.0.0.0/8");

    expected->n_cert_principals = 1;
    expected->cert_principals = calloc(1, sizeof(char *));
    assert_non_null(expected->cert_principals);
    expected->cert_principals[0] = strdup("libssh");
    assert_non_null(expected->cert_principals[0]);

    tss->ss->expected_auth_opts = expected;

    /* Run server now */
    run_test_server_now(state);
    /**--------------------------------------------------*/

    /*
     * CERTIFICATE INFO (ALL CERTS HAVE THE SAME KEY ID, SERIAL AND SIGNING CA)
     * Principals:      libssh
     * Validity:        forever
     * Critical opts:   source-address="127.0.0.0/8"
     * Extensions:      permit-X11-forwarding, permit-agent-forwarding
     *                  permit-port-forwarding, permit-pty, permit-user-rc
     *                  (default)
     */
    snprintf(command,
             sizeof(command),
             "ssh-keygen -q -s %s/user_ca -I %s -n %s "
             "-O source-address=\"127.0.0.0/8\" %s %s",
             tss->client.temp_dir,
             TORTURE_SSH_SERVER,
             "libssh",
             "",
             tss->client.test_key_pub);

    rc = system(command);
    assert_return_code(rc, errno);

    /* Try auth now */
    session_setup(state);
    session = tss->state->ssh.session;
    rc = ssh_options_set(session, SSH_OPTIONS_USER, SSHD_DEFAULT_USER);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_connect(session);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_pki_import_privkey_file(tss->client.test_key,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_pki_import_cert_file(tss->client.test_cert_key, &cert);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_pki_copy_cert_to_privkey(cert, privkey);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_userauth_publickey(session, NULL, privkey);
    assert_int_equal(rc, SSH_AUTH_SUCCESS);

    /* Restart and test also a matching "from" option */
    ssh_disconnect(session);
    ssh_free(session);
    torture_terminate_process(tss->state->srv_pidfile);

    setenv("TORTURE_SKIP_CLEANUP", "1", 1);

    /**--------------------------------------------------*/
    /*
     * Update the server config file. Try with explicit address matching
     * against "from" option list
     */
    snprintf(auth_key_line,
             sizeof(auth_key_line),
             "cert-authority,from=\"random,host2,fe80::/64,127.0.0.1,::1\" %s",
             torture_get_testkey_user_ca_public());
    update_server_config_file(state, auth_key_line, NULL, NULL);

    /* Update the server state with the expected auth_options struct  */
    tss->ss->expected_auth_opts->authkey_from_addr_host =
        strdup("random,host2,fe80::/64,127.0.0.1,::1");
    assert_non_null(tss->ss->expected_auth_opts->authkey_from_addr_host);

    /* Run server now */
    run_test_server_now(state);
    /**--------------------------------------------------*/

    /* Try auth now */
    session_setup(state);
    session = tss->state->ssh.session;
    rc = ssh_options_set(session, SSH_OPTIONS_USER, SSHD_DEFAULT_USER);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_connect(session);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_userauth_publickey(session, NULL, privkey);
    assert_int_equal(rc, SSH_AUTH_SUCCESS);

    SSH_KEY_FREE(cert);
    SSH_KEY_FREE(privkey);

    session_teardown(state);
}

static void
torture_cert_auth_only_authorized_keys_all_options(void **state)
{
    struct test_server_st *tss = *state;
    struct ssh_auth_options *expected = NULL;
    ssh_session session = NULL;
    ssh_key cert = NULL;
    ssh_key privkey = NULL;
    char auth_key_line[4096];
    char command[4096];
    const char *opt_list = NULL;
    int rc;

    assert_non_null(tss);
    assert_non_null(tss->state);
    assert_non_null(tss->ss);

    /**--------------------------------------------------*/
    /* Set up the server config file */
    opt_list = "cert-authority,restrict,verify-required,"
               "principals=\"bob,alice,libssh\","
               "permitlisten=\"localhost:8080\","
               "permitopen=\"127.0.0.52:25\","
               "tunnel=\"0\","
               "command=\"sh /etc/netstart tun0\","
               "from=\"127.0.0.0/8,fe80::/64\","
               "environment="
               "\"LD_PRELOAD=/path/to/randlib.so\"";


    snprintf(auth_key_line,
             sizeof(auth_key_line),
             "%s %s",
             opt_list,
             torture_get_testkey_user_ca_public());
    setup_server_config_file(state, auth_key_line, NULL, NULL);

    /* Update the server state with the expected auth_options struct  */
    expected = ssh_auth_option_new();
    assert_non_null(expected);
    expected->opt_flags = RESTRICTED_OPT | VERIFY_REQUIRED_OPT;

    expected->n_cert_principals = 3;
    expected->cert_principals = calloc(3, sizeof(char *));
    assert_non_null(expected->cert_principals);
    expected->cert_principals[0] = strdup("bob");
    assert_non_null(expected->cert_principals[0]);
    expected->cert_principals[1] = strdup("alice");
    assert_non_null(expected->cert_principals[1]);
    expected->cert_principals[2] = strdup("libssh");
    assert_non_null(expected->cert_principals[2]);

    expected->n_permit_listen = 1;
    expected->permit_listen = calloc(1, sizeof(char *));
    assert_non_null(expected->permit_listen);
    expected->permit_listen[0] = strdup("localhost:8080");
    assert_non_null(expected->permit_listen[0]);

    expected->n_permit_open = 1;
    expected->permit_open = calloc(1, sizeof(char *));
    assert_non_null(expected->permit_open);
    expected->permit_open[0] = strdup("127.0.0.52:25");
    assert_non_null(expected->permit_open[0]);

    expected->force_command = strdup("sh /etc/netstart tun0");
    assert_non_null(expected->force_command);
    expected->authkey_from_addr_host = strdup("127.0.0.0/8,fe80::/64");
    assert_non_null(expected->authkey_from_addr_host);

    expected->tun_device = 0;

    expected->n_envs = 1;
    expected->envs = calloc(1, sizeof(char *));
    assert_non_null(expected->envs);
    expected->envs[0] = strdup("LD_PRELOAD=/path/to/randlib.so");
    assert_non_null(expected->envs[0]);

    tss->ss->expected_auth_opts = expected;

    /* Run server now */
    run_test_server_now(state);
    /**--------------------------------------------------*/

    /* Set up session */
    session_setup(state);
    session = tss->state->ssh.session;

    /* Setup client keys */
    setup_test_keys(state);

    /*
     * CERTIFICATE INFO (ALL CERTS HAVE THE SAME KEY ID, SERIAL AND SIGNING CA)
     * Principals:      libssh,doe,user1,test
     * Validity:        forever
     * Critical opts:   (none)
     * Extensions:      permit-X11-forwarding, permit-agent-forwarding
     *                  permit-port-forwarding, permit-pty, permit-user-rc
     *                  (default)
     */
    snprintf(command,
             sizeof(command),
             "ssh-keygen -q -s %s/user_ca -I %s -n %s %s %s",
             tss->client.temp_dir,
             TORTURE_SSH_SERVER,
             "libssh,doe,user1,test",
             "",
             tss->client.test_key_pub);

    rc = system(command);
    assert_return_code(rc, errno);

    /* Try auth now */
    rc = ssh_options_set(session, SSH_OPTIONS_USER, SSHD_DEFAULT_USER);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_connect(session);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_pki_import_privkey_file(tss->client.test_key,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_pki_import_cert_file(tss->client.test_cert_key, &cert);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_pki_copy_cert_to_privkey(cert, privkey);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_userauth_publickey(session, NULL, privkey);
    assert_int_equal(rc, SSH_AUTH_SUCCESS);

    SSH_KEY_FREE(cert);
    SSH_KEY_FREE(privkey);

    session_teardown(state);
}

static void
torture_cert_auth_trusted_user_ca(void **state)
{
    struct test_server_st *tss = *state;
    struct ssh_auth_options *expected = NULL;
    ssh_session session = NULL;
    ssh_key cert = NULL;
    ssh_key privkey = NULL;
    char auth_key_line[4096];
    char trusted_user_ca_line[4096];
    char command[4096];
    int rc;

    assert_non_null(tss);
    assert_non_null(tss->state);
    assert_non_null(tss->ss);

    /**--------------------------------------------------*/
    /*
     * Set up the server config file. Put a non-matching key in AuthorizedKeys
     * file and a non-matching user CA inside TrustedUserCAKeys file. Leaving
     * AuthorizedKeys or TrustedUserCAKeys file empty would be the same.
     */
    snprintf(auth_key_line,
             sizeof(auth_key_line),
             "%s",
             torture_get_testkey_pub(SSH_KEYTYPE_ECDSA_P521));
    snprintf(trusted_user_ca_line,
             sizeof(trusted_user_ca_line),
             "%s",
             torture_get_testkey_pub(SSH_KEYTYPE_RSA));
    setup_server_config_file(state, auth_key_line, NULL, trusted_user_ca_line);

    /* Expected auth_options not needed since the auth request will be denied */

    /* Run server now */
    run_test_server_now(state);
    /**--------------------------------------------------*/

    /* Set up session */
    session_setup(state);
    session = tss->state->ssh.session;

    /* Setup client keys */
    setup_test_keys(state);

    /*
     * CERTIFICATE INFO (ALL CERTS HAVE THE SAME KEY ID, SERIAL AND SIGNING CA)
     * Principals:      libssh
     * Validity:        forever
     * Critical opts:   (none)
     * Extensions:      permit-X11-forwarding, permit-agent-forwarding
     *                  permit-port-forwarding, permit-pty, permit-user-rc
     *                  (default)
     */
    snprintf(command,
             sizeof(command),
             "ssh-keygen -q -s %s/user_ca -I %s -n %s %s %s",
             tss->client.temp_dir,
             TORTURE_SSH_SERVER,
             "libssh",
             "",
             tss->client.test_key_pub);

    rc = system(command);
    assert_return_code(rc, errno);

    /* Try auth now */
    rc = ssh_options_set(session, SSH_OPTIONS_USER, SSHD_DEFAULT_USER);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_connect(session);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_pki_import_privkey_file(tss->client.test_key,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_pki_import_cert_file(tss->client.test_cert_key, &cert);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_pki_copy_cert_to_privkey(cert, privkey);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_userauth_publickey(session, NULL, privkey);
    assert_int_equal(rc, SSH_AUTH_DENIED);

    SSH_KEY_FREE(cert);
    SSH_KEY_FREE(privkey);

    /* Restart and test a matching key in TrustedUserCAKeys file */
    ssh_disconnect(session);
    ssh_free(session);
    torture_terminate_process(tss->state->srv_pidfile);

    /**--------------------------------------------------*/
    /* Update the server config file */
    snprintf(trusted_user_ca_line,
             sizeof(trusted_user_ca_line),
             "%s",
             torture_get_testkey_user_ca_public());
    update_server_config_file(state, auth_key_line, NULL, trusted_user_ca_line);

    /* Update the server state with the expected auth_options struct  */
    expected = ssh_auth_option_new();
    assert_non_null(expected);
    expected->opt_flags = PERMIT_X11_FORWARDING_OPT | PERMIT_USER_RC_OPT |
                          PERMIT_PORT_FORWARDING_OPT | PERMIT_PTY_OPT |
                          PERMIT_AGENT_FORWARDING_OPT;
    expected->n_cert_principals = 1;
    expected->cert_principals = calloc(1, sizeof(char *));
    assert_non_null(expected->cert_principals);
    expected->cert_principals[0] = strdup("libssh");
    assert_non_null(expected->cert_principals[0]);

    tss->ss->expected_auth_opts = expected;

    /* Run server now */
    run_test_server_now(state);
    /**--------------------------------------------------*/

    /* Try auth now */
    session_setup(state);
    session = tss->state->ssh.session;
    rc = ssh_options_set(session, SSH_OPTIONS_USER, SSHD_DEFAULT_USER);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_connect(session);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_pki_import_privkey_file(tss->client.test_key,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_pki_import_cert_file(tss->client.test_cert_key, &cert);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_pki_copy_cert_to_privkey(cert, privkey);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_userauth_publickey(session, NULL, privkey);
    assert_int_equal(rc, SSH_AUTH_SUCCESS);

    SSH_KEY_FREE(cert);
    SSH_KEY_FREE(privkey);

    session_teardown(state);
}

static void
torture_cert_auth_trusted_user_ca_and_authorized_principals_file(void **state)
{
    struct test_server_st *tss = *state;
    struct ssh_auth_options *expected = NULL;
    ssh_session session = NULL;
    ssh_key cert = NULL;
    ssh_key privkey = NULL;
    char trusted_user_ca_line[4096];
    char auth_principals_line[1024];
    char command[4096];
    int rc;

    assert_non_null(tss);
    assert_non_null(tss->state);
    assert_non_null(tss->ss);

    /**--------------------------------------------------*/
    /*
     * Set up the server config file. Leave AuthorizedKeys file empty and put
     * a matching CA key in the TrustedUserCAKeys file. Test now a certificate
     * with no valid principals listed in the following AuthorizedPrincipals
     * file.
     */
    snprintf(trusted_user_ca_line,
             sizeof(trusted_user_ca_line),
             "%s",
             torture_get_testkey_user_ca_public());
    snprintf(auth_principals_line,
             sizeof(auth_principals_line),
             "command=\"/usr/bin/date\" alice");
    setup_server_config_file(state, NULL, auth_principals_line, trusted_user_ca_line);

    /* Expected auth_options not needed since the auth request will be denied */

    /* Run server now */
    run_test_server_now(state);
    /**--------------------------------------------------*/

    /* Set up session */
    session_setup(state);
    session = tss->state->ssh.session;

    /* Setup client keys */
    setup_test_keys(state);

    /*
     * CERTIFICATE INFO (ALL CERTS HAVE THE SAME KEY ID, SERIAL AND SIGNING CA)
     * Principals:      libssh
     * Validity:        forever
     * Critical opts:   (none)
     * Extensions:      permit-X11-forwarding, permit-agent-forwarding
     *                  permit-port-forwarding, permit-pty, permit-user-rc
     *                  (default)
     */
    snprintf(command,
             sizeof(command),
             "ssh-keygen -q -s %s/user_ca -I %s -n %s %s %s",
             tss->client.temp_dir,
             TORTURE_SSH_SERVER,
             "libssh",
             "",
             tss->client.test_key_pub);

    rc = system(command);
    assert_return_code(rc, errno);

    /* Try auth now */
    rc = ssh_options_set(session, SSH_OPTIONS_USER, SSHD_DEFAULT_USER);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_connect(session);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_pki_import_privkey_file(tss->client.test_key,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_pki_import_cert_file(tss->client.test_cert_key, &cert);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_pki_copy_cert_to_privkey(cert, privkey);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_userauth_publickey(session, NULL, privkey);
    assert_int_equal(rc, SSH_AUTH_DENIED);

    SSH_KEY_FREE(cert);
    SSH_KEY_FREE(privkey);

    /* Restart and test a matching principal in AuthorizedPrincipals file */
    ssh_disconnect(session);
    ssh_free(session);
    torture_terminate_process(tss->state->srv_pidfile);

    /**--------------------------------------------------*/
    /* Update the server config file */
    snprintf(auth_principals_line,
             sizeof(auth_principals_line),
             "command=\"/usr/bin/date\" libssh");
    update_server_config_file(state, NULL, auth_principals_line, NULL);

    /* Update the server state with the expected auth_options struct  */
    expected = ssh_auth_option_new();
    assert_non_null(expected);
    expected->opt_flags = PERMIT_X11_FORWARDING_OPT | PERMIT_USER_RC_OPT |
                          PERMIT_PORT_FORWARDING_OPT | PERMIT_PTY_OPT |
                          PERMIT_AGENT_FORWARDING_OPT;
    expected->n_cert_principals = 1;
    expected->cert_principals = calloc(1, sizeof(char *));
    assert_non_null(expected->cert_principals);
    expected->cert_principals[0] = strdup("libssh");
    assert_non_null(expected->cert_principals[0]);

    expected->force_command = strdup("/usr/bin/date");
    assert_non_null(expected->force_command);
    tss->ss->expected_auth_opts = expected;

    /* Run server now */
    run_test_server_now(state);
    /**--------------------------------------------------*/

    /* Try auth now */
    session_setup(state);
    session = tss->state->ssh.session;
    rc = ssh_options_set(session, SSH_OPTIONS_USER, SSHD_DEFAULT_USER);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_connect(session);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_pki_import_privkey_file(tss->client.test_key,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_pki_import_cert_file(tss->client.test_cert_key, &cert);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_pki_copy_cert_to_privkey(cert, privkey);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_userauth_publickey(session, NULL, privkey);
    assert_int_equal(rc, SSH_AUTH_SUCCESS);

    SSH_KEY_FREE(cert);
    SSH_KEY_FREE(privkey);

    session_teardown(state);
}

int torture_run_tests(void) {
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(
            torture_cert_auth_only_authorized_keys_no_option,
            setup_default_server,
            teardown_default_server),
        cmocka_unit_test_setup_teardown(
            torture_cert_auth_only_authorized_keys_principals_option,
            setup_default_server,
            teardown_default_server),
        cmocka_unit_test_setup_teardown(
            torture_cert_auth_only_authorized_keys_match_user,
            setup_default_server,
            teardown_default_server),
        cmocka_unit_test_setup_teardown(
            torture_cert_auth_only_authorized_keys_expiry_time,
            setup_default_server,
            teardown_default_server),
        cmocka_unit_test_setup_teardown(
            torture_cert_auth_only_authorized_keys_source_address,
            setup_default_server,
            teardown_default_server),
        cmocka_unit_test_setup_teardown(
            torture_cert_auth_only_authorized_keys_all_options,
            setup_default_server,
            teardown_default_server),
        cmocka_unit_test_setup_teardown(torture_cert_auth_trusted_user_ca,
                                        setup_default_server,
                                        teardown_default_server),
        cmocka_unit_test_setup_teardown(
            torture_cert_auth_trusted_user_ca_and_authorized_principals_file,
            setup_default_server,
            teardown_default_server),
    };

    ssh_init();

    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, NULL, NULL);
    ssh_finalize();

    return rc;
}
