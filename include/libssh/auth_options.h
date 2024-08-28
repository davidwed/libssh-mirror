#ifndef AUTH_OPTIONS_H
#define AUTH_OPTIONS_H

enum ssh_auth_opts_flags {
    NO_TOUCH_REQUIRED_OPT       = 1 << 0,
    PERMIT_X11_FORWARDING_OPT   = 1 << 1,
    PERMIT_AGENT_FORWARDING_OPT = 1 << 2,
    PERMIT_PORT_FORWARDING_OPT  = 1 << 3,
    PERMIT_PTY_OPT              = 1 << 4,
    PERMIT_USER_RC_OPT          = 1 << 5,
    VERIFY_REQUIRED_OPT         = 1 << 6,
    CERT_AUTHORITY_OPT          = 1 << 7,
    RESTRICTED_OPT              = 1 << 8,
};

struct ssh_auth_options {
    /* Option flags bitmap */
    uint32_t opt_flags;

    /* Force the execution of a command after authentication */
    char *force_command;

    /*
     * Comma-separated list of source addresses or hostnames eligible
     * for authentication.
     */
    char *authkey_from_addr_host;

    /* Certificate source-address option (comma-separated CIDR list) */
    char *cert_source_address;

    /* Expiry time (seconds) */
    uint64_t valid_before;

    /* Custom environments */
    unsigned int n_envs;
    char **envs;

    /* Limit remote port-forwarding to specific [host:]port list */
    unsigned int n_permit_listen;
    char **permit_listen;

    /* Limit local port-forwarding to specific host:port list */
    unsigned int n_permit_open;
    char **permit_open;

    /* Allowed principals list for certificate authentication */
    unsigned int n_cert_principals;
    char **cert_principals;

    /* TUN device to be enforced on the server */
    int tun_device;
};

struct ssh_auth_options *ssh_auth_option_new(void);
void ssh_auth_options_free(struct ssh_auth_options *auth_opts);
#define SSH_AUTH_OPTS_FREE(x) \
    do { if ((x) != NULL) { ssh_auth_options_free(x); x = NULL; } } while(0)

struct ssh_tokens_st *
ssh_tokenize_with_auth_options(const char *chain, char delimiter);
struct ssh_auth_options *ssh_auth_options_list_parse(const char *list);
struct ssh_auth_options *
ssh_auth_options_merge_cert_opts(ssh_key certkey,
                                 struct ssh_auth_options *src_opts);
struct ssh_auth_options *ssh_auth_options_from_cert(ssh_key certkey);
#endif
