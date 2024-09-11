#ifndef AUTHORIZED_KEYS_H
#define AUTHORIZED_KEYS_H

#include "libssh/pki.h"
#include "libssh/auth_options.h"

#ifdef __cplusplus
extern "C" {
#endif

int
ssh_authorized_keys_check_file(ssh_key key,
                               const char *filename,
                               const char *pw_name,
                               struct ssh_auth_options **auth_opts,
                               const char *remote_peer_ip,
                               const char *remote_peer_hostname,
                               const char *allowed_ca_sign_algos);
int
ssh_authorized_principals_check_file(ssh_key cert,
                                     const char *filename,
                                     struct ssh_auth_options **auth_opts,
                                     const char *remote_peer_ip,
                                     const char *remote_peer_hostname,
                                     const char *allowed_ca_sign_algos);
int
ssh_authorize_authkey_options(struct ssh_auth_options *auth_opts,
                              const char *remote_peer_ip,
                              const char *remote_peer_hostname,
                              bool with_cert);

#ifdef __cplusplus
}
#endif

#endif /* AUTHORIZED_KEYS_H */
