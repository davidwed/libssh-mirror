#include "libssh/libssh.h"
#include "libssh/session.h"

int mux_client(ssh_session session);
int mux_listener_setup(ssh_session session);
