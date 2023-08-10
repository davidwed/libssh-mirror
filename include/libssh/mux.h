#include "libssh/libssh.h"
#include "libssh/session.h"
#include "libssh/channels.h"
#include "libssh/callbacks.h"
#include "libssh/socket.h"
#include "buffer.h"

int mux_client(ssh_session session);
int mux_listener_setup(ssh_session session);