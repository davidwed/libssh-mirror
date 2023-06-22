#include "libssh/libssh.h"
#include "libssh/session.h"
#include "libssh/channels.h"
#include "libssh/socket.h"
#include "buffer.h"

// enum ssh_mux_state_e {
//     SSH_MUX_UNKNOWN,
//     SSH_MUX_SERVER,
//     SSH_MUX_CLIENT,
//     SSH_MUX_LISTENER
// };

// enum ssh_mux_channel_state_e {
//     SSH_MUX_CHANNEL_UNKNOWN,
//     SSH_MUX_CHANNEL_OPENING,
//     SSH_MUX_CHANNEL_OPENED,
//     SSH_MUX_CHANNEL_CLOSING,
//     SSH_MUX_CHANNEL_CLOSED
// };

// enum ssh_mux_channel_type_e {
//     SSH_MUX_CHANNEL_UNKNOWN_TYPE,
//     SSH_MUX_CHANNEL_SESSION,
//     SSH_MUX_CHANNEL_X11,
//     SSH_MUX_CHANNEL_AGENT,
//     SSH_MUX_CHANNEL_FORWARDED_TCPIP,
//     SSH_MUX_CHANNEL_DIRECT_TCPIP
// };

// enum ssh_mux_channel_direction_e {
//     SSH_MUX_CHANNEL_UNKNOWN_DIRECTION,
//     SSH_MUX_CHANNEL_INCOMING,
//     SSH_MUX_CHANNEL_OUTGOING
// };

int mux_client(ssh_session session);
// int mux_listener_setup(ssh_session session);
// int mux_client_exchange_hello(ssh_socket sock);
// int mux_client_write_packet(ssh_socket sock, ssh_buffer msg);
// void mux_loop(ssh_session session);
// int mux_master_read_callback(ssh_session session, int client_sock);
// int mux_master_process_hello(ssh_session ssh, u_int rid, ssh_buffer msg, ssh_buffer reply);