#include "config.h"
#include "libssh/mux.h"
#include <errno.h>
#include <stdio.h>
#include "libssh/priv.h"
#include "libssh/callbacks.h"
#include "libssh/socket.h"
#include "libssh/buffer.h"

#ifndef _WIN32

#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

typedef unsigned int u_int;
typedef unsigned char u_char;
typedef unsigned long u_long;

#define MAX_CLIENTS 10
#define SSH_MUX_VERSION 4

#define MUX_MSG_HELLO			0x00000001
#define MUX_C_NEW_SESSION		0x10000002
#define MUX_C_ALIVE_CHECK		0x10000004
#define MUX_S_ALIVE				0x80000005

int mux_server_fd = -1;
ssh_socket mux_server_sock = NULL;
struct pollfd client_fds[MAX_CLIENTS+1];
int connected_clients = 0;
int hello_received[MAX_CLIENTS+1];

int stop = 0;
unsigned int mux_client_request_id = 0;
unsigned int mux_server_pid = 0;
ssh_buffer msg;

int mux_client_open_session(ssh_socket sock, ssh_session session);
int mux_client(ssh_session session);
int send_fd(int sock, int fd);
int mux_client_alive_check(ssh_socket sock);
int mux_client_write_packet(ssh_socket sock);
int mux_client_exchange_hello(ssh_socket sock);
int mux_master_process_hello(ssh_session ssh, u_int rid, ssh_buffer msg, ssh_buffer reply, int idx, int client_sock);
int mux_master_read_callback(ssh_session session, int client_sock, int idx);
void mux_loop(ssh_session session);
int mux_listener_setup(ssh_session session);
int mux_master_write_packet(int sock, ssh_buffer b);
int mux_master_read_packet(int fd, ssh_buffer m);
int mux_master_read(int sock, ssh_buffer b, u_long need);
size_t mux_client_socket_callback(const void *data, size_t len, void *user);
int mux_master_process_alive_check(ssh_session ssh, u_int rid, ssh_buffer in, ssh_buffer out, int idx, int client_sock);
int mux_master_process_new_session (ssh_session session, u_int rid, ssh_buffer in, ssh_buffer out, int idx, int client_sock);
int mux_master_pollcallback(struct ssh_poll_handle_struct *p, socket_t fd, int revents, void *v_s);
int kbhit(void);
int receive_fd(int sock);

struct {
    u_int type;
    int (*handler)(ssh_session session, u_int rid, ssh_buffer in, ssh_buffer out, int idx, int client_sock);
} mux_master_handlers[] = {
    { MUX_MSG_HELLO, mux_master_process_hello },
    { MUX_C_ALIVE_CHECK, mux_master_process_alive_check },
    { MUX_C_NEW_SESSION, mux_master_process_new_session},
    { 0, NULL }
};

size_t mux_client_socket_callback(const void *data, size_t len, void *user){
    stop = 1;
    ssh_buffer_add_data(msg, data, len);
    return len;
}

static void mux_exception_callback(int code, int errno_code,void *user){
    SSH_LOG(SSH_LOG_RARE,"Socket exception callback: %d (%d)",code, errno_code);
    stop = 1;
}

int mux_client_write_packet(ssh_socket sock)
{
    ssh_buffer queue;
    int rc;

    if ((queue = ssh_buffer_new()) == NULL){
        return SSH_ERROR;
    }

    if ((rc = ssh_buffer_add_u32(queue, htonl(ssh_buffer_get_len(msg)))) != SSH_OK){
        return SSH_ERROR;
    }

    if ((rc = ssh_buffer_add_buffer(queue, msg)) != SSH_OK){
        return SSH_ERROR;
    }

    if (ssh_socket_write(sock, ssh_buffer_get(queue), ssh_buffer_get_len(queue)) != SSH_OK){
        return SSH_ERROR;
    }

    ssh_buffer_free(queue);
    return SSH_OK;
}

int mux_client_exchange_hello(ssh_socket sock)
{
    u_int type, ver;
    int rc;
    u_int len;
    ssh_poll_ctx ctx = NULL;

    ssh_buffer_reinit(msg);

    rc = ssh_buffer_pack(msg, "dd", MUX_MSG_HELLO, SSH_MUX_VERSION);
    if (rc != SSH_OK) {
        return SSH_ERROR;
    }

    if (mux_client_write_packet(sock) != SSH_OK) {
        SSH_LOG(SSH_LOG_DEBUG, "write mux packet failed");
        return SSH_ERROR;
    }

    ssh_buffer_reinit(msg);

    ctx = ssh_poll_get_ctx(ssh_socket_get_poll_handle(sock));
    if (ctx == NULL) {
        return SSH_ERROR;
    }
    while(!stop){
        ssh_poll_ctx_dopoll(ctx, -1);
    }

    stop = 0;

    ssh_buffer_get_u32(msg, &len);
    len = ntohl(len);
    SSH_LOG(SSH_LOG_DEBUG, "Received packet size: %u", len);

    if ((rc = ssh_buffer_get_u32(msg, &type)) != 4){
        return SSH_ERROR;
    }

    type = ntohl(type);
    if (type != MUX_MSG_HELLO) {
        SSH_LOG(SSH_LOG_DEBUG, "expected HELLO (%u) got %u", MUX_MSG_HELLO, type);
        return SSH_ERROR;
    }

    if ((rc = ssh_buffer_get_u32(msg, &ver)) != 4){
        return SSH_ERROR;
    }
    
    ver = ntohl(ver);
    if (ver != SSH_MUX_VERSION) {
        SSH_LOG(SSH_LOG_DEBUG, "Unsupported multiplexing protocol version %d "
            "(expected %d)", ver, SSH_MUX_VERSION);
        return SSH_ERROR;
    }

    SSH_LOG(SSH_LOG_DEBUG, "hello exchange successful, mux master version: %u", ver);
    
    return SSH_OK;
}

int mux_client_alive_check(ssh_socket sock) {
    int rc;
    u_int len, type, rid, pid;
    ssh_poll_ctx ctx = NULL;

    ssh_buffer_reinit(msg);

    rc = ssh_buffer_pack(msg, "dd", MUX_C_ALIVE_CHECK, mux_client_request_id);
    if (rc != SSH_OK) {
        return SSH_ERROR;
    }

    if (mux_client_write_packet(sock) != 0) {
        SSH_LOG(SSH_LOG_DEBUG, "write mux packet failed");
        return SSH_ERROR;
    }

    ssh_buffer_reinit(msg);

    ctx = ssh_poll_get_ctx(ssh_socket_get_poll_handle(sock));
    if (ctx == NULL) {
        return SSH_ERROR;
    }
    while(!stop){
        ssh_poll_ctx_dopoll(ctx, -1);
    }

    stop = 0;

    ssh_buffer_get_u32(msg, &len);
    len = ntohl(len);
    SSH_LOG(SSH_LOG_DEBUG, "Received packet size: %u", len);

    if ((rc = ssh_buffer_get_u32(msg, &type)) != 0){
        return SSH_ERROR;
    }
    type = ntohl(type);
    if (type != MUX_S_ALIVE) {
        SSH_LOG(SSH_LOG_DEBUG, "mux master not alive");
        return SSH_ERROR;
    }

    if ((rc = ssh_buffer_get_u32(msg, &rid)) != 0){
        return SSH_ERROR;
    }
    rid = ntohl(rid);
    if (rid != mux_client_request_id) {
        SSH_LOG(SSH_LOG_DEBUG, "out of sequence reply");
        return SSH_ERROR;
    }

    if ((rc = ssh_buffer_get_u32(msg, &pid)) != 0){
        return SSH_ERROR;
    }
    pid = ntohl(pid);
    SSH_LOG(SSH_LOG_DEBUG, "mux master alive pid: %u", pid);

    mux_client_request_id++;

    return pid;
}

int send_fd(int sock, int fd)
{
    struct msghdr msgh;
    union {
        struct cmsghdr hdr;
        char buf[CMSG_SPACE(sizeof(int))];
    } cmsgbuf;
    struct cmsghdr *cmsg;
    struct iovec vec;
    char ch = '\0';
    int n;
    struct pollfd pfd;

    memset(&msgh, 0, sizeof(msgh));
    memset(&cmsgbuf, 0, sizeof(cmsgbuf));
    msgh.msg_control = (caddr_t)&cmsgbuf.buf;
    msgh.msg_controllen = sizeof(cmsgbuf.buf);
    cmsg = CMSG_FIRSTHDR(&msgh);
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    *((int *) ((void *)CMSG_DATA(cmsg))) = fd;

    vec.iov_base = &ch;
    vec.iov_len = 1;
    msgh.msg_iov = &vec;
    msgh.msg_iovlen = 1;

    pfd.fd = sock;
    pfd.events = POLLOUT;
    while ((n = sendmsg(sock, &msgh, 0)) == -1 &&
        (errno == EAGAIN || errno == EINTR)) {
        SSH_LOG(SSH_LOG_DEBUG, "sendmsg(%d): %s", fd, strerror(errno));
        (void)poll(&pfd, 1, -1);
    }
    if (n == -1) {
        SSH_LOG(SSH_LOG_DEBUG, "sendmsg(%d): %s", fd, strerror(errno));
        return -1;
    }

    if (n != 1) {
        SSH_LOG(SSH_LOG_DEBUG, "sendmsg: expected sent 1 got %d", n);
        return -1;
    }
    return 0;
}

int receive_fd(int sock)
{
    struct msghdr msgh;
    union {
        struct cmsghdr hdr;
        char buf[CMSG_SPACE(sizeof(int))];
    } cmsgbuf;
    struct cmsghdr *cmsg;
    struct iovec vec;
    char ch = '\0';
    int n;
    int fd;
    struct pollfd pfd;

    memset(&msgh, 0, sizeof(msgh));
    memset(&cmsgbuf, 0, sizeof(cmsgbuf));
    msgh.msg_control = (caddr_t)&cmsgbuf.buf;
    msgh.msg_controllen = sizeof(cmsgbuf.buf);
    cmsg = CMSG_FIRSTHDR(&msgh);
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;

    vec.iov_base = &ch;
    vec.iov_len = 1;
    msgh.msg_iov = &vec;
    msgh.msg_iovlen = 1;

    pfd.fd = sock;
    pfd.events = POLLOUT;
    while ((n = recvmsg(sock, &msgh, 0)) == -1 &&
        (errno == EAGAIN || errno == EINTR)) {
        SSH_LOG(SSH_LOG_DEBUG, "recvmsg: %s", strerror(errno));
        (void)poll(&pfd, 1, -1);
    }

    if (n == -1) {
        SSH_LOG(SSH_LOG_DEBUG, "recvmsg: %s", strerror(errno));
        return -1;
    }

    if (n != 1) {
        SSH_LOG(SSH_LOG_DEBUG, "recvmsg: expected sent 1 got %d", n);
        return -1;
    }

    fd = *((int *) ((void *)CMSG_DATA(cmsg)));
    return fd;
}

int mux_client_open_session(ssh_socket sock, ssh_session session) {
    const char *term = NULL;
    u_int echar;
    int fd;

    if ((mux_server_pid = mux_client_alive_check(sock)) == 0) {
        return -1;
    }

    term = getenv("TERM");
    echar = 0xffffffff;

    ssh_buffer_reinit(msg);

    ssh_buffer_pack(msg, "ddsdddddss",
                    MUX_C_NEW_SESSION,
                    mux_client_request_id,
                    "",
                    1,
                    0,
                    0,
                    0,
                    echar,
                    term == NULL ? "" : term,
                    ""
    );

    if (mux_client_write_packet(sock) != 0) {
        SSH_LOG(SSH_LOG_DEBUG, "write mux packet failed");
        return SSH_ERROR;
    }

    fd = ssh_socket_get_fd(sock);

    if (send_fd(fd, STDIN_FILENO) == -1 || send_fd(fd, STDOUT_FILENO) == -1 || send_fd(fd, STDERR_FILENO) == -1) {
        SSH_LOG(SSH_LOG_DEBUG, "send fd failed");
        return SSH_ERROR;
    }

    SSH_LOG(SSH_LOG_DEBUG, "send fds success");

    mux_client_request_id++;
    return SSH_OK;
}

int mux_client(ssh_session session)
{
    ssh_socket sock;
    ssh_poll_handle h = NULL;
    ssh_poll_ctx ctx = NULL;
    ssh_socket_callbacks mux_client_callbacks;

    sock = ssh_socket_new(session);

    if (sock == NULL || ssh_socket_unix(sock, session->opts.control_path) != SSH_OK) {
        SSH_LOG(SSH_LOG_DEBUG, "Could not create socket");
        ssh_socket_free(sock);
        return SSH_ERROR;
    }

    ssh_socket_set_nonblocking(ssh_socket_get_fd(sock));
    ssh_socket_set_write_wontblock(sock);

    mux_client_callbacks = malloc(sizeof(struct ssh_socket_callbacks_struct));
    mux_client_callbacks->data = mux_client_socket_callback;
    mux_client_callbacks->exception = mux_exception_callback;
    mux_client_callbacks->connected = NULL;
    mux_client_callbacks->controlflow = NULL;
    ssh_socket_set_callbacks(sock, mux_client_callbacks);

    h = ssh_socket_get_poll_handle(sock);
    if (h == NULL) {
        return SSH_ERROR;
    }
    ctx = ssh_poll_get_ctx(h);
    if (ctx == NULL) {
        ctx = ssh_poll_get_default_ctx(session);
    }
    ssh_poll_ctx_add(ctx, h);

    if ((msg = ssh_buffer_new()) == NULL){
        SSH_LOG(SSH_LOG_DEBUG, "Could not create buffer");
        ssh_socket_close(sock);
        return SSH_ERROR;
    }

    if (mux_client_exchange_hello(sock) != 0) {
        SSH_LOG(SSH_LOG_DEBUG, "mux hello exchange failed");
        ssh_socket_close(sock);
        return SSH_ERROR;
    }

    if (mux_client_alive_check(sock) == SSH_ERROR) {
        SSH_LOG(SSH_LOG_DEBUG, "mux alive check failed");
        ssh_socket_close(sock);
        return SSH_ERROR;
    }

    if (mux_client_open_session(sock, session) == SSH_ERROR) {
        SSH_LOG(SSH_LOG_DEBUG, "mux open session failed");
        ssh_socket_close(sock);
        return SSH_ERROR;
    }

    session->mux_socket = sock;
    return ssh_socket_get_fd(sock);
}

int mux_listener_setup(ssh_session session)
{
     struct sockaddr_un sunaddr;
    SSH_LOG(SSH_LOG_DEBUG, "setting up mux master socket");
    memset(&sunaddr, 0, sizeof(sunaddr));
    sunaddr.sun_family = AF_UNIX;
    strcpy(sunaddr.sun_path, session->opts.control_path);
    // error handling
    mux_server_fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (mux_server_fd == SSH_ERROR) {
        SSH_LOG(SSH_LOG_DEBUG, "mux server socket failed");
        return SSH_ERROR;
    }
    if (bind(mux_server_fd, (struct sockaddr *)&sunaddr, sizeof(sunaddr)) == SSH_ERROR) {
        close(mux_server_fd);
        unlink(session->opts.control_path);
        return SSH_ERROR;
    }
    if (listen(mux_server_fd, 64) == -1) {
        close(mux_server_fd);
        unlink(session->opts.control_path);
        return SSH_ERROR;
    }

    mux_server_sock = ssh_socket_new(session);
    ssh_socket_set_nonblocking(mux_server_fd);
    ssh_socket_set_fd(mux_server_sock, mux_server_fd);

    SSH_LOG(SSH_LOG_DEBUG, "mux server fd: %d", mux_server_fd);

    for (int i = 0; i < MAX_CLIENTS; i++) {
        hello_received[i] = 0;
        client_fds[i].fd = 0;
    }

    mux_loop(session);

    SSH_LOG(SSH_LOG_DEBUG, "mux listener setup success");
    return SSH_OK;
}

void mux_loop(ssh_session session)
{
    client_fds[0].fd = mux_server_fd;
    client_fds[0].events = POLLIN;

    while (1) {
        int pollResult = poll(client_fds, connected_clients + 1, 5000);
        if (pollResult > 0) {
            if (client_fds[0].revents & POLLIN) {
                struct sockaddr_un cliaddr;
                u_int addrlen = sizeof(cliaddr);
                int client_socket = accept(mux_server_fd, (struct sockaddr *)&cliaddr, &addrlen);
                SSH_LOG(SSH_LOG_DEBUG, "accepting mux client");
                for (int i = 1; i <= MAX_CLIENTS; i++) {
                    if (client_fds[i].fd == 0) {
                        client_fds[i].fd = client_socket;
                        client_fds[i].events = POLLIN;
                        connected_clients++;
                        break;
                    }
                }
            }
            for (int i = 1; i <= MAX_CLIENTS; i++) {
                if (client_fds[i].fd > 0 && client_fds[i].revents & POLLIN) {
                   mux_master_read_callback(session, client_fds[i].fd, i);
                }
            }
        }
    }
}

int mux_master_read(int sock, ssh_buffer b, u_long need)
{
    u_long have;
    long len;
    u_char *p;
    struct pollfd pfd;

    pfd.fd = sock;
    pfd.events = POLLIN;

    p = ssh_buffer_allocate(b, need);

    for (have = 0; have < need; ) {
        len = read(sock, p + have, need - have);
        if (len == -1) {
            (void)poll(&pfd, 1, -1);
            continue;
        }
        if (len == 0) {
            return SSH_ERROR;
        }
        have += (u_long)len;
    }
    return SSH_OK;
}

int mux_master_read_packet(int fd, ssh_buffer m)
{
    ssh_buffer queue;
    u_int need, have;
    const u_char *ptr;
    int rc;

    if ((queue = ssh_buffer_new()) == NULL) {
        return SSH_ERROR;
    }

    if (mux_master_read(fd, queue, 4) != 0) {
        ssh_buffer_free(queue);
        return SSH_ERROR;
    }

    ssh_buffer_get_u32(queue, &need);
    need = ntohl(need);

    if (mux_master_read(fd, queue, need) != 0) {
        ssh_buffer_free(queue);
        return SSH_ERROR;
    }

    ptr = ssh_buffer_get(queue);
    have = ssh_buffer_get_len(queue);

    if ((rc = ssh_buffer_add_data(m, ptr, have)) != 0){
        return rc;
    }
    ssh_buffer_free(queue);
    return 0;
}

int mux_master_write_packet(int sock, ssh_buffer b)
{
    u_char *p;
    u_long len, have;
    ssh_buffer queue;
    int rc;

    if ((queue = ssh_buffer_new()) == NULL){
        return SSH_ERROR;
    }

    if ((rc = ssh_buffer_add_u32(queue, htonl(ssh_buffer_get_len(b)))) != 0){
        return rc;
    }

    if ((rc = ssh_buffer_add_buffer(queue, b)) != 0){
        return rc;
    }

    p = ssh_buffer_get(queue);
    len = ssh_buffer_get_len(queue);

    SSH_LOG(SSH_LOG_DEBUG, "sending mux packet of len %lu", len);

    have = 0;
    while (have < len) {
        rc = write(sock, p + have, len - have);
        if (rc == -1) {
            SSH_LOG(SSH_LOG_DEBUG, "error writing mux packet");
            return SSH_ERROR;
        }
        have += rc;
    }

    ssh_buffer_free(queue);
    ssh_buffer_reinit(b);
    return 0;
}

int mux_master_read_callback(ssh_session session, int client_sock, int idx)
{
    ssh_buffer in = NULL, out = NULL;
    u_int type, rid, i;
    int rc, ret = SSH_ERROR;

    if ((in = ssh_buffer_new()) == NULL) {
        return SSH_ERROR;
    }

    if ((out = ssh_buffer_new()) == NULL) {
        ssh_buffer_free(in);
        return SSH_ERROR;
    }

    SSH_LOG(SSH_LOG_DEBUG, "read callback for mux client fd %d", client_sock);

    if (hello_received[idx] == 0) {
        /* Send hello from master */
        rc = ssh_buffer_pack(out, "dd", MUX_MSG_HELLO, SSH_MUX_VERSION);
        if (rc != SSH_OK) {
            goto end;
        }
        if (mux_master_write_packet(client_sock, out) != 0) {
            goto end;
        }
        SSH_LOG(SSH_LOG_DEBUG, "hello sent from mux server");
    }

    mux_master_read_packet(client_sock, in);

    if ((rc = ssh_buffer_get_u32(in, &type)) != 4) {
        goto end;
    }

    type = ntohl(type);

    SSH_LOG(SSH_LOG_DEBUG, "received packet type: %d", type);

    if (type == MUX_MSG_HELLO){
        rid = 0;
    } else {
        if (!hello_received[idx]) {
            SSH_LOG(SSH_LOG_DEBUG, "first packet is not hello");
            goto end;
        }
        if ((rc = ssh_buffer_get_u32(in, &rid)) != 0) {
            goto end;
        }
        rid = ntohl(rid);
    }
    for (i = 0; mux_master_handlers[i].handler != NULL; i++) {
        if (type == mux_master_handlers[i].type) {
            ret = mux_master_handlers[i].handler(session, rid, in, out, idx, client_sock);
            break;
        }
    }
    if (mux_master_handlers[i].handler == NULL) {
        SSH_LOG(SSH_LOG_DEBUG, "unknown mux message type");
        ret = SSH_ERROR;
    }

    if (ssh_buffer_get_len(out) != 0 && mux_master_write_packet(client_sock, out) != 0) {
        ret = SSH_ERROR;
    }

 end:
    ssh_buffer_free(in);
    ssh_buffer_free(out);
    return ret;
}

int mux_master_process_hello(ssh_session session, u_int rid, ssh_buffer in, ssh_buffer out, int idx, int client_sock)
{
    u_int ver;
    int rc;

    if (hello_received[idx]) {
        SSH_LOG(SSH_LOG_DEBUG, "hello received twice");
        return SSH_ERROR;
    }
    if ((rc = ssh_buffer_get_u32(in, &ver)) != 4) {
        SSH_LOG(SSH_LOG_DEBUG, "error getting version");
        return SSH_ERROR;
    }
    ver = ntohl(ver);
    if (ver != SSH_MUX_VERSION) {
        SSH_LOG(SSH_LOG_DEBUG, "unsupported mux version %u (expected %u)", ver, SSH_MUX_VERSION);
        return SSH_ERROR;
    }

    SSH_LOG(SSH_LOG_DEBUG, "received hello with mux version %d", ver);
    hello_received[idx] = 1;
    return SSH_OK;
}

int mux_master_process_alive_check (ssh_session session, u_int rid, ssh_buffer in, ssh_buffer out, int idx, int client_sock)
{
    if (!hello_received[idx]) {
        SSH_LOG(SSH_LOG_DEBUG, "hello not received");
        return SSH_ERROR;
    }
    
    ssh_buffer_pack(out, "ddd", MUX_S_ALIVE, rid, (u_int)getpid());

    return SSH_OK;
}

int kbhit(void) {
    struct timeval tv = { 0L, 0L };
    fd_set fds;

    FD_ZERO(&fds);
    FD_SET(0, &fds);

    return select(1, &fds, NULL, NULL, &tv);
}

int mux_master_process_new_session (ssh_session session, u_int rid, ssh_buffer in, ssh_buffer out, int idx, int client_sock)
{
    ssh_channel channel;
    char *term = NULL;
    char *cmd = NULL;
    char *m = NULL;
    u_int want_tty, want_x11_fwd, want_agent_fwd, want_subsys, escape_char;
    int pid, received_fd[3], i, j, nbytes, nwritten;
    char buffer[1024];

    ssh_buffer_unpack(in, "sdddddss",
                        &m,
                        &want_tty,
                        &want_x11_fwd,
                        &want_agent_fwd,
                        &want_subsys,
                        &escape_char,
                        &term,
                        &cmd);

    for(i = 0; i < 3; i++) {
        if ((received_fd[i] = receive_fd(client_sock)) == -1) {
            SSH_LOG(SSH_LOG_DEBUG, "failed to receive fd %d from client", i);
            for (j = 0; j < i; j++)
                close(received_fd[j]);
            return -1;
        }
    }

    SSH_LOG(SSH_LOG_DEBUG, "received fds: %d, %d, %d", received_fd[0], received_fd[1], received_fd[2]);

    channel = ssh_channel_new(session);
    if (channel == NULL) {
        SSH_LOG(SSH_LOG_DEBUG, "Error creating channel");
        return SSH_ERROR;
    }

    if (ssh_channel_open_session(channel)) {
        SSH_LOG(SSH_LOG_DEBUG, "Error opening session channel");
        ssh_channel_free(channel);
        return SSH_ERROR;
    }

    ssh_channel_request_pty(channel);

    if (ssh_channel_request_shell(channel)) {
        SSH_LOG(SSH_LOG_DEBUG, "Error requesting shell");
        ssh_channel_free(channel);
        return SSH_ERROR;
    }
    
    pid = fork();

    if (pid == 0) {
        while (ssh_channel_is_open(channel) &&
         !ssh_channel_is_eof(channel))
        {
            nbytes = ssh_channel_read_nonblocking(channel, buffer, sizeof(buffer), 0);
            if (nbytes < 0) return SSH_ERROR;
            if (nbytes > 0)
            {
                nwritten = write(received_fd[1], buffer, nbytes);
                if (nwritten != nbytes) return SSH_ERROR;
            }

            if (!kbhit())
            {
                usleep(50000L); // 0.05 second
                continue;
            }

            nbytes = read(received_fd[0], buffer, sizeof(buffer));
            if (nbytes < 0) return SSH_ERROR;
            if (nbytes > 0)
            {
                nwritten = ssh_channel_write(channel, buffer, nbytes);
                if (nwritten != nbytes) return SSH_ERROR;
            }
        }
    }

    return SSH_OK;
}

#endif /*WIN32*/
