#include "config.h"
#include "libssh/mux.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include <sys/un.h>
#include <poll.h>
#include <errno.h>

typedef unsigned int u_int;
typedef unsigned char u_char;
typedef unsigned long size_t;
#define SSH_MUX_VERSION 4

#define MUX_MSG_HELLO			0x00000001
#define MUX_C_NEW_SESSION		0x10000002
#define MUX_C_ALIVE_CHECK		0x10000004
#define MUX_S_ALIVE				0x80000005

int mux_server_sock = -1;
ssh_channel mux_listener_channel = NULL;
int connected_clients = 0;
int hello_received = 0;
int stop = 0;
unsigned int mux_client_request_id = 0;
unsigned int mux_server_pid = 0;
ssh_buffer msg;

static size_t mux_client_socket_callback(const void *data, size_t len, void *user){
	ssh_log_hexdump("Received data: ", data, len);
	stop = 1;
	ssh_buffer_add_data(msg, data, len);
	return len;
}

static void mux_exception_callback(int code, int errno_code,void *user){
	printf("Exception: %d (%d)\n",code,errno_code);
	stop = 1;
}

int mux_client_write_packet(ssh_socket sock, ssh_buffer msg)
{
	ssh_buffer queue;
	u_int have, need;
	int rc, len;
	const u_char *ptr;

	if ((queue = ssh_buffer_new()) == NULL){
		// error handling
	}

	if ((rc = ssh_buffer_add_u32(queue, htonl(ssh_buffer_get_len(msg)))) != 0){
		// error handling
	}

	if ((rc = ssh_buffer_add_buffer(queue, msg)) != 0){
		// error handling
	}

	if (ssh_socket_write(sock, ssh_buffer_get(queue), ssh_buffer_get_len(queue)) != SSH_OK){
		// error handling
		printf("couldn't write\n");
	}

	ssh_buffer_free(queue);
	return 0;
}

int mux_client_exchange_hello(ssh_socket sock)
{
	u_int type, ver;
	int rc, ret = -1;
	int len;
	ssh_poll_ctx ctx = NULL;

	ssh_buffer_reinit(msg);

	rc = ssh_buffer_pack(msg, "dd", MUX_MSG_HELLO, SSH_MUX_VERSION);
	if (rc != SSH_OK) {
        // error handling
    }

	if (mux_client_write_packet(sock, msg) != 0) {
		// error handling
		goto out;
	}

	ssh_buffer_reinit(msg);

	ctx = ssh_poll_get_ctx(ssh_socket_get_poll_handle(sock));
	if (ctx == NULL) {
		printf("ctx is null\n");
		goto out;
	}
	while(!stop){
		ssh_poll_ctx_dopoll(ctx, -1);
	}

	stop = 0;

	ssh_buffer_get_u32(msg, &len);
	len = ntohl(len);
	printf("read packet size: %lu\n", len);

	if ((rc = ssh_buffer_get_u32(msg, &type)) != 0){
		// error handling
	}

	type = ntohl(type);
	if (type != MUX_MSG_HELLO) {
		printf("expected HELLO (%u) got %u", MUX_MSG_HELLO, type);
		goto out;
	}

	if ((rc = ssh_buffer_get_u32(msg, &ver)) != 0){
		// fatal error
	}
	
	ver = ntohl(ver);
	if (ver != SSH_MUX_VERSION) {
		printf("Unsupported multiplexing protocol version %d "
		    "(expected %d)", ver, SSH_MUX_VERSION);
		goto out;
	}

	printf("master version: %u\n", ver);
	
	ret = SSH_OK;
 out:
	return ret;
}

int mux_client_alive_check(ssh_socket sock) {
	int rc, len, ret = -1;
	u_int type, rid, pid;
	ssh_poll_ctx ctx = NULL;

	ssh_buffer_reinit(msg);

	rc = ssh_buffer_pack(msg, "dd", MUX_C_ALIVE_CHECK, mux_client_request_id);
	if (rc != SSH_OK) {
        // error handling
    }

	if (mux_client_write_packet(sock, msg) != 0) {
		// error handling
		goto out;
	}

	ssh_buffer_reinit(msg);

	ctx = ssh_poll_get_ctx(ssh_socket_get_poll_handle(sock));
	if (ctx == NULL) {
		printf("ctx is null\n");
		goto out;
	}
	while(!stop){
		ssh_poll_ctx_dopoll(ctx, -1);
	}

	stop = 0;

	ssh_buffer_get_u32(msg, &len);
	len = ntohl(len);
	printf("read packet size: %lu\n", len);

	if ((rc = ssh_buffer_get_u32(msg, &type)) != 0){
		// error handling
	}
	type = ntohl(type);
	if (type != MUX_S_ALIVE) {
		printf("not alive\n");
		goto out;
	}

	if ((rc = ssh_buffer_get_u32(msg, &rid)) != 0){
		// error handling
	}
	rid = ntohl(rid);
	if (rid != mux_client_request_id) {
		printf("out of sequence reply\n");
		goto out;
	}

	if ((rc = ssh_buffer_get_u32(msg, &pid)) != 0){
		// error handling
	}
	pid = ntohl(pid);
	printf("alive pid: %u\n", pid);

	mux_client_request_id++;

	ret = pid;
 out:
	return ret;
}

int send_fd(int sock, int fd)
{
	struct msghdr msg;
	union {
		struct cmsghdr hdr;
		char buf[CMSG_SPACE(sizeof(int))];
	} cmsgbuf;
	struct cmsghdr *cmsg;
	struct iovec vec;
	char ch = '\0';
	ssize_t n;
	struct pollfd pfd;

	memset(&msg, 0, sizeof(msg));
	memset(&cmsgbuf, 0, sizeof(cmsgbuf));
	msg.msg_control = (caddr_t)&cmsgbuf.buf;
	msg.msg_controllen = sizeof(cmsgbuf.buf);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(int *)CMSG_DATA(cmsg) = fd;

	vec.iov_base = &ch;
	vec.iov_len = 1;
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;

	pfd.fd = sock;
	pfd.events = POLLOUT;
	while ((n = sendmsg(sock, &msg, 0)) == -1 &&
	    (errno == EAGAIN || errno == EINTR)) {
		printf("sendmsg(%d): %s", fd, strerror(errno));
		(void)poll(&pfd, 1, -1);
	}
	if (n == -1) {
		printf("sendmsg(%d): %s", fd, strerror(errno));
		return -1;
	}

	if (n != 1) {
		printf("sendmsg: expected sent 1 got %zd", n);
		return -1;
	}
	return 0;
}

int mux_client_open_session(ssh_socket sock, ssh_session session) {
	const char *term = NULL;
	u_int echar;
	int r, rawmode, fd;

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

	if (mux_client_write_packet(sock, msg) != 0) {
		printf("write packet failed\n");
		return SSH_ERROR;
	}

	fd = ssh_socket_get_fd(sock);

	if (send_fd(fd, STDIN_FILENO) == -1 || send_fd(fd, STDOUT_FILENO) == -1 || send_fd(fd, STDERR_FILENO) == -1) {
		printf("send fd failed\n");
		return SSH_ERROR;
	}

	printf("send fd success\n");

	mux_client_request_id++;
	return SSH_OK;
}

int mux_client(ssh_session session){
    
	ssh_socket sock;
    ssh_poll_handle h = NULL;
	ssh_poll_ctx ctx = NULL;
	ssh_socket_callbacks mux_client_callbacks;

	sock = ssh_socket_new(session);

	if (sock == NULL || ssh_socket_unix(sock, session->opts.control_path) != SSH_OK) {
		printf("ssh_socket_unix failed\n");
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
		ssh_poll_ctx_add(ctx, h);
	}

	if ((msg = ssh_buffer_new()) == NULL){
		// error handling
	}

	if (mux_client_exchange_hello(sock) != 0) {
		printf("mux_client_exchange_hello failed\n");
		ssh_socket_close(sock);
		return -1;
	}

	if (mux_client_alive_check(sock) == SSH_ERROR) {
		printf("alive check failed\n");
		ssh_socket_close(sock);
		return -1;
	}

	if (mux_client_open_session(sock, session) == SSH_ERROR) {
		printf("open session failed\n");
		ssh_socket_close(sock);
		return -1;
	}

	return ssh_socket_get_fd(sock);
}