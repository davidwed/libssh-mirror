#include "config.h"
#include "libssh/mux.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include <sys/un.h>
#include <poll.h>
#include <fcntl.h>
#include <errno.h>



typedef unsigned int u_int;
typedef unsigned char u_char;
typedef unsigned long size_t;

#define CHANNEL_MAX_PACKET 32768
#define CHANNEL_INITIAL_WINDOW 64000
#define MAX_CLIENTS 10
#define SSH_MUX_VERSION 4

#define MUX_MSG_HELLO			0x00000001
#define MUX_C_NEW_SESSION		0x10000002
#define MUX_C_ALIVE_CHECK		0x10000004
#define MUX_S_ALIVE				0x80000005

#define PEEK_U32(p) \
	(((u_int32_t)(((const u_char *)(p))[0]) << 24) | \
	 ((u_int32_t)(((const u_char *)(p))[1]) << 16) | \
	 ((u_int32_t)(((const u_char *)(p))[2]) << 8) | \
	  (u_int32_t)(((const u_char *)(p))[3]))

// struct {
// 	u_int type;
// 	int (*handler)(ssh_session session, u_int rid, ssh_buffer in, ssh_buffer out);
// } mux_master_handlers[] = {
// 	{ MUX_MSG_HELLO, mux_master_process_hello },
// 	{ 0, NULL }
// };

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

int mux_client_read(int sock, ssh_buffer b, size_t need)
{
	size_t have;
	long len;
	u_char *p;
	struct pollfd pfd;
	int rc;

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
			printf("len == 0\n");
			return -1;
		}
		printf("len: %ld\n", len);
		have += (size_t)len;
	}
	return SSH_OK;
}

int mux_client_read_packet(ssh_socket sock, ssh_buffer m)
{
	ssh_buffer queue;
	unsigned long need, have;
	const u_char *ptr;
	int rc;
	int fd = ssh_socket_get_fd(sock);
	// int oerrno;

	if ((queue = ssh_buffer_new()) == NULL) {
		
	}

	if (mux_client_read(fd, queue, 4) != 0) {
		ssh_buffer_free(queue);
		return -1;
	}

	ssh_buffer_get_u32(queue, &need);
	need = ntohl(need);
	printf("need read packet: %lu\n", need);

	if (mux_client_read(fd, queue, need) != 0) {
		// oerrno = errno;
		// debug3_f("read body failed: %s", strerror(errno));
		ssh_buffer_free(queue);
		// errno = oerrno;
		return -1;
	}

	ssh_log_hexdump("after read buffer: ", ssh_buffer_get(queue), ssh_buffer_get_len(queue));

	ptr = ssh_buffer_get(queue);
	have = ssh_buffer_get_len(queue);

	if ((rc = ssh_buffer_add_data(m, ptr, have)) != 0){
		// fatal error
	}
	ssh_buffer_free(queue);
	return 0;
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

	ssh_log_hexdump("buffer before write: ", ssh_buffer_get(queue), ssh_buffer_get_len(queue));

	if (ssh_socket_write(sock, ssh_buffer_get(queue), ssh_buffer_get_len(queue)) != SSH_OK){
		// error handling
		printf("couldn't write\n");
	}

	// need = ssh_buffer_get_len(queue);
	// ptr = ssh_buffer_get(queue);
	// for (have = 0; have < need; ) {
	// 	len = write(sock, ptr + have, need - have);
	// 	if (len == -1) {
	// 		printf("couldn't write\n");
	// 	}
	// 	if (len == 0) {
	// 		ssh_buffer_free(queue);
	// 		return -1;
	// 	}
	// 	have += (u_int)len;
	// }

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
		printf("polling\n");
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
		printf("polling\n");
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

int
mm_send_fd(int sock, int fd)
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
	char *e;
	const char *term = NULL;
	u_int i, echar, rid, sid, esid, exitval, type, exitval_seen;
	extern char **environ;
	int r, rawmode, fd;

	if ((mux_server_pid = mux_client_alive_check(sock)) == 0) {
		return -1;
	}

	// ssh_signal(SIGPIPE, SIG_IGN);

	// if (options.stdin_null && stdfd_devnull(1, 0, 0) == -1)
	// 	fatal_f("stdfd_devnull failed");


	term = getenv("TERM");
	echar = 0xffffffff;
	
	// if (session->options.escape_char != SSH_ESCAPECHAR_NONE)
	//     echar = (u_int)options.escape_char;

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

	// /* Pass environment */
	// if (options.num_send_env > 0 && environ != NULL) {
	// 	for (i = 0; environ[i] != NULL; i++) {
	// 		if (!env_permitted(environ[i]))
	// 			continue;
	// 		if ((r = sshbuf_put_cstring(m, environ[i])) != 0)
	// 			fatal_fr(r, "request sendenv");
	// 	}
	// }
	// for (i = 0; i < options.num_setenv; i++) {
	// 	if ((r = sshbuf_put_cstring(m, options.setenv[i])) != 0)
	// 		fatal_fr(r, "request setenv");
	// }

	if (mux_client_write_packet(sock, msg) != 0) {
		printf("write packet failed\n");
		return SSH_ERROR;
	}

	/* Send the stdio file descriptors */

	fd = ssh_socket_get_fd(sock);

	if (mm_send_fd(fd, STDIN_FILENO) == -1 || mm_send_fd(fd, STDOUT_FILENO) == -1 || mm_send_fd(fd, STDERR_FILENO) == -1) {
		printf("send fd failed\n");
		return SSH_ERROR;
	}

	printf("send fd success\n");

	// /* Read their reply */
	// sshbuf_reset(m);
	// if (mux_client_read_packet(fd, m) != 0) {
	// 	error_f("read from master failed: %s", strerror(errno));
	// 	sshbuf_free(m);
	// 	return -1;
	// }

	// if ((r = sshbuf_get_u32(m, &type)) != 0 ||
	//     (r = sshbuf_get_u32(m, &rid)) != 0)
	// 	fatal_fr(r, "parse");
	// if (rid != muxclient_request_id)
	// 	fatal_f("out of sequence reply: my id %u theirs %u",
	// 	    muxclient_request_id, rid);

	// switch (type) {
	// case MUX_S_SESSION_OPENED:
	// 	if ((r = sshbuf_get_u32(m, &sid)) != 0)
	// 		fatal_fr(r, "parse session ID");
	// 	debug_f("master session id: %u", sid);
	// 	break;
	// case MUX_S_PERMISSION_DENIED:
	// 	if ((r = sshbuf_get_cstring(m, &e, NULL)) != 0)
	// 		fatal_fr(r, "parse error message");
	// 	error("Master refused session request: %s", e);
	// 	sshbuf_free(m);
	// 	return -1;
	// case MUX_S_FAILURE:
	// 	if ((r = sshbuf_get_cstring(m, &e, NULL)) != 0)
	// 		fatal_fr(r, "parse error message");
	// 	error_f("session request failed: %s", e);
	// 	sshbuf_free(m);
	// 	return -1;
	// default:
	// 	sshbuf_free(m);
	// 	error_f("unexpected response from master 0x%08x", type);
	// 	return -1;
	// }
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

	// struct sockaddr_un addr;
	// int sock;
	// memset(&addr, '\0', sizeof(addr));
	// addr.sun_family = AF_UNIX;
	// strcpy(addr.sun_path, session->opts.control_path);
	// sock = socket(PF_UNIX, SOCK_STREAM, 0);
	// if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
	// 	// error handling
	// 	close(sock);
	// 	return SSH_ERROR;
	// }
	// fcntl(sock, F_SETFL, O_NONBLOCK);

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

	ssh_buffer_free(msg);
	return ssh_socket_get_fd(sock);
}

// int mux_listener_setup(ssh_session session){
//  struct sockaddr_un sunaddr;
// 	SSH_LOG(SSH_LOG_DEBUG, "setting up mux master socket");
// 	memset(&sunaddr, 0, sizeof(sunaddr));
// 	sunaddr.sun_family = AF_UNIX;
// 	strcpy(sunaddr.sun_path, session->opts.control_path);
//     // error handling
// 	mux_server_sock = socket(PF_UNIX, SOCK_STREAM, 0);
// 	if (mux_server_sock == SSH_ERROR) {
// 		// error handling
// 		return SSH_ERROR;
// 	}
// 	if (bind(mux_server_sock, (struct sockaddr *)&sunaddr, sizeof(sunaddr)) == SSH_ERROR) {
// 		// error handling
// 		close(mux_server_sock);
// 		unlink(session->opts.control_path);
// 		return SSH_ERROR;
// 	}
// 	if (listen(mux_server_sock, 64) == -1) {
// 		// error handling
// 		close(mux_server_sock);
// 		unlink(session->opts.control_path);
// 		return SSH_ERROR;
// 	}
// 	unlink(session->opts.control_path);
// 	// ssh_socket_set_blocking(mux_server_sock);
// 	fcntl(mux_server_sock, F_SETFL, O_NONBLOCK);
// 	mux_loop(session);
// 	// mux_listener_channel = ssh_channel_new(session);
// 	// mux_listener_channel->local_channel = ssh_channel_new_id(session);
//     // mux_listener_channel->local_maxpacket = CHANNEL_MAX_PACKET;
//     // mux_listener_channel->local_window = CHANNEL_INITIAL_WINDOW;
// 	// ssh_set_channel_callbacks(mux_listener_channel, channel_cb);
// 	return SSH_OK;
// }

// void mux_loop(ssh_session session){
// 	struct pollfd pollfds[MAX_CLIENTS + 1];
//     pollfds[0].fd = mux_server_sock;
//     pollfds[0].events = POLLIN;
//     while (1) {
//         int pollResult = poll(pollfds, connected_clients + 1, 5000);
//         if (pollResult > 0) {
//             if (pollfds[0].revents & POLLIN) {
//                 struct sockaddr_un cliaddr;
//                 int addrlen = sizeof(cliaddr);
//                 int client_socket = accept(mux_server_sock, (struct sockaddr *)&cliaddr, &addrlen);
//                 for (int i = 1; i < MAX_CLIENTS; i++) {
//                     if (pollfds[i].fd == 0) {
//                         pollfds[i].fd = client_socket;
//                         pollfds[i].events = POLLIN;
//                         connected_clients++;
//                         break;
//                     }
//                 }
//             }
//             for (int i = 1; i < MAX_CLIENTS; i++) {
//                 if (pollfds[i].fd > 0 && pollfds[i].revents & POLLIN) {
//                    mux_master_read_callback(session, pollfds[i].fd);
//                 }
//             }
//         }
// 		printf("loop\n");
//     }
// 	// 	memset(&addr, 0, sizeof(addr));
// 	// addrlen = sizeof(addr);
// 	// if ((newsock = accept(c->sock, (struct sockaddr*)&addr,
// 	//     &addrlen)) == -1) {
// 	// 	error_f("accept: %s", strerror(errno));
// 	// 	if (errno == EMFILE || errno == ENFILE)
// 	// 		c->notbefore = monotime() + 1;
// 	// 	return;
// 	// }
// 	// if (getpeereid(newsock, &euid, &egid) == -1) {
// 	// 	error_f("getpeereid failed: %s", strerror(errno));
// 	// 	close(newsock);
// 	// 	return;
// 	// }
// 	// if ((euid != 0) && (getuid() != euid)) {
// 	// 	error("multiplex uid mismatch: peer euid %u != uid %u",
// 	// 	    (u_int)euid, (u_int)getuid());
// 	// 	close(newsock);
// 	// 	return;
// 	// }
// 	// nc = channel_new(ssh, "mux-control", SSH_CHANNEL_MUX_CLIENT,
// 	//     newsock, newsock, -1, c->local_window_max,
// 	//     c->local_maxpacket, 0, "mux-control", 1);
// 	// nc->mux_rcb = c->mux_rcb;
// 	// debug3_f("new mux channel %d fd %d", nc->self, nc->sock);
// 	// /* establish state */
// 	// nc->mux_rcb(ssh, nc);
// 	// /* mux state transitions must not elicit protocol messages */
// 	// nc->flags |= CHAN_LOCAL;
// }

// int mux_master_read_callback(ssh_session session, int client_sock)
// // {
// // 	char buffer[1024];
// // 	int read_size = read(client_socket, buffer, 1024);
// // 	if (read_size > 0) {
// // 		buffer[read_size] = '\0';
// // 		printf("Received: %s\n", buffer);
// // 	} else if (read_size == 0) {
// // 		printf("Client disconnected\n");
// // 		close(client_socket);
// // 		connected_clients--;
// // 	} else {
// // 		printf("Error reading\n");
// // 	}
// // 	return 0;
// // }
// {
// 	ssh_buffer in = NULL, out = NULL;
// 	u_int type, rid, i;
// 	int rc, ret = -1;
// 	if ((out = ssh_buffer_new()) == NULL) {
// 		// error handling
// 	}
// 	// if (hello_received == 0) {
// 	// 	state = xcalloc(1, sizeof(*state));
// 	// 	c->mux_ctx = state;
// 	// 	channel_register_cleanup(ssh, c->self,
// 	// 	    mux_master_control_cleanup_cb, 0);
// 	// 	/* Send hello */
// 	// 	rc = ssh_buffer_pack(session->out_buffer,
//     //                      "bsddd",
//     //                      SSH2_MSG_CHANNEL_OPEN,
//     //                      type,
//     //                      channel->local_channel,
//     //                      channel->local_window,
//     //                      channel->local_maxpacket);
// 	// 	debug3_f("channel %d: hello sent", c->self);
// 	// 	ret = 0;
// 	// 	goto out;
// 	// }
// 	if ((rc = ssh_buffer_get_u32(in, &type)) != 0) {
// 		// error handling
// 	}
// 	// debug3_f("channel %d packet type 0x%08x len %zu", c->self,
// 	//     type, sshbuf_len(in));
// 	if (type == MUX_MSG_HELLO)
// 		rid = 0;
// 	else {
// 		if (!hello_received) {
// 			//error handling
// 			goto out;
// 		}
// 		if ((rc = ssh_buffer_get_u32(in, &rid)) != 0) {
// 			// error handling
// 		}
// 	}
// 	for (i = 0; mux_master_handlers[i].handler != NULL; i++) {
// 		if (type == mux_master_handlers[i].type) {
// 			ret = mux_master_handlers[i].handler(session, rid, in, out);
// 			break;
// 		}
// 	}
// 	if (mux_master_handlers[i].handler == NULL) {
// 		// error handling
// 		ret = 0;
// 	}
//  out:
// 	return ret;
// }

// int mux_master_process_hello(ssh_session ssh, u_int rid, ssh_buffer msg, ssh_buffer reply)
// {
// 	u_int ver;
// 	int rc;
// 	if (!hello_received) {
// 		// error handling
// 		return -1;
// 	}
// 	if ((rc = ssh_buffer_get_u32(msg, &ver)) != 0) {
// 		// error handling
// 		return -1;
// 	}
// 	// if (ver != SSHMUX_VER) {
// 	// 	error_f("unsupported multiplexing protocol version %u "
// 	// 	    "(expected %u)", ver, SSHMUX_VER);
// 	// 	return -1;
// 	// }
// 	// debug2_f("channel %d client version %u", c->self, ver);
// 	// while (ssh_buffer_get_len(msg) > 0) {
// 	// 	ssh_string name = NULL;
// 	// 	name = ssh_buffer_get_ssh_string(msg);
// 	// 	// free(name);
// 	// }
// 	printf("RECEIVED HELLO !!!!!!!!!");
// 	hello_received = 1;
// 	return 0;
// }