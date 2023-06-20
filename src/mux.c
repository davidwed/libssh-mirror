#include "config.h"
#include "libssh/mux.h"
#include <sys/socket.h>
#include <stdio.h>
#include <sys/un.h>
#include <poll.h>
#include <fcntl.h>


typedef unsigned int u_int;
typedef unsigned char u_char;
typedef unsigned long size_t;

#define CHANNEL_MAX_PACKET 32768
#define CHANNEL_INITIAL_WINDOW 64000
#define MAX_CLIENTS 10
#define SSH_MUX_VERSION 4

#define MUX_MSG_HELLO		0x00000001

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

int mux_client_read_packet(int fd, ssh_buffer m)
{
	ssh_buffer queue;
	unsigned long need, have;
	const u_char *ptr;
	int rc;
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

int mux_client_write_packet(int sock, ssh_buffer msg)
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

	need = ssh_buffer_get_len(queue);
	ptr = ssh_buffer_get(queue);
	for (have = 0; have < need; ) {
		len = write(sock, ptr + have, need - have);
		if (len == -1) {
			printf("couldn't write\n");
		}
		if (len == 0) {
			ssh_buffer_free(queue);
			return -1;
		}

		have += (u_int)len;
	}
	ssh_buffer_free(queue);
	return 0;
}

int mux_client_exchange_hello(int fd)
{
	u_int type, ver;
	int rc, ret = -1;
	ssh_buffer msg;

	if ((msg = ssh_buffer_new()) == NULL){
		// error handling
	}

	if ((rc = ssh_buffer_add_u32(msg, htonl(MUX_MSG_HELLO))) != SSH_OK ) {
		// error handling
		printf("some error\n");
	}

	if ((rc = ssh_buffer_add_u32(msg, htonl(SSH_MUX_VERSION))) != SSH_OK ) {
		// error handling
		printf("some error 2\n");
	}

	ssh_log_hexdump("my buffer: ", ssh_buffer_get(msg), ssh_buffer_get_len(msg));

	if (mux_client_write_packet(fd, msg) != 0) {
		// error handling
		goto out;
	}

	ssh_buffer_reinit(msg);

	if (mux_client_read_packet(fd, msg) != 0) {
		// error handling
		goto out;
	}

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

	// debug2_f("master version %u", ver);

	// while (ssh_buffer_get_len(msg) > 0) {
	// 	char *name = NULL;

	// 	if ((rc = sshbuf_get_cstring(msg, &name, NULL)) != 0 ||
	// 	    (rc = sshbuf_skip_string(msg)) != 0) { 
	// 		// error handling
	// 		goto out;
	// 	}
	// 	debug2("Unrecognised master extension \"%s\"", name);
	// 	free(name);
	// }
	
	ret = SSH_OK;
 out:
	ssh_buffer_free(msg);
	return ret;
}

int mux_client(ssh_session session){
    
	struct sockaddr_un addr;
	int sock;

	memset(&addr, '\0', sizeof(addr));
	addr.sun_family = AF_UNIX;

	strcpy(addr.sun_path, session->opts.control_path);

	sock = socket(PF_UNIX, SOCK_STREAM, 0);

	if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		// error handling
		close(sock);
		return SSH_ERROR;
	}

	fcntl(sock, F_SETFL, O_NONBLOCK);

	if (mux_client_exchange_hello(sock) != 0) {
		printf("mux_client_exchange_hello failed\n");
		close(sock);
		return -1;
	}

	return SSH_OK;

	// SSHMUX_COMMAND_OPEN

	// if (mux_client_forwards(sock, 0) != 0) {
	// 	printf("mux_client_forwards failed\n");
	// 	return -1;
	// }
	// mux_client_request_session(sock);
	// return -1;
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