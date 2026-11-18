/*
 * Runs the real iscsiadm SendTargets discovery (discovery_sendtargets()) against a byte stream
 * a target would send, for the fuzz_sendtargets harness and the oracle probe. The environment
 * the discovery needs is stood in for at the libc boundary only:
 *   - connect() hands the session one end of a socketpair that already holds the target's stream,
 *     and never touches the network (a second connect, e.g. after a redirect, is refused);
 *   - scandir() of the sysfs transport directory fails, so the "tcp" transport registered here is
 *     the one discovery finds, whatever the host's sysfs holds;
 *   - access() of the idbm database root succeeds, so idbm_init() works without /var/lib/iscsi;
 *   - getaddrinfo() is numeric-only, so a TargetAddress resolves the same way on every run.
 * Include from one translation unit only.
 */
#ifndef DISCOVERY_ENV_H
#define DISCOVERY_ENV_H
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "config.h"
#include "discovery.h"
#include "iface.h"
#include "idbm.h"
#include "initiator.h"
#include "iscsi_if.h"
#include "iscsi_proto.h"
#include "iscsi_settings.h"
#include "iscsi_sysfs.h"
#include "transport.h"

static int env_peer_fd = -1;

int connect(int fd, const struct sockaddr *addr, socklen_t len)
{
	if (env_peer_fd < 0) {
		errno = ECONNREFUSED;
		return -1;
	}
	if (dup2(env_peer_fd, fd) < 0)
		return -1;
	close(env_peer_fd);
	env_peer_fd = -1;
	return 0;
}

int scandir(const char *dir, struct dirent ***namelist,
	    int (*sel)(const struct dirent *),
	    int (*cmp)(const struct dirent **, const struct dirent **))
{
	static int (*real)(const char *, struct dirent ***,
			   int (*)(const struct dirent *),
			   int (*)(const struct dirent **, const struct dirent **));

	if (!strcmp(dir, "/sys/class/iscsi_transport")) {
		errno = ENOENT;
		return -1;
	}
	if (!real)
		real = dlsym(RTLD_NEXT, "scandir");
	return real(dir, namelist, sel, cmp);
}

int access(const char *path, int mode)
{
	static int (*real)(const char *, int);

	if (!strcmp(path, ISCSI_DB_ROOT))
		return 0;
	if (!real)
		real = dlsym(RTLD_NEXT, "access");
	return real(path, mode);
}

int getaddrinfo(const char *node, const char *service,
		const struct addrinfo *hints, struct addrinfo **res)
{
	static int (*real)(const char *, const char *, const struct addrinfo *,
			   struct addrinfo **);
	struct addrinfo h;

	if (!real)
		real = dlsym(RTLD_NEXT, "getaddrinfo");
	memset(&h, 0, sizeof(h));
	if (hints)
		h = *hints;
	h.ai_flags |= AI_NUMERICHOST;
	return real(node, service, &h, res);
}

static int discovery_env_init(void)
{
	static struct iscsi_transport tcp;

	if (idbm_init(NULL))
		return -1;
	INIT_LIST_HEAD(&tcp.list);
	INIT_LIST_HEAD(&tcp.sessions);
	strcpy(tcp.name, "tcp");
	if (set_transport_template(&tcp))
		return -1;
	tcp.handle = 1;
	tcp.caps = CAP_RECOVERY_L0 | CAP_MULTI_R2T | CAP_HDRDGST | CAP_DATADGST |
		   CAP_MULTI_CONN | CAP_MARKERS;
	list_add_tail(&tcp.list, &transports);
	return 0;
}

/*
 * sel bits 0-1: CHAP off / one-way / mutual. Appends the node records discovery found to
 * rec_list (the caller frees them). If sent is not NULL, the bytes the initiator wrote to the
 * target are copied to it (up to sent_size) and the length is returned in *sent_len.
 */
static int discovery_env_run(const uint8_t *stream, size_t len, int sel,
			     struct list_head *rec_list, char *sent,
			     size_t sent_size, size_t *sent_len)
{
	static struct discovery_rec drec;
	static struct iface_rec iface;
	struct iscsi_sendtargets_config *cfg = &drec.u.sendtargets;
	int sv[2], rc, sndbuf = 1 << 20;
	ssize_t n;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv))
		return -1;
	/* room for every request the initiator can send before it has read the whole stream */
	setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
	if (len && write(sv[1], stream, len) != (ssize_t)len) {
		close(sv[0]);
		close(sv[1]);
		return -1;
	}
	shutdown(sv[1], SHUT_WR);
	env_peer_fd = sv[0];

	memset(&drec, 0, sizeof(drec));
	drec.type = DISCOVERY_TYPE_SENDTARGETS;
	strcpy(drec.address, "127.0.0.1");
	drec.port = ISCSI_LISTEN_PORT;
	idbm_sendtargets_defaults(cfg);
	cfg->reopen_max = 0;
	cfg->conn_timeo.login_timeout = 60;
	cfg->conn_timeo.auth_timeout = 60;
	cfg->conn_timeo.active_timeout = 1;
	cfg->auth.chap_algs[0] = AUTH_CHAP_ALG_MD5;
	cfg->auth.chap_algs[1] = AUTH_CHAP_ALG_SHA1;
	cfg->auth.chap_algs[2] = AUTH_CHAP_ALG_SHA256;
	cfg->auth.chap_algs[3] = AUTH_CHAP_ALG_SHA3_256;
	cfg->auth.authmethod = ISCSI_AUTH_METHOD_NONE;
	if ((sel & 3) == 1 || (sel & 3) == 2) {
		cfg->auth.authmethod = ISCSI_AUTH_METHOD_CHAP;
		strcpy(cfg->auth.username, "initiator-user");
		memcpy(cfg->auth.password, "secret-password", 15);
		cfg->auth.password_length = 15;
		if ((sel & 3) == 2) {
			strcpy(cfg->auth.username_in, "target-user");
			memcpy(cfg->auth.password_in, "target-secret-pw", 16);
			cfg->auth.password_in_length = 16;
		}
	}

	memset(&iface, 0, sizeof(iface));
	strcpy(iface.transport_name, "tcp");
	strcpy(iface.iname, "iqn.2004-10.org.example:fuzz");

	rc = discovery_sendtargets(&drec, &iface, rec_list);

	if (env_peer_fd >= 0) {
		close(env_peer_fd);
		env_peer_fd = -1;
	}
	if (sent_len)
		*sent_len = 0;
	if (sent) {
		fcntl(sv[1], F_SETFL, O_NONBLOCK);
		n = read(sv[1], sent, sent_size);
		if (sent_len && n > 0)
			*sent_len = n;
	}
	close(sv[1]);
	return rc;
}

static void discovery_env_free_records(struct list_head *rec_list)
{
	struct node_rec *rec, *tmp;

	list_for_each_entry_safe(rec, tmp, rec_list, list) {
		list_del(&rec->list);
		free(rec);
	}
}
#endif
