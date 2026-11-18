/*
 * libFuzzer harness for the iSCSI initiator's login exchange. The bytes a target
 * would send (Login Response PDUs: header, text keys, CHAP challenge, redirect
 * TargetAddress, ...) are placed on a socketpair and the real iscsi_login() runs
 * against them: iscsi_io_recv_pdu(), iscsi_process_login_response(), the
 * security / operational key parsers and the CHAP client (auth.c, chap.c).
 *
 * Input: byte 0 selects the session config, the rest is the target's byte stream.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "config.h"
#include "idbm.h"
#include "initiator.h"
#include "iscsi_proto.h"
#include "iscsi_settings.h"
#include "log.h"
#include "transport.h"

#define FUZZ_MAX_STREAM (96 * 1024)
#define LOGIN_BUFSIZE 8192

/* No DNS: a redirect TargetAddress must resolve the same way on every run. */
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

static void quiet_log(int prio, void *priv, const char *fmt, va_list ap)
{
	char buf[1024];

	vsnprintf(buf, sizeof(buf), fmt, ap);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	log_init("fuzz_iscsi_login", 0, quiet_log, NULL);
	log_level = 0;
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static struct iscsi_transport_template tmpl;
	static struct iscsi_transport transport;
	static char buffer[LOGIN_BUFSIZE];
	static char target[] = "iqn.2001-04.com.example:storage.disk1";
	static char initiator[] = "iqn.2004-10.org.example:fuzz";
	struct iscsi_session *session;
	struct node_rec rec;
	struct iscsi_conn *conn;
	uint8_t status_class = 0, status_detail = 0;
	int sv[2], sel;
	size_t len;

	if (size < 1)
		return -1;
	sel = data[0];
	data++;
	size--;
	len = size > FUZZ_MAX_STREAM ? FUZZ_MAX_STREAM : size;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv))
		return -1;

	session = calloc(1, sizeof(*session));
	if (!session) {
		close(sv[0]);
		close(sv[1]);
		return -1;
	}

	idbm_node_setup_defaults(&rec);
	switch (sel & 3) {
	case 1:
	case 2:
		rec.session.auth.authmethod = ISCSI_AUTH_METHOD_CHAP;
		strcpy(rec.session.auth.username, "initiator-user");
		memcpy(rec.session.auth.password, "secret-password", 15);
		rec.session.auth.password_length = 15;
		if ((sel & 3) == 2) {
			strcpy(rec.session.auth.username_in, "target-user");
			memcpy(rec.session.auth.password_in, "target-secret-pw", 16);
			rec.session.auth.password_in_length = 16;
		}
		break;
	}
	rec.session.auth.chap_algs[0] = AUTH_CHAP_ALG_MD5;
	rec.session.auth.chap_algs[1] = AUTH_CHAP_ALG_SHA1;
	rec.session.auth.chap_algs[2] = AUTH_CHAP_ALG_SHA256;
	rec.session.auth.chap_algs[3] = AUTH_CHAP_ALG_SHA3_256;
	rec.conn[0].timeo.login_timeout = 60;
	rec.conn[0].timeo.auth_timeout = 60;
	rec.conn[0].timeo.active_timeout = 5;
	if (sel & 4) {
		rec.conn[0].iscsi.HeaderDigest = CONFIG_DIGEST_PREFER_ON;
		rec.conn[0].iscsi.DataDigest = CONFIG_DIGEST_PREFER_ON;
	}

	tmpl.rdma = (sel >> 3) & 1;
	transport.template = &tmpl;
	snprintf(transport.name, sizeof(transport.name), "tcp");

	INIT_LIST_HEAD(&session->list);
	session->t = &transport;
	session->type = (sel & 0x10) ? ISCSI_SESSION_TYPE_NORMAL :
				       ISCSI_SESSION_TYPE_DISCOVERY;
	session->use_ipc = 0;
	session->id = 1;
	session->initiator_name = initiator;
	session->initiator_alias = "fuzz";
	if (sel & 0x10)
		strcpy(session->target_name, target);
	session->portal_group_tag = 1;
	session->isid[0] = DRIVER_ISID_0;
	session->isid[1] = DRIVER_ISID_1;
	session->isid[2] = DRIVER_ISID_2;
	session->reopen_cnt = 1;
	session->sess_reopen_log_freq = DEF_SESSION_REOPEN_LOG_FREQ;
	if (sel & 0x10)
		iscsi_session_init_params(session);

	conn = &session->conn[0];
	conn->id = 0;
	conn->session = session;
	conn->socket_fd = sv[0];
	conn->login_timeout = rec.conn[0].timeo.login_timeout;
	conn->auth_timeout = rec.conn[0].timeo.auth_timeout;
	conn->active_timeout = rec.conn[0].timeo.active_timeout;
	iscsi_copy_operational_params(conn, &rec.session.iscsi, &rec.conn[0].iscsi);

	if (iscsi_setup_authentication(session, &rec.session.auth) == 0) {
		/* the whole stream is already queued; EOF ends the exchange */
		if (write(sv[1], data, len) == (ssize_t)len) {
			shutdown(sv[1], SHUT_WR);
			iscsi_login(session, 0, buffer, sizeof(buffer),
				    &status_class, &status_detail);
		}
	}

	close(sv[0]);
	close(sv[1]);
	free(session->target_alias);
	free(session);
	return 0;
}
