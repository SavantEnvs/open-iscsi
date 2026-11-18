/*
 * Known-answer probe for the test oracle (mayhem/test.sh). Built with the project's
 * normal flags and linked against the real usr/ and libopeniscsiusr code. Every check
 * asserts a concrete value derived from a known input.
 */
#define _GNU_SOURCE
#include <netdb.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "config.h"
#include "iface.h"
#include "idbm.h"
#include "initiator.h"
#include "iscsi_proto.h"
#include "iscsi_settings.h"
#include "log.h"
#include "transport.h"
#include "discovery_env.h"

static int passed, failed;

#define CHECK(name, cond)                                                  \
	do {                                                               \
		if (cond) {                                                \
			passed++;                                          \
			printf("ok   %s\n", name);                         \
		} else {                                                   \
			failed++;                                          \
			printf("FAIL %s (%s:%d)\n", name, __FILE__, __LINE__); \
		}                                                          \
	} while (0)

static void quiet_log(int prio, void *priv, const char *fmt, va_list ap) {}

static void put_pdu(char **p, int csg, int nsg, int transit, const char *text, int tlen)
{
	unsigned char *h = (unsigned char *)*p;

	memset(h, 0, 48);
	h[0] = 0x23;
	h[1] = (transit ? 0x80 : 0) | (csg << 2) | nsg;
	h[5] = (tlen >> 16) & 0xff;
	h[6] = (tlen >> 8) & 0xff;
	h[7] = tlen & 0xff;
	h[8] = 0;
	h[9] = 2;
	h[10] = 0x3D;
	h[28] = 0;
	h[29] = 0;
	h[30] = 0;
	h[31] = 1;
	h[32] = 0;
	h[33] = 0;
	h[34] = 0;
	h[35] = 1;
	memcpy(h + 48, text, tlen);
	*p += 48 + ((tlen + 3) & ~3);
	memset(*p - ((tlen + 3) & ~3) + tlen, 0, ((tlen + 3) & ~3) - tlen);
}

static struct iscsi_session *new_session(int fd, int chap, int normal, struct node_rec *rec)
{
	static struct iscsi_transport_template tmpl;
	static struct iscsi_transport transport;
	static char target[] = "iqn.2001-04.com.example:storage.disk1";
	static char initiator[] = "iqn.2004-10.org.example:probe";
	struct iscsi_session *s = calloc(1, sizeof(*s));
	struct iscsi_conn *conn;

	idbm_node_setup_defaults(rec);
	if (chap) {
		rec->session.auth.authmethod = ISCSI_AUTH_METHOD_CHAP;
		strcpy(rec->session.auth.username, "initiator-user");
		memcpy(rec->session.auth.password, "secret-password", 15);
		rec->session.auth.password_length = 15;
	}
	rec->session.auth.chap_algs[0] = AUTH_CHAP_ALG_MD5;
	transport.template = &tmpl;
	INIT_LIST_HEAD(&s->list);
	s->t = &transport;
	s->type = normal ? ISCSI_SESSION_TYPE_NORMAL : ISCSI_SESSION_TYPE_DISCOVERY;
	s->id = 1;
	s->initiator_name = initiator;
	s->initiator_alias = "probe";
	if (normal)
		strcpy(s->target_name, target);
	s->portal_group_tag = 1;
	s->reopen_cnt = 1;
	s->sess_reopen_log_freq = DEF_SESSION_REOPEN_LOG_FREQ;
	conn = &s->conn[0];
	conn->session = s;
	conn->socket_fd = fd;
	conn->login_timeout = 60;
	conn->auth_timeout = 60;
	conn->active_timeout = 5;
	iscsi_copy_operational_params(conn, &rec->session.iscsi, &rec->conn[0].iscsi);
	if (iscsi_setup_authentication(s, &rec->session.auth))
		return NULL;
	return s;
}

static void kat_record(void)
{
	static const char text[] =
		"# BEGIN RECORD 2.1.13\n"
		"node.name = iqn.2001-04.com.example:storage.disk1\n"
		"node.tpgt = 7\n"
		"node.startup = automatic\n"
		"node.session.auth.authmethod = CHAP\n"
		"node.session.auth.username = alice\n"
		"node.session.iscsi.FirstBurstLength = 131072\n"
		"node.conn[0].address = 192.168.7.9\n"
		"node.conn[0].port = 3261\n"
		"# END RECORD\n";
	static node_rec_t node;
	recinfo_t *info = idbm_recinfo_alloc(MAX_KEYS);
	char *out = NULL;
	size_t outlen = 0;
	FILE *in = fmemopen((void *)text, sizeof(text) - 1, "r");
	FILE *f = open_memstream(&out, &outlen);

	memset(&node, 0, sizeof(node));
	idbm_node_setup_defaults(&node);
	idbm_recinfo_node(&node, info);
	idbm_recinfo_config(info, in);
	CHECK("record: node.name", !strcmp(node.name, "iqn.2001-04.com.example:storage.disk1"));
	CHECK("record: node.tpgt", node.tpgt == 7);
	CHECK("record: address", !strcmp(node.conn[0].address, "192.168.7.9"));
	CHECK("record: port", node.conn[0].port == 3261);
	CHECK("record: username", !strcmp(node.session.auth.username, "alice"));
	CHECK("record: authmethod", node.session.auth.authmethod == ISCSI_AUTH_METHOD_CHAP);
	CHECK("record: FirstBurstLength", node.session.iscsi.FirstBurstLength == 131072);
	idbm_print(IDBM_PRINT_TYPE_NODE, &node, 1, f);
	fclose(f);
	CHECK("record: print startup", out && strstr(out, "node.startup = automatic\n"));
	CHECK("record: print port", out && strstr(out, "node.conn[0].port = 3261\n"));
	fclose(in);
	free(out);
	free(info);
}

static void kat_login(void)
{
	static const char ops[] =
		"HeaderDigest=None\0DataDigest=None\0MaxRecvDataSegmentLength=4096";
	static struct node_rec rec;
	char buf[8192], rsp[4096], *p = rsp;
	struct iscsi_session *s;
	uint8_t cls = 99, det = 99;
	int sv[2];
	ssize_t n;

	socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
	s = new_session(sv[0], 0, 0, &rec);
	put_pdu(&p, 1, 3, 1, ops, sizeof(ops));
	write(sv[1], rsp, p - rsp);
	shutdown(sv[1], SHUT_WR);
	CHECK("login: discovery completes", iscsi_login(s, 0, buf, sizeof(buf), &cls, &det) == LOGIN_OK);
	CHECK("login: status class success", cls == 0 && det == 0);
	CHECK("login: reached full feature phase", s->conn[0].current_stage == 3);
	CHECK("login: target MaxRecvDataSegmentLength applied", s->conn[0].max_xmit_dlength == 4096);
	n = read(sv[1], rsp, sizeof(rsp));
	CHECK("login: request names initiator",
	      n > 48 && memmem(rsp, n, "InitiatorName=iqn.2004-10.org.example:probe", 43));
	CHECK("login: request is a discovery session", n > 48 && memmem(rsp, n, "SessionType=Discovery", 21));
	close(sv[0]);
	close(sv[1]);
	free(s);
}

static void kat_chap(void)
{
	static const char alg[] = "AuthMethod=CHAP";
	static char chal[256];
	static struct node_rec rec;
	char buf[8192], rsp[4096], out[8192], *p = rsp;
	struct iscsi_session *s;
	int sv[2], clen;
	ssize_t n;
	char *r;

	socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
	s = new_session(sv[0], 1, 1, &rec);
	put_pdu(&p, 0, 0, 0, alg, sizeof(alg));
	clen = snprintf(chal, sizeof(chal), "CHAP_A=5%cCHAP_I=77%cCHAP_C=0x%s", 0, 0,
			"abababababababababababababababab") + 1;
	put_pdu(&p, 0, 0, 0, chal, clen);
	write(sv[1], rsp, p - rsp);
	shutdown(sv[1], SHUT_WR);
	iscsi_login(s, 0, buf, sizeof(buf), NULL, NULL);
	n = read(sv[1], out, sizeof(out) - 1);
	out[n > 0 ? n : 0] = 0;
	CHECK("chap: initiator offers algorithm", n > 0 && memmem(out, n, "CHAP_A=5", 8));
	r = n > 0 ? memmem(out, n, "CHAP_R=0x", 9) : NULL;
	CHECK("chap: MD5 response for id 77 / known challenge",
	      r && !strncasecmp(r + 9, "c3e903cb3cf706929e6ec272adc169b2", 32));
	CHECK("chap: username sent", n > 0 && memmem(out, n, "CHAP_N=initiator-user", 21));
	close(sv[0]);
	close(sv[1]);
	free(s);
}

static void put_text(char **p, int final, uint32_t ttt, const char *text, int tlen)
{
	unsigned char *h = (unsigned char *)*p;
	int padded = (tlen + 3) & ~3;

	memset(h, 0, 48 + padded);
	h[0] = 0x24;
	h[1] = final ? 0x80 : 0;
	h[5] = (tlen >> 16) & 0xff;
	h[6] = (tlen >> 8) & 0xff;
	h[7] = tlen & 0xff;
	h[20] = ttt >> 24;
	h[21] = ttt >> 16;
	h[22] = ttt >> 8;
	h[23] = ttt;
	h[31] = 2;
	h[35] = 2;
	h[39] = 2;
	memcpy(h + 48, text, tlen);
	*p += 48 + padded;
}

static struct node_rec *nth_record(struct list_head *list, int n)
{
	struct node_rec *rec;

	list_for_each_entry(rec, list, list)
		if (n-- == 0)
			return rec;
	return NULL;
}

static int count_records(struct list_head *list)
{
	struct node_rec *rec;
	int n = 0;

	list_for_each_entry(rec, list, list)
		n++;
	return n;
}

static void kat_sendtargets(void)
{
	static const char ops[] =
		"HeaderDigest=None\0DataDigest=None\0MaxRecvDataSegmentLength=4096";
	static const char whole[] =
		"TargetName=iqn.2001-04.com.example:storage.disk1\0TargetAddress=10.1.2.3:3261,2\0"
		"TargetName=iqn.2001-04.com.example:storage.disk2\0TargetAddress=[::1]:3262,5";
	static const char part1[] =
		"TargetName=iqn.2001-04.com.example:storage.disk1\0TargetAddress=10.1.2.3:3261,2\0"
		"TargetName=iqn.2001-04.com.example:stor";
	static const char part2[] = "age.disk2\0TargetAddress=192.0.2.9,7";
	char stream[4096], sent[4096], *p = stream;
	struct list_head recs;
	struct node_rec *r;
	size_t sent_len;
	int rc;

	INIT_LIST_HEAD(&recs);
	put_pdu(&p, 1, 3, 1, ops, sizeof(ops));
	put_text(&p, 1, 0xffffffff, whole, sizeof(whole));
	rc = discovery_env_run((uint8_t *)stream, p - stream, 0, &recs, sent, sizeof(sent), &sent_len);
	CHECK("sendtargets: discovery completes", rc == 0);
	CHECK("sendtargets: two records", count_records(&recs) == 2);
	r = nth_record(&recs, 0);
	CHECK("sendtargets: first target name",
	      r && !strcmp(r->name, "iqn.2001-04.com.example:storage.disk1"));
	CHECK("sendtargets: first portal", r && !strcmp(r->conn[0].address, "10.1.2.3") &&
	      r->conn[0].port == 3261 && r->tpgt == 2);
	CHECK("sendtargets: first record remembers the discovery portal",
	      r && !strcmp(r->disc_address, "127.0.0.1") && r->disc_port == 3260);
	r = nth_record(&recs, 1);
	CHECK("sendtargets: second target name",
	      r && !strcmp(r->name, "iqn.2001-04.com.example:storage.disk2"));
	CHECK("sendtargets: IPv6 portal", r && !strcmp(r->conn[0].address, "::1") &&
	      r->conn[0].port == 3262 && r->tpgt == 5);
	CHECK("sendtargets: request asks for all targets", memmem(sent, sent_len, "SendTargets=All", 15) != NULL);
	discovery_env_free_records(&recs);

	INIT_LIST_HEAD(&recs);
	p = stream;
	put_pdu(&p, 1, 3, 1, ops, sizeof(ops));
	put_text(&p, 0, 0x1234, part1, sizeof(part1) - 1);
	put_text(&p, 1, 0xffffffff, part2, sizeof(part2));
	rc = discovery_env_run((uint8_t *)stream, p - stream, 0, &recs, NULL, 0, NULL);
	CHECK("sendtargets: multi-PDU answer completes", rc == 0);
	CHECK("sendtargets: multi-PDU answer gives two records", count_records(&recs) == 2);
	r = nth_record(&recs, 1);
	CHECK("sendtargets: target name split across PDUs is rejoined",
	      r && !strcmp(r->name, "iqn.2001-04.com.example:storage.disk2"));
	CHECK("sendtargets: address after the split", r && !strcmp(r->conn[0].address, "192.0.2.9") &&
	      r->conn[0].port == 3260 && r->tpgt == 7);
	discovery_env_free_records(&recs);
}

int main(void)
{
	log_init("oracle_probe", 0, quiet_log, NULL);
	if (discovery_env_init()) {
		printf("FAIL discovery environment setup\n");
		return 1;
	}
	kat_record();
	kat_login();
	kat_chap();
	kat_sendtargets();
	printf("PROBE passed=%d failed=%d\n", passed, failed);
	return failed ? 1 : 0;
}
