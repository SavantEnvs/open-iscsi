/*
 * libFuzzer harness for open-iscsi's record/config file parser, the format of
 * /etc/iscsi/iscsid.conf, nodes/<target>/<portal>/<iface> and ifaces/<name>
 * (idbm_recinfo_config() filling an idbm_recinfo_node()/idbm_recinfo_iface() table),
 * followed by the printers that render the parsed record back out.
 *
 * Input: byte 0 selects node or iface record, the rest is the file's text.
 */
#define _GNU_SOURCE
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "iface.h"
#include "idbm.h"
#include "log.h"

static void quiet_log(int prio, void *priv, const char *fmt, va_list ap)
{
	char buf[1024];

	vsnprintf(buf, sizeof(buf), fmt, ap);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	log_init("fuzz_idbm_record", 0, quiet_log, NULL);
	log_level = 0;
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static node_rec_t node;
	static struct iface_rec iface;
	recinfo_t *info;
	FILE *in, *out;
	char *outbuf = NULL;
	size_t outlen = 0;
	int kind;

	if (size < 2)
		return -1;
	kind = data[0] & 1;

	info = idbm_recinfo_alloc(MAX_KEYS);
	if (!info)
		return -1;
	in = fmemopen((void *)(data + 1), size - 1, "r");
	out = open_memstream(&outbuf, &outlen);
	if (!in || !out) {
		if (in)
			fclose(in);
		if (out)
			fclose(out);
		free(outbuf);
		free(info);
		return -1;
	}

	if (kind == 0) {
		memset(&node, 0, sizeof(node));
		idbm_node_setup_defaults(&node);
		idbm_recinfo_node(&node, info);
		idbm_recinfo_config(info, in);
		idbm_print(IDBM_PRINT_TYPE_NODE, &node, 1, out);
	} else {
		memset(&iface, 0, sizeof(iface));
		iface_setup_defaults(&iface);
		idbm_recinfo_iface(&iface, info);
		idbm_recinfo_config(info, in);
		idbm_print(IDBM_PRINT_TYPE_IFACE, &iface, 1, out);
	}

	fclose(in);
	fclose(out);
	free(outbuf);
	free(info);
	return 0;
}
