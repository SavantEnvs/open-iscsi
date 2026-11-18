/*
 * libFuzzer harness for iscsiadm's SendTargets discovery. The bytes a remote target would
 * send (Login Response PDUs, then Text Response PDUs carrying TargetName=/TargetAddress=
 * lists, possibly split over several PDUs) are queued on a socketpair and the real
 * discovery_sendtargets() runs against them: iscsi_login(), iscsi_io_recv_pdu(),
 * process_recvd_pdu(), process_sendtargets_response(), add_target_record() and add_portal().
 *
 * Input: byte 0 selects the login auth config, the rest is the target's byte stream.
 */
#include <stdio.h>
#include <stdarg.h>

#include "discovery_env.h"
#include "log.h"

/* One request is queued per non-final Text Response; a socketpair holds only a few hundred such small writes. */
#define FUZZ_MAX_STREAM 8192

static void quiet_log(int prio, void *priv, const char *fmt, va_list ap)
{
	char buf[1024];

	vsnprintf(buf, sizeof(buf), fmt, ap);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	log_init("fuzz_sendtargets", 0, quiet_log, NULL);
	log_level = 0;
	if (discovery_env_init()) {
		fprintf(stderr, "fuzz_sendtargets: environment setup failed\n");
		abort();
	}
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct list_head rec_list;
	size_t len;

	if (size < 1)
		return -1;
	len = size - 1 > FUZZ_MAX_STREAM ? FUZZ_MAX_STREAM : size - 1;

	INIT_LIST_HEAD(&rec_list);
	discovery_env_run(data + 1, len, data[0], &rec_list, NULL, 0, NULL);
	discovery_env_free_records(&rec_list);
	return 0;
}
