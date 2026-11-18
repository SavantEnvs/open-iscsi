#!/usr/bin/env bash
#
# mayhem/build.sh — builds open-iscsi's initiator library (usr/, libopeniscsiusr/, sysdeps/) and the
# iscsiuio network stack with sanitizers for the fuzz targets (+ standalone reproducers), and
# the same usr/ code with normal flags for the test oracle (mayhem/oracle_probe.c).
#
# usr/ and its harnesses are compiled with -D__compiler_offsetof=__builtin_offsetof: include/list.h only uses the builtin when
# that macro is defined, and otherwise spells offsetof as &((T *)0)->m, which UBSan reports ("member access
# within null pointer") on every list_for_each_entry(). No sanitizer check is relaxed for it.
#
# UBSan checks relaxed in usr/discovery.c only: pointer-overflow, nonnull-attribute. process_recvd_pdu() computes
# str_buffer_data(buf) + curr_data_length for a memcpy of a Text Response's data, and a zero-length first
# Text Response reaches it with a NULL buffer and a zero offset (NULL + 0, then a zero-byte memcpy to NULL). That is
# benign, and halting on it would end every run on the shortest input before the parser is exercised.
#
# UBSan checks relaxed, all in iscsiuio only (the rest of usr/ runs with full UBSan):
#   alignment        - the uIP stack casts Ethernet frame buffers (14-byte header) to struct pointers
#   pointer-overflow - iscsiuio/src/unix/nic.c only: prepare_ipv{4,6}_packet() adds a header offset to a
#                      NULL data_link_layer pointer on its timer-driven path
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${AR:=ar}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

SRC="${SRC:-/mayhem}"
cd "$SRC"
B="$SRC/mayhem/build"
mkdir -p "$B/fuzz/usr" "$B/fuzz/lib" "$B/fuzz/uio" "$B/normal/usr" "$B/normal/lib" "$B/utest/lib"

# Quoted -D values live in a response file so they survive xargs/sh.
cat > "$B/defs.rsp" <<'DEFS'
'-DISCSI_CONFIG_ROOT="/etc/iscsi"'
'-DISCSI_DB_ROOT="/var/lib/iscsi"'
'-DLOCK_DIR="/run/lock/iscsi"'
'-DISCSI_VERSION_STR="2.1.13"'
'-DISCSI_NAME_PREFIX="iqn.2016-04.com.open-iscsi"'
'-DPACKAGE_VERSION="0.7.8.8"'
DEFS
# upstream's libopeniscsiusr tests (libopeniscsiusr/tests/test_*.c) run as the non-root mayhem user, so their
# copy of the library keeps its idbm root and lock dir in the build tree; mayhem/test.sh recreates $B/utest-db.
sed -e "s|/var/lib/iscsi|$B/utest-db|" -e "s|/run/lock/iscsi|$B/utest-db/lock|" "$B/defs.rsp" > "$B/utest-defs.rsp"
COMMON="-D_GNU_SOURCE -DNO_SYSTEMD -DSHA3_256_SUPPORTED @$B/defs.rsp -w"
USR_INC="-Iinclude -Iusr -Ilibopeniscsiusr -D__compiler_offsetof=__builtin_offsetof"
U=iscsiuio/src
UIO_INC="-I$U/uip -I$U/unix -I$U/apps/dhcpc -I$U/apps/brcm-iscsi -I$U/unix/libs -Iinclude -Iusr -I$B/fuzz/uio"

USR_SRCS="discovery local_strings iscsi_util io auth iscsi_timer login log iface idbm sysfs host session_info iscsi_sysfs iscsi_net_util iscsid_req transport iser cxgbi be2iscsi initiator_common iscsi_err flashnode uip_mgmt_ipc netlink"
LIB_SRCS="context misc session sysfs iface idbm node default"
FW_SRCS="fw_entry fwparam_ppc fwparam_sysfs prom_lex prom_parse.tab"
UIO_SRCS="unix/clock-arch unix/logger unix/nic unix/nic_id unix/nic_vlan unix/nic_nl unix/nic_utils unix/packet unix/iscsid_ipc unix/ping uip/uip uip/uip_arp uip/psock uip/timer uip/uip-neighbor uip/uip_eth uip/ipv6_ndpc uip/ipv6 apps/dhcpc/dhcpc apps/dhcpc/dhcpv6 apps/brcm-iscsi/brcm_iscsi unix/libs/bnx2 unix/libs/bnx2x unix/libs/cnic unix/libs/qedi"

bash "$U/unix/build_date.sh" -c "$B/fuzz/uio/build_date.c" -i "$B/fuzz/uio/build_date.h"

CMDS="$B/cmds.txt"
: > "$CMDS"
# <flags> <outdir>: one compile command per usr/, libopeniscsiusr/, sysdeps/ and fwparam source
queue_usr() {
	local flags="$1" out="$2" s
	for s in $USR_SRCS; do
		x=""
		case $s in discovery) x="-fno-sanitize=pointer-overflow,nonnull-attribute" ;; esac
		echo "$CC $flags $x -c usr/$s.c -o $out/usr/$s.o" >> "$CMDS"
	done
	for s in $LIB_SRCS; do echo "$CC $flags -c libopeniscsiusr/$s.c -o $out/lib/$s.o" >> "$CMDS"; done
	echo "$CC $flags -c sysdeps/sysdeps.c -o $out/sysdeps.o" >> "$CMDS"
	for s in $FW_SRCS; do echo "$CC $flags -c usr/fwparam_ibft/$s.c -o $out/fw_$s.o" >> "$CMDS"; done
}

FUZZ_CF="$SANITIZER_FLAGS $DEBUG_FLAGS -O1 -fsanitize=fuzzer-no-link $COMMON"
queue_usr "$FUZZ_CF $USR_INC" "$B/fuzz"
for s in $UIO_SRCS; do
	x=""
	case $s in unix/nic) x="-fno-sanitize=pointer-overflow" ;; esac
	echo "$CC $FUZZ_CF -fno-sanitize=alignment $x $UIO_INC -c $U/$s.c -o $B/fuzz/uio/$(basename "$s").o" >> "$CMDS"
done
echo "$CC $FUZZ_CF -fno-sanitize=alignment $UIO_INC -c $B/fuzz/uio/build_date.c -o $B/fuzz/uio/build_date.o" >> "$CMDS"
echo "$CC $FUZZ_CF -fno-sanitize=alignment $UIO_INC -Dmain=iscsiuio_main -c $U/unix/main.c -o $B/fuzz/uio/main.o" >> "$CMDS"
for h in fuzz_iscsi_login fuzz_idbm_record fuzz_sendtargets; do
	echo "$CC $FUZZ_CF $USR_INC -c mayhem/$h.c -o $B/fuzz/$h.o" >> "$CMDS"
done
echo "$CC $FUZZ_CF -fno-sanitize=alignment $UIO_INC -c mayhem/fuzz_uip_packet.c -o $B/fuzz/fuzz_uip_packet.o" >> "$CMDS"
echo "$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o $B/fuzz/lsan_off.o" >> "$CMDS"

# normal-flags build for the test oracle, independent of the sanitized one
NORM_CF="-O1 $COVERAGE_FLAGS $COMMON"
queue_usr "$NORM_CF $USR_INC" "$B/normal"
echo "$CC $NORM_CF $USR_INC -c mayhem/oracle_probe.c -o $B/normal/oracle_probe.o" >> "$CMDS"
# upstream's test suite: LIB_SRCS again with the build-tree idbm root (asserts stay on: no -DNDEBUG anywhere)
UTEST_CF="-O1 $COVERAGE_FLAGS ${COMMON/@$B\/defs.rsp/@$B/utest-defs.rsp} -Iinclude -Ilibopeniscsiusr"
UTESTS="context iface node session"
for s in $LIB_SRCS; do echo "$CC $UTEST_CF -c libopeniscsiusr/$s.c -o $B/utest/lib/$s.o" >> "$CMDS"; done
for t in $UTESTS; do echo "$CC $UTEST_CF -c libopeniscsiusr/tests/test_$t.c -o $B/utest/test_$t.o" >> "$CMDS"; done

xargs -P "$MAYHEM_JOBS" -I{} sh -c '{}' < "$CMDS"

rm -f "$B/fuzz/libusr.a" "$B/fuzz/libuio.a" "$B/normal/libusr.a"
"$AR" rcs "$B/fuzz/libusr.a" "$B"/fuzz/usr/*.o "$B"/fuzz/lib/*.o "$B/fuzz/sysdeps.o" "$B"/fuzz/fw_*.o
"$AR" rcs "$B/fuzz/libuio.a" "$B"/fuzz/uio/*.o
"$AR" rcs "$B/normal/libusr.a" "$B"/normal/usr/*.o "$B"/normal/lib/*.o "$B/normal/sysdeps.o" "$B"/normal/fw_*.o

USR_LIBS="-lcrypto -lkmod -lmount -lrt -lpthread -lm"
UIO_LIBS="-lpthread -ldl -lm"

link_target() { # <name> <archive> <extra libs>
	local name="$1" lib="$2" libs="$3"
	$CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$B/fuzz/$name.o" "$B/fuzz/lsan_off.o" "$lib" $libs -o "/mayhem/$name"
	$CC $SANITIZER_FLAGS $DEBUG_FLAGS "$STANDALONE_FUZZ_MAIN" "$B/fuzz/$name.o" "$B/fuzz/lsan_off.o" "$lib" $libs -o "/mayhem/$name-standalone"
}
link_target fuzz_iscsi_login "$B/fuzz/libusr.a" "$USR_LIBS"
link_target fuzz_idbm_record "$B/fuzz/libusr.a" "$USR_LIBS"
link_target fuzz_sendtargets "$B/fuzz/libusr.a" "$USR_LIBS"
link_target fuzz_uip_packet "$B/fuzz/libuio.a" "$UIO_LIBS"

# test oracle: dynamically linked, normal flags
$CC $COVERAGE_FLAGS "$B/normal/oracle_probe.o" "$B/normal/libusr.a" $USR_LIBS -o "$B/oracle_probe"
rm -f "$B/utest/libopeniscsiusr.a"
"$AR" rcs "$B/utest/libopeniscsiusr.a" "$B"/utest/lib/*.o
for t in $UTESTS; do
	$CC $COVERAGE_FLAGS "$B/utest/test_$t.o" "$B/utest/libopeniscsiusr.a" -lkmod -o "$B/test_$t"
done
