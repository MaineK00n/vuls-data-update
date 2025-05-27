package diff_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/diff"
	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/util"
)

func TestDiff(t *testing.T) {
	type args struct {
		minus string
		plus  string
	}
	tests := []struct {
		name     string
		dotgit   string
		args     args
		want     string
		hasError bool
	}{
		{
			name:   "9/rhel-9-including-unpatched/definitions/oval:com.redhat.cve:def:202426815.json",
			dotgit: "testdata/fixtures/vuls-data-raw-redhat-ovalv2.tar.zst",
			args: args{
				minus: "63a30ff24dea0d2198c1e3160c33b52df66970a4:9/rhel-9-including-unpatched/definitions/oval:com.redhat.cve:def:202426815.json",
				plus:  "main:9/rhel-9-including-unpatched/definitions/oval:com.redhat.cve:def:202426815.json",
			},
			want: `diff --git a/9/rhel-9-including-unpatched/definitions/oval:com.redhat.cve:def:202426815.json b/9/rhel-9-including-unpatched/definitions/oval:com.redhat.cve:def:202426815.json
index 321cb11fd6d4a6ddd6f6d2209828a70b1777475e..11d5d7549484e47231829a01eadd9cdb66458174 100644
--- a/9/rhel-9-including-unpatched/definitions/oval:com.redhat.cve:def:202426815.json
+++ b/9/rhel-9-including-unpatched/definitions/oval:com.redhat.cve:def:202426815.json
@@ -11,12 +11,12 @@ 				"ref_url": "https://access.redhat.com/security/cve/CVE-2024-26815",
 				"source": "CVE"
 			}
 		],
-		"description": "DOCUMENTATION: The MITRE CVE dictionary describes this issue as: In the Linux kernel, the following vulnerability has been resolved:\n\nnet/sched: taprio: proper TCA_TAPRIO_TC_ENTRY_INDEX check\n\ntaprio_parse_tc_entry() is not correctly checking\nTCA_TAPRIO_TC_ENTRY_INDEX attribute:\n\n\tint tc; // Signed value\n\n\ttc = nla_get_u32(tb[TCA_TAPRIO_TC_ENTRY_INDEX]);\n\tif (tc >= TC_QOPT_MAX_QUEUE) {\n\t\tNL_SET_ERR_MSG_MOD(extack, \"TC entry index out of range\");\n\t\treturn -ERANGE;\n\t}\n\nsyzbot reported that it could fed arbitary negative values:\n\nUBSAN: shift-out-of-bounds in net/sched/sch_taprio.c:1722:18\nshift exponent -2147418108 is negative\nCPU: 0 PID: 5066 Comm: syz-executor367 Not tainted 6.8.0-rc7-syzkaller-00136-gc8a5c731fd12 #0\nHardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 02/29/2024\nCall Trace:\n <TASK>\n  __dump_stack lib/dump_stack.c:88 [inline]\n  dump_stack_lvl+0x1e7/0x2e0 lib/dump_stack.c:106\n  ubsan_epilogue lib/ubsan.c:217 [inline]\n  __ubsan_handle_shift_out_of_bounds+0x3c7/0x420 lib/ubsan.c:386\n  taprio_parse_tc_entry net/sched/sch_taprio.c:1722 [inline]\n  taprio_parse_tc_entries net/sched/sch_taprio.c:1768 [inline]\n  taprio_change+0xb87/0x57d0 net/sched/sch_taprio.c:1877\n  taprio_init+0x9da/0xc80 net/sched/sch_taprio.c:2134\n  qdisc_create+0x9d4/0x1190 net/sched/sch_api.c:1355\n  tc_modify_qdisc+0xa26/0x1e40 net/sched/sch_api.c:1776\n  rtnetlink_rcv_msg+0x885/0x1040 net/core/rtnetlink.c:6617\n  netlink_rcv_skb+0x1e3/0x430 net/netlink/af_netlink.c:2543\n  netlink_unicast_kernel net/netlink/af_netlink.c:1341 [inline]\n  netlink_unicast+0x7ea/0x980 net/netlink/af_netlink.c:1367\n  netlink_sendmsg+0xa3b/0xd70 net/netlink/af_netlink.c:1908\n  sock_sendmsg_nosec net/socket.c:730 [inline]\n  __sock_sendmsg+0x221/0x270 net/socket.c:745\n  ____sys_sendmsg+0x525/0x7d0 net/socket.c:2584\n  ___sys_sendmsg net/socket.c:2638 [inline]\n  __sys_sendmsg+0x2b0/0x3a0 net/socket.c:2667\n do_syscall_64+0xf9/0x240\n entry_SYSCALL_64_after_hwframe+0x6f/0x77\nRIP: 0033:0x7f1b2dea3759\nCode: 48 83 c4 28 c3 e8 d7 19 00 00 0f 1f 80 00 00 00 00 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 c7 c1 b8 ff ff ff f7 d8 64 89 01 48\nRSP: 002b:00007ffd4de452f8 EFLAGS: 00000246 ORIG_RAX: 000000000000002e\nRAX: ffffffffffffffda RBX: 00007f1b2def0390 RCX: 00007f1b2dea3759\nRDX: 0000000000000000 RSI: 00000000200007c0 RDI: 0000000000000004\nRBP: 0000000000000003 R08: 0000555500000000 R09: 0000555500000000\nR10: 0000555500000000 R11: 0000000000000246 R12: 00007ffd4de45340\nR13: 00007ffd4de45310 R14: 0000000000000001 R15: 00007ffd4de45340",
+		"description": "DOCUMENTATION: The CVE program describes this issue as: In the Linux kernel, the following vulnerability has been resolved:\n\nnet/sched: taprio: proper TCA_TAPRIO_TC_ENTRY_INDEX check\n\ntaprio_parse_tc_entry() is not correctly checking\nTCA_TAPRIO_TC_ENTRY_INDEX attribute:\n\n\tint tc; // Signed value\n\n\ttc = nla_get_u32(tb[TCA_TAPRIO_TC_ENTRY_INDEX]);\n\tif (tc >= TC_QOPT_MAX_QUEUE) {\n\t\tNL_SET_ERR_MSG_MOD(extack, \"TC entry index out of range\");\n\t\treturn -ERANGE;\n\t}\n\nsyzbot reported that it could fed arbitary negative values:\n\nUBSAN: shift-out-of-bounds in net/sched/sch_taprio.c:1722:18\nshift exponent -2147418108 is negative\nCPU: 0 PID: 5066 Comm: syz-executor367 Not tainted 6.8.0-rc7-syzkaller-00136-gc8a5c731fd12 #0\nHardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 02/29/2024\nCall Trace:\n <TASK>\n  __dump_stack lib/dump_stack.c:88 [inline]\n  dump_stack_lvl+0x1e7/0x2e0 lib/dump_stack.c:106\n  ubsan_epilogue lib/ubsan.c:217 [inline]\n  __ubsan_handle_shift_out_of_bounds+0x3c7/0x420 lib/ubsan.c:386\n  taprio_parse_tc_entry net/sched/sch_taprio.c:1722 [inline]\n  taprio_parse_tc_entries net/sched/sch_taprio.c:1768 [inline]\n  taprio_change+0xb87/0x57d0 net/sched/sch_taprio.c:1877\n  taprio_init+0x9da/0xc80 net/sched/sch_taprio.c:2134\n  qdisc_create+0x9d4/0x1190 net/sched/sch_api.c:1355\n  tc_modify_qdisc+0xa26/0x1e40 net/sched/sch_api.c:1776\n  rtnetlink_rcv_msg+0x885/0x1040 net/core/rtnetlink.c:6617\n  netlink_rcv_skb+0x1e3/0x430 net/netlink/af_netlink.c:2543\n  netlink_unicast_kernel net/netlink/af_netlink.c:1341 [inline]\n  netlink_unicast+0x7ea/0x980 net/netlink/af_netlink.c:1367\n  netlink_sendmsg+0xa3b/0xd70 net/netlink/af_netlink.c:1908\n  sock_sendmsg_nosec net/socket.c:730 [inline]\n  __sock_sendmsg+0x221/0x270 net/socket.c:745\n  ____sys_sendmsg+0x525/0x7d0 net/socket.c:2584\n  ___sys_sendmsg net/socket.c:2638 [inline]\n  __sys_sendmsg+0x2b0/0x3a0 net/socket.c:2667\n do_syscall_64+0xf9/0x240\n entry_SYSCALL_64_after_hwframe+0x6f/0x77\nRIP: 0033:0x7f1b2dea3759\nCode: 48 83 c4 28 c3 e8 d7 19 00 00 0f 1f 80 00 00 00 00 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 c7 c1 b8 ff ff ff f7 d8 64 89 01 48\nRSP: 002b:00007ffd4de452f8 EFLAGS: 00000246 ORIG_RAX: 000000000000002e\nRAX: ffffffffffffffda RBX: 00007f1b2def0390 RCX: 00007f1b2dea3759\nRDX: 0000000000000000 RSI: 00000000200007c0 RDI: 0000000000000004\nRBP: 0000000000000003 R08: 0000555500000000 R09: 0000555500000000\nR10: 0000555500000000 R11: 0000000000000246 R12: 00007ffd4de45340\nR13: 00007ffd4de45310 R14: 0000000000000001 R15: 00007ffd4de45340",
 		"advisory": {
 			"from": "secalert@redhat.com",
 			"severity": "Low",
 			"updated": {
-				"date": "2024-10-28"
+				"date": "2025-03-27"
 			},
 			"cve": [
 				{
@@ -33,109 +33,27 @@ 				"resolution": [
 					{
 						"state": "Affected",
 						"component": [
-							"bpftool",
-							"kernel",
-							"kernel-64k",
-							"kernel-64k-core",
-							"kernel-64k-debug",
-							"kernel-64k-debug-core",
-							"kernel-64k-debug-devel",
-							"kernel-64k-debug-devel-matched",
-							"kernel-64k-debug-modules",
-							"kernel-64k-debug-modules-core",
-							"kernel-64k-debug-modules-extra",
-							"kernel-64k-debug-modules-internal",
-							"kernel-64k-debug-modules-partner",
-							"kernel-64k-devel",
-							"kernel-64k-devel-matched",
-							"kernel-64k-modules",
-							"kernel-64k-modules-core",
-							"kernel-64k-modules-extra",
-							"kernel-64k-modules-internal",
-							"kernel-64k-modules-partner",
-							"kernel-abi-stablelists",
-							"kernel-core",
-							"kernel-cross-headers",
-							"kernel-debug",
-							"kernel-debug-core",
-							"kernel-debug-devel",
-							"kernel-debug-devel-matched",
-							"kernel-debug-modules",
-							"kernel-debug-modules-core",
-							"kernel-debug-modules-extra",
-							"kernel-debug-modules-internal",
-							"kernel-debug-modules-partner",
-							"kernel-debug-uki-virt",
-							"kernel-devel",
-							"kernel-devel-matched",
-							"kernel-doc",
-							"kernel-headers",
-							"kernel-ipaclones-internal",
-							"kernel-modules",
-							"kernel-modules-core",
-							"kernel-modules-extra",
-							"kernel-modules-internal",
-							"kernel-modules-partner",
 							"kernel-rt",
-							"kernel-rt",
-							"kernel-rt-core",
 							"kernel-rt-core",
 							"kernel-rt-debug",
-							"kernel-rt-debug",
-							"kernel-rt-debug-core",
 							"kernel-rt-debug-core",
 							"kernel-rt-debug-devel",
-							"kernel-rt-debug-devel",
-							"kernel-rt-debug-devel-matched",
 							"kernel-rt-debug-devel-matched",
 							"kernel-rt-debug-kvm",
-							"kernel-rt-debug-kvm",
-							"kernel-rt-debug-modules",
 							"kernel-rt-debug-modules",
 							"kernel-rt-debug-modules-core",
-							"kernel-rt-debug-modules-core",
-							"kernel-rt-debug-modules-extra",
 							"kernel-rt-debug-modules-extra",
 							"kernel-rt-debug-modules-internal",
-							"kernel-rt-debug-modules-internal",
-							"kernel-rt-debug-modules-partner",
 							"kernel-rt-debug-modules-partner",
 							"kernel-rt-devel",
-							"kernel-rt-devel",
 							"kernel-rt-devel-matched",
-							"kernel-rt-devel-matched",
-							"kernel-rt-kvm",
 							"kernel-rt-kvm",
 							"kernel-rt-modules",
-							"kernel-rt-modules",
-							"kernel-rt-modules-core",
 							"kernel-rt-modules-core",
 							"kernel-rt-modules-extra",
-							"kernel-rt-modules-extra",
-							"kernel-rt-modules-internal",
 							"kernel-rt-modules-internal",
 							"kernel-rt-modules-partner",
-							"kernel-rt-modules-partner",
-							"kernel-rt-selftests-internal",
-							"kernel-selftests-internal",
-							"kernel-tools",
-							"kernel-tools-libs",
-							"kernel-tools-libs-devel",
-							"kernel-uki-virt",
-							"kernel-zfcpdump",
-							"kernel-zfcpdump-core",
-							"kernel-zfcpdump-devel",
-							"kernel-zfcpdump-devel-matched",
-							"kernel-zfcpdump-modules",
-							"kernel-zfcpdump-modules-core",
-							"kernel-zfcpdump-modules-extra",
-							"kernel-zfcpdump-modules-internal",
-							"kernel-zfcpdump-modules-partner",
-							"libperf",
-							"perf",
-							"python3-perf",
-							"rtla",
-							"rv"
+							"kernel-rt-selftests-internal"
 						]
 					}
 				]
@@ -173,32 +91,6 @@ 							{
 								"operator": "AND",
 								"criterions": [
 									{
-										"test_ref": "oval:com.redhat.cve:tst:202010135133",
-										"comment": "kernel-debug-modules-internal is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:202010135134",
-										"comment": "kernel-debug-modules-internal is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:202010135111",
-										"comment": "kernel-64k-debug-modules-internal is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:202010135112",
-										"comment": "kernel-64k-debug-modules-internal is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
 										"test_ref": "oval:com.redhat.cve:tst:201925162001",
 										"comment": "kernel-rt is installed"
 									},
@@ -212,12 +104,12 @@ 							{
 								"operator": "AND",
 								"criterions": [
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089021",
-										"comment": "kernel-64k-debug-devel is installed"
+										"test_ref": "oval:com.redhat.cve:tst:201925162019",
+										"comment": "kernel-rt-debug-modules-internal is installed"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089022",
-										"comment": "kernel-64k-debug-devel is signed with Red Hat redhatrelease2 key"
+										"test_ref": "oval:com.redhat.cve:tst:201925162020",
+										"comment": "kernel-rt-debug-modules-internal is signed with Red Hat redhatrelease2 key"
 									}
 								]
 							},
@@ -225,12 +117,12 @@ 							{
 								"operator": "AND",
 								"criterions": [
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089077",
-										"comment": "kernel-uki-virt is installed"
+										"test_ref": "oval:com.redhat.cve:tst:201925162017",
+										"comment": "kernel-rt-modules-internal is installed"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089078",
-										"comment": "kernel-uki-virt is signed with Red Hat redhatrelease2 key"
+										"test_ref": "oval:com.redhat.cve:tst:201925162018",
+										"comment": "kernel-rt-modules-internal is signed with Red Hat redhatrelease2 key"
 									}
 								]
 							},
@@ -251,318 +143,6 @@ 							{
 								"operator": "AND",
 								"criterions": [
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089043",
-										"comment": "kernel-core is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089044",
-										"comment": "kernel-core is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089081",
-										"comment": "kernel-64k-modules-extra is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089082",
-										"comment": "kernel-64k-modules-extra is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089085",
-										"comment": "kernel-debug-devel-matched is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089086",
-										"comment": "kernel-debug-devel-matched is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089013",
-										"comment": "kernel-zfcpdump-devel is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089014",
-										"comment": "kernel-zfcpdump-devel is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089053",
-										"comment": "kernel-tools-libs is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089054",
-										"comment": "kernel-tools-libs is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089003",
-										"comment": "kernel-zfcpdump is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089004",
-										"comment": "kernel-zfcpdump is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089001",
-										"comment": "kernel-tools-libs-devel is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089002",
-										"comment": "kernel-tools-libs-devel is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162003",
-										"comment": "kernel-rt-modules is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162004",
-										"comment": "kernel-rt-modules is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089033",
-										"comment": "kernel-debug-modules is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089034",
-										"comment": "kernel-debug-modules is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089049",
-										"comment": "kernel-64k-debug is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089050",
-										"comment": "kernel-64k-debug is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089037",
-										"comment": "kernel-debug-modules-extra is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089038",
-										"comment": "kernel-debug-modules-extra is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162011",
-										"comment": "kernel-rt-core is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162012",
-										"comment": "kernel-rt-core is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:202010135069",
-										"comment": "kernel-debug-modules-partner is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:202010135070",
-										"comment": "kernel-debug-modules-partner is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089061",
-										"comment": "kernel-64k-debug-modules-core is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089062",
-										"comment": "kernel-64k-debug-modules-core is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089055",
-										"comment": "kernel-64k-modules-core is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089056",
-										"comment": "kernel-64k-modules-core is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089047",
-										"comment": "kernel-modules-core is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089048",
-										"comment": "kernel-modules-core is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089075",
-										"comment": "kernel-tools is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089076",
-										"comment": "kernel-tools is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:202010135089",
-										"comment": "libperf is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:202010135090",
-										"comment": "libperf is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089039",
-										"comment": "kernel-doc is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089040",
-										"comment": "kernel-doc is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089065",
-										"comment": "kernel-64k-devel-matched is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089066",
-										"comment": "kernel-64k-devel-matched is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162023",
-										"comment": "kernel-rt-kvm is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162024",
-										"comment": "kernel-rt-kvm is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162015",
-										"comment": "kernel-rt-devel is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162016",
-										"comment": "kernel-rt-devel is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:202010135019",
-										"comment": "kernel-ipaclones-internal is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:202010135020",
-										"comment": "kernel-ipaclones-internal is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089023",
-										"comment": "kernel-zfcpdump-devel-matched is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089024",
-										"comment": "kernel-zfcpdump-devel-matched is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
 										"test_ref": "oval:com.redhat.cve:tst:201925162027",
 										"comment": "kernel-rt-debug-kvm is installed"
 									},
@@ -576,45 +156,6 @@ 							{
 								"operator": "AND",
 								"criterions": [
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089067",
-										"comment": "kernel-64k-debug-devel-matched is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089068",
-										"comment": "kernel-64k-debug-devel-matched is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162007",
-										"comment": "kernel-rt-debug-devel-matched is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162008",
-										"comment": "kernel-rt-debug-devel-matched is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:202010135045",
-										"comment": "kernel-64k-modules-partner is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:202010135046",
-										"comment": "kernel-64k-modules-partner is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
 										"test_ref": "oval:com.redhat.cve:tst:201925162009",
 										"comment": "kernel-rt-modules-extra is installed"
 									},
@@ -628,103 +169,12 @@ 							{
 								"operator": "AND",
 								"criterions": [
 									{
-										"test_ref": "oval:com.redhat.cve:tst:202010135079",
-										"comment": "kernel-modules-partner is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:202010135080",
-										"comment": "kernel-modules-partner is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089083",
-										"comment": "kernel-devel is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089084",
-										"comment": "kernel-devel is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089035",
-										"comment": "kernel-64k-modules is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089036",
-										"comment": "kernel-64k-modules is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162041",
-										"comment": "kernel-rt-debug is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162042",
-										"comment": "kernel-rt-debug is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089073",
-										"comment": "kernel-zfcpdump-core is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089074",
-										"comment": "kernel-zfcpdump-core is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089079",
-										"comment": "kernel-zfcpdump-modules-extra is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089080",
-										"comment": "kernel-zfcpdump-modules-extra is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:202010135151",
-										"comment": "kernel-selftests-internal is installed"
+										"test_ref": "oval:com.redhat.cve:tst:201925162029",
+										"comment": "kernel-rt-debug-modules-extra is installed"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:202010135152",
-										"comment": "kernel-selftests-internal is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:202010135025",
-										"comment": "rv is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:202010135026",
-										"comment": "rv is signed with Red Hat redhatrelease2 key"
+										"test_ref": "oval:com.redhat.cve:tst:201925162030",
+										"comment": "kernel-rt-debug-modules-extra is signed with Red Hat redhatrelease2 key"
 									}
 								]
 							},
@@ -745,32 +195,6 @@ 							{
 								"operator": "AND",
 								"criterions": [
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089071",
-										"comment": "kernel-modules-extra is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089072",
-										"comment": "kernel-modules-extra is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089015",
-										"comment": "kernel-64k-debug-modules is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089016",
-										"comment": "kernel-64k-debug-modules is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
 										"test_ref": "oval:com.redhat.cve:tst:201925162037",
 										"comment": "kernel-rt-debug-modules-partner is installed"
 									},
@@ -784,64 +208,12 @@ 							{
 								"operator": "AND",
 								"criterions": [
 									{
-										"test_ref": "oval:com.redhat.cve:tst:202010135055",
-										"comment": "kernel-modules-internal is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:202010135056",
-										"comment": "kernel-modules-internal is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162017",
-										"comment": "kernel-rt-modules-internal is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162018",
-										"comment": "kernel-rt-modules-internal is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089095",
-										"comment": "kernel-64k is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089096",
-										"comment": "kernel-64k is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089093",
-										"comment": "kernel-64k-devel is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089094",
-										"comment": "kernel-64k-devel is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089019",
-										"comment": "kernel-zfcpdump-modules-core is installed"
+										"test_ref": "oval:com.redhat.cve:tst:201925162003",
+										"comment": "kernel-rt-modules is installed"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089020",
-										"comment": "kernel-zfcpdump-modules-core is signed with Red Hat redhatrelease2 key"
+										"test_ref": "oval:com.redhat.cve:tst:201925162004",
+										"comment": "kernel-rt-modules is signed with Red Hat redhatrelease2 key"
 									}
 								]
 							},
@@ -849,12 +221,12 @@ 							{
 								"operator": "AND",
 								"criterions": [
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089063",
-										"comment": "kernel-modules is installed"
+										"test_ref": "oval:com.redhat.cve:tst:201925162041",
+										"comment": "kernel-rt-debug is installed"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089064",
-										"comment": "kernel-modules is signed with Red Hat redhatrelease2 key"
+										"test_ref": "oval:com.redhat.cve:tst:201925162042",
+										"comment": "kernel-rt-debug is signed with Red Hat redhatrelease2 key"
 									}
 								]
 							},
@@ -862,12 +234,12 @@ 							{
 								"operator": "AND",
 								"criterions": [
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089025",
-										"comment": "rtla is installed"
+										"test_ref": "oval:com.redhat.cve:tst:201925162021",
+										"comment": "kernel-rt-modules-partner is installed"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089026",
-										"comment": "rtla is signed with Red Hat redhatrelease2 key"
+										"test_ref": "oval:com.redhat.cve:tst:201925162022",
+										"comment": "kernel-rt-modules-partner is signed with Red Hat redhatrelease2 key"
 									}
 								]
 							},
@@ -888,149 +260,6 @@ 							{
 								"operator": "AND",
 								"criterions": [
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162013",
-										"comment": "kernel-rt-selftests-internal is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162014",
-										"comment": "kernel-rt-selftests-internal is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089009",
-										"comment": "kernel-64k-debug-core is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089010",
-										"comment": "kernel-64k-debug-core is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089011",
-										"comment": "python3-perf is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089012",
-										"comment": "python3-perf is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089091",
-										"comment": "kernel-abi-stablelists is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089092",
-										"comment": "kernel-abi-stablelists is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089057",
-										"comment": "kernel-debug is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089058",
-										"comment": "kernel-debug is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089069",
-										"comment": "kernel-debug-core is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089070",
-										"comment": "kernel-debug-core is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089059",
-										"comment": "kernel-64k-debug-modules-extra is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089060",
-										"comment": "kernel-64k-debug-modules-extra is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:202010135061",
-										"comment": "kernel-zfcpdump-modules-internal is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:202010135062",
-										"comment": "kernel-zfcpdump-modules-internal is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162033",
-										"comment": "kernel-rt-devel-matched is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162034",
-										"comment": "kernel-rt-devel-matched is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089089",
-										"comment": "kernel-headers is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089090",
-										"comment": "kernel-headers is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089041",
-										"comment": "kernel-debug-uki-virt is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089042",
-										"comment": "kernel-debug-uki-virt is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
 										"test_ref": "oval:com.redhat.cve:tst:201925162005",
 										"comment": "kernel-rt-debug-devel is installed"
 									},
@@ -1044,51 +273,12 @@ 							{
 								"operator": "AND",
 								"criterions": [
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089051",
-										"comment": "kernel-zfcpdump-modules is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089052",
-										"comment": "kernel-zfcpdump-modules is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089031",
-										"comment": "kernel-devel-matched is installed"
+										"test_ref": "oval:com.redhat.cve:tst:201925162015",
+										"comment": "kernel-rt-devel is installed"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089032",
-										"comment": "kernel-devel-matched is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162029",
-										"comment": "kernel-rt-debug-modules-extra is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162030",
-										"comment": "kernel-rt-debug-modules-extra is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162021",
-										"comment": "kernel-rt-modules-partner is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162022",
-										"comment": "kernel-rt-modules-partner is signed with Red Hat redhatrelease2 key"
+										"test_ref": "oval:com.redhat.cve:tst:201925162016",
+										"comment": "kernel-rt-devel is signed with Red Hat redhatrelease2 key"
 									}
 								]
 							},
@@ -1109,12 +299,12 @@ 							{
 								"operator": "AND",
 								"criterions": [
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089087",
-										"comment": "kernel-debug-modules-core is installed"
+										"test_ref": "oval:com.redhat.cve:tst:201925162023",
+										"comment": "kernel-rt-kvm is installed"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089088",
-										"comment": "kernel-debug-modules-core is signed with Red Hat redhatrelease2 key"
+										"test_ref": "oval:com.redhat.cve:tst:201925162024",
+										"comment": "kernel-rt-kvm is signed with Red Hat redhatrelease2 key"
 									}
 								]
 							},
@@ -1122,25 +312,12 @@ 							{
 								"operator": "AND",
 								"criterions": [
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162019",
-										"comment": "kernel-rt-debug-modules-internal is installed"
+										"test_ref": "oval:com.redhat.cve:tst:201925162007",
+										"comment": "kernel-rt-debug-devel-matched is installed"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162020",
-										"comment": "kernel-rt-debug-modules-internal is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089005",
-										"comment": "kernel is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089006",
-										"comment": "kernel is signed with Red Hat redhatrelease2 key"
+										"test_ref": "oval:com.redhat.cve:tst:201925162008",
+										"comment": "kernel-rt-debug-devel-matched is signed with Red Hat redhatrelease2 key"
 									}
 								]
 							},
@@ -1148,12 +325,12 @@ 							{
 								"operator": "AND",
 								"criterions": [
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089029",
-										"comment": "bpftool is installed"
+										"test_ref": "oval:com.redhat.cve:tst:201925162013",
+										"comment": "kernel-rt-selftests-internal is installed"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089030",
-										"comment": "bpftool is signed with Red Hat redhatrelease2 key"
+										"test_ref": "oval:com.redhat.cve:tst:201925162014",
+										"comment": "kernel-rt-selftests-internal is signed with Red Hat redhatrelease2 key"
 									}
 								]
 							},
@@ -1161,12 +338,12 @@ 							{
 								"operator": "AND",
 								"criterions": [
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089017",
-										"comment": "kernel-64k-core is installed"
+										"test_ref": "oval:com.redhat.cve:tst:201925162011",
+										"comment": "kernel-rt-core is installed"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089018",
-										"comment": "kernel-64k-core is signed with Red Hat redhatrelease2 key"
+										"test_ref": "oval:com.redhat.cve:tst:201925162012",
+										"comment": "kernel-rt-core is signed with Red Hat redhatrelease2 key"
 									}
 								]
 							},
@@ -1174,77 +351,12 @@ 							{
 								"operator": "AND",
 								"criterions": [
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089045",
-										"comment": "perf is installed"
+										"test_ref": "oval:com.redhat.cve:tst:201925162033",
+										"comment": "kernel-rt-devel-matched is installed"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089046",
-										"comment": "perf is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089027",
-										"comment": "kernel-debug-devel is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089028",
-										"comment": "kernel-debug-devel is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089007",
-										"comment": "kernel-cross-headers is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089008",
-										"comment": "kernel-cross-headers is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:202010135081",
-										"comment": "kernel-64k-debug-modules-partner is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:202010135082",
-										"comment": "kernel-64k-debug-modules-partner is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:202010135031",
-										"comment": "kernel-64k-modules-internal is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:202010135032",
-										"comment": "kernel-64k-modules-internal is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:202010135013",
-										"comment": "kernel-zfcpdump-modules-partner is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:202010135014",
-										"comment": "kernel-zfcpdump-modules-partner is signed with Red Hat redhatrelease2 key"
+										"test_ref": "oval:com.redhat.cve:tst:201925162034",
+										"comment": "kernel-rt-devel-matched is signed with Red Hat redhatrelease2 key"
 									}
 								]
 							}
`,
		},
		{
			name:   "no diff",
			dotgit: "testdata/fixtures/vuls-data-raw-redhat-ovalv2.tar.zst",
			args: args{
				minus: "63a30ff24dea0d2198c1e3160c33b52df66970a4:9/rhel-9-including-unpatched/definitions/oval:com.redhat.cve:def:202426815.json",
				plus:  "63a30ff24dea0d2198c1e3160c33b52df66970a4:9/rhel-9-including-unpatched/definitions/oval:com.redhat.cve:def:202426815.json",
			},
			want: "diff --git a/9/rhel-9-including-unpatched/definitions/oval:com.redhat.cve:def:202426815.json b/9/rhel-9-including-unpatched/definitions/oval:com.redhat.cve:def:202426815.json\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.dotgit)
			if err != nil {
				t.Errorf("open %s. err: %v", tt.dotgit, err)
			}
			defer f.Close()

			dir := t.TempDir()
			if err := util.ExtractDotgitTarZst(f, filepath.Join(dir, strings.TrimSuffix(filepath.Base(tt.dotgit), ".tar.zst"))); err != nil {
				t.Errorf("extract %s. err: %v", tt.dotgit, err)
			}

			got, err := diff.Diff(filepath.Join(dir, strings.TrimSuffix(filepath.Base(tt.dotgit), ".tar.zst")), tt.args.minus, tt.args.plus)
			switch {
			case err != nil && !tt.hasError:
				t.Errorf("unexpected err: %v", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			default:
				if diff := cmp.Diff(tt.want, got); diff != "" {
					t.Errorf("Cat(). (-expected +got):\n%s", diff)
				}
			}
		})
	}
}
