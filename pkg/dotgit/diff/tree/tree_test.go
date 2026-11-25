package tree_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/diff/tree"
	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/util"
)

func TestDiff(t *testing.T) {
	type args struct {
		repository string
		minus      string
		plus       string
		opts       []tree.Option
	}
	tests := []struct {
		name     string
		args     args
		want     string
		hasError bool
	}{
		{
			name: "diff-tree -p 63a30ff24dea0d2198c1e3160c33b52df66970a4 6e6128f16b40edf3963ebb0036a3e0a55a54d0de",
			args: args{
				repository: "testdata/fixtures/vuls-data-raw-redhat-ovalv2.tar.zst",
				minus:      "63a30ff24dea0d2198c1e3160c33b52df66970a4",
				plus:       "6e6128f16b40edf3963ebb0036a3e0a55a54d0de",
				opts:       []tree.Option{tree.WithColor(false)},
			},
			want: `diff --git a/9/rhel-9-including-unpatched/definitions/oval:com.redhat.cve:def:202426815.json b/9/rhel-9-including-unpatched/definitions/oval:com.redhat.cve:def:202426815.json
index 321cb11..11d5d75 100644
--- a/9/rhel-9-including-unpatched/definitions/oval:com.redhat.cve:def:202426815.json
+++ b/9/rhel-9-including-unpatched/definitions/oval:com.redhat.cve:def:202426815.json
@@ -11,12 +11,12 @@
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
@@ -33,109 +33,27 @@
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
-							"kernel-rt-devel-matched",
 							"kernel-rt-devel-matched",
 							"kernel-rt-kvm",
-							"kernel-rt-kvm",
-							"kernel-rt-modules",
 							"kernel-rt-modules",
 							"kernel-rt-modules-core",
-							"kernel-rt-modules-core",
-							"kernel-rt-modules-extra",
 							"kernel-rt-modules-extra",
 							"kernel-rt-modules-internal",
-							"kernel-rt-modules-internal",
-							"kernel-rt-modules-partner",
 							"kernel-rt-modules-partner",
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
@@ -169,32 +87,6 @@
 					{
 						"operator": "OR",
 						"criterias": [
-							{
-								"operator": "AND",
-								"criterions": [
-									{
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
 							{
 								"operator": "AND",
 								"criterions": [
@@ -212,12 +104,12 @@
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
@@ -225,12 +117,12 @@
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
@@ -251,38 +143,12 @@
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
+										"test_ref": "oval:com.redhat.cve:tst:201925162027",
+										"comment": "kernel-rt-debug-kvm is installed"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089086",
-										"comment": "kernel-debug-devel-matched is signed with Red Hat redhatrelease2 key"
+										"test_ref": "oval:com.redhat.cve:tst:201925162028",
+										"comment": "kernel-rt-debug-kvm is signed with Red Hat redhatrelease2 key"
 									}
 								]
 							},
@@ -290,12 +156,12 @@
 								"operator": "AND",
 								"criterions": [
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089013",
-										"comment": "kernel-zfcpdump-devel is installed"
+										"test_ref": "oval:com.redhat.cve:tst:201925162009",
+										"comment": "kernel-rt-modules-extra is installed"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089014",
-										"comment": "kernel-zfcpdump-devel is signed with Red Hat redhatrelease2 key"
+										"test_ref": "oval:com.redhat.cve:tst:201925162010",
+										"comment": "kernel-rt-modules-extra is signed with Red Hat redhatrelease2 key"
 									}
 								]
 							},
@@ -303,12 +169,12 @@
 								"operator": "AND",
 								"criterions": [
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089053",
-										"comment": "kernel-tools-libs is installed"
+										"test_ref": "oval:com.redhat.cve:tst:201925162029",
+										"comment": "kernel-rt-debug-modules-extra is installed"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089054",
-										"comment": "kernel-tools-libs is signed with Red Hat redhatrelease2 key"
+										"test_ref": "oval:com.redhat.cve:tst:201925162030",
+										"comment": "kernel-rt-debug-modules-extra is signed with Red Hat redhatrelease2 key"
 									}
 								]
 							},
@@ -316,12 +182,12 @@
 								"operator": "AND",
 								"criterions": [
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089003",
-										"comment": "kernel-zfcpdump is installed"
+										"test_ref": "oval:com.redhat.cve:tst:201925162035",
+										"comment": "kernel-rt-debug-core is installed"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089004",
-										"comment": "kernel-zfcpdump is signed with Red Hat redhatrelease2 key"
+										"test_ref": "oval:com.redhat.cve:tst:201925162036",
+										"comment": "kernel-rt-debug-core is signed with Red Hat redhatrelease2 key"
 									}
 								]
 							},
@@ -329,12 +195,12 @@
 								"operator": "AND",
 								"criterions": [
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089001",
-										"comment": "kernel-tools-libs-devel is installed"
+										"test_ref": "oval:com.redhat.cve:tst:201925162037",
+										"comment": "kernel-rt-debug-modules-partner is installed"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089002",
-										"comment": "kernel-tools-libs-devel is signed with Red Hat redhatrelease2 key"
+										"test_ref": "oval:com.redhat.cve:tst:201925162038",
+										"comment": "kernel-rt-debug-modules-partner is signed with Red Hat redhatrelease2 key"
 									}
 								]
 							},
@@ -355,129 +221,12 @@
 								"operator": "AND",
 								"criterions": [
 									{
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
+										"test_ref": "oval:com.redhat.cve:tst:201925162041",
+										"comment": "kernel-rt-debug is installed"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:202010135090",
-										"comment": "libperf is signed with Red Hat redhatrelease2 key"
+										"test_ref": "oval:com.redhat.cve:tst:201925162042",
+										"comment": "kernel-rt-debug is signed with Red Hat redhatrelease2 key"
 									}
 								]
 							},
@@ -485,12 +234,12 @@
 								"operator": "AND",
 								"criterions": [
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089039",
-										"comment": "kernel-doc is installed"
+										"test_ref": "oval:com.redhat.cve:tst:201925162021",
+										"comment": "kernel-rt-modules-partner is installed"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089040",
-										"comment": "kernel-doc is signed with Red Hat redhatrelease2 key"
+										"test_ref": "oval:com.redhat.cve:tst:201925162022",
+										"comment": "kernel-rt-modules-partner is signed with Red Hat redhatrelease2 key"
 									}
 								]
 							},
@@ -498,12 +247,12 @@
 								"operator": "AND",
 								"criterions": [
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089065",
-										"comment": "kernel-64k-devel-matched is installed"
+										"test_ref": "oval:com.redhat.cve:tst:201925162039",
+										"comment": "kernel-rt-debug-modules is installed"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089066",
-										"comment": "kernel-64k-devel-matched is signed with Red Hat redhatrelease2 key"
+										"test_ref": "oval:com.redhat.cve:tst:201925162040",
+										"comment": "kernel-rt-debug-modules is signed with Red Hat redhatrelease2 key"
 									}
 								]
 							},
@@ -511,12 +260,12 @@
 								"operator": "AND",
 								"criterions": [
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162023",
-										"comment": "kernel-rt-kvm is installed"
+										"test_ref": "oval:com.redhat.cve:tst:201925162005",
+										"comment": "kernel-rt-debug-devel is installed"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162024",
-										"comment": "kernel-rt-kvm is signed with Red Hat redhatrelease2 key"
+										"test_ref": "oval:com.redhat.cve:tst:201925162006",
+										"comment": "kernel-rt-debug-devel is signed with Red Hat redhatrelease2 key"
 									}
 								]
 							},
@@ -537,38 +286,12 @@
 								"operator": "AND",
 								"criterions": [
 									{
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
-										"test_ref": "oval:com.redhat.cve:tst:201925162027",
-										"comment": "kernel-rt-debug-kvm is installed"
+										"test_ref": "oval:com.redhat.cve:tst:201925162025",
+										"comment": "kernel-rt-modules-core is installed"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162028",
-										"comment": "kernel-rt-debug-kvm is signed with Red Hat redhatrelease2 key"
+										"test_ref": "oval:com.redhat.cve:tst:201925162026",
+										"comment": "kernel-rt-modules-core is signed with Red Hat redhatrelease2 key"
 									}
 								]
 							},
@@ -576,12 +299,12 @@
 								"operator": "AND",
 								"criterions": [
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089067",
-										"comment": "kernel-64k-debug-devel-matched is installed"
+										"test_ref": "oval:com.redhat.cve:tst:201925162023",
+										"comment": "kernel-rt-kvm is installed"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089068",
-										"comment": "kernel-64k-debug-devel-matched is signed with Red Hat redhatrelease2 key"
+										"test_ref": "oval:com.redhat.cve:tst:201925162024",
+										"comment": "kernel-rt-kvm is signed with Red Hat redhatrelease2 key"
 									}
 								]
 							},
@@ -602,38 +325,12 @@
 								"operator": "AND",
 								"criterions": [
 									{
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
-										"test_ref": "oval:com.redhat.cve:tst:201925162009",
-										"comment": "kernel-rt-modules-extra is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162010",
-										"comment": "kernel-rt-modules-extra is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:202010135079",
-										"comment": "kernel-modules-partner is installed"
+										"test_ref": "oval:com.redhat.cve:tst:201925162013",
+										"comment": "kernel-rt-selftests-internal is installed"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:202010135080",
-										"comment": "kernel-modules-partner is signed with Red Hat redhatrelease2 key"
+										"test_ref": "oval:com.redhat.cve:tst:201925162014",
+										"comment": "kernel-rt-selftests-internal is signed with Red Hat redhatrelease2 key"
 									}
 								]
 							},
@@ -641,12 +338,12 @@
 								"operator": "AND",
 								"criterions": [
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089083",
-										"comment": "kernel-devel is installed"
+										"test_ref": "oval:com.redhat.cve:tst:201925162011",
+										"comment": "kernel-rt-core is installed"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089084",
-										"comment": "kernel-devel is signed with Red Hat redhatrelease2 key"
+										"test_ref": "oval:com.redhat.cve:tst:201925162012",
+										"comment": "kernel-rt-core is signed with Red Hat redhatrelease2 key"
 									}
 								]
 							},
@@ -654,599 +351,14 @@
 								"operator": "AND",
 								"criterions": [
 									{
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
-									},
-									{
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
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162035",
-										"comment": "kernel-rt-debug-core is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162036",
-										"comment": "kernel-rt-debug-core is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
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
-										"test_ref": "oval:com.redhat.cve:tst:201925162037",
-										"comment": "kernel-rt-debug-modules-partner is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162038",
-										"comment": "kernel-rt-debug-modules-partner is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
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
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089020",
-										"comment": "kernel-zfcpdump-modules-core is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089063",
-										"comment": "kernel-modules is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089064",
-										"comment": "kernel-modules is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089025",
-										"comment": "rtla is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089026",
-										"comment": "rtla is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162039",
-										"comment": "kernel-rt-debug-modules is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162040",
-										"comment": "kernel-rt-debug-modules is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
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
+										"test_ref": "oval:com.redhat.cve:tst:201925162033",
+										"comment": "kernel-rt-devel-matched is installed"
 									},
 									{
 										"test_ref": "oval:com.redhat.cve:tst:201925162034",
 										"comment": "kernel-rt-devel-matched is signed with Red Hat redhatrelease2 key"
 									}
 								]
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
-										"test_ref": "oval:com.redhat.cve:tst:201925162005",
-										"comment": "kernel-rt-debug-devel is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162006",
-										"comment": "kernel-rt-debug-devel is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
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
-									},
-									{
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
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162025",
-										"comment": "kernel-rt-modules-core is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162026",
-										"comment": "kernel-rt-modules-core is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089087",
-										"comment": "kernel-debug-modules-core is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089088",
-										"comment": "kernel-debug-modules-core is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162019",
-										"comment": "kernel-rt-debug-modules-internal is installed"
-									},
-									{
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
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089029",
-										"comment": "bpftool is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089030",
-										"comment": "bpftool is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089017",
-										"comment": "kernel-64k-core is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089018",
-										"comment": "kernel-64k-core is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089045",
-										"comment": "perf is installed"
-									},
-									{
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
-									}
-								]
 							}
 						]
 					}
diff --git a/9/rhel-9-including-unpatched/definitions/oval:com.redhat.rhsa:def:20249315.json b/9/rhel-9-including-unpatched/definitions/oval:com.redhat.rhsa:def:20249315.json
index d59f905..1922f47 100644
--- a/9/rhel-9-including-unpatched/definitions/oval:com.redhat.rhsa:def:20249315.json
+++ b/9/rhel-9-including-unpatched/definitions/oval:com.redhat.rhsa:def:20249315.json
@@ -1,6 +1,6 @@
 {
 	"id": "oval:com.redhat.rhsa:def:20249315",
-	"version": "648",
+	"version": "649",
 	"class": "patch",
 	"metadata": {
 		"title": "RHSA-2024:9315: kernel security update (Moderate)",
@@ -780,6 +780,11 @@
 				"ref_url": "https://access.redhat.com/security/cve/CVE-2024-26733",
 				"source": "CVE"
 			},
+			{
+				"ref_id": "CVE-2024-26734",
+				"ref_url": "https://access.redhat.com/security/cve/CVE-2024-26734",
+				"source": "CVE"
+			},
 			{
 				"ref_id": "CVE-2024-26740",
 				"ref_url": "https://access.redhat.com/security/cve/CVE-2024-26740",
@@ -3620,6 +3625,14 @@
 					"impact": "moderate",
 					"public": "20240403"
 				},
+				{
+					"text": "CVE-2024-26734",
+					"cvss3": "5.5/CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
+					"cwe": "CWE-416",
+					"href": "https://access.redhat.com/security/cve/CVE-2024-26734",
+					"impact": "moderate",
+					"public": "20240403"
+				},
 				{
 					"text": "CVE-2024-26740",
 					"cvss3": "5.5/CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
@@ -5942,7 +5955,7 @@
 				},
 				{
 					"text": "CVE-2024-42301",
-					"cvss3": "5.5/CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
+					"cvss3": "7.1/CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
 					"href": "https://access.redhat.com/security/cve/CVE-2024-42301",
 					"impact": "moderate",
 					"public": "20240817"
@@ -6587,6 +6600,11 @@
 					"href": "https://bugzilla.redhat.com/2273242",
 					"id": "2273242"
 				},
+				{
+					"text": "kernel: devlink: fix possible use-after-free and memory leaks in devlink_init()",
+					"href": "https://bugzilla.redhat.com/2273244",
+					"id": "2273244"
+				},
 				{
 					"text": "kernel: arp: Prevent overflow in arp_req_get().",
 					"href": "https://bugzilla.redhat.com/2273247",
diff --git a/9/rhel-9-including-unpatched/objects/textfilecontent54_object/oval:com.redhat.rhba:obj:20243983066.json b/9/rhel-9-including-unpatched/objects/textfilecontent54_object/oval:com.redhat.rhba:obj:20243983066.json
new file mode 100644
index 0000000..f54b7bc
--- /dev/null
+++ b/9/rhel-9-including-unpatched/objects/textfilecontent54_object/oval:com.redhat.rhba:obj:20243983066.json
@@ -0,0 +1,16 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983066",
+	"version": "637",
+	"filepath": {
+		"text": "/boot/grub2/grubenv",
+		"datatype": "string"
+	},
+	"pattern": {
+		"text": "(?<=^saved_entry=).*",
+		"operation": "pattern match"
+	},
+	"instance": {
+		"text": "1",
+		"datatype": "int"
+	}
+}
diff --git a/9/rhel-9-including-unpatched/objects/uname_object/oval:com.redhat.rhba:obj:20243983065.json b/9/rhel-9-including-unpatched/objects/uname_object/oval:com.redhat.rhba:obj:20243983065.json
new file mode 100644
index 0000000..e1da94b
--- /dev/null
+++ b/9/rhel-9-including-unpatched/objects/uname_object/oval:com.redhat.rhba:obj:20243983065.json
@@ -0,0 +1,4 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983065",
+	"version": "637"
+}
diff --git a/9/rhel-9-including-unpatched/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315001.json b/9/rhel-9-including-unpatched/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315001.json
index 901d935..5ceb0de 100644
--- a/9/rhel-9-including-unpatched/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315001.json
+++ b/9/rhel-9-including-unpatched/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315001.json
@@ -1,6 +1,6 @@
 {
 	"id": "oval:com.redhat.rhsa:ste:20249315001",
-	"version": "648",
+	"version": "649",
 	"evr": {
 		"text": "0:7.4.0-503.11.1.el9_5",
 		"datatype": "evr_string",
diff --git a/9/rhel-9-including-unpatched/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315003.json b/9/rhel-9-including-unpatched/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315003.json
index b252110..f2afdf6 100644
--- a/9/rhel-9-including-unpatched/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315003.json
+++ b/9/rhel-9-including-unpatched/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315003.json
@@ -1,6 +1,6 @@
 {
 	"id": "oval:com.redhat.rhsa:ste:20249315003",
-	"version": "648",
+	"version": "649",
 	"evr": {
 		"text": "0:5.14.0-503.11.1.el9_5",
 		"datatype": "evr_string",
diff --git a/9/rhel-9-including-unpatched/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315004.json b/9/rhel-9-including-unpatched/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315004.json
index 9c689bb..ed0b4f4 100644
--- a/9/rhel-9-including-unpatched/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315004.json
+++ b/9/rhel-9-including-unpatched/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315004.json
@@ -1,6 +1,6 @@
 {
 	"id": "oval:com.redhat.rhsa:ste:20249315004",
-	"version": "648",
+	"version": "649",
 	"evr": {
 		"text": "0:5.14.0-503.11.1.el9_5",
 		"datatype": "evr_string",
diff --git a/9/rhel-9-including-unpatched/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315005.json b/9/rhel-9-including-unpatched/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315005.json
index b802194..a4d831d 100644
--- a/9/rhel-9-including-unpatched/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315005.json
+++ b/9/rhel-9-including-unpatched/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315005.json
@@ -1,6 +1,6 @@
 {
 	"id": "oval:com.redhat.rhsa:ste:20249315005",
-	"version": "648",
+	"version": "649",
 	"evr": {
 		"text": "0:5.14.0-503.11.1.el9_5",
 		"datatype": "evr_string",
diff --git a/9/rhel-9-including-unpatched/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315006.json b/9/rhel-9-including-unpatched/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315006.json
index 57042d4..cf93b71 100644
--- a/9/rhel-9-including-unpatched/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315006.json
+++ b/9/rhel-9-including-unpatched/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315006.json
@@ -1,6 +1,6 @@
 {
 	"id": "oval:com.redhat.rhsa:ste:20249315006",
-	"version": "648",
+	"version": "649",
 	"evr": {
 		"text": "0:5.14.0-503.11.1.el9_5",
 		"datatype": "evr_string",
diff --git a/9/rhel-9-including-unpatched/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315007.json b/9/rhel-9-including-unpatched/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315007.json
index d4e8713..c3edea8 100644
--- a/9/rhel-9-including-unpatched/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315007.json
+++ b/9/rhel-9-including-unpatched/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315007.json
@@ -1,6 +1,6 @@
 {
 	"id": "oval:com.redhat.rhsa:ste:20249315007",
-	"version": "648",
+	"version": "649",
 	"evr": {
 		"text": "0:5.14.0-503.11.1.el9_5",
 		"datatype": "evr_string",
diff --git a/9/rhel-9-including-unpatched/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315008.json b/9/rhel-9-including-unpatched/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315008.json
index 5a06381..e9cfd85 100644
--- a/9/rhel-9-including-unpatched/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315008.json
+++ b/9/rhel-9-including-unpatched/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315008.json
@@ -1,6 +1,6 @@
 {
 	"id": "oval:com.redhat.rhsa:ste:20249315008",
-	"version": "648",
+	"version": "649",
 	"evr": {
 		"text": "0:5.14.0-503.11.1.el9_5",
 		"datatype": "evr_string",
diff --git a/9/rhel-9-including-unpatched/states/textfilecontent54_state/oval:com.redhat.rhsa:ste:20249315010.json b/9/rhel-9-including-unpatched/states/textfilecontent54_state/oval:com.redhat.rhsa:ste:20249315010.json
index c6d8284..9e8ec88 100644
--- a/9/rhel-9-including-unpatched/states/textfilecontent54_state/oval:com.redhat.rhsa:ste:20249315010.json
+++ b/9/rhel-9-including-unpatched/states/textfilecontent54_state/oval:com.redhat.rhsa:ste:20249315010.json
@@ -1,8 +1,8 @@
 {
 	"id": "oval:com.redhat.rhsa:ste:20249315010",
-	"version": "648",
+	"version": "649",
 	"text": {
-		"text": "\\(([0-4]\\.\\d+\\.\\d+-)|(5\\.([0-9]|1[0-3])\\.\\d+-)|(5\\.14\\.0-([0-9]{1,2}|[1-4][0-9]{2}|50[0-2])\\.)|(5\\.14\\.0-503\\.[^\\.]*[a-zA-Z])|(5\\.14\\.0-503\\.([0-9]|10)\\.)|(5\\.14\\.0-503\\.11\\.[^\\.]*[a-zA-Z])|(5\\.14\\.0-503\\.11\\.0\\.)",
+		"text": "([0-4]\\.\\d+\\.\\d+-)|(5\\.([0-9]|1[0-3])\\.\\d+-)|(5\\.14\\.0-([0-9]{1,2}|[1-4][0-9]{2}|50[0-2])\\.)|(5\\.14\\.0-503\\.[^\\.]*[a-zA-Z])|(5\\.14\\.0-503\\.([0-9]|10)\\.)|(5\\.14\\.0-503\\.11\\.[^\\.]*[a-zA-Z])|(5\\.14\\.0-503\\.11\\.0\\.)",
 		"operation": "pattern match"
 	}
 }
diff --git a/9/rhel-9-including-unpatched/states/uname_state/oval:com.redhat.rhsa:ste:20249315009.json b/9/rhel-9-including-unpatched/states/uname_state/oval:com.redhat.rhsa:ste:20249315009.json
index 2f3b1ed..193ea0d 100644
--- a/9/rhel-9-including-unpatched/states/uname_state/oval:com.redhat.rhsa:ste:20249315009.json
+++ b/9/rhel-9-including-unpatched/states/uname_state/oval:com.redhat.rhsa:ste:20249315009.json
@@ -1,6 +1,6 @@
 {
 	"id": "oval:com.redhat.rhsa:ste:20249315009",
-	"version": "648",
+	"version": "649",
 	"os_release": {
 		"text": "([0-4]\\.\\d+\\.\\d+-)|(5\\.([0-9]|1[0-3])\\.\\d+-)|(5\\.14\\.0-([0-9]{1,2}|[1-4][0-9]{2}|50[0-2])\\.)|(5\\.14\\.0-503\\.[^\\.]*[a-zA-Z])|(5\\.14\\.0-503\\.([0-9]|10)\\.)|(5\\.14\\.0-503\\.11\\.[^\\.]*[a-zA-Z])|(5\\.14\\.0-503\\.11\\.0\\.)",
 		"operation": "pattern match"
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315001.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315001.json
index 76eb137..cf3135a 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315001.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315001.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "bpftool is earlier than 0:7.4.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315001",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089015"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315003.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315003.json
index ac252ac..f752380 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315003.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315003.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315003",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089003"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315005.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315005.json
index a657185..deffa6f 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315005.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315005.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-64k is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315005",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089048"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315007.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315007.json
index 0701fc0..787b41e 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315007.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315007.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-64k-core is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315007",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089009"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315009.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315009.json
index 335629e..0394f98 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315009.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315009.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-64k-debug is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315009",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089025"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315011.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315011.json
index 8ae9748..024874a 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315011.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315011.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-64k-debug-core is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315011",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089005"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315013.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315013.json
index e447e98..e802577 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315013.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315013.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-64k-debug-devel is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315013",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089011"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315015.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315015.json
index aa34bed..31ce544 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315015.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315015.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-64k-debug-devel-matched is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315015",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089034"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315017.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315017.json
index e09acbc..2c34d4f 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315017.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315017.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-64k-debug-modules is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315017",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089008"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315019.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315019.json
index ed2aad8..879213c 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315019.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315019.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-64k-debug-modules-core is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315019",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089031"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315021.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315021.json
index 017a806..f6f4e43 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315021.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315021.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-64k-debug-modules-extra is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315021",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089030"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315023.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315023.json
index 015525d..93071c1 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315023.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315023.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-64k-devel is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315023",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089047"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315025.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315025.json
index 496e40d..8c9a4c1 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315025.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315025.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-64k-devel-matched is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315025",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089033"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315027.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315027.json
index 63cad48..cb6270b 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315027.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315027.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-64k-modules is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315027",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089018"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315029.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315029.json
index cace1e8..fa88b92 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315029.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315029.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-64k-modules-core is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315029",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089028"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315031.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315031.json
index 42ccbb3..9c27140 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315031.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315031.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-64k-modules-extra is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315031",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089041"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315033.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315033.json
index e3ef259..356dcd4 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315033.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315033.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-abi-stablelists is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315033",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089046"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315035.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315035.json
index aa7a550..ff1e812 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315035.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315035.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-core is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315035",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089022"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315037.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315037.json
index a108914..13fb495 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315037.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315037.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-cross-headers is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315037",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089004"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315039.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315039.json
index 6677da9..b8253bd 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315039.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315039.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-debug is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315039",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089029"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315041.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315041.json
index 5f33d4b..15e9b49 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315041.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315041.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-debug-core is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315041",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089035"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315043.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315043.json
index b7a5539..078f1c2 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315043.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315043.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-debug-devel is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315043",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089014"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315045.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315045.json
index 226b5ae..8b63816 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315045.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315045.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-debug-devel-matched is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315045",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089043"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315047.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315047.json
index 2272736..14b2705 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315047.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315047.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-debug-modules is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315047",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089017"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315049.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315049.json
index 33b5cd9..6d2aae6 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315049.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315049.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-debug-modules-core is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315049",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089044"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315051.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315051.json
index 03bbe92..b2b9409 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315051.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315051.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-debug-modules-extra is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315051",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089019"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315053.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315053.json
index 10a8157..3744285 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315053.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315053.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-debug-uki-virt is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315053",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089021"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315055.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315055.json
index 86b9513..a53e923 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315055.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315055.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-devel is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315055",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089042"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315057.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315057.json
index 9cddcf6..3c171ad 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315057.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315057.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-devel-matched is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315057",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089016"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315059.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315059.json
index 1108179..4b455d0 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315059.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315059.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-doc is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315059",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089020"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315061.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315061.json
index 3ae0b9d..623dd29 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315061.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315061.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-headers is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315061",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089045"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315063.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315063.json
index a5d0547..ac83ac1 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315063.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315063.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-modules is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315063",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089032"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315065.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315065.json
index 058e931..36b467a 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315065.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315065.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-modules-core is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315065",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089024"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315067.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315067.json
index 5abe985..c35ab1e 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315067.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315067.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-modules-extra is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315067",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089036"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315069.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315069.json
index f593e40..3f1b1a1 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315069.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315069.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-rt is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315069",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201925162001"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315071.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315071.json
index b7893c1..c3c041e 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315071.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315071.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-rt-core is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315071",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201925162006"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315073.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315073.json
index b84093d..5302c20 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315073.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315073.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-rt-debug is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315073",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201925162021"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315075.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315075.json
index f4d6254..eea7e90 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315075.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315075.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-rt-debug-core is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315075",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201925162018"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315077.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315077.json
index cc10401..97052d5 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315077.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315077.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-rt-debug-devel is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315077",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201925162003"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315079.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315079.json
index e2d2358..355f47a 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315079.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315079.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-rt-debug-kvm is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315079",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201925162014"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315081.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315081.json
index d8c50c9..6e3889b 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315081.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315081.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-rt-debug-modules is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315081",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201925162020"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315083.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315083.json
index cdf798c..23ba8a7 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315083.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315083.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-rt-debug-modules-core is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315083",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201925162016"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315085.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315085.json
index a9216c4..d501432 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315085.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315085.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-rt-debug-modules-extra is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315085",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201925162015"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315087.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315087.json
index 2f4f9cf..3eb75da 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315087.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315087.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-rt-devel is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315087",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201925162008"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315089.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315089.json
index 02de707..af8df88 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315089.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315089.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-rt-kvm is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315089",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201925162012"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315091.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315091.json
index f7bb9dd..9d426a8 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315091.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315091.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-rt-modules is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315091",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201925162002"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315093.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315093.json
index b50fb09..78122c5 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315093.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315093.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-rt-modules-core is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315093",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201925162013"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315095.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315095.json
index 1f2d78a..9a2564d 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315095.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315095.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-rt-modules-extra is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315095",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201925162005"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315097.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315097.json
index 26aed61..90d3f15 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315097.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315097.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-tools is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315097",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089038"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315099.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315099.json
index d84668f..5cf7924 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315099.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315099.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-tools-libs is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315099",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089027"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315101.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315101.json
index 675605c..d265361 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315101.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315101.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-tools-libs-devel is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315101",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089001"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315103.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315103.json
index 203f622..f68d879 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315103.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315103.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-uki-virt is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315103",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089039"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315105.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315105.json
index 81b0879..d3ad6be 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315105.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315105.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-uki-virt-addons is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315105",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:202036781073"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315107.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315107.json
index 3e1362e..f9435ca 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315107.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315107.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-zfcpdump is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315107",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089002"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315109.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315109.json
index abdc899..05b18a4 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315109.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315109.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-zfcpdump-core is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315109",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089037"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315111.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315111.json
index 182bd76..fea6e16 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315111.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315111.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-zfcpdump-devel is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315111",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089007"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315113.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315113.json
index f59a97d..8c5df33 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315113.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315113.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-zfcpdump-devel-matched is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315113",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089012"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315115.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315115.json
index a55f43e..730adb6 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315115.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315115.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-zfcpdump-modules is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315115",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089026"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315117.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315117.json
index cc115f5..42458ba 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315117.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315117.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-zfcpdump-modules-core is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315117",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089010"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315119.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315119.json
index f1abf54..2615fd9 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315119.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315119.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "kernel-zfcpdump-modules-extra is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315119",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089040"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315121.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315121.json
index ca128ed..88a32c1 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315121.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315121.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "libperf is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315121",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:202010135045"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315123.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315123.json
index 497bf87..2054185 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315123.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315123.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "perf is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315123",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089023"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315125.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315125.json
index 903ab8e..4b4b7bf 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315125.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315125.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "python3-perf is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315125",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089006"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315127.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315127.json
index 36cd6bc..0b7ee0f 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315127.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315127.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "rtla is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315127",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089013"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315129.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315129.json
index 95922fa..8bf1446 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315129.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315129.json
@@ -2,7 +2,7 @@
 	"check": "at least one",
 	"comment": "rv is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315129",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:202010135013"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/textfilecontent54_test/oval:com.redhat.rhsa:tst:20249315132.json b/9/rhel-9-including-unpatched/tests/textfilecontent54_test/oval:com.redhat.rhsa:tst:20249315132.json
index 8a1d7c3..494de51 100644
--- a/9/rhel-9-including-unpatched/tests/textfilecontent54_test/oval:com.redhat.rhsa:tst:20249315132.json
+++ b/9/rhel-9-including-unpatched/tests/textfilecontent54_test/oval:com.redhat.rhsa:tst:20249315132.json
@@ -2,9 +2,9 @@
 	"check": "all",
 	"comment": "kernel earlier than 0:5.14.0-503.11.1.el9_5 is set to boot up on next boot",
 	"id": "oval:com.redhat.rhsa:tst:20249315132",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.rhsa:obj:20249315068"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983066"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315010"
diff --git a/9/rhel-9-including-unpatched/tests/uname_test/oval:com.redhat.rhsa:tst:20249315131.json b/9/rhel-9-including-unpatched/tests/uname_test/oval:com.redhat.rhsa:tst:20249315131.json
index 3b911e5..00fffb6 100644
--- a/9/rhel-9-including-unpatched/tests/uname_test/oval:com.redhat.rhsa:tst:20249315131.json
+++ b/9/rhel-9-including-unpatched/tests/uname_test/oval:com.redhat.rhsa:tst:20249315131.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel earlier than 0:5.14.0-503.11.1.el9_5 is currently running",
 	"id": "oval:com.redhat.rhsa:tst:20249315131",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.rhsa:obj:20225214003"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983065"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315009"
diff --git a/9/rhel-9/definitions/oval:com.redhat.rhsa:def:20249315.json b/9/rhel-9/definitions/oval:com.redhat.rhsa:def:20249315.json
index d59f905..ff5fc85 100644
--- a/9/rhel-9/definitions/oval:com.redhat.rhsa:def:20249315.json
+++ b/9/rhel-9/definitions/oval:com.redhat.rhsa:def:20249315.json
@@ -1,6 +1,6 @@
 {
 	"id": "oval:com.redhat.rhsa:def:20249315",
-	"version": "648",
+	"version": "649",
 	"class": "patch",
 	"metadata": {
 		"title": "RHSA-2024:9315: kernel security update (Moderate)",
@@ -780,6 +780,11 @@
 				"ref_url": "https://access.redhat.com/security/cve/CVE-2024-26733",
 				"source": "CVE"
 			},
+			{
+				"ref_id": "CVE-2024-26734",
+				"ref_url": "https://access.redhat.com/security/cve/CVE-2024-26734",
+				"source": "CVE"
+			},
 			{
 				"ref_id": "CVE-2024-26740",
 				"ref_url": "https://access.redhat.com/security/cve/CVE-2024-26740",
@@ -3620,6 +3625,14 @@
 					"impact": "moderate",
 					"public": "20240403"
 				},
+				{
+					"text": "CVE-2024-26734",
+					"cvss3": "5.5/CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
+					"cwe": "CWE-416",
+					"href": "https://access.redhat.com/security/cve/CVE-2024-26734",
+					"impact": "moderate",
+					"public": "20240403"
+				},
 				{
 					"text": "CVE-2024-26740",
 					"cvss3": "5.5/CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
@@ -5942,7 +5955,7 @@
 				},
 				{
 					"text": "CVE-2024-42301",
-					"cvss3": "5.5/CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
+					"cvss3": "7.1/CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
 					"href": "https://access.redhat.com/security/cve/CVE-2024-42301",
 					"impact": "moderate",
 					"public": "20240817"
@@ -6587,6 +6600,11 @@
 					"href": "https://bugzilla.redhat.com/2273242",
 					"id": "2273242"
 				},
+				{
+					"text": "kernel: devlink: fix possible use-after-free and memory leaks in devlink_init()",
+					"href": "https://bugzilla.redhat.com/2273244",
+					"id": "2273244"
+				},
 				{
 					"text": "kernel: arp: Prevent overflow in arp_req_get().",
 					"href": "https://bugzilla.redhat.com/2273247",
@@ -8579,7 +8597,7 @@
 										"comment": "bpftool is earlier than 0:7.4.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089030",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983002",
 										"comment": "bpftool is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8592,7 +8610,7 @@
 										"comment": "kernel is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089006",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983004",
 										"comment": "kernel is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8605,7 +8623,7 @@
 										"comment": "kernel-64k is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089096",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983006",
 										"comment": "kernel-64k is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8618,7 +8636,7 @@
 										"comment": "kernel-64k-core is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089018",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983008",
 										"comment": "kernel-64k-core is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8631,7 +8649,7 @@
 										"comment": "kernel-64k-debug is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089050",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983010",
 										"comment": "kernel-64k-debug is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8644,7 +8662,7 @@
 										"comment": "kernel-64k-debug-core is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089010",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983012",
 										"comment": "kernel-64k-debug-core is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8657,7 +8675,7 @@
 										"comment": "kernel-64k-debug-devel is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089022",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983014",
 										"comment": "kernel-64k-debug-devel is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8670,7 +8688,7 @@
 										"comment": "kernel-64k-debug-devel-matched is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089068",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983016",
 										"comment": "kernel-64k-debug-devel-matched is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8683,7 +8701,7 @@
 										"comment": "kernel-64k-debug-modules is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089016",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983018",
 										"comment": "kernel-64k-debug-modules is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8696,7 +8714,7 @@
 										"comment": "kernel-64k-debug-modules-core is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089062",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983020",
 										"comment": "kernel-64k-debug-modules-core is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8709,7 +8727,7 @@
 										"comment": "kernel-64k-debug-modules-extra is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089060",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983022",
 										"comment": "kernel-64k-debug-modules-extra is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8722,7 +8740,7 @@
 										"comment": "kernel-64k-devel is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089094",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983024",
 										"comment": "kernel-64k-devel is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8735,7 +8753,7 @@
 										"comment": "kernel-64k-devel-matched is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089066",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983026",
 										"comment": "kernel-64k-devel-matched is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8748,7 +8766,7 @@
 										"comment": "kernel-64k-modules is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089036",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983028",
 										"comment": "kernel-64k-modules is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8761,7 +8779,7 @@
 										"comment": "kernel-64k-modules-core is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089056",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983030",
 										"comment": "kernel-64k-modules-core is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8774,7 +8792,7 @@
 										"comment": "kernel-64k-modules-extra is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089082",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983032",
 										"comment": "kernel-64k-modules-extra is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8787,7 +8805,7 @@
 										"comment": "kernel-abi-stablelists is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089092",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983034",
 										"comment": "kernel-abi-stablelists is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8800,7 +8818,7 @@
 										"comment": "kernel-core is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089044",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983036",
 										"comment": "kernel-core is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8813,7 +8831,7 @@
 										"comment": "kernel-cross-headers is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089008",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983038",
 										"comment": "kernel-cross-headers is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8826,7 +8844,7 @@
 										"comment": "kernel-debug is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089058",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983040",
 										"comment": "kernel-debug is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8839,7 +8857,7 @@
 										"comment": "kernel-debug-core is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089070",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983042",
 										"comment": "kernel-debug-core is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8852,7 +8870,7 @@
 										"comment": "kernel-debug-devel is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089028",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983044",
 										"comment": "kernel-debug-devel is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8865,7 +8883,7 @@
 										"comment": "kernel-debug-devel-matched is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089086",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983046",
 										"comment": "kernel-debug-devel-matched is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8878,7 +8896,7 @@
 										"comment": "kernel-debug-modules is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089034",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983048",
 										"comment": "kernel-debug-modules is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8891,7 +8909,7 @@
 										"comment": "kernel-debug-modules-core is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089088",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983050",
 										"comment": "kernel-debug-modules-core is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8904,7 +8922,7 @@
 										"comment": "kernel-debug-modules-extra is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089038",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983052",
 										"comment": "kernel-debug-modules-extra is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8917,7 +8935,7 @@
 										"comment": "kernel-debug-uki-virt is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089042",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983054",
 										"comment": "kernel-debug-uki-virt is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8930,7 +8948,7 @@
 										"comment": "kernel-devel is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089084",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983056",
 										"comment": "kernel-devel is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8943,7 +8961,7 @@
 										"comment": "kernel-devel-matched is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089032",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983058",
 										"comment": "kernel-devel-matched is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8956,7 +8974,7 @@
 										"comment": "kernel-doc is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089040",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983060",
 										"comment": "kernel-doc is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8969,7 +8987,7 @@
 										"comment": "kernel-headers is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089090",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983062",
 										"comment": "kernel-headers is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8982,7 +9000,7 @@
 										"comment": "kernel-modules is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089064",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983064",
 										"comment": "kernel-modules is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8995,7 +9013,7 @@
 										"comment": "kernel-modules-core is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089048",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983066",
 										"comment": "kernel-modules-core is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9008,7 +9026,7 @@
 										"comment": "kernel-modules-extra is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089072",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983068",
 										"comment": "kernel-modules-extra is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9021,7 +9039,7 @@
 										"comment": "kernel-rt is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162002",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983070",
 										"comment": "kernel-rt is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9034,7 +9052,7 @@
 										"comment": "kernel-rt-core is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162012",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983072",
 										"comment": "kernel-rt-core is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9047,7 +9065,7 @@
 										"comment": "kernel-rt-debug is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162042",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983074",
 										"comment": "kernel-rt-debug is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9060,7 +9078,7 @@
 										"comment": "kernel-rt-debug-core is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162036",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983076",
 										"comment": "kernel-rt-debug-core is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9073,7 +9091,7 @@
 										"comment": "kernel-rt-debug-devel is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162006",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983078",
 										"comment": "kernel-rt-debug-devel is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9086,7 +9104,7 @@
 										"comment": "kernel-rt-debug-kvm is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162028",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983080",
 										"comment": "kernel-rt-debug-kvm is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9099,7 +9117,7 @@
 										"comment": "kernel-rt-debug-modules is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162040",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983082",
 										"comment": "kernel-rt-debug-modules is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9112,7 +9130,7 @@
 										"comment": "kernel-rt-debug-modules-core is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162032",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983084",
 										"comment": "kernel-rt-debug-modules-core is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9125,7 +9143,7 @@
 										"comment": "kernel-rt-debug-modules-extra is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162030",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983086",
 										"comment": "kernel-rt-debug-modules-extra is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9138,7 +9156,7 @@
 										"comment": "kernel-rt-devel is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162016",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983088",
 										"comment": "kernel-rt-devel is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9151,7 +9169,7 @@
 										"comment": "kernel-rt-kvm is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162024",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983090",
 										"comment": "kernel-rt-kvm is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9164,7 +9182,7 @@
 										"comment": "kernel-rt-modules is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162004",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983092",
 										"comment": "kernel-rt-modules is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9177,7 +9195,7 @@
 										"comment": "kernel-rt-modules-core is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162026",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983094",
 										"comment": "kernel-rt-modules-core is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9190,7 +9208,7 @@
 										"comment": "kernel-rt-modules-extra is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162010",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983096",
 										"comment": "kernel-rt-modules-extra is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9203,7 +9221,7 @@
 										"comment": "kernel-tools is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089076",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983098",
 										"comment": "kernel-tools is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9216,7 +9234,7 @@
 										"comment": "kernel-tools-libs is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089054",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983100",
 										"comment": "kernel-tools-libs is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9229,7 +9247,7 @@
 										"comment": "kernel-tools-libs-devel is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089002",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983102",
 										"comment": "kernel-tools-libs-devel is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9242,7 +9260,7 @@
 										"comment": "kernel-uki-virt is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089078",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983104",
 										"comment": "kernel-uki-virt is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9255,7 +9273,7 @@
 										"comment": "kernel-uki-virt-addons is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:202036781146",
+										"test_ref": "oval:com.redhat.rhsa:tst:202410274106",
 										"comment": "kernel-uki-virt-addons is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9268,7 +9286,7 @@
 										"comment": "kernel-zfcpdump is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089004",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983106",
 										"comment": "kernel-zfcpdump is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9281,7 +9299,7 @@
 										"comment": "kernel-zfcpdump-core is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089074",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983108",
 										"comment": "kernel-zfcpdump-core is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9294,7 +9312,7 @@
 										"comment": "kernel-zfcpdump-devel is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089014",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983110",
 										"comment": "kernel-zfcpdump-devel is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9307,7 +9325,7 @@
 										"comment": "kernel-zfcpdump-devel-matched is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089024",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983112",
 										"comment": "kernel-zfcpdump-devel-matched is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9320,7 +9338,7 @@
 										"comment": "kernel-zfcpdump-modules is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089052",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983114",
 										"comment": "kernel-zfcpdump-modules is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9333,7 +9351,7 @@
 										"comment": "kernel-zfcpdump-modules-core is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089020",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983116",
 										"comment": "kernel-zfcpdump-modules-core is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9346,7 +9364,7 @@
 										"comment": "kernel-zfcpdump-modules-extra is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089080",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983118",
 										"comment": "kernel-zfcpdump-modules-extra is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9359,7 +9377,7 @@
 										"comment": "libperf is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:202010135090",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983120",
 										"comment": "libperf is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9372,7 +9390,7 @@
 										"comment": "perf is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089046",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983122",
 										"comment": "perf is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9385,7 +9403,7 @@
 										"comment": "python3-perf is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089012",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983124",
 										"comment": "python3-perf is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9398,7 +9416,7 @@
 										"comment": "rtla is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089026",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983126",
 										"comment": "rtla is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9411,7 +9429,7 @@
 										"comment": "rv is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:202010135026",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983128",
 										"comment": "rv is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9421,7 +9439,7 @@
 				],
 				"criterions": [
 					{
-						"test_ref": "oval:com.redhat.cve:tst:20052541003",
+						"test_ref": "oval:com.redhat.rhba:tst:20223893007",
 						"comment": "Red Hat Enterprise Linux 9 is installed"
 					}
 				]
@@ -9429,7 +9447,7 @@
 		],
 		"criterions": [
 			{
-				"test_ref": "oval:com.redhat.cve:tst:20052541004",
+				"test_ref": "oval:com.redhat.rhba:tst:20223893008",
 				"comment": "Red Hat Enterprise Linux must be installed"
 			}
 		]
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983001.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983001.json
new file mode 100644
index 0000000..decb53f
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983001.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983001",
+	"version": "637",
+	"Name": "bpftool"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983002.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983002.json
new file mode 100644
index 0000000..8872b6d
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983002.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983002",
+	"version": "637",
+	"Name": "kernel"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983003.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983003.json
new file mode 100644
index 0000000..31140bd
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983003.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983003",
+	"version": "637",
+	"Name": "kernel-64k"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983004.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983004.json
new file mode 100644
index 0000000..ddd3b36
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983004.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983004",
+	"version": "637",
+	"Name": "kernel-64k-core"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983005.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983005.json
new file mode 100644
index 0000000..d3da575
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983005.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983005",
+	"version": "637",
+	"Name": "kernel-64k-debug"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983006.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983006.json
new file mode 100644
index 0000000..7dd6e8e
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983006.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983006",
+	"version": "637",
+	"Name": "kernel-64k-debug-core"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983007.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983007.json
new file mode 100644
index 0000000..2199e79
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983007.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983007",
+	"version": "637",
+	"Name": "kernel-64k-debug-devel"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983008.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983008.json
new file mode 100644
index 0000000..19a9b85
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983008.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983008",
+	"version": "637",
+	"Name": "kernel-64k-debug-devel-matched"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983009.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983009.json
new file mode 100644
index 0000000..364ece6
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983009.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983009",
+	"version": "637",
+	"Name": "kernel-64k-debug-modules"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983010.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983010.json
new file mode 100644
index 0000000..39e45a0
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983010.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983010",
+	"version": "637",
+	"Name": "kernel-64k-debug-modules-core"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983011.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983011.json
new file mode 100644
index 0000000..6e45dfe
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983011.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983011",
+	"version": "637",
+	"Name": "kernel-64k-debug-modules-extra"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983012.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983012.json
new file mode 100644
index 0000000..ee626b2
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983012.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983012",
+	"version": "637",
+	"Name": "kernel-64k-devel"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983013.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983013.json
new file mode 100644
index 0000000..46ea168
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983013.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983013",
+	"version": "637",
+	"Name": "kernel-64k-devel-matched"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983014.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983014.json
new file mode 100644
index 0000000..de9c2fa
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983014.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983014",
+	"version": "637",
+	"Name": "kernel-64k-modules"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983015.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983015.json
new file mode 100644
index 0000000..f46c78a
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983015.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983015",
+	"version": "637",
+	"Name": "kernel-64k-modules-core"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983016.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983016.json
new file mode 100644
index 0000000..59a7913
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983016.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983016",
+	"version": "637",
+	"Name": "kernel-64k-modules-extra"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983017.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983017.json
new file mode 100644
index 0000000..35ae8d2
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983017.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983017",
+	"version": "637",
+	"Name": "kernel-abi-stablelists"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983018.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983018.json
new file mode 100644
index 0000000..ef90031
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983018.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983018",
+	"version": "637",
+	"Name": "kernel-core"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983019.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983019.json
new file mode 100644
index 0000000..6ba7831
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983019.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983019",
+	"version": "637",
+	"Name": "kernel-cross-headers"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983020.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983020.json
new file mode 100644
index 0000000..cfa13a0
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983020.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983020",
+	"version": "637",
+	"Name": "kernel-debug"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983021.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983021.json
new file mode 100644
index 0000000..44651f9
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983021.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983021",
+	"version": "637",
+	"Name": "kernel-debug-core"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983022.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983022.json
new file mode 100644
index 0000000..8ef5d74
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983022.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983022",
+	"version": "637",
+	"Name": "kernel-debug-devel"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983023.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983023.json
new file mode 100644
index 0000000..faaa67f
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983023.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983023",
+	"version": "637",
+	"Name": "kernel-debug-devel-matched"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983024.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983024.json
new file mode 100644
index 0000000..51df63f
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983024.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983024",
+	"version": "637",
+	"Name": "kernel-debug-modules"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983025.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983025.json
new file mode 100644
index 0000000..3c79c43
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983025.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983025",
+	"version": "637",
+	"Name": "kernel-debug-modules-core"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983026.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983026.json
new file mode 100644
index 0000000..fc3533a
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983026.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983026",
+	"version": "637",
+	"Name": "kernel-debug-modules-extra"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983027.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983027.json
new file mode 100644
index 0000000..6a8601a
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983027.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983027",
+	"version": "637",
+	"Name": "kernel-debug-uki-virt"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983028.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983028.json
new file mode 100644
index 0000000..7586ad3
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983028.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983028",
+	"version": "637",
+	"Name": "kernel-devel"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983029.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983029.json
new file mode 100644
index 0000000..31dd0b4
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983029.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983029",
+	"version": "637",
+	"Name": "kernel-devel-matched"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983030.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983030.json
new file mode 100644
index 0000000..8749df6
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983030.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983030",
+	"version": "637",
+	"Name": "kernel-doc"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983031.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983031.json
new file mode 100644
index 0000000..4e500f8
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983031.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983031",
+	"version": "637",
+	"Name": "kernel-headers"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983032.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983032.json
new file mode 100644
index 0000000..a849ed1
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983032.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983032",
+	"version": "637",
+	"Name": "kernel-modules"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983033.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983033.json
new file mode 100644
index 0000000..55c4e9a
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983033.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983033",
+	"version": "637",
+	"Name": "kernel-modules-core"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983034.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983034.json
new file mode 100644
index 0000000..c16036b
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983034.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983034",
+	"version": "637",
+	"Name": "kernel-modules-extra"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983035.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983035.json
new file mode 100644
index 0000000..d9433af
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983035.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983035",
+	"version": "637",
+	"Name": "kernel-rt"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983036.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983036.json
new file mode 100644
index 0000000..de0184d
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983036.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983036",
+	"version": "637",
+	"Name": "kernel-rt-core"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983037.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983037.json
new file mode 100644
index 0000000..f38dc7e
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983037.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983037",
+	"version": "637",
+	"Name": "kernel-rt-debug"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983038.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983038.json
new file mode 100644
index 0000000..6e2f1ed
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983038.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983038",
+	"version": "637",
+	"Name": "kernel-rt-debug-core"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983039.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983039.json
new file mode 100644
index 0000000..2e9177e
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983039.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983039",
+	"version": "637",
+	"Name": "kernel-rt-debug-devel"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983040.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983040.json
new file mode 100644
index 0000000..9a7a265
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983040.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983040",
+	"version": "637",
+	"Name": "kernel-rt-debug-kvm"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983041.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983041.json
new file mode 100644
index 0000000..39158ad
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983041.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983041",
+	"version": "637",
+	"Name": "kernel-rt-debug-modules"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983042.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983042.json
new file mode 100644
index 0000000..d179d41
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983042.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983042",
+	"version": "637",
+	"Name": "kernel-rt-debug-modules-core"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983043.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983043.json
new file mode 100644
index 0000000..36527da
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983043.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983043",
+	"version": "637",
+	"Name": "kernel-rt-debug-modules-extra"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983044.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983044.json
new file mode 100644
index 0000000..7472d58
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983044.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983044",
+	"version": "637",
+	"Name": "kernel-rt-devel"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983045.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983045.json
new file mode 100644
index 0000000..471d42c
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983045.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983045",
+	"version": "637",
+	"Name": "kernel-rt-kvm"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983046.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983046.json
new file mode 100644
index 0000000..1a45541
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983046.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983046",
+	"version": "637",
+	"Name": "kernel-rt-modules"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983047.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983047.json
new file mode 100644
index 0000000..47f90f6
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983047.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983047",
+	"version": "637",
+	"Name": "kernel-rt-modules-core"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983048.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983048.json
new file mode 100644
index 0000000..8d0fe98
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983048.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983048",
+	"version": "637",
+	"Name": "kernel-rt-modules-extra"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983049.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983049.json
new file mode 100644
index 0000000..8bfbd01
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983049.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983049",
+	"version": "637",
+	"Name": "kernel-tools"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983050.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983050.json
new file mode 100644
index 0000000..857b783
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983050.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983050",
+	"version": "637",
+	"Name": "kernel-tools-libs"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983051.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983051.json
new file mode 100644
index 0000000..bafc60c
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983051.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983051",
+	"version": "637",
+	"Name": "kernel-tools-libs-devel"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983052.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983052.json
new file mode 100644
index 0000000..e3ab47c
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983052.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983052",
+	"version": "637",
+	"Name": "kernel-uki-virt"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983053.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983053.json
new file mode 100644
index 0000000..005f06f
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983053.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983053",
+	"version": "637",
+	"Name": "kernel-zfcpdump"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983054.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983054.json
new file mode 100644
index 0000000..813fb7c
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983054.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983054",
+	"version": "637",
+	"Name": "kernel-zfcpdump-core"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983055.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983055.json
new file mode 100644
index 0000000..8e5bb23
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983055.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983055",
+	"version": "637",
+	"Name": "kernel-zfcpdump-devel"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983056.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983056.json
new file mode 100644
index 0000000..606564f
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983056.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983056",
+	"version": "637",
+	"Name": "kernel-zfcpdump-devel-matched"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983057.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983057.json
new file mode 100644
index 0000000..c9bd731
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983057.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983057",
+	"version": "637",
+	"Name": "kernel-zfcpdump-modules"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983058.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983058.json
new file mode 100644
index 0000000..dda2bd9
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983058.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983058",
+	"version": "637",
+	"Name": "kernel-zfcpdump-modules-core"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983059.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983059.json
new file mode 100644
index 0000000..fca225a
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983059.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983059",
+	"version": "637",
+	"Name": "kernel-zfcpdump-modules-extra"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983060.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983060.json
new file mode 100644
index 0000000..c97f429
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983060.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983060",
+	"version": "637",
+	"Name": "libperf"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983061.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983061.json
new file mode 100644
index 0000000..6a64f3f
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983061.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983061",
+	"version": "637",
+	"Name": "perf"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983062.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983062.json
new file mode 100644
index 0000000..409f17d
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983062.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983062",
+	"version": "637",
+	"Name": "python3-perf"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983063.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983063.json
new file mode 100644
index 0000000..c5c69ec
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983063.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983063",
+	"version": "637",
+	"Name": "rtla"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983064.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983064.json
new file mode 100644
index 0000000..a333d96
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhba:obj:20243983064.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983064",
+	"version": "637",
+	"Name": "rv"
+}
diff --git a/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhsa:obj:202410274053.json b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhsa:obj:202410274053.json
new file mode 100644
index 0000000..b3b5862
--- /dev/null
+++ b/9/rhel-9/objects/rpminfo_object/oval:com.redhat.rhsa:obj:202410274053.json
@@ -0,0 +1,5 @@
+{
+	"id": "oval:com.redhat.rhsa:obj:202410274053",
+	"version": "637",
+	"Name": "kernel-uki-virt-addons"
+}
diff --git a/9/rhel-9/objects/rpmverifyfile_object/oval:com.redhat.rhba:obj:20223893004.json b/9/rhel-9/objects/rpmverifyfile_object/oval:com.redhat.rhba:obj:20223893004.json
new file mode 100644
index 0000000..bac63de
--- /dev/null
+++ b/9/rhel-9/objects/rpmverifyfile_object/oval:com.redhat.rhba:obj:20223893004.json
@@ -0,0 +1,32 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20223893004",
+	"attr_version": "635",
+	"behaviors": {
+		"noconfigfiles": "true",
+		"noghostfiles": "true",
+		"nogroup": "true",
+		"nolinkto": "true",
+		"nomd5": "true",
+		"nomode": "true",
+		"nomtime": "true",
+		"nordev": "true",
+		"nosize": "true",
+		"nouser": "true"
+	},
+	"name": {
+		"operation": "pattern match"
+	},
+	"epoch": {
+		"operation": "pattern match"
+	},
+	"version": {
+		"operation": "pattern match"
+	},
+	"release": {
+		"operation": "pattern match"
+	},
+	"arch": {
+		"operation": "pattern match"
+	},
+	"Filepath": "/etc/redhat-release"
+}
diff --git a/9/rhel-9/objects/textfilecontent54_object/oval:com.redhat.rhba:obj:20243983066.json b/9/rhel-9/objects/textfilecontent54_object/oval:com.redhat.rhba:obj:20243983066.json
new file mode 100644
index 0000000..f54b7bc
--- /dev/null
+++ b/9/rhel-9/objects/textfilecontent54_object/oval:com.redhat.rhba:obj:20243983066.json
@@ -0,0 +1,16 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983066",
+	"version": "637",
+	"filepath": {
+		"text": "/boot/grub2/grubenv",
+		"datatype": "string"
+	},
+	"pattern": {
+		"text": "(?<=^saved_entry=).*",
+		"operation": "pattern match"
+	},
+	"instance": {
+		"text": "1",
+		"datatype": "int"
+	}
+}
diff --git a/9/rhel-9/objects/uname_object/oval:com.redhat.rhba:obj:20243983065.json b/9/rhel-9/objects/uname_object/oval:com.redhat.rhba:obj:20243983065.json
new file mode 100644
index 0000000..e1da94b
--- /dev/null
+++ b/9/rhel-9/objects/uname_object/oval:com.redhat.rhba:obj:20243983065.json
@@ -0,0 +1,4 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983065",
+	"version": "637"
+}
diff --git a/9/rhel-9/states/rpminfo_state/oval:com.redhat.rhba:ste:20223893002.json b/9/rhel-9/states/rpminfo_state/oval:com.redhat.rhba:ste:20223893002.json
new file mode 100644
index 0000000..65dcbca
--- /dev/null
+++ b/9/rhel-9/states/rpminfo_state/oval:com.redhat.rhba:ste:20223893002.json
@@ -0,0 +1,8 @@
+{
+	"id": "oval:com.redhat.rhba:ste:20223893002",
+	"version": "635",
+	"signature_keyid": {
+		"text": "199e2f91fd431d51",
+		"operation": "equals"
+	}
+}
diff --git a/9/rhel-9/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315001.json b/9/rhel-9/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315001.json
index 901d935..5ceb0de 100644
--- a/9/rhel-9/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315001.json
+++ b/9/rhel-9/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315001.json
@@ -1,6 +1,6 @@
 {
 	"id": "oval:com.redhat.rhsa:ste:20249315001",
-	"version": "648",
+	"version": "649",
 	"evr": {
 		"text": "0:7.4.0-503.11.1.el9_5",
 		"datatype": "evr_string",
diff --git a/9/rhel-9/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315003.json b/9/rhel-9/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315003.json
index b252110..f2afdf6 100644
--- a/9/rhel-9/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315003.json
+++ b/9/rhel-9/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315003.json
@@ -1,6 +1,6 @@
 {
 	"id": "oval:com.redhat.rhsa:ste:20249315003",
-	"version": "648",
+	"version": "649",
 	"evr": {
 		"text": "0:5.14.0-503.11.1.el9_5",
 		"datatype": "evr_string",
diff --git a/9/rhel-9/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315004.json b/9/rhel-9/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315004.json
index 9c689bb..ed0b4f4 100644
--- a/9/rhel-9/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315004.json
+++ b/9/rhel-9/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315004.json
@@ -1,6 +1,6 @@
 {
 	"id": "oval:com.redhat.rhsa:ste:20249315004",
-	"version": "648",
+	"version": "649",
 	"evr": {
 		"text": "0:5.14.0-503.11.1.el9_5",
 		"datatype": "evr_string",
diff --git a/9/rhel-9/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315005.json b/9/rhel-9/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315005.json
index b802194..a4d831d 100644
--- a/9/rhel-9/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315005.json
+++ b/9/rhel-9/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315005.json
@@ -1,6 +1,6 @@
 {
 	"id": "oval:com.redhat.rhsa:ste:20249315005",
-	"version": "648",
+	"version": "649",
 	"evr": {
 		"text": "0:5.14.0-503.11.1.el9_5",
 		"datatype": "evr_string",
diff --git a/9/rhel-9/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315006.json b/9/rhel-9/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315006.json
index 57042d4..cf93b71 100644
--- a/9/rhel-9/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315006.json
+++ b/9/rhel-9/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315006.json
@@ -1,6 +1,6 @@
 {
 	"id": "oval:com.redhat.rhsa:ste:20249315006",
-	"version": "648",
+	"version": "649",
 	"evr": {
 		"text": "0:5.14.0-503.11.1.el9_5",
 		"datatype": "evr_string",
diff --git a/9/rhel-9/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315007.json b/9/rhel-9/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315007.json
index d4e8713..c3edea8 100644
--- a/9/rhel-9/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315007.json
+++ b/9/rhel-9/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315007.json
@@ -1,6 +1,6 @@
 {
 	"id": "oval:com.redhat.rhsa:ste:20249315007",
-	"version": "648",
+	"version": "649",
 	"evr": {
 		"text": "0:5.14.0-503.11.1.el9_5",
 		"datatype": "evr_string",
diff --git a/9/rhel-9/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315008.json b/9/rhel-9/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315008.json
index 5a06381..e9cfd85 100644
--- a/9/rhel-9/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315008.json
+++ b/9/rhel-9/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315008.json
@@ -1,6 +1,6 @@
 {
 	"id": "oval:com.redhat.rhsa:ste:20249315008",
-	"version": "648",
+	"version": "649",
 	"evr": {
 		"text": "0:5.14.0-503.11.1.el9_5",
 		"datatype": "evr_string",
diff --git a/9/rhel-9/states/rpmverifyfile_state/oval:com.redhat.rhba:ste:20223893004.json b/9/rhel-9/states/rpmverifyfile_state/oval:com.redhat.rhba:ste:20223893004.json
new file mode 100644
index 0000000..fc4177a
--- /dev/null
+++ b/9/rhel-9/states/rpmverifyfile_state/oval:com.redhat.rhba:ste:20223893004.json
@@ -0,0 +1,12 @@
+{
+	"id": "oval:com.redhat.rhba:ste:20223893004",
+	"attr_version": "635",
+	"name": {
+		"text": "^redhat-release",
+		"operation": "pattern match"
+	},
+	"version": {
+		"text": "^9[^\\d]",
+		"operation": "pattern match"
+	}
+}
diff --git a/9/rhel-9/states/rpmverifyfile_state/oval:com.redhat.rhba:ste:20223893005.json b/9/rhel-9/states/rpmverifyfile_state/oval:com.redhat.rhba:ste:20223893005.json
new file mode 100644
index 0000000..b388e83
--- /dev/null
+++ b/9/rhel-9/states/rpmverifyfile_state/oval:com.redhat.rhba:ste:20223893005.json
@@ -0,0 +1,9 @@
+{
+	"id": "oval:com.redhat.rhba:ste:20223893005",
+	"attr_version": "635",
+	"name": {
+		"text": "^redhat-release",
+		"operation": "pattern match"
+	},
+	"version": {}
+}
diff --git a/9/rhel-9/states/textfilecontent54_state/oval:com.redhat.rhsa:ste:20249315010.json b/9/rhel-9/states/textfilecontent54_state/oval:com.redhat.rhsa:ste:20249315010.json
index c6d8284..9e8ec88 100644
--- a/9/rhel-9/states/textfilecontent54_state/oval:com.redhat.rhsa:ste:20249315010.json
+++ b/9/rhel-9/states/textfilecontent54_state/oval:com.redhat.rhsa:ste:20249315010.json
@@ -1,8 +1,8 @@
 {
 	"id": "oval:com.redhat.rhsa:ste:20249315010",
-	"version": "648",
+	"version": "649",
 	"text": {
-		"text": "\\(([0-4]\\.\\d+\\.\\d+-)|(5\\.([0-9]|1[0-3])\\.\\d+-)|(5\\.14\\.0-([0-9]{1,2}|[1-4][0-9]{2}|50[0-2])\\.)|(5\\.14\\.0-503\\.[^\\.]*[a-zA-Z])|(5\\.14\\.0-503\\.([0-9]|10)\\.)|(5\\.14\\.0-503\\.11\\.[^\\.]*[a-zA-Z])|(5\\.14\\.0-503\\.11\\.0\\.)",
+		"text": "([0-4]\\.\\d+\\.\\d+-)|(5\\.([0-9]|1[0-3])\\.\\d+-)|(5\\.14\\.0-([0-9]{1,2}|[1-4][0-9]{2}|50[0-2])\\.)|(5\\.14\\.0-503\\.[^\\.]*[a-zA-Z])|(5\\.14\\.0-503\\.([0-9]|10)\\.)|(5\\.14\\.0-503\\.11\\.[^\\.]*[a-zA-Z])|(5\\.14\\.0-503\\.11\\.0\\.)",
 		"operation": "pattern match"
 	}
 }
diff --git a/9/rhel-9/states/uname_state/oval:com.redhat.rhsa:ste:20249315009.json b/9/rhel-9/states/uname_state/oval:com.redhat.rhsa:ste:20249315009.json
index 2f3b1ed..193ea0d 100644
--- a/9/rhel-9/states/uname_state/oval:com.redhat.rhsa:ste:20249315009.json
+++ b/9/rhel-9/states/uname_state/oval:com.redhat.rhsa:ste:20249315009.json
@@ -1,6 +1,6 @@
 {
 	"id": "oval:com.redhat.rhsa:ste:20249315009",
-	"version": "648",
+	"version": "649",
 	"os_release": {
 		"text": "([0-4]\\.\\d+\\.\\d+-)|(5\\.([0-9]|1[0-3])\\.\\d+-)|(5\\.14\\.0-([0-9]{1,2}|[1-4][0-9]{2}|50[0-2])\\.)|(5\\.14\\.0-503\\.[^\\.]*[a-zA-Z])|(5\\.14\\.0-503\\.([0-9]|10)\\.)|(5\\.14\\.0-503\\.11\\.[^\\.]*[a-zA-Z])|(5\\.14\\.0-503\\.11\\.0\\.)",
 		"operation": "pattern match"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983002.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983002.json
new file mode 100644
index 0000000..110675d
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983002.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "bpftool is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983002",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983001"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983004.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983004.json
new file mode 100644
index 0000000..7db6d03
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983004.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983004",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983002"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983006.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983006.json
new file mode 100644
index 0000000..307de21
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983006.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-64k is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983006",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983003"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983008.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983008.json
new file mode 100644
index 0000000..f8af528
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983008.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-64k-core is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983008",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983004"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983010.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983010.json
new file mode 100644
index 0000000..d87125f
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983010.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-64k-debug is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983010",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983005"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983012.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983012.json
new file mode 100644
index 0000000..873eaf3
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983012.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-64k-debug-core is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983012",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983006"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983014.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983014.json
new file mode 100644
index 0000000..372e865
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983014.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-64k-debug-devel is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983014",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983007"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983016.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983016.json
new file mode 100644
index 0000000..cc53862
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983016.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-64k-debug-devel-matched is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983016",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983008"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983018.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983018.json
new file mode 100644
index 0000000..ee03d51
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983018.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-64k-debug-modules is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983018",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983009"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983020.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983020.json
new file mode 100644
index 0000000..a1b77bc
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983020.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-64k-debug-modules-core is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983020",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983010"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983022.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983022.json
new file mode 100644
index 0000000..e9e3660
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983022.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-64k-debug-modules-extra is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983022",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983011"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983024.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983024.json
new file mode 100644
index 0000000..ac926f5
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983024.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-64k-devel is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983024",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983012"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983026.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983026.json
new file mode 100644
index 0000000..789de88
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983026.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-64k-devel-matched is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983026",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983013"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983028.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983028.json
new file mode 100644
index 0000000..317c67a
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983028.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-64k-modules is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983028",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983014"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983030.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983030.json
new file mode 100644
index 0000000..64d3aee
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983030.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-64k-modules-core is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983030",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983015"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983032.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983032.json
new file mode 100644
index 0000000..feb2919
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983032.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-64k-modules-extra is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983032",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983016"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983034.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983034.json
new file mode 100644
index 0000000..2701726
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983034.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-abi-stablelists is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983034",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983017"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983036.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983036.json
new file mode 100644
index 0000000..032a639
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983036.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-core is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983036",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983018"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983038.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983038.json
new file mode 100644
index 0000000..ac94c33
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983038.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-cross-headers is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983038",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983019"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983040.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983040.json
new file mode 100644
index 0000000..55e4f8f
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983040.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-debug is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983040",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983020"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983042.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983042.json
new file mode 100644
index 0000000..c07ba28
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983042.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-debug-core is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983042",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983021"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983044.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983044.json
new file mode 100644
index 0000000..b1c708f
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983044.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-debug-devel is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983044",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983022"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983046.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983046.json
new file mode 100644
index 0000000..1588f3c
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983046.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-debug-devel-matched is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983046",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983023"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983048.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983048.json
new file mode 100644
index 0000000..41859ce
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983048.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-debug-modules is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983048",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983024"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983050.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983050.json
new file mode 100644
index 0000000..ece0a88
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983050.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-debug-modules-core is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983050",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983025"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983052.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983052.json
new file mode 100644
index 0000000..8a31b73
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983052.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-debug-modules-extra is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983052",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983026"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983054.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983054.json
new file mode 100644
index 0000000..460aa12
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983054.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-debug-uki-virt is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983054",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983027"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983056.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983056.json
new file mode 100644
index 0000000..2fb8cd7
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983056.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-devel is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983056",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983028"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983058.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983058.json
new file mode 100644
index 0000000..542cdb2
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983058.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-devel-matched is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983058",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983029"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983060.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983060.json
new file mode 100644
index 0000000..2787d29
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983060.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-doc is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983060",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983030"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983062.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983062.json
new file mode 100644
index 0000000..9848be6
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983062.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-headers is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983062",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983031"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983064.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983064.json
new file mode 100644
index 0000000..83b9a28
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983064.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-modules is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983064",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983032"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983066.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983066.json
new file mode 100644
index 0000000..8a6aa56
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983066.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-modules-core is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983066",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983033"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983068.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983068.json
new file mode 100644
index 0000000..9cc8318
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983068.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-modules-extra is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983068",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983034"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983070.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983070.json
new file mode 100644
index 0000000..6cf81c4
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983070.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-rt is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983070",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983035"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983072.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983072.json
new file mode 100644
index 0000000..4b1d02b
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983072.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-rt-core is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983072",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983036"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983074.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983074.json
new file mode 100644
index 0000000..661826d
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983074.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-rt-debug is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983074",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983037"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983076.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983076.json
new file mode 100644
index 0000000..1663ab6
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983076.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-rt-debug-core is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983076",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983038"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983078.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983078.json
new file mode 100644
index 0000000..33ce4b7
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983078.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-rt-debug-devel is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983078",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983039"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983080.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983080.json
new file mode 100644
index 0000000..ba23576
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983080.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-rt-debug-kvm is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983080",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983040"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983082.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983082.json
new file mode 100644
index 0000000..0e8d99b
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983082.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-rt-debug-modules is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983082",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983041"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983084.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983084.json
new file mode 100644
index 0000000..ec6c3ec
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983084.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-rt-debug-modules-core is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983084",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983042"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983086.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983086.json
new file mode 100644
index 0000000..e0c5916
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983086.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-rt-debug-modules-extra is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983086",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983043"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983088.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983088.json
new file mode 100644
index 0000000..38bdb6d
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983088.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-rt-devel is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983088",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983044"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983090.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983090.json
new file mode 100644
index 0000000..2b37cba
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983090.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-rt-kvm is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983090",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983045"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983092.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983092.json
new file mode 100644
index 0000000..3ed3fb1
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983092.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-rt-modules is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983092",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983046"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983094.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983094.json
new file mode 100644
index 0000000..f24c77b
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983094.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-rt-modules-core is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983094",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983047"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983096.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983096.json
new file mode 100644
index 0000000..38ad742
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983096.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-rt-modules-extra is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983096",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983048"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983098.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983098.json
new file mode 100644
index 0000000..93da34f
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983098.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-tools is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983098",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983049"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983100.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983100.json
new file mode 100644
index 0000000..71bfb4b
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983100.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-tools-libs is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983100",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983050"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983102.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983102.json
new file mode 100644
index 0000000..69843a0
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983102.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-tools-libs-devel is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983102",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983051"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983104.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983104.json
new file mode 100644
index 0000000..0c31d43
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983104.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-uki-virt is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983104",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983052"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983106.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983106.json
new file mode 100644
index 0000000..9ae0239
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983106.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-zfcpdump is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983106",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983053"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983108.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983108.json
new file mode 100644
index 0000000..149f12d
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983108.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-zfcpdump-core is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983108",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983054"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983110.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983110.json
new file mode 100644
index 0000000..59ef7d0
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983110.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-zfcpdump-devel is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983110",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983055"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983112.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983112.json
new file mode 100644
index 0000000..06d08f7
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983112.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-zfcpdump-devel-matched is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983112",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983056"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983114.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983114.json
new file mode 100644
index 0000000..fae56dc
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983114.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-zfcpdump-modules is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983114",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983057"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983116.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983116.json
new file mode 100644
index 0000000..4b2975f
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983116.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-zfcpdump-modules-core is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983116",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983058"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983118.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983118.json
new file mode 100644
index 0000000..29ddccb
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983118.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-zfcpdump-modules-extra is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983118",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983059"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983120.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983120.json
new file mode 100644
index 0000000..7cf3084
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983120.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "libperf is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983120",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983060"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983122.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983122.json
new file mode 100644
index 0000000..6f985cf
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983122.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "perf is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983122",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983061"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983124.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983124.json
new file mode 100644
index 0000000..e662b46
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983124.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "python3-perf is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983124",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983062"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983126.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983126.json
new file mode 100644
index 0000000..a0220dd
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983126.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "rtla is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983126",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983063"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983128.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983128.json
new file mode 100644
index 0000000..68dee3a
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhba:tst:20243983128.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "rv is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhba:tst:20243983128",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20243983064"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:202410274106.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:202410274106.json
new file mode 100644
index 0000000..6f820e3
--- /dev/null
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:202410274106.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "kernel-uki-virt-addons is signed with Red Hat redhatrelease2 key",
+	"id": "oval:com.redhat.rhsa:tst:202410274106",
+	"version": "637",
+	"object": {
+		"object_ref": "oval:com.redhat.rhsa:obj:202410274053"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893002"
+	}
+}
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315001.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315001.json
index 76eb137..dd71e29 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315001.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315001.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "bpftool is earlier than 0:7.4.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315001",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089015"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983001"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315001"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315003.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315003.json
index ac252ac..e84424e 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315003.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315003.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315003",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089003"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983002"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315003"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315005.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315005.json
index a657185..ab4642e 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315005.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315005.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-64k is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315005",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089048"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983003"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315004"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315007.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315007.json
index 0701fc0..edc4332 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315007.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315007.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-64k-core is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315007",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089009"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983004"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315004"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315009.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315009.json
index 335629e..61c74b8 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315009.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315009.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-64k-debug is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315009",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089025"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983005"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315004"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315011.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315011.json
index 8ae9748..fb82a29 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315011.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315011.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-64k-debug-core is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315011",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089005"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983006"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315004"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315013.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315013.json
index e447e98..9a6defd 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315013.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315013.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-64k-debug-devel is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315013",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089011"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983007"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315004"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315015.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315015.json
index aa34bed..dbf5186 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315015.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315015.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-64k-debug-devel-matched is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315015",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089034"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983008"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315004"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315017.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315017.json
index e09acbc..ac8c69b 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315017.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315017.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-64k-debug-modules is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315017",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089008"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983009"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315004"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315019.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315019.json
index ed2aad8..450c887 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315019.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315019.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-64k-debug-modules-core is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315019",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089031"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983010"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315004"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315021.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315021.json
index 017a806..3a4332b 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315021.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315021.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-64k-debug-modules-extra is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315021",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089030"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983011"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315004"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315023.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315023.json
index 015525d..4b6ea95 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315023.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315023.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-64k-devel is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315023",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089047"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983012"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315004"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315025.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315025.json
index 496e40d..6337bbd 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315025.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315025.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-64k-devel-matched is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315025",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089033"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983013"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315004"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315027.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315027.json
index 63cad48..dc9b0fb 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315027.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315027.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-64k-modules is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315027",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089018"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983014"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315004"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315029.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315029.json
index cace1e8..697cbf3 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315029.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315029.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-64k-modules-core is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315029",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089028"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983015"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315004"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315031.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315031.json
index 42ccbb3..964cbff 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315031.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315031.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-64k-modules-extra is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315031",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089041"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983016"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315004"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315033.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315033.json
index e3ef259..445e3e7 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315033.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315033.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-abi-stablelists is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315033",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089046"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983017"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315005"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315035.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315035.json
index aa7a550..6a2d800 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315035.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315035.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-core is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315035",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089022"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983018"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315003"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315037.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315037.json
index a108914..79b54b3 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315037.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315037.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-cross-headers is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315037",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089004"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983019"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315003"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315039.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315039.json
index 6677da9..67668e0 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315039.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315039.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-debug is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315039",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089029"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983020"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315003"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315041.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315041.json
index 5f33d4b..54d1390 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315041.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315041.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-debug-core is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315041",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089035"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983021"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315003"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315043.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315043.json
index b7a5539..6d7b749 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315043.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315043.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-debug-devel is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315043",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089014"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983022"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315003"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315045.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315045.json
index 226b5ae..4b958cb 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315045.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315045.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-debug-devel-matched is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315045",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089043"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983023"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315003"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315047.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315047.json
index 2272736..fdc1d45 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315047.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315047.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-debug-modules is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315047",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089017"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983024"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315003"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315049.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315049.json
index 33b5cd9..7dbd83c 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315049.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315049.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-debug-modules-core is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315049",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089044"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983025"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315003"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315051.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315051.json
index 03bbe92..ef51c94 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315051.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315051.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-debug-modules-extra is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315051",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089019"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983026"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315003"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315053.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315053.json
index 10a8157..508933c 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315053.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315053.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-debug-uki-virt is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315053",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089021"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983027"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315006"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315055.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315055.json
index 86b9513..97e6749 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315055.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315055.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-devel is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315055",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089042"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983028"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315003"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315057.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315057.json
index 9cddcf6..89cf029 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315057.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315057.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-devel-matched is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315057",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089016"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983029"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315003"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315059.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315059.json
index 1108179..ace2df6 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315059.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315059.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-doc is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315059",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089020"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983030"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315005"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315061.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315061.json
index 3ae0b9d..2317698 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315061.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315061.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-headers is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315061",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089045"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983031"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315003"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315063.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315063.json
index a5d0547..ee4a886 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315063.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315063.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-modules is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315063",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089032"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983032"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315003"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315065.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315065.json
index 058e931..776d426 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315065.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315065.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-modules-core is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315065",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089024"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983033"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315003"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315067.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315067.json
index 5abe985..0709282 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315067.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315067.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-modules-extra is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315067",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089036"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983034"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315003"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315069.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315069.json
index f593e40..2f68ab4 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315069.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315069.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-rt is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315069",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201925162001"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983035"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315006"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315071.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315071.json
index b7893c1..b3b339e 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315071.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315071.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-rt-core is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315071",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201925162006"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983036"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315006"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315073.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315073.json
index b84093d..b23322e 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315073.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315073.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-rt-debug is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315073",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201925162021"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983037"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315006"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315075.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315075.json
index f4d6254..f5289d8 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315075.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315075.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-rt-debug-core is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315075",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201925162018"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983038"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315006"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315077.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315077.json
index cc10401..e588b28 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315077.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315077.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-rt-debug-devel is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315077",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201925162003"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983039"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315006"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315079.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315079.json
index e2d2358..df5db81 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315079.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315079.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-rt-debug-kvm is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315079",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201925162014"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983040"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315006"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315081.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315081.json
index d8c50c9..b37a8ac 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315081.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315081.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-rt-debug-modules is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315081",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201925162020"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983041"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315006"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315083.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315083.json
index cdf798c..a1daca8 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315083.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315083.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-rt-debug-modules-core is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315083",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201925162016"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983042"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315006"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315085.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315085.json
index a9216c4..22b57fa 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315085.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315085.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-rt-debug-modules-extra is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315085",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201925162015"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983043"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315006"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315087.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315087.json
index 2f4f9cf..7ee0bdb 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315087.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315087.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-rt-devel is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315087",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201925162008"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983044"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315006"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315089.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315089.json
index 02de707..7d1369b 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315089.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315089.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-rt-kvm is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315089",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201925162012"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983045"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315006"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315091.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315091.json
index f7bb9dd..708fe3c 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315091.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315091.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-rt-modules is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315091",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201925162002"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983046"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315006"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315093.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315093.json
index b50fb09..3482a8a 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315093.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315093.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-rt-modules-core is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315093",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201925162013"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983047"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315006"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315095.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315095.json
index 1f2d78a..b1066f4 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315095.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315095.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-rt-modules-extra is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315095",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201925162005"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983048"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315006"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315097.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315097.json
index 26aed61..5ea360e 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315097.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315097.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-tools is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315097",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089038"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983049"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315003"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315099.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315099.json
index d84668f..c29a053 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315099.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315099.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-tools-libs is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315099",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089027"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983050"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315007"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315101.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315101.json
index 675605c..cd1e017 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315101.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315101.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-tools-libs-devel is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315101",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089001"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983051"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315007"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315103.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315103.json
index 203f622..012167f 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315103.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315103.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-uki-virt is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315103",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089039"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983052"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315006"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315105.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315105.json
index 81b0879..cb0b6b8 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315105.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315105.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-uki-virt-addons is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315105",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:202036781073"
+		"object_ref": "oval:com.redhat.rhsa:obj:202410274053"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315006"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315107.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315107.json
index 3e1362e..5474dbe 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315107.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315107.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-zfcpdump is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315107",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089002"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983053"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315008"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315109.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315109.json
index abdc899..a9c3834 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315109.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315109.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-zfcpdump-core is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315109",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089037"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983054"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315008"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315111.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315111.json
index 182bd76..f12003b 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315111.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315111.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-zfcpdump-devel is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315111",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089007"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983055"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315008"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315113.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315113.json
index f59a97d..c99ec85 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315113.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315113.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-zfcpdump-devel-matched is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315113",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089012"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983056"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315008"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315115.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315115.json
index a55f43e..7d94177 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315115.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315115.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-zfcpdump-modules is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315115",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089026"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983057"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315008"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315117.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315117.json
index cc115f5..5d071d3 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315117.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315117.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-zfcpdump-modules-core is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315117",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089010"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983058"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315008"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315119.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315119.json
index f1abf54..55d5fc1 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315119.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315119.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel-zfcpdump-modules-extra is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315119",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089040"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983059"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315008"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315121.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315121.json
index ca128ed..76f3764 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315121.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315121.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "libperf is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315121",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:202010135045"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983060"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315003"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315123.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315123.json
index 497bf87..a060e47 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315123.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315123.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "perf is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315123",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089023"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983061"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315003"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315125.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315125.json
index 903ab8e..554560e 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315125.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315125.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "python3-perf is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315125",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089006"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983062"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315003"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315127.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315127.json
index 36cd6bc..ecd4f1f 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315127.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315127.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "rtla is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315127",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:201916089013"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983063"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315003"
diff --git a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315129.json b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315129.json
index 95922fa..0390056 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315129.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315129.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "rv is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315129",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.cve:obj:202010135013"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983064"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315003"
diff --git a/9/rhel-9/tests/rpmverifyfile_test/oval:com.redhat.rhba:tst:20223893007.json b/9/rhel-9/tests/rpmverifyfile_test/oval:com.redhat.rhba:tst:20223893007.json
new file mode 100644
index 0000000..68aed09
--- /dev/null
+++ b/9/rhel-9/tests/rpmverifyfile_test/oval:com.redhat.rhba:tst:20223893007.json
@@ -0,0 +1,12 @@
+{
+	"check": "at least one",
+	"comment": "Red Hat Enterprise Linux 9 is installed",
+	"id": "oval:com.redhat.rhba:tst:20223893007",
+	"version": "635",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20223893004"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893004"
+	}
+}
diff --git a/9/rhel-9/tests/rpmverifyfile_test/oval:com.redhat.rhba:tst:20223893008.json b/9/rhel-9/tests/rpmverifyfile_test/oval:com.redhat.rhba:tst:20223893008.json
new file mode 100644
index 0000000..7519aac
--- /dev/null
+++ b/9/rhel-9/tests/rpmverifyfile_test/oval:com.redhat.rhba:tst:20223893008.json
@@ -0,0 +1,12 @@
+{
+	"check": "none satisfy",
+	"comment": "Red Hat Enterprise Linux must be installed",
+	"id": "oval:com.redhat.rhba:tst:20223893008",
+	"version": "635",
+	"object": {
+		"object_ref": "oval:com.redhat.rhba:obj:20223893004"
+	},
+	"state": {
+		"state_ref": "oval:com.redhat.rhba:ste:20223893005"
+	}
+}
diff --git a/9/rhel-9/tests/textfilecontent54_test/oval:com.redhat.rhsa:tst:20249315132.json b/9/rhel-9/tests/textfilecontent54_test/oval:com.redhat.rhsa:tst:20249315132.json
index 8a1d7c3..494de51 100644
--- a/9/rhel-9/tests/textfilecontent54_test/oval:com.redhat.rhsa:tst:20249315132.json
+++ b/9/rhel-9/tests/textfilecontent54_test/oval:com.redhat.rhsa:tst:20249315132.json
@@ -2,9 +2,9 @@
 	"check": "all",
 	"comment": "kernel earlier than 0:5.14.0-503.11.1.el9_5 is set to boot up on next boot",
 	"id": "oval:com.redhat.rhsa:tst:20249315132",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.rhsa:obj:20249315068"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983066"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315010"
diff --git a/9/rhel-9/tests/uname_test/oval:com.redhat.rhsa:tst:20249315131.json b/9/rhel-9/tests/uname_test/oval:com.redhat.rhsa:tst:20249315131.json
index 3b911e5..00fffb6 100644
--- a/9/rhel-9/tests/uname_test/oval:com.redhat.rhsa:tst:20249315131.json
+++ b/9/rhel-9/tests/uname_test/oval:com.redhat.rhsa:tst:20249315131.json
@@ -2,9 +2,9 @@
 	"check": "at least one",
 	"comment": "kernel earlier than 0:5.14.0-503.11.1.el9_5 is currently running",
 	"id": "oval:com.redhat.rhsa:tst:20249315131",
-	"version": "648",
+	"version": "649",
 	"object": {
-		"object_ref": "oval:com.redhat.rhsa:obj:20225214003"
+		"object_ref": "oval:com.redhat.rhba:obj:20243983065"
 	},
 	"state": {
 		"state_ref": "oval:com.redhat.rhsa:ste:20249315009"
`,
		},
		{
			name: "diff-tree -p 63a30ff24dea0d2198c1e3160c33b52df66970a4 6e6128f16b40edf3963ebb0036a3e0a55a54d0de -- \"*/definitions/oval:com\\.redhat\\.cve:def:*\\.json\"",
			args: args{
				repository: "testdata/fixtures/vuls-data-raw-redhat-ovalv2.tar.zst",
				minus:      "63a30ff24dea0d2198c1e3160c33b52df66970a4",
				plus:       "6e6128f16b40edf3963ebb0036a3e0a55a54d0de",
				opts: []tree.Option{
					tree.WithColor(false),
					tree.WithPathSpecs([]string{"*/definitions/oval:com\\.redhat\\.cve:def:*\\.json"}),
				},
			},
			want: `diff --git a/9/rhel-9-including-unpatched/definitions/oval:com.redhat.cve:def:202426815.json b/9/rhel-9-including-unpatched/definitions/oval:com.redhat.cve:def:202426815.json
index 321cb11..11d5d75 100644
--- a/9/rhel-9-including-unpatched/definitions/oval:com.redhat.cve:def:202426815.json
+++ b/9/rhel-9-including-unpatched/definitions/oval:com.redhat.cve:def:202426815.json
@@ -11,12 +11,12 @@
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
@@ -33,109 +33,27 @@
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
-							"kernel-rt-devel-matched",
 							"kernel-rt-devel-matched",
 							"kernel-rt-kvm",
-							"kernel-rt-kvm",
-							"kernel-rt-modules",
 							"kernel-rt-modules",
 							"kernel-rt-modules-core",
-							"kernel-rt-modules-core",
-							"kernel-rt-modules-extra",
 							"kernel-rt-modules-extra",
 							"kernel-rt-modules-internal",
-							"kernel-rt-modules-internal",
-							"kernel-rt-modules-partner",
 							"kernel-rt-modules-partner",
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
@@ -169,32 +87,6 @@
 					{
 						"operator": "OR",
 						"criterias": [
-							{
-								"operator": "AND",
-								"criterions": [
-									{
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
 							{
 								"operator": "AND",
 								"criterions": [
@@ -212,12 +104,12 @@
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
@@ -225,12 +117,12 @@
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
@@ -251,38 +143,12 @@
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
+										"test_ref": "oval:com.redhat.cve:tst:201925162027",
+										"comment": "kernel-rt-debug-kvm is installed"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089086",
-										"comment": "kernel-debug-devel-matched is signed with Red Hat redhatrelease2 key"
+										"test_ref": "oval:com.redhat.cve:tst:201925162028",
+										"comment": "kernel-rt-debug-kvm is signed with Red Hat redhatrelease2 key"
 									}
 								]
 							},
@@ -290,12 +156,12 @@
 								"operator": "AND",
 								"criterions": [
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089013",
-										"comment": "kernel-zfcpdump-devel is installed"
+										"test_ref": "oval:com.redhat.cve:tst:201925162009",
+										"comment": "kernel-rt-modules-extra is installed"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089014",
-										"comment": "kernel-zfcpdump-devel is signed with Red Hat redhatrelease2 key"
+										"test_ref": "oval:com.redhat.cve:tst:201925162010",
+										"comment": "kernel-rt-modules-extra is signed with Red Hat redhatrelease2 key"
 									}
 								]
 							},
@@ -303,12 +169,12 @@
 								"operator": "AND",
 								"criterions": [
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089053",
-										"comment": "kernel-tools-libs is installed"
+										"test_ref": "oval:com.redhat.cve:tst:201925162029",
+										"comment": "kernel-rt-debug-modules-extra is installed"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089054",
-										"comment": "kernel-tools-libs is signed with Red Hat redhatrelease2 key"
+										"test_ref": "oval:com.redhat.cve:tst:201925162030",
+										"comment": "kernel-rt-debug-modules-extra is signed with Red Hat redhatrelease2 key"
 									}
 								]
 							},
@@ -316,12 +182,12 @@
 								"operator": "AND",
 								"criterions": [
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089003",
-										"comment": "kernel-zfcpdump is installed"
+										"test_ref": "oval:com.redhat.cve:tst:201925162035",
+										"comment": "kernel-rt-debug-core is installed"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089004",
-										"comment": "kernel-zfcpdump is signed with Red Hat redhatrelease2 key"
+										"test_ref": "oval:com.redhat.cve:tst:201925162036",
+										"comment": "kernel-rt-debug-core is signed with Red Hat redhatrelease2 key"
 									}
 								]
 							},
@@ -329,12 +195,12 @@
 								"operator": "AND",
 								"criterions": [
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089001",
-										"comment": "kernel-tools-libs-devel is installed"
+										"test_ref": "oval:com.redhat.cve:tst:201925162037",
+										"comment": "kernel-rt-debug-modules-partner is installed"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089002",
-										"comment": "kernel-tools-libs-devel is signed with Red Hat redhatrelease2 key"
+										"test_ref": "oval:com.redhat.cve:tst:201925162038",
+										"comment": "kernel-rt-debug-modules-partner is signed with Red Hat redhatrelease2 key"
 									}
 								]
 							},
@@ -355,129 +221,12 @@
 								"operator": "AND",
 								"criterions": [
 									{
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
+										"test_ref": "oval:com.redhat.cve:tst:201925162041",
+										"comment": "kernel-rt-debug is installed"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:202010135090",
-										"comment": "libperf is signed with Red Hat redhatrelease2 key"
+										"test_ref": "oval:com.redhat.cve:tst:201925162042",
+										"comment": "kernel-rt-debug is signed with Red Hat redhatrelease2 key"
 									}
 								]
 							},
@@ -485,12 +234,12 @@
 								"operator": "AND",
 								"criterions": [
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089039",
-										"comment": "kernel-doc is installed"
+										"test_ref": "oval:com.redhat.cve:tst:201925162021",
+										"comment": "kernel-rt-modules-partner is installed"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089040",
-										"comment": "kernel-doc is signed with Red Hat redhatrelease2 key"
+										"test_ref": "oval:com.redhat.cve:tst:201925162022",
+										"comment": "kernel-rt-modules-partner is signed with Red Hat redhatrelease2 key"
 									}
 								]
 							},
@@ -498,12 +247,12 @@
 								"operator": "AND",
 								"criterions": [
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089065",
-										"comment": "kernel-64k-devel-matched is installed"
+										"test_ref": "oval:com.redhat.cve:tst:201925162039",
+										"comment": "kernel-rt-debug-modules is installed"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089066",
-										"comment": "kernel-64k-devel-matched is signed with Red Hat redhatrelease2 key"
+										"test_ref": "oval:com.redhat.cve:tst:201925162040",
+										"comment": "kernel-rt-debug-modules is signed with Red Hat redhatrelease2 key"
 									}
 								]
 							},
@@ -511,12 +260,12 @@
 								"operator": "AND",
 								"criterions": [
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162023",
-										"comment": "kernel-rt-kvm is installed"
+										"test_ref": "oval:com.redhat.cve:tst:201925162005",
+										"comment": "kernel-rt-debug-devel is installed"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162024",
-										"comment": "kernel-rt-kvm is signed with Red Hat redhatrelease2 key"
+										"test_ref": "oval:com.redhat.cve:tst:201925162006",
+										"comment": "kernel-rt-debug-devel is signed with Red Hat redhatrelease2 key"
 									}
 								]
 							},
@@ -537,38 +286,12 @@
 								"operator": "AND",
 								"criterions": [
 									{
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
-										"test_ref": "oval:com.redhat.cve:tst:201925162027",
-										"comment": "kernel-rt-debug-kvm is installed"
+										"test_ref": "oval:com.redhat.cve:tst:201925162025",
+										"comment": "kernel-rt-modules-core is installed"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162028",
-										"comment": "kernel-rt-debug-kvm is signed with Red Hat redhatrelease2 key"
+										"test_ref": "oval:com.redhat.cve:tst:201925162026",
+										"comment": "kernel-rt-modules-core is signed with Red Hat redhatrelease2 key"
 									}
 								]
 							},
@@ -576,12 +299,12 @@
 								"operator": "AND",
 								"criterions": [
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089067",
-										"comment": "kernel-64k-debug-devel-matched is installed"
+										"test_ref": "oval:com.redhat.cve:tst:201925162023",
+										"comment": "kernel-rt-kvm is installed"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089068",
-										"comment": "kernel-64k-debug-devel-matched is signed with Red Hat redhatrelease2 key"
+										"test_ref": "oval:com.redhat.cve:tst:201925162024",
+										"comment": "kernel-rt-kvm is signed with Red Hat redhatrelease2 key"
 									}
 								]
 							},
@@ -602,38 +325,12 @@
 								"operator": "AND",
 								"criterions": [
 									{
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
-										"test_ref": "oval:com.redhat.cve:tst:201925162009",
-										"comment": "kernel-rt-modules-extra is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162010",
-										"comment": "kernel-rt-modules-extra is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:202010135079",
-										"comment": "kernel-modules-partner is installed"
+										"test_ref": "oval:com.redhat.cve:tst:201925162013",
+										"comment": "kernel-rt-selftests-internal is installed"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:202010135080",
-										"comment": "kernel-modules-partner is signed with Red Hat redhatrelease2 key"
+										"test_ref": "oval:com.redhat.cve:tst:201925162014",
+										"comment": "kernel-rt-selftests-internal is signed with Red Hat redhatrelease2 key"
 									}
 								]
 							},
@@ -641,12 +338,12 @@
 								"operator": "AND",
 								"criterions": [
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089083",
-										"comment": "kernel-devel is installed"
+										"test_ref": "oval:com.redhat.cve:tst:201925162011",
+										"comment": "kernel-rt-core is installed"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089084",
-										"comment": "kernel-devel is signed with Red Hat redhatrelease2 key"
+										"test_ref": "oval:com.redhat.cve:tst:201925162012",
+										"comment": "kernel-rt-core is signed with Red Hat redhatrelease2 key"
 									}
 								]
 							},
@@ -654,599 +351,14 @@
 								"operator": "AND",
 								"criterions": [
 									{
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
-									},
-									{
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
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162035",
-										"comment": "kernel-rt-debug-core is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162036",
-										"comment": "kernel-rt-debug-core is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
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
-										"test_ref": "oval:com.redhat.cve:tst:201925162037",
-										"comment": "kernel-rt-debug-modules-partner is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162038",
-										"comment": "kernel-rt-debug-modules-partner is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
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
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089020",
-										"comment": "kernel-zfcpdump-modules-core is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089063",
-										"comment": "kernel-modules is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089064",
-										"comment": "kernel-modules is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089025",
-										"comment": "rtla is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089026",
-										"comment": "rtla is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162039",
-										"comment": "kernel-rt-debug-modules is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162040",
-										"comment": "kernel-rt-debug-modules is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
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
+										"test_ref": "oval:com.redhat.cve:tst:201925162033",
+										"comment": "kernel-rt-devel-matched is installed"
 									},
 									{
 										"test_ref": "oval:com.redhat.cve:tst:201925162034",
 										"comment": "kernel-rt-devel-matched is signed with Red Hat redhatrelease2 key"
 									}
 								]
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
-										"test_ref": "oval:com.redhat.cve:tst:201925162005",
-										"comment": "kernel-rt-debug-devel is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162006",
-										"comment": "kernel-rt-debug-devel is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
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
-									},
-									{
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
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162025",
-										"comment": "kernel-rt-modules-core is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162026",
-										"comment": "kernel-rt-modules-core is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089087",
-										"comment": "kernel-debug-modules-core is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089088",
-										"comment": "kernel-debug-modules-core is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162019",
-										"comment": "kernel-rt-debug-modules-internal is installed"
-									},
-									{
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
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089029",
-										"comment": "bpftool is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089030",
-										"comment": "bpftool is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089017",
-										"comment": "kernel-64k-core is installed"
-									},
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089018",
-										"comment": "kernel-64k-core is signed with Red Hat redhatrelease2 key"
-									}
-								]
-							},
-							{
-								"operator": "AND",
-								"criterions": [
-									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089045",
-										"comment": "perf is installed"
-									},
-									{
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
-									}
-								]
 							}
 						]
 					}
`,
		},
		{
			name: "diff-tree -p 6e6128f16b40edf3963ebb0036a3e0a55a54d0de 6e6128f16b40edf3963ebb0036a3e0a55a54d0de",
			args: args{
				repository: "testdata/fixtures/vuls-data-raw-redhat-ovalv2.tar.zst",
				minus:      "6e6128f16b40edf3963ebb0036a3e0a55a54d0de",
				plus:       "6e6128f16b40edf3963ebb0036a3e0a55a54d0de",
				opts:       []tree.Option{tree.WithColor(false)},
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.args.repository)
			if err != nil {
				t.Errorf("open %s. err: %v", tt.args.repository, err)
			}
			defer f.Close()

			dir := t.TempDir()
			if err := util.ExtractDotgitTarZst(f, filepath.Join(dir, strings.TrimSuffix(filepath.Base(tt.args.repository), ".tar.zst"))); err != nil {
				t.Errorf("extract %s. err: %v", tt.args.repository, err)
			}

			got, err := tree.Diff(filepath.Join(dir, strings.TrimSuffix(filepath.Base(tt.args.repository), ".tar.zst")), tt.args.minus, tt.args.plus, tt.args.opts...)
			switch {
			case err != nil && !tt.hasError:
				t.Errorf("unexpected err: %v", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			default:
				if diff := cmp.Diff(tt.want, got); diff != "" {
					t.Errorf("Diff(). (-expected +got):\n%s", diff)
				}
			}
		})
	}
}
