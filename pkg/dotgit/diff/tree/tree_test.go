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
			name: "diff-tree -p 63a30ff24dea0d2198c1e3160c33b52df66970a4 6e6128f16b40edf3963ebb0036a3e0a55a54d0de, native git",
			args: args{
				repository: "testdata/fixtures/vuls-data-raw-redhat-ovalv2.tar.zst",
				minus:      "63a30ff24dea0d2198c1e3160c33b52df66970a4",
				plus:       "6e6128f16b40edf3963ebb0036a3e0a55a54d0de",
				opts:       []tree.Option{tree.WithUseNativeGit(true), tree.WithColor(false)},
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
			name: "diff-tree -p 63a30ff24dea0d2198c1e3160c33b52df66970a4 6e6128f16b40edf3963ebb0036a3e0a55a54d0de, go-git",
			args: args{
				repository: "testdata/fixtures/vuls-data-raw-redhat-ovalv2.tar.zst",
				minus:      "63a30ff24dea0d2198c1e3160c33b52df66970a4",
				plus:       "6e6128f16b40edf3963ebb0036a3e0a55a54d0de",
				opts:       []tree.Option{tree.WithUseNativeGit(false), tree.WithColor(false)},
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
diff --git a/9/rhel-9-including-unpatched/definitions/oval:com.redhat.rhsa:def:20249315.json b/9/rhel-9-including-unpatched/definitions/oval:com.redhat.rhsa:def:20249315.json
index d59f9057073067fd4ca31c4953a472025642d8d0..1922f47e9efa3e828a75df6c017997c32087597d 100644
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
@@ -778,6 +778,11 @@ 			},
 			{
 				"ref_id": "CVE-2024-26733",
 				"ref_url": "https://access.redhat.com/security/cve/CVE-2024-26733",
+				"source": "CVE"
+			},
+			{
+				"ref_id": "CVE-2024-26734",
+				"ref_url": "https://access.redhat.com/security/cve/CVE-2024-26734",
 				"source": "CVE"
 			},
 			{
@@ -3621,6 +3626,14 @@ 					"impact": "moderate",
 					"public": "20240403"
 				},
 				{
+					"text": "CVE-2024-26734",
+					"cvss3": "5.5/CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
+					"cwe": "CWE-416",
+					"href": "https://access.redhat.com/security/cve/CVE-2024-26734",
+					"impact": "moderate",
+					"public": "20240403"
+				},
+				{
 					"text": "CVE-2024-26740",
 					"cvss3": "5.5/CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
 					"cwe": "CWE-833",
@@ -5942,7 +5955,7 @@ 					"public": "20240817"
 				},
 				{
 					"text": "CVE-2024-42301",
-					"cvss3": "5.5/CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
+					"cvss3": "7.1/CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
 					"href": "https://access.redhat.com/security/cve/CVE-2024-42301",
 					"impact": "moderate",
 					"public": "20240817"
@@ -6586,6 +6599,11 @@ 				{
 					"text": "kernel: ext4: avoid allocating blocks from corrupted group in ext4_mb_find_by_goal()",
 					"href": "https://bugzilla.redhat.com/2273242",
 					"id": "2273242"
+				},
+				{
+					"text": "kernel: devlink: fix possible use-after-free and memory leaks in devlink_init()",
+					"href": "https://bugzilla.redhat.com/2273244",
+					"id": "2273244"
 				},
 				{
 					"text": "kernel: arp: Prevent overflow in arp_req_get().",
diff --git a/9/rhel-9-including-unpatched/objects/textfilecontent54_object/oval:com.redhat.rhba:obj:20243983066.json b/9/rhel-9-including-unpatched/objects/textfilecontent54_object/oval:com.redhat.rhba:obj:20243983066.json
new file mode 100644
index 0000000000000000000000000000000000000000..f54b7bc58d219f21379f4775863db55d4e3f78c7
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
index 0000000000000000000000000000000000000000..e1da94beb65b7b3c69596b73d07f84a68c8c51b1
--- /dev/null
+++ b/9/rhel-9-including-unpatched/objects/uname_object/oval:com.redhat.rhba:obj:20243983065.json
@@ -0,0 +1,4 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983065",
+	"version": "637"
+}
diff --git a/9/rhel-9-including-unpatched/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315001.json b/9/rhel-9-including-unpatched/states/rpminfo_state/oval:com.redhat.rhsa:ste:20249315001.json
index 901d935ffff4e39fde8612d0359548a94e06fc8b..5ceb0de254a11c423c1884b0c4d68fb3a5486766 100644
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
index b2521103c663eda2ffba6cef8ed445ec55d4e3e4..f2afdf670445d2ad4f2fff4d47e2db32d14a6973 100644
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
index 9c689bb23c6d4eab9900d5c0fa1401ffcb62e2e3..ed0b4f44ef120711830552f4521db1887cd7eb7d 100644
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
index b8021944647e4211433d6c5268eca558eb8beac3..a4d831ded2574727e5d6eb192e239b82a7cef3e8 100644
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
index 57042d476d945e6764d09282bfd8b4a87eb94ef7..cf93b71234449ba906c94b831422b4bf3c291be8 100644
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
index d4e8713004705c223fa13acc557d5daa67a59a12..c3edea8bf32484dc0408df04bace777a7fb7ee8a 100644
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
index 5a063810c68d27ee183a41643268b38ac79617b7..e9cfd85c0f442bcc3bbe36aa6f9c988e547a366d 100644
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
index c6d828446f5a7951a69af47cba987d7cb2e89125..9e8ec882580401cc1ce1855bd836beff985f6c04 100644
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
index 2f3b1edf7943a19dd68afeb82d4194dc31c84edb..193ea0d0d1f3064a7d8afbefd885a05e3ff8109c 100644
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
index 76eb137e66a1f93da1981942f6177080e8b9e782..cf3135af060b41cc53304727ebe0f3f13b802ca9 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315001.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315001.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "bpftool is earlier than 0:7.4.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315001",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089015"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315003.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315003.json
index ac252ac2d027e2a5cba86188a088a21bcafc1d76..f75238010ff83534b3ba8c2c13be41cdd1270595 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315003.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315003.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315003",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089003"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315005.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315005.json
index a657185c8218c54e4719e147e7d54b9afaa5d4f9..deffa6f336ffad4199214a374a5fd6e550fa807d 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315005.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315005.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-64k is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315005",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089048"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315007.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315007.json
index 0701fc07db23c5a8238bfe63d3dbb9e8b3ced939..787b41e686674991d3bfadc4e592c9c8ffc03dc7 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315007.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315007.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-64k-core is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315007",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089009"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315009.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315009.json
index 335629e2d83e051fad070495c82f8c1e8a82addb..0394f9804955fde282b8bed36659e0d3655fbd7b 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315009.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315009.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-64k-debug is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315009",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089025"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315011.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315011.json
index 8ae974840dc04a1555bd536c1d722ef1e1c96b5a..024874ab251b5c66e5a4b203cdf2c49220b1ead8 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315011.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315011.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-64k-debug-core is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315011",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089005"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315013.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315013.json
index e447e98ed1976a50ce43492eb65bae633f86535f..e802577bdd88ecdd03846e4c4d2c5e0ab184e71f 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315013.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315013.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-64k-debug-devel is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315013",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089011"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315015.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315015.json
index aa34bed0924e42eeae0f9b6b153b415bec193547..31ce54469571cf648fba96841f153e52253fa719 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315015.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315015.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-64k-debug-devel-matched is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315015",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089034"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315017.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315017.json
index e09acbce585b7fed4bd1dbb2fb04ad442b7c0a56..2c34d4f354c0ffedbf40f77b91041970249e1bde 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315017.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315017.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-64k-debug-modules is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315017",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089008"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315019.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315019.json
index ed2aad8f576d9dfdf47858ef8068e17b244ed214..879213c3af45d7a5a247e0be8cca6d9c1bed8362 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315019.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315019.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-64k-debug-modules-core is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315019",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089031"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315021.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315021.json
index 017a8064192b4cea1fc83cf8a714c93b39b53874..f6f4e430514437aec8d4e7669128638a4fc0d3d5 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315021.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315021.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-64k-debug-modules-extra is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315021",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089030"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315023.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315023.json
index 015525d5e58b4b27e6a6650940cf1043b67da84e..93071c1c65f6732c8a1a5cb7b4ad33a7f1d3bb27 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315023.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315023.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-64k-devel is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315023",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089047"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315025.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315025.json
index 496e40d50fc5a23e2f4f358483f760300215632c..8c9a4c1b4f897cc3a61611f4914ac5e77c0ef944 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315025.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315025.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-64k-devel-matched is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315025",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089033"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315027.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315027.json
index 63cad481245540acc2784a99924221965fb64619..cb6270b21fc7e7b7530aa3046e85ab28bd0347f0 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315027.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315027.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-64k-modules is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315027",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089018"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315029.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315029.json
index cace1e8ab35a147a5af47b17200c71598700ab7b..fa88b9246fa0384f9bcab7dc8055864db9907a38 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315029.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315029.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-64k-modules-core is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315029",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089028"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315031.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315031.json
index 42ccbb346b1f0d4a77bb2a2dbfb831af5e2d26d9..9c27140b4159a911dc7dfdc8db13f7a03d942213 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315031.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315031.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-64k-modules-extra is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315031",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089041"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315033.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315033.json
index e3ef259fa8d028f51e4fde40b60314f7665eaad6..356dcd41b0dbcfdf57c230cc4c60ed7d4bb73a90 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315033.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315033.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-abi-stablelists is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315033",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089046"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315035.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315035.json
index aa7a550022e074cd9659e1e221384ac6b334c984..ff1e81209ba37f78edb315e80b78b4950a5c2d9d 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315035.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315035.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-core is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315035",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089022"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315037.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315037.json
index a1089142f8276259092b2be6edf4436a105d59e3..13fb4957ccdbdf539ce272b73a00ecd822c5fb33 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315037.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315037.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-cross-headers is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315037",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089004"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315039.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315039.json
index 6677da96f9c47cd42b0ea6f5e61183cae4ab16e4..b8253bd551feb0222f3ad9a97d35e60e34876a28 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315039.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315039.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-debug is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315039",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089029"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315041.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315041.json
index 5f33d4b859ec4576ed534d56dca204f659dbc16a..15e9b495faee90bc09699e817c3d9a1a5ee1052a 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315041.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315041.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-debug-core is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315041",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089035"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315043.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315043.json
index b7a5539e9bb6e1c31c1c878a01f3148ed86c54ad..078f1c28f69973cc0937151cfd8f91aba1779ae1 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315043.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315043.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-debug-devel is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315043",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089014"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315045.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315045.json
index 226b5aee74e5b6304be06bc15d59d1a8dccb9454..8b6381697bb56ab3d6166bc6f9f12e8bb34965a1 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315045.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315045.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-debug-devel-matched is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315045",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089043"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315047.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315047.json
index 2272736d4cd70f81a131917a16423e1fee4e2408..14b27051a3cf96bc5ecda2b4a738c2422a4aa860 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315047.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315047.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-debug-modules is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315047",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089017"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315049.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315049.json
index 33b5cd97501a8902f54b53fe3af7b2ac08819904..6d2aae6d1bccdbcd2f69a5d8618307462d1354c1 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315049.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315049.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-debug-modules-core is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315049",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089044"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315051.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315051.json
index 03bbe925daa7c1de39f6e4c62415b36939cdf9cd..b2b9409f7f303efba3f34918d5ecba82fd1b45ab 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315051.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315051.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-debug-modules-extra is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315051",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089019"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315053.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315053.json
index 10a81570b54c7b843c6c28b24556b937ad53cbd8..37442859868725ad821b20093fb6bb792a47bd36 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315053.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315053.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-debug-uki-virt is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315053",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089021"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315055.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315055.json
index 86b9513988558ffd9acce51c4fbe1279e0fa087a..a53e9230abe3ba6c7c16e3ed6f94d765c01e74d6 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315055.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315055.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-devel is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315055",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089042"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315057.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315057.json
index 9cddcf67c4257ee6ab5f89e0606e2b784607f9e5..3c171ad8ad6a24923a9edb420342184e661d417e 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315057.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315057.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-devel-matched is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315057",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089016"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315059.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315059.json
index 11081798029ba2e3849c61c6ad82b50e38d3ab51..4b455d0e354b4f608d2d16b2bfdd3634602026b9 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315059.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315059.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-doc is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315059",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089020"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315061.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315061.json
index 3ae0b9da696809d9f476449a759fbae4ca6d81d5..623dd29aa9686be49edb2382c3291cd746db6c01 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315061.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315061.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-headers is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315061",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089045"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315063.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315063.json
index a5d05470a0100d414891e28d67bbb9f7fc0b0505..ac83ac10afaa40a36b52dbf393b52cd2ad689a10 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315063.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315063.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-modules is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315063",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089032"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315065.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315065.json
index 058e931e1d3411252b96ae962792ad54453f5199..36b467ac440c401d6b5a9c9f5135fa42cb03b469 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315065.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315065.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-modules-core is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315065",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089024"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315067.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315067.json
index 5abe985ee6bef99da920c7379a1dd7d32cffe280..c35ab1e41e6ae5904c495422914e503ba6fff1ba 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315067.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315067.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-modules-extra is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315067",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089036"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315069.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315069.json
index f593e405283017d8463485cc491d0f3d70adca7d..3f1b1a1703a6fcf744d34f8e1f347bae8551d253 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315069.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315069.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-rt is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315069",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201925162001"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315071.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315071.json
index b7893c168afc9981be2e755e1c3c178ee2c6acaa..c3c041ea2d8acab91b4d753e5a801b661d6755ca 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315071.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315071.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-rt-core is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315071",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201925162006"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315073.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315073.json
index b84093d69141d23cab12d8aaf3fde1bd0b26c7f6..5302c20bb908abbdb5eba1ce96723f859f30f71b 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315073.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315073.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-rt-debug is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315073",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201925162021"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315075.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315075.json
index f4d625437927a3d5412907166152f4a2c3729d71..eea7e905204919927c9472491400142e63e3e0ec 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315075.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315075.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-rt-debug-core is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315075",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201925162018"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315077.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315077.json
index cc10401be955146df5a41ccea7855be75abce23a..97052d51a73e2e5b9dcd0e18df95ecd59db221cc 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315077.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315077.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-rt-debug-devel is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315077",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201925162003"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315079.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315079.json
index e2d2358a4b3bcc2d02ae79be43b48d03318d6e1c..355f47a399afff3e606d5ae0c675af054884ec68 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315079.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315079.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-rt-debug-kvm is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315079",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201925162014"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315081.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315081.json
index d8c50c9f4dd595c05132c0efe93723444a4d220e..6e3889b6f2b0049262724f72f731fa9511879d73 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315081.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315081.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-rt-debug-modules is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315081",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201925162020"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315083.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315083.json
index cdf798cd7c2c236f73b559d330640abf52be61d1..23ba8a7b916dffd1731e33e7d8e5c9a85361c310 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315083.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315083.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-rt-debug-modules-core is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315083",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201925162016"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315085.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315085.json
index a9216c47107fee8337d058e9191f7be4f9f71e98..d501432f8e7267e82a7847d1697fc695cb45ea37 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315085.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315085.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-rt-debug-modules-extra is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315085",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201925162015"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315087.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315087.json
index 2f4f9cfb876a8d87265a05db919b95c8aad45589..3eb75da6f637aae780d5fecb3b0b1a4655f5c564 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315087.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315087.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-rt-devel is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315087",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201925162008"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315089.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315089.json
index 02de7076f08b7ceb7e564050ab3e5f4728ffa3da..af8df88e263fbad2f0b756c3635a66667c0e091d 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315089.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315089.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-rt-kvm is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315089",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201925162012"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315091.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315091.json
index f7bb9ddadaee5fe7ca4a44c8a98322436c55509d..9d426a8981e9ffa975253b718cafa03e5a817e65 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315091.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315091.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-rt-modules is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315091",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201925162002"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315093.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315093.json
index b50fb0937a62b1ec84d8d8d417a1d10bd7de7774..78122c549d03764cd3febb71a471f453e27ad8e5 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315093.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315093.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-rt-modules-core is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315093",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201925162013"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315095.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315095.json
index 1f2d78abe395f9cd3aae679b60f419cb7a8a128f..9a2564da7c0af1bbf73aa4033666ef8a8bda52a0 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315095.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315095.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-rt-modules-extra is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315095",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201925162005"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315097.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315097.json
index 26aed6192727db39d1329eca276bf86a88632efc..90d3f1517c1c1000cc09d29b3edd29e5979aabaf 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315097.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315097.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-tools is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315097",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089038"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315099.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315099.json
index d84668f09464fec3415241d210bcf54e95cbdf74..5cf7924b14c8cbd48746ff4afacce159926b5337 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315099.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315099.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-tools-libs is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315099",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089027"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315101.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315101.json
index 675605c2ba6dd1b7b2b7059806283447d693ccdb..d265361c224a84312796c1e074c3579cddfeff25 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315101.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315101.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-tools-libs-devel is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315101",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089001"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315103.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315103.json
index 203f622aedf19c6bc79892f3e4d06689d50c45e5..f68d879905c8fd4d2d52f27352bbf2078dcbc095 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315103.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315103.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-uki-virt is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315103",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089039"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315105.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315105.json
index 81b087921722eaaa33bd18fd7ac23ce924d4d48b..d3ad6be4a54daf8e72ecc7d274945a3f4e0128f7 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315105.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315105.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-uki-virt-addons is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315105",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:202036781073"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315107.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315107.json
index 3e1362e94301f0563c39b47be960ced7d794061b..f9435ca20aae8e0fa4b6502b22f8adab8a87cfc4 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315107.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315107.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-zfcpdump is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315107",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089002"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315109.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315109.json
index abdc8997106222c2c43b8d730f7e6304a423abfa..05b18a4f0d6925f9ff209f354a4092651bd103c1 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315109.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315109.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-zfcpdump-core is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315109",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089037"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315111.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315111.json
index 182bd76132c522d10524ee4df611a8a3e256eb9f..fea6e163921dcac70e61cc53ac32978ae606a933 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315111.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315111.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-zfcpdump-devel is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315111",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089007"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315113.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315113.json
index f59a97dbfd41d8d4942f7c85ca421666d05bc1e7..8c5df336d345afcf8a6da0228094fee09a38c30d 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315113.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315113.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-zfcpdump-devel-matched is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315113",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089012"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315115.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315115.json
index a55f43ef2ac06bcba70b4996388a5e485d3b0f82..730adb6070511b43618232e3fb26ad2cad49283a 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315115.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315115.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-zfcpdump-modules is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315115",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089026"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315117.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315117.json
index cc115f5b9a97d12ab4df943ae8a80ba346edc536..42458ba437b4570584c384712f4dd953f197bb7e 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315117.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315117.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-zfcpdump-modules-core is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315117",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089010"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315119.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315119.json
index f1abf54e0177aa6520ed9733f63d67ccfad60642..2615fd920fc94533cfee43105b1eec57f99698fb 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315119.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315119.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "kernel-zfcpdump-modules-extra is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315119",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089040"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315121.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315121.json
index ca128ed96e7304445099c7daab7c95d540afed39..88a32c1310ece8604ccc9dc54241fc0d8867d864 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315121.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315121.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "libperf is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315121",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:202010135045"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315123.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315123.json
index 497bf87519e19be8b41058975223321f945fb281..2054185ca0e7e6b82e5b3fa26938c18264f6b293 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315123.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315123.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "perf is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315123",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089023"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315125.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315125.json
index 903ab8e95b4de9d9528f697f21c2010c5d7c5ea2..4b4b7bf647deb643e7abb7810384e4ab7a41da59 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315125.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315125.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "python3-perf is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315125",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089006"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315127.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315127.json
index 36cd6bc115e454f0dd7d80058d726da89a81bd4b..0b7ee0f626977acbda2ae1b6ed2ee11948ac80af 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315127.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315127.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "rtla is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315127",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:201916089013"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315129.json b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315129.json
index 95922fab31793f38b4a3e720088c243cb4dcc93c..8bf1446da7832bed18f563a654b9b0ff36118d0a 100644
--- a/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315129.json
+++ b/9/rhel-9-including-unpatched/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315129.json
@@ -2,7 +2,7 @@ {
 	"check": "at least one",
 	"comment": "rv is earlier than 0:5.14.0-503.11.1.el9_5",
 	"id": "oval:com.redhat.rhsa:tst:20249315129",
-	"version": "648",
+	"version": "649",
 	"object": {
 		"object_ref": "oval:com.redhat.cve:obj:202010135013"
 	},
diff --git a/9/rhel-9-including-unpatched/tests/textfilecontent54_test/oval:com.redhat.rhsa:tst:20249315132.json b/9/rhel-9-including-unpatched/tests/textfilecontent54_test/oval:com.redhat.rhsa:tst:20249315132.json
index 8a1d7c34008f2c6e48786e76c8a760f29666531f..494de51fd5c182150a5a52d916dc63ca327c4409 100644
--- a/9/rhel-9-including-unpatched/tests/textfilecontent54_test/oval:com.redhat.rhsa:tst:20249315132.json
+++ b/9/rhel-9-including-unpatched/tests/textfilecontent54_test/oval:com.redhat.rhsa:tst:20249315132.json
@@ -2,9 +2,9 @@ {
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
index 3b911e57cfa038e943e6194c74302651068d4335..00fffb610a29e673c7bd204e67e3f7078f9c98f0 100644
--- a/9/rhel-9-including-unpatched/tests/uname_test/oval:com.redhat.rhsa:tst:20249315131.json
+++ b/9/rhel-9-including-unpatched/tests/uname_test/oval:com.redhat.rhsa:tst:20249315131.json
@@ -2,9 +2,9 @@ {
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
index d59f9057073067fd4ca31c4953a472025642d8d0..ff5fc8565eae867b1681bbfc2953068f6894bb4a 100644
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
@@ -778,6 +778,11 @@ 			},
 			{
 				"ref_id": "CVE-2024-26733",
 				"ref_url": "https://access.redhat.com/security/cve/CVE-2024-26733",
+				"source": "CVE"
+			},
+			{
+				"ref_id": "CVE-2024-26734",
+				"ref_url": "https://access.redhat.com/security/cve/CVE-2024-26734",
 				"source": "CVE"
 			},
 			{
@@ -3621,6 +3626,14 @@ 					"impact": "moderate",
 					"public": "20240403"
 				},
 				{
+					"text": "CVE-2024-26734",
+					"cvss3": "5.5/CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
+					"cwe": "CWE-416",
+					"href": "https://access.redhat.com/security/cve/CVE-2024-26734",
+					"impact": "moderate",
+					"public": "20240403"
+				},
+				{
 					"text": "CVE-2024-26740",
 					"cvss3": "5.5/CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
 					"cwe": "CWE-833",
@@ -5942,7 +5955,7 @@ 					"public": "20240817"
 				},
 				{
 					"text": "CVE-2024-42301",
-					"cvss3": "5.5/CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
+					"cvss3": "7.1/CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
 					"href": "https://access.redhat.com/security/cve/CVE-2024-42301",
 					"impact": "moderate",
 					"public": "20240817"
@@ -6588,6 +6601,11 @@ 					"href": "https://bugzilla.redhat.com/2273242",
 					"id": "2273242"
 				},
 				{
+					"text": "kernel: devlink: fix possible use-after-free and memory leaks in devlink_init()",
+					"href": "https://bugzilla.redhat.com/2273244",
+					"id": "2273244"
+				},
+				{
 					"text": "kernel: arp: Prevent overflow in arp_req_get().",
 					"href": "https://bugzilla.redhat.com/2273247",
 					"id": "2273247"
@@ -8579,7 +8597,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315001",
 										"comment": "bpftool is earlier than 0:7.4.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089030",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983002",
 										"comment": "bpftool is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8592,7 +8610,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315003",
 										"comment": "kernel is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089006",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983004",
 										"comment": "kernel is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8605,7 +8623,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315005",
 										"comment": "kernel-64k is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089096",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983006",
 										"comment": "kernel-64k is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8618,7 +8636,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315007",
 										"comment": "kernel-64k-core is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089018",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983008",
 										"comment": "kernel-64k-core is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8631,7 +8649,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315009",
 										"comment": "kernel-64k-debug is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089050",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983010",
 										"comment": "kernel-64k-debug is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8644,7 +8662,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315011",
 										"comment": "kernel-64k-debug-core is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089010",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983012",
 										"comment": "kernel-64k-debug-core is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8657,7 +8675,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315013",
 										"comment": "kernel-64k-debug-devel is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089022",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983014",
 										"comment": "kernel-64k-debug-devel is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8670,7 +8688,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315015",
 										"comment": "kernel-64k-debug-devel-matched is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089068",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983016",
 										"comment": "kernel-64k-debug-devel-matched is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8683,7 +8701,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315017",
 										"comment": "kernel-64k-debug-modules is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089016",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983018",
 										"comment": "kernel-64k-debug-modules is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8696,7 +8714,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315019",
 										"comment": "kernel-64k-debug-modules-core is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089062",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983020",
 										"comment": "kernel-64k-debug-modules-core is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8709,7 +8727,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315021",
 										"comment": "kernel-64k-debug-modules-extra is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089060",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983022",
 										"comment": "kernel-64k-debug-modules-extra is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8722,7 +8740,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315023",
 										"comment": "kernel-64k-devel is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089094",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983024",
 										"comment": "kernel-64k-devel is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8735,7 +8753,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315025",
 										"comment": "kernel-64k-devel-matched is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089066",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983026",
 										"comment": "kernel-64k-devel-matched is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8748,7 +8766,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315027",
 										"comment": "kernel-64k-modules is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089036",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983028",
 										"comment": "kernel-64k-modules is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8761,7 +8779,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315029",
 										"comment": "kernel-64k-modules-core is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089056",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983030",
 										"comment": "kernel-64k-modules-core is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8774,7 +8792,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315031",
 										"comment": "kernel-64k-modules-extra is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089082",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983032",
 										"comment": "kernel-64k-modules-extra is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8787,7 +8805,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315033",
 										"comment": "kernel-abi-stablelists is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089092",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983034",
 										"comment": "kernel-abi-stablelists is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8800,7 +8818,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315035",
 										"comment": "kernel-core is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089044",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983036",
 										"comment": "kernel-core is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8813,7 +8831,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315037",
 										"comment": "kernel-cross-headers is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089008",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983038",
 										"comment": "kernel-cross-headers is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8826,7 +8844,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315039",
 										"comment": "kernel-debug is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089058",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983040",
 										"comment": "kernel-debug is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8839,7 +8857,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315041",
 										"comment": "kernel-debug-core is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089070",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983042",
 										"comment": "kernel-debug-core is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8852,7 +8870,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315043",
 										"comment": "kernel-debug-devel is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089028",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983044",
 										"comment": "kernel-debug-devel is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8865,7 +8883,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315045",
 										"comment": "kernel-debug-devel-matched is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089086",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983046",
 										"comment": "kernel-debug-devel-matched is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8878,7 +8896,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315047",
 										"comment": "kernel-debug-modules is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089034",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983048",
 										"comment": "kernel-debug-modules is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8891,7 +8909,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315049",
 										"comment": "kernel-debug-modules-core is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089088",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983050",
 										"comment": "kernel-debug-modules-core is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8904,7 +8922,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315051",
 										"comment": "kernel-debug-modules-extra is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089038",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983052",
 										"comment": "kernel-debug-modules-extra is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8917,7 +8935,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315053",
 										"comment": "kernel-debug-uki-virt is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089042",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983054",
 										"comment": "kernel-debug-uki-virt is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8930,7 +8948,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315055",
 										"comment": "kernel-devel is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089084",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983056",
 										"comment": "kernel-devel is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8943,7 +8961,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315057",
 										"comment": "kernel-devel-matched is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089032",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983058",
 										"comment": "kernel-devel-matched is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8956,7 +8974,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315059",
 										"comment": "kernel-doc is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089040",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983060",
 										"comment": "kernel-doc is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8969,7 +8987,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315061",
 										"comment": "kernel-headers is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089090",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983062",
 										"comment": "kernel-headers is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8982,7 +9000,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315063",
 										"comment": "kernel-modules is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089064",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983064",
 										"comment": "kernel-modules is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -8995,7 +9013,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315065",
 										"comment": "kernel-modules-core is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089048",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983066",
 										"comment": "kernel-modules-core is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9008,7 +9026,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315067",
 										"comment": "kernel-modules-extra is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089072",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983068",
 										"comment": "kernel-modules-extra is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9021,7 +9039,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315069",
 										"comment": "kernel-rt is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162002",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983070",
 										"comment": "kernel-rt is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9034,7 +9052,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315071",
 										"comment": "kernel-rt-core is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162012",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983072",
 										"comment": "kernel-rt-core is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9047,7 +9065,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315073",
 										"comment": "kernel-rt-debug is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162042",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983074",
 										"comment": "kernel-rt-debug is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9060,7 +9078,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315075",
 										"comment": "kernel-rt-debug-core is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162036",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983076",
 										"comment": "kernel-rt-debug-core is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9073,7 +9091,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315077",
 										"comment": "kernel-rt-debug-devel is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162006",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983078",
 										"comment": "kernel-rt-debug-devel is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9086,7 +9104,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315079",
 										"comment": "kernel-rt-debug-kvm is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162028",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983080",
 										"comment": "kernel-rt-debug-kvm is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9099,7 +9117,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315081",
 										"comment": "kernel-rt-debug-modules is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162040",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983082",
 										"comment": "kernel-rt-debug-modules is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9112,7 +9130,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315083",
 										"comment": "kernel-rt-debug-modules-core is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162032",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983084",
 										"comment": "kernel-rt-debug-modules-core is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9125,7 +9143,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315085",
 										"comment": "kernel-rt-debug-modules-extra is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162030",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983086",
 										"comment": "kernel-rt-debug-modules-extra is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9138,7 +9156,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315087",
 										"comment": "kernel-rt-devel is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162016",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983088",
 										"comment": "kernel-rt-devel is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9151,7 +9169,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315089",
 										"comment": "kernel-rt-kvm is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162024",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983090",
 										"comment": "kernel-rt-kvm is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9164,7 +9182,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315091",
 										"comment": "kernel-rt-modules is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162004",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983092",
 										"comment": "kernel-rt-modules is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9177,7 +9195,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315093",
 										"comment": "kernel-rt-modules-core is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162026",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983094",
 										"comment": "kernel-rt-modules-core is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9190,7 +9208,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315095",
 										"comment": "kernel-rt-modules-extra is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201925162010",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983096",
 										"comment": "kernel-rt-modules-extra is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9203,7 +9221,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315097",
 										"comment": "kernel-tools is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089076",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983098",
 										"comment": "kernel-tools is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9216,7 +9234,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315099",
 										"comment": "kernel-tools-libs is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089054",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983100",
 										"comment": "kernel-tools-libs is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9229,7 +9247,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315101",
 										"comment": "kernel-tools-libs-devel is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089002",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983102",
 										"comment": "kernel-tools-libs-devel is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9242,7 +9260,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315103",
 										"comment": "kernel-uki-virt is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089078",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983104",
 										"comment": "kernel-uki-virt is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9255,7 +9273,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315105",
 										"comment": "kernel-uki-virt-addons is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:202036781146",
+										"test_ref": "oval:com.redhat.rhsa:tst:202410274106",
 										"comment": "kernel-uki-virt-addons is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9268,7 +9286,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315107",
 										"comment": "kernel-zfcpdump is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089004",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983106",
 										"comment": "kernel-zfcpdump is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9281,7 +9299,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315109",
 										"comment": "kernel-zfcpdump-core is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089074",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983108",
 										"comment": "kernel-zfcpdump-core is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9294,7 +9312,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315111",
 										"comment": "kernel-zfcpdump-devel is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089014",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983110",
 										"comment": "kernel-zfcpdump-devel is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9307,7 +9325,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315113",
 										"comment": "kernel-zfcpdump-devel-matched is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089024",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983112",
 										"comment": "kernel-zfcpdump-devel-matched is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9320,7 +9338,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315115",
 										"comment": "kernel-zfcpdump-modules is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089052",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983114",
 										"comment": "kernel-zfcpdump-modules is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9333,7 +9351,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315117",
 										"comment": "kernel-zfcpdump-modules-core is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089020",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983116",
 										"comment": "kernel-zfcpdump-modules-core is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9346,7 +9364,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315119",
 										"comment": "kernel-zfcpdump-modules-extra is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089080",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983118",
 										"comment": "kernel-zfcpdump-modules-extra is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9359,7 +9377,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315121",
 										"comment": "libperf is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:202010135090",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983120",
 										"comment": "libperf is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9372,7 +9390,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315123",
 										"comment": "perf is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089046",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983122",
 										"comment": "perf is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9385,7 +9403,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315125",
 										"comment": "python3-perf is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089012",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983124",
 										"comment": "python3-perf is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9398,7 +9416,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315127",
 										"comment": "rtla is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:201916089026",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983126",
 										"comment": "rtla is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9411,7 +9429,7 @@ 										"test_ref": "oval:com.redhat.rhsa:tst:20249315129",
 										"comment": "rv is earlier than 0:5.14.0-503.11.1.el9_5"
 									},
 									{
-										"test_ref": "oval:com.redhat.cve:tst:202010135026",
+										"test_ref": "oval:com.redhat.rhba:tst:20243983128",
 										"comment": "rv is signed with Red Hat redhatrelease2 key"
 									}
 								]
@@ -9421,7 +9439,7 @@ 					}
 				],
 				"criterions": [
 					{
-						"test_ref": "oval:com.redhat.cve:tst:20052541003",
+						"test_ref": "oval:com.redhat.rhba:tst:20223893007",
 						"comment": "Red Hat Enterprise Linux 9 is installed"
 					}
 				]
@@ -9429,7 +9447,7 @@ 			}
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
index 0000000000000000000000000000000000000000..decb53f369967a9fcf4b534211699c6b5cee832c
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
index 0000000000000000000000000000000000000000..8872b6d29e5643580630391f1986bd8dcff73c9b
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
index 0000000000000000000000000000000000000000..31140bd2a6e497b4b1b8fa31d112c488ec6028e9
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
index 0000000000000000000000000000000000000000..ddd3b368f5776ee02f5ae49132e920ff178feb9f
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
index 0000000000000000000000000000000000000000..d3da575dc3206fc805af440d50029e5a48aa1778
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
index 0000000000000000000000000000000000000000..7dd6e8e9a5b7f521841f0eb5885d7efd289c4114
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
index 0000000000000000000000000000000000000000..2199e79344b9e90cbce8ce0213b1d5e75a95f3d5
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
index 0000000000000000000000000000000000000000..19a9b85db5e96b46338b15d9a6831a2223f64730
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
index 0000000000000000000000000000000000000000..364ece636474bbaa8ea4ccce4ca1aa9615671d53
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
index 0000000000000000000000000000000000000000..39e45a084cf56be87fb0be98fb05d93bd18a75ef
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
index 0000000000000000000000000000000000000000..6e45dfe48e5fa54190b69a43a8918587a2c1ad88
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
index 0000000000000000000000000000000000000000..ee626b257dbe719ee9c18d8c7e5cfbe295078c4f
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
index 0000000000000000000000000000000000000000..46ea1682c3aea4a4cff19b44c370b9de1c8ab638
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
index 0000000000000000000000000000000000000000..de9c2fac0ca9ad90ad8632c85d2877c8d534abc7
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
index 0000000000000000000000000000000000000000..f46c78a3f1349da3dbdc7e6d5b1aeeaf137b5123
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
index 0000000000000000000000000000000000000000..59a79131a958c9b2dd758377537667d28c926c36
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
index 0000000000000000000000000000000000000000..35ae8d2fc9ad9c97e457497f761b81363d75b6ba
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
index 0000000000000000000000000000000000000000..ef900316cd86a99fc20dc6eb770521976fc35a81
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
index 0000000000000000000000000000000000000000..6ba7831d438b73426c6cdba958417401e28f87a0
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
index 0000000000000000000000000000000000000000..cfa13a0530be03a96873fbb4b39d3f91980f67b9
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
index 0000000000000000000000000000000000000000..44651f9d75a731bea12d22c616aff987a8429144
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
index 0000000000000000000000000000000000000000..8ef5d742beab0559e2333deef865eee389f08fab
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
index 0000000000000000000000000000000000000000..faaa67f6e719cc0d7504bd29092dba1d7540bde1
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
index 0000000000000000000000000000000000000000..51df63f495eedc32d4f1a164a6227019c2851dcd
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
index 0000000000000000000000000000000000000000..3c79c433eb03bcd844d4ec31ff264fadc01de53d
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
index 0000000000000000000000000000000000000000..fc3533ae93fbddd2c179030ae9c117d62a1cdb4d
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
index 0000000000000000000000000000000000000000..6a8601a0693fa940c634eb2f92aa52caf5ae5f15
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
index 0000000000000000000000000000000000000000..7586ad361fe50ad534a9c842d96dde6ad3ee7ed7
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
index 0000000000000000000000000000000000000000..31dd0b4704da28bfde37f562cf51e8fcaf957d3c
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
index 0000000000000000000000000000000000000000..8749df686002e4541057fb53b5bbb0eabb2ebb9a
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
index 0000000000000000000000000000000000000000..4e500f8a477a95111170cd7a69bd798416474b95
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
index 0000000000000000000000000000000000000000..a849ed1844f17cff2f838550cb5abfff5c2e6042
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
index 0000000000000000000000000000000000000000..55c4e9ad4f1c114fa7502507ff80b0f855d5ff15
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
index 0000000000000000000000000000000000000000..c16036b7f612ecba1251cfeeaf2f6372bf578c34
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
index 0000000000000000000000000000000000000000..d9433af2af3da4a2d6d7b3917ce19f720ef2a5ca
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
index 0000000000000000000000000000000000000000..de0184d24e8ae8780052805b0b69a46c96947e74
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
index 0000000000000000000000000000000000000000..f38dc7ed8b123206366d2a08d08a67cefff120c5
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
index 0000000000000000000000000000000000000000..6e2f1ed88f468b9894565ce3e989ca4dad048c59
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
index 0000000000000000000000000000000000000000..2e9177e90e9de3bd4b1636dae649452a4f4c6182
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
index 0000000000000000000000000000000000000000..9a7a265be30b79b5d2a615678417fde34969d343
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
index 0000000000000000000000000000000000000000..39158ad46a27bddc74582661fb434498a4a5919d
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
index 0000000000000000000000000000000000000000..d179d41bf5a590062d68f9ecb803e1c1366ee381
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
index 0000000000000000000000000000000000000000..36527dad8cae928c0afd6565a89a74fd3134014d
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
index 0000000000000000000000000000000000000000..7472d58f567f81c374c9efb2e9af47a7ed99c334
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
index 0000000000000000000000000000000000000000..471d42c469e9558cdbe55774224a44e5bdb96c7e
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
index 0000000000000000000000000000000000000000..1a455413a339ac6378ec05d0258a457c88a988fb
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
index 0000000000000000000000000000000000000000..47f90f63291d1f836a5b157d4ecf0b57916887ef
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
index 0000000000000000000000000000000000000000..8d0fe986dd204eba412c81367c86dad1975c8783
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
index 0000000000000000000000000000000000000000..8bfbd01bfe4b2603910041c87b9d3c892560af10
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
index 0000000000000000000000000000000000000000..857b7838ff90df0f2dd348fad2148decb07b4220
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
index 0000000000000000000000000000000000000000..bafc60cef12f3952032075517146c8cc7795f8fd
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
index 0000000000000000000000000000000000000000..e3ab47ccbd1eea4b1dd396e5f51080ef36d97ba7
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
index 0000000000000000000000000000000000000000..005f06f89ebb68f7fd2f986cf96bc355ed23a760
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
index 0000000000000000000000000000000000000000..813fb7c3b2d47fac18d2d70bbb07d5edb0f88433
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
index 0000000000000000000000000000000000000000..8e5bb23bbee72fd0def9580df744ddb07423ca63
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
index 0000000000000000000000000000000000000000..606564f74a0dfea153148d24f36851dfea66d70b
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
index 0000000000000000000000000000000000000000..c9bd731dde295df5fccca021514a0b8b2fba1eee
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
index 0000000000000000000000000000000000000000..dda2bd9596c8c504f3343df86ea92cedcf8034be
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
index 0000000000000000000000000000000000000000..fca225a848de7aa9c2b199354db32ea6633be148
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
index 0000000000000000000000000000000000000000..c97f4294b73bb039178c78038db5d3d1e09f7ec9
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
index 0000000000000000000000000000000000000000..6a64f3f0d989e903efd6e6d91aa4dacfc76ec2d5
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
index 0000000000000000000000000000000000000000..409f17d50e81f1b743b1bdc441acaece2e015738
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
index 0000000000000000000000000000000000000000..c5c69ece10cbbace322ceb6533c8d3fef12119f0
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
index 0000000000000000000000000000000000000000..a333d9637f20e86817576cd8969082629134b56a
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
index 0000000000000000000000000000000000000000..b3b58629973c5a8e29fb72e4b53583faed050910
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
index 0000000000000000000000000000000000000000..bac63ded6af8b134c3cb20bd61c416440476985a
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
index 0000000000000000000000000000000000000000..f54b7bc58d219f21379f4775863db55d4e3f78c7
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
index 0000000000000000000000000000000000000000..e1da94beb65b7b3c69596b73d07f84a68c8c51b1
--- /dev/null
+++ b/9/rhel-9/objects/uname_object/oval:com.redhat.rhba:obj:20243983065.json
@@ -0,0 +1,4 @@
+{
+	"id": "oval:com.redhat.rhba:obj:20243983065",
+	"version": "637"
+}
diff --git a/9/rhel-9/states/rpminfo_state/oval:com.redhat.rhba:ste:20223893002.json b/9/rhel-9/states/rpminfo_state/oval:com.redhat.rhba:ste:20223893002.json
new file mode 100644
index 0000000000000000000000000000000000000000..65dcbca0e396f51e8f8a07b77d9ed282174045f4
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
index 901d935ffff4e39fde8612d0359548a94e06fc8b..5ceb0de254a11c423c1884b0c4d68fb3a5486766 100644
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
index b2521103c663eda2ffba6cef8ed445ec55d4e3e4..f2afdf670445d2ad4f2fff4d47e2db32d14a6973 100644
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
index 9c689bb23c6d4eab9900d5c0fa1401ffcb62e2e3..ed0b4f44ef120711830552f4521db1887cd7eb7d 100644
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
index b8021944647e4211433d6c5268eca558eb8beac3..a4d831ded2574727e5d6eb192e239b82a7cef3e8 100644
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
index 57042d476d945e6764d09282bfd8b4a87eb94ef7..cf93b71234449ba906c94b831422b4bf3c291be8 100644
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
index d4e8713004705c223fa13acc557d5daa67a59a12..c3edea8bf32484dc0408df04bace777a7fb7ee8a 100644
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
index 5a063810c68d27ee183a41643268b38ac79617b7..e9cfd85c0f442bcc3bbe36aa6f9c988e547a366d 100644
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
index 0000000000000000000000000000000000000000..fc4177ab36a06153d9f3bfc705a545eb4df7b488
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
index 0000000000000000000000000000000000000000..b388e8395572f8fc4e16fe5972e0bc28cd5de368
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
index c6d828446f5a7951a69af47cba987d7cb2e89125..9e8ec882580401cc1ce1855bd836beff985f6c04 100644
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
index 2f3b1edf7943a19dd68afeb82d4194dc31c84edb..193ea0d0d1f3064a7d8afbefd885a05e3ff8109c 100644
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
index 0000000000000000000000000000000000000000..110675d2d955c2135a851c579d4892cd41a86e9c
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
index 0000000000000000000000000000000000000000..7db6d037233865673dc0d60b40f3e224df235ab8
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
index 0000000000000000000000000000000000000000..307de21950ea30f81318e7f1935c8242a794d112
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
index 0000000000000000000000000000000000000000..f8af528e99a531c8957f5d0b13db0c975f6f3ed1
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
index 0000000000000000000000000000000000000000..d87125f4cb057b8a68bc5a60967cbb9a706ee750
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
index 0000000000000000000000000000000000000000..873eaf3c62b94c5e6d333bc67a91bab244a08c9f
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
index 0000000000000000000000000000000000000000..372e865437ec063246f08f35b92993ad23f81f1f
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
index 0000000000000000000000000000000000000000..cc53862331553c202cd88de932d73ac5be998f96
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
index 0000000000000000000000000000000000000000..ee03d5162626ccb893999dde9cf9b305ebc02249
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
index 0000000000000000000000000000000000000000..a1b77bc8c416f160b84311ea59a21f2316f04627
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
index 0000000000000000000000000000000000000000..e9e3660ec84e7bf3b2f79b7f5e298209c0a4cfeb
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
index 0000000000000000000000000000000000000000..ac926f5e1fca46285db49b61ef0ed78a895e012d
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
index 0000000000000000000000000000000000000000..789de88654120ef9a744e17184561c784ee52f33
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
index 0000000000000000000000000000000000000000..317c67a813787f9bdc161d19337912f065bf0fbb
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
index 0000000000000000000000000000000000000000..64d3aeeb5121a22e772453162820e5f5b5f4c571
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
index 0000000000000000000000000000000000000000..feb2919e1ffe238dafbaeff1fdf24173b84f856d
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
index 0000000000000000000000000000000000000000..2701726487a06926a7f793bf31f8c5a42b3375ce
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
index 0000000000000000000000000000000000000000..032a63960f839b29e6b1aa3dadd3bc2f09b16a8e
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
index 0000000000000000000000000000000000000000..ac94c331088dd5408d583e560dbe80a94e1577ef
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
index 0000000000000000000000000000000000000000..55e4f8fdc96f7eda51670de93320b4a027f718ed
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
index 0000000000000000000000000000000000000000..c07ba28a3847d30b027fe8cf8a6dd3203136b5e4
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
index 0000000000000000000000000000000000000000..b1c708f5b115cd1d34bad0815a8e5c951b6334ab
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
index 0000000000000000000000000000000000000000..1588f3c02cb3eeb2030581d1c7e770bf145d6e18
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
index 0000000000000000000000000000000000000000..41859ceef7990a77ba26ca51932649d0d67cf637
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
index 0000000000000000000000000000000000000000..ece0a880bcb3f195a7b612e8b3d38bfa5005ceec
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
index 0000000000000000000000000000000000000000..8a31b73da1c841f123dc5771516c56f0908616ae
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
index 0000000000000000000000000000000000000000..460aa120779c7c4f721a30e85da3fd4bd3d5f0e5
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
index 0000000000000000000000000000000000000000..2fb8cd751abe7b489f177c03772751b5af4a74fe
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
index 0000000000000000000000000000000000000000..542cdb28796a85e320b6a28867b76988ddf9aab5
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
index 0000000000000000000000000000000000000000..2787d297c926c0889a692d764164b186393347b6
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
index 0000000000000000000000000000000000000000..9848be60d1444607c683cc8c179a910f1d7af0b9
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
index 0000000000000000000000000000000000000000..83b9a28b0f9005671a28a2ff727de161e726006f
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
index 0000000000000000000000000000000000000000..8a6aa5630773e6869c601f677a8fda3dd14b52a5
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
index 0000000000000000000000000000000000000000..9cc83186ae6a476772f611581dbb69796ea89e03
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
index 0000000000000000000000000000000000000000..6cf81c424c7c6d8229c4cf5f27d6a7ea1cff6220
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
index 0000000000000000000000000000000000000000..4b1d02bd54e841b6f6e7304c66699f00ed9f25ff
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
index 0000000000000000000000000000000000000000..661826d28e9c608fdf257b7e1b25f279cd5e4bce
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
index 0000000000000000000000000000000000000000..1663ab6801e274627c12b6e4756cb64c35db1686
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
index 0000000000000000000000000000000000000000..33ce4b7272dc1d27a32685fa410971fbdcf4d0cc
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
index 0000000000000000000000000000000000000000..ba23576de7450ce15bb29beb6fbe4d7578995e4f
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
index 0000000000000000000000000000000000000000..0e8d99b1f45377becea1adbf055a258b9715ad32
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
index 0000000000000000000000000000000000000000..ec6c3ecdcbbec8bbf66a6790e6e80dfcd3654d53
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
index 0000000000000000000000000000000000000000..e0c5916b77398197b72d9e6b64a52a155524c2ab
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
index 0000000000000000000000000000000000000000..38bdb6dcf40e330500cdaa418289ed421f8370d2
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
index 0000000000000000000000000000000000000000..2b37cba26bd04fa772075ed924c19818c9e75c54
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
index 0000000000000000000000000000000000000000..3ed3fb19965580c181eb8bd5fe2ff77b05d7ae25
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
index 0000000000000000000000000000000000000000..f24c77b3a077562ec72e21511fc4300b9f528d3d
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
index 0000000000000000000000000000000000000000..38ad742c727dcd5a8bab74df68b8299a5919f64b
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
index 0000000000000000000000000000000000000000..93da34f990293a9a21af4035da49084caaacdc5b
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
index 0000000000000000000000000000000000000000..71bfb4bd0a74673ed08b065f65aa75fe0a3befce
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
index 0000000000000000000000000000000000000000..69843a0c0a56d4f891e47bc916ce3a2de03e151f
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
index 0000000000000000000000000000000000000000..0c31d43ffd87c424e8447171e1d7a2d9e4fbb843
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
index 0000000000000000000000000000000000000000..9ae02392f30690869f90be1bdf04a8c272e87238
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
index 0000000000000000000000000000000000000000..149f12de9ad07d0307fcb3e068d7fb4e981bc29c
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
index 0000000000000000000000000000000000000000..59ef7d0d7305e6ac11c3f51ae535961f9a3d5049
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
index 0000000000000000000000000000000000000000..06d08f74efe8f1f9039154e9635df4b7b6ffaa87
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
index 0000000000000000000000000000000000000000..fae56dc5a09a8d14e0665caf0b3b3e1986c91973
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
index 0000000000000000000000000000000000000000..4b2975f8f9e0cc5e35afe725c5ae741481583069
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
index 0000000000000000000000000000000000000000..29ddccbc591d5758eafc3a504e9e5d22b9faa72c
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
index 0000000000000000000000000000000000000000..7cf3084c31fd98d8fdc7dc7de7b7192d1f7e90f2
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
index 0000000000000000000000000000000000000000..6f985cf38223f5c85bfc118605f9457b81f48421
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
index 0000000000000000000000000000000000000000..e662b4635072f3542cf5194bd62c86f1fc663ee5
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
index 0000000000000000000000000000000000000000..a0220dd0223f9fd938c970463f85ce47cb3cc2f1
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
index 0000000000000000000000000000000000000000..68dee3aedda8442bf05c6dbd6077736817f3360b
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
index 0000000000000000000000000000000000000000..6f820e33f79b4a203bada367935043f622233ab0
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
index 76eb137e66a1f93da1981942f6177080e8b9e782..dd71e29c1ffd8972afe34dd41150cd1e60bb89a6 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315001.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315001.json
@@ -2,9 +2,9 @@ {
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
index ac252ac2d027e2a5cba86188a088a21bcafc1d76..e84424e3c02e3163d0cb3b89dd22e0f0eb9ac1a0 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315003.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315003.json
@@ -2,9 +2,9 @@ {
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
index a657185c8218c54e4719e147e7d54b9afaa5d4f9..ab4642ecf65d855abab0104691bdf2de6d511b83 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315005.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315005.json
@@ -2,9 +2,9 @@ {
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
index 0701fc07db23c5a8238bfe63d3dbb9e8b3ced939..edc43329048dde836f0eddaa2e8c2141ac5161d5 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315007.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315007.json
@@ -2,9 +2,9 @@ {
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
index 335629e2d83e051fad070495c82f8c1e8a82addb..61c74b8b068c901a8f01d7e15cac0adbb3039e10 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315009.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315009.json
@@ -2,9 +2,9 @@ {
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
index 8ae974840dc04a1555bd536c1d722ef1e1c96b5a..fb82a295babe81698fd606a64a25ab85117a36b0 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315011.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315011.json
@@ -2,9 +2,9 @@ {
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
index e447e98ed1976a50ce43492eb65bae633f86535f..9a6defdbeba3a8a32d2c422a489bfe8dc2e00c10 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315013.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315013.json
@@ -2,9 +2,9 @@ {
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
index aa34bed0924e42eeae0f9b6b153b415bec193547..dbf5186220d8c1676fc63eba069c82bdabcd12d0 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315015.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315015.json
@@ -2,9 +2,9 @@ {
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
index e09acbce585b7fed4bd1dbb2fb04ad442b7c0a56..ac8c69b2a9110dc1a8b0ced54cad1be04786a416 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315017.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315017.json
@@ -2,9 +2,9 @@ {
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
index ed2aad8f576d9dfdf47858ef8068e17b244ed214..450c887361fba55cbd3f948d74bb51c1167119f7 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315019.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315019.json
@@ -2,9 +2,9 @@ {
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
index 017a8064192b4cea1fc83cf8a714c93b39b53874..3a4332bb14ed228b2726fc0ee2a3817c5c3dbbc6 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315021.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315021.json
@@ -2,9 +2,9 @@ {
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
index 015525d5e58b4b27e6a6650940cf1043b67da84e..4b6ea95d6479abd3b76a8b8447a034c309af10bc 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315023.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315023.json
@@ -2,9 +2,9 @@ {
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
index 496e40d50fc5a23e2f4f358483f760300215632c..6337bbd0410642477c8e03a21ed20561100bffa1 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315025.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315025.json
@@ -2,9 +2,9 @@ {
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
index 63cad481245540acc2784a99924221965fb64619..dc9b0fbc8d128f3f653d0d387a6669aa482c97c4 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315027.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315027.json
@@ -2,9 +2,9 @@ {
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
index cace1e8ab35a147a5af47b17200c71598700ab7b..697cbf329c9c5d1ca244cdb1c309df231e6c685b 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315029.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315029.json
@@ -2,9 +2,9 @@ {
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
index 42ccbb346b1f0d4a77bb2a2dbfb831af5e2d26d9..964cbffa450b759a007fb91f0d72f81ead0b903d 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315031.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315031.json
@@ -2,9 +2,9 @@ {
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
index e3ef259fa8d028f51e4fde40b60314f7665eaad6..445e3e743e2703f05d31d006619df4c38ec5f472 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315033.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315033.json
@@ -2,9 +2,9 @@ {
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
index aa7a550022e074cd9659e1e221384ac6b334c984..6a2d8004425fe16617c5960b55aa13395305f3ef 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315035.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315035.json
@@ -2,9 +2,9 @@ {
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
index a1089142f8276259092b2be6edf4436a105d59e3..79b54b3e509363814292b1e5d5f1bb99a56a3aef 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315037.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315037.json
@@ -2,9 +2,9 @@ {
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
index 6677da96f9c47cd42b0ea6f5e61183cae4ab16e4..67668e09b522de1b1fc762900c46330a65ca1b49 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315039.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315039.json
@@ -2,9 +2,9 @@ {
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
index 5f33d4b859ec4576ed534d56dca204f659dbc16a..54d13905787789d8f099ac6769882cf15c16829f 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315041.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315041.json
@@ -2,9 +2,9 @@ {
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
index b7a5539e9bb6e1c31c1c878a01f3148ed86c54ad..6d7b749e8b90aa4fb3ed8fb2c48247102052117b 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315043.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315043.json
@@ -2,9 +2,9 @@ {
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
index 226b5aee74e5b6304be06bc15d59d1a8dccb9454..4b958cbdc8a9212c09ac33ebef985a05d9cf1baf 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315045.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315045.json
@@ -2,9 +2,9 @@ {
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
index 2272736d4cd70f81a131917a16423e1fee4e2408..fdc1d452a23d14a83075d8ed49e710615473e0e4 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315047.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315047.json
@@ -2,9 +2,9 @@ {
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
index 33b5cd97501a8902f54b53fe3af7b2ac08819904..7dbd83cf75222266767818690d855c11adcc8337 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315049.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315049.json
@@ -2,9 +2,9 @@ {
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
index 03bbe925daa7c1de39f6e4c62415b36939cdf9cd..ef51c949bd7e8bf757e444c368b632405704e3f0 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315051.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315051.json
@@ -2,9 +2,9 @@ {
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
index 10a81570b54c7b843c6c28b24556b937ad53cbd8..508933c7e9dbdca4794dc7ada7713cc8eb79057e 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315053.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315053.json
@@ -2,9 +2,9 @@ {
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
index 86b9513988558ffd9acce51c4fbe1279e0fa087a..97e674955fef73b87e44dbe9c768bacdf75c64d3 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315055.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315055.json
@@ -2,9 +2,9 @@ {
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
index 9cddcf67c4257ee6ab5f89e0606e2b784607f9e5..89cf0298155d2d5751825c81ca19f9cd1dadec6a 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315057.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315057.json
@@ -2,9 +2,9 @@ {
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
index 11081798029ba2e3849c61c6ad82b50e38d3ab51..ace2df6354c056600508eba4f7f78c5ab89b73a0 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315059.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315059.json
@@ -2,9 +2,9 @@ {
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
index 3ae0b9da696809d9f476449a759fbae4ca6d81d5..2317698a7e62a059f159e79286ef586922ac4ec5 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315061.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315061.json
@@ -2,9 +2,9 @@ {
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
index a5d05470a0100d414891e28d67bbb9f7fc0b0505..ee4a886c156aad6d2fdcf9a15bf77aa0fbfadd6a 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315063.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315063.json
@@ -2,9 +2,9 @@ {
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
index 058e931e1d3411252b96ae962792ad54453f5199..776d426cdb80d56cb0575abfab87c890a23ac0ff 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315065.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315065.json
@@ -2,9 +2,9 @@ {
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
index 5abe985ee6bef99da920c7379a1dd7d32cffe280..070928266609acece16626fe3195bc0eba863f2f 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315067.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315067.json
@@ -2,9 +2,9 @@ {
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
index f593e405283017d8463485cc491d0f3d70adca7d..2f68ab4a40e22bf892f087232956f36d2bdcea7c 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315069.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315069.json
@@ -2,9 +2,9 @@ {
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
index b7893c168afc9981be2e755e1c3c178ee2c6acaa..b3b339ea44af3d19df07cc7b8b46e78f0218872f 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315071.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315071.json
@@ -2,9 +2,9 @@ {
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
index b84093d69141d23cab12d8aaf3fde1bd0b26c7f6..b23322eb0d114998ae50f29144fc5247927c87e0 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315073.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315073.json
@@ -2,9 +2,9 @@ {
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
index f4d625437927a3d5412907166152f4a2c3729d71..f5289d8fbc4f1d0118c0ab47e3e31b7d921aac55 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315075.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315075.json
@@ -2,9 +2,9 @@ {
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
index cc10401be955146df5a41ccea7855be75abce23a..e588b28749f6123525f2ad8e8423532cca1a8d9d 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315077.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315077.json
@@ -2,9 +2,9 @@ {
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
index e2d2358a4b3bcc2d02ae79be43b48d03318d6e1c..df5db81b7c3e74e8fe83fa75bbba25819caae5d2 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315079.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315079.json
@@ -2,9 +2,9 @@ {
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
index d8c50c9f4dd595c05132c0efe93723444a4d220e..b37a8ac539aadf14a5a6a0803b2d96e837b76ff7 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315081.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315081.json
@@ -2,9 +2,9 @@ {
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
index cdf798cd7c2c236f73b559d330640abf52be61d1..a1daca802290cb5d93e43d5410891241ca298efb 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315083.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315083.json
@@ -2,9 +2,9 @@ {
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
index a9216c47107fee8337d058e9191f7be4f9f71e98..22b57fa8ba8f18c611f2737d204adf6a4c278b8a 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315085.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315085.json
@@ -2,9 +2,9 @@ {
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
index 2f4f9cfb876a8d87265a05db919b95c8aad45589..7ee0bdb1f2dcff500beabc0b45fb295150094007 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315087.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315087.json
@@ -2,9 +2,9 @@ {
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
index 02de7076f08b7ceb7e564050ab3e5f4728ffa3da..7d1369b81a8baf2f758231b69c4d8c3967aa9e15 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315089.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315089.json
@@ -2,9 +2,9 @@ {
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
index f7bb9ddadaee5fe7ca4a44c8a98322436c55509d..708fe3cf76cc2f72af35fe4599f072ab4200ef0c 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315091.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315091.json
@@ -2,9 +2,9 @@ {
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
index b50fb0937a62b1ec84d8d8d417a1d10bd7de7774..3482a8a0c2889a7d626f996aa8cc428b46e59a3d 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315093.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315093.json
@@ -2,9 +2,9 @@ {
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
index 1f2d78abe395f9cd3aae679b60f419cb7a8a128f..b1066f4128bc48534f2a81bc86bbc338454597b4 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315095.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315095.json
@@ -2,9 +2,9 @@ {
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
index 26aed6192727db39d1329eca276bf86a88632efc..5ea360e67777a1de6751f25f6a1a335e22419896 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315097.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315097.json
@@ -2,9 +2,9 @@ {
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
index d84668f09464fec3415241d210bcf54e95cbdf74..c29a053d8bcabb8aac10f505d65237826ff6f188 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315099.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315099.json
@@ -2,9 +2,9 @@ {
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
index 675605c2ba6dd1b7b2b7059806283447d693ccdb..cd1e017ebe0ee605f7ce331968002566db31114d 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315101.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315101.json
@@ -2,9 +2,9 @@ {
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
index 203f622aedf19c6bc79892f3e4d06689d50c45e5..012167f5ae175080756b4f62cb391a367f58eb5f 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315103.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315103.json
@@ -2,9 +2,9 @@ {
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
index 81b087921722eaaa33bd18fd7ac23ce924d4d48b..cb0b6b86bb9fb83cc55bf168c2dcbe19f12c3f33 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315105.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315105.json
@@ -2,9 +2,9 @@ {
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
index 3e1362e94301f0563c39b47be960ced7d794061b..5474dbe80ba3df340a39cd67bbe20f75ae8c09a1 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315107.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315107.json
@@ -2,9 +2,9 @@ {
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
index abdc8997106222c2c43b8d730f7e6304a423abfa..a9c3834e7ac394dcf9f4d00cf92b91e2eb14ead3 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315109.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315109.json
@@ -2,9 +2,9 @@ {
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
index 182bd76132c522d10524ee4df611a8a3e256eb9f..f12003b10bb00af233ecdcf15a17736748058283 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315111.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315111.json
@@ -2,9 +2,9 @@ {
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
index f59a97dbfd41d8d4942f7c85ca421666d05bc1e7..c99ec859ac91e1b72cbf3eb13f0e00084cc5394e 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315113.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315113.json
@@ -2,9 +2,9 @@ {
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
index a55f43ef2ac06bcba70b4996388a5e485d3b0f82..7d94177cc84a31b32169e1e6a750b513530bcdae 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315115.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315115.json
@@ -2,9 +2,9 @@ {
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
index cc115f5b9a97d12ab4df943ae8a80ba346edc536..5d071d303fffe6ac273e1bc0995afce4f137060c 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315117.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315117.json
@@ -2,9 +2,9 @@ {
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
index f1abf54e0177aa6520ed9733f63d67ccfad60642..55d5fc1be6e5254f5985bb2565df17f80aff572e 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315119.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315119.json
@@ -2,9 +2,9 @@ {
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
index ca128ed96e7304445099c7daab7c95d540afed39..76f3764a9fee019f1b07cea9a31f02d5594d4044 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315121.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315121.json
@@ -2,9 +2,9 @@ {
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
index 497bf87519e19be8b41058975223321f945fb281..a060e47f984bc7546c5ff2052326099779a44d6b 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315123.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315123.json
@@ -2,9 +2,9 @@ {
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
index 903ab8e95b4de9d9528f697f21c2010c5d7c5ea2..554560ec6d6f43ce3e9de18dd2d1e2e1f7a8c790 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315125.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315125.json
@@ -2,9 +2,9 @@ {
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
index 36cd6bc115e454f0dd7d80058d726da89a81bd4b..ecd4f1ff4dcb6289121647ea2b9058ff09467ae0 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315127.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315127.json
@@ -2,9 +2,9 @@ {
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
index 95922fab31793f38b4a3e720088c243cb4dcc93c..03900560ec51e4830520880cbb50f70885b7f73c 100644
--- a/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315129.json
+++ b/9/rhel-9/tests/rpminfo_test/oval:com.redhat.rhsa:tst:20249315129.json
@@ -2,9 +2,9 @@ {
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
index 0000000000000000000000000000000000000000..68aed093de6a9979a19fe367010b97e4da5577a8
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
index 0000000000000000000000000000000000000000..7519aace599a8cc17f115c0b596a9d5db98c552f
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
index 8a1d7c34008f2c6e48786e76c8a760f29666531f..494de51fd5c182150a5a52d916dc63ca327c4409 100644
--- a/9/rhel-9/tests/textfilecontent54_test/oval:com.redhat.rhsa:tst:20249315132.json
+++ b/9/rhel-9/tests/textfilecontent54_test/oval:com.redhat.rhsa:tst:20249315132.json
@@ -2,9 +2,9 @@ {
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
index 3b911e57cfa038e943e6194c74302651068d4335..00fffb610a29e673c7bd204e67e3f7078f9c98f0 100644
--- a/9/rhel-9/tests/uname_test/oval:com.redhat.rhsa:tst:20249315131.json
+++ b/9/rhel-9/tests/uname_test/oval:com.redhat.rhsa:tst:20249315131.json
@@ -2,9 +2,9 @@ {
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
			name: "diff-tree -p 63a30ff24dea0d2198c1e3160c33b52df66970a4 6e6128f16b40edf3963ebb0036a3e0a55a54d0de -- \"*/definitions/oval:com\\.redhat\\.cve:def:*\\.json\", native git",
			args: args{
				repository: "testdata/fixtures/vuls-data-raw-redhat-ovalv2.tar.zst",
				minus:      "63a30ff24dea0d2198c1e3160c33b52df66970a4",
				plus:       "6e6128f16b40edf3963ebb0036a3e0a55a54d0de",
				opts: []tree.Option{
					tree.WithUseNativeGit(true), tree.WithColor(false),
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
			name: "diff-tree -p 63a30ff24dea0d2198c1e3160c33b52df66970a4 6e6128f16b40edf3963ebb0036a3e0a55a54d0de -- definitions/oval:com\\.redhat\\.cve:def:.*\\.json, go-git",
			args: args{
				repository: "testdata/fixtures/vuls-data-raw-redhat-ovalv2.tar.zst",
				minus:      "63a30ff24dea0d2198c1e3160c33b52df66970a4",
				plus:       "6e6128f16b40edf3963ebb0036a3e0a55a54d0de",
				opts: []tree.Option{
					tree.WithUseNativeGit(false), tree.WithColor(false),
					tree.WithPathSpecs([]string{"definitions/oval:com\\.redhat\\.cve:def:.*\\.json"}),
				},
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
			name: "diff-tree -p 6e6128f16b40edf3963ebb0036a3e0a55a54d0de 6e6128f16b40edf3963ebb0036a3e0a55a54d0de, native git",
			args: args{
				repository: "testdata/fixtures/vuls-data-raw-redhat-ovalv2.tar.zst",
				minus:      "6e6128f16b40edf3963ebb0036a3e0a55a54d0de",
				plus:       "6e6128f16b40edf3963ebb0036a3e0a55a54d0de",
				opts:       []tree.Option{tree.WithUseNativeGit(true), tree.WithColor(false)},
			},
			want: "",
		},
		{
			name: "diff-tree -p 6e6128f16b40edf3963ebb0036a3e0a55a54d0de 6e6128f16b40edf3963ebb0036a3e0a55a54d0de, go-git",
			args: args{
				repository: "testdata/fixtures/vuls-data-raw-redhat-ovalv2.tar.zst",
				minus:      "6e6128f16b40edf3963ebb0036a3e0a55a54d0de",
				plus:       "6e6128f16b40edf3963ebb0036a3e0a55a54d0de",
				opts:       []tree.Option{tree.WithUseNativeGit(false), tree.WithColor(false)},
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
