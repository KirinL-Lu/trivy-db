package openeuler

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrctest"
)

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}


func TestVulnSrc_Update(t *testing.T) {
	tests := []struct {
		name       string
		dir        string
		wantValues []vulnsrctest.WantValues
		wantErr    string
	}{
		{
			name: "happy path with openEuler",
			dir:  filepath.Join("testdata", "happy"),
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{"data-source", "openEuler-22.03-LTS-SP2"},
					Value: types.DataSource{
						ID:   vulnerability.OpenEuler,
						Name: "openEuler CVRF",
						URL:  "https://repo.openeuler.org/security/data/cvrf",
					},
				},
				{
					Key: []string{"advisory-detail", "openEuler-SA-2024-1349", "openEuler-22.03-LTS-SP2", "perf"},
					Value: types.Advisory{
						FixedVersion: "5.10.0-153.48.0.126",
					},
				},
				{
					Key: []string{"advisory-detail", "openEuler-SA-2024-1349", "openEuler-22.03-LTS-SP2", "kernel-tools"},
					Value: types.Advisory{
						FixedVersion: "5.10.0-153.48.0.126",
					},
				},
				{
					Key: []string{"vulnerability-detail", "openEuler-SA-2024-1349", "openeuler"},
					Value: types.VulnerabilityDetail{
						Title:       "An update for kernel is now available for openEuler-22.03-LTS-SP2",
						Description: "The Linux Kernel, the operating system core itself.\n\nSecurity Fix(es):\n\nIn the Linux kernel, the following vulnerability has been resolved:\n\nnet/sched: act_ct: fix wild memory access when clearing fragments\n\nwhile testing re-assembly/re-fragmentation using act_ct, it's possible to\nobserve a crash like the following one:\n\n KASAN: maybe wild-memory-access in range [0x0001000000000448-0x000100000000044f]\n CPU: 50 PID: 0 Comm: swapper/50 Tainted: G S                5.12.0-rc7+ #424\n Hardware name: Dell Inc. PowerEdge R730/072T6D, BIOS 2.4.3 01/17/2017\n RIP: 0010:inet_frag_rbtree_purge+0x50/0xc0\n Code: 00 fc ff df 48 89 c3 31 ed 48 89 df e8 a9 7a 38 ff 4c 89 fe 48 89 df 49 89 c6 e8 5b 3a 38 ff 48 8d 7b 40 48 89 f8 48 c1 e8 03 \u003c42\u003e 80 3c 20 00 75 59 48 8d bb d0 00 00 00 4c 8b 6b 40 48 89 f8 48\n RSP: 0018:ffff888c31449db8 EFLAGS: 00010203\n RAX: 0000200000000089 RBX: 000100000000040e RCX: ffffffff989eb960\n RDX: 0000000000000140 RSI: ffffffff97cfb977 RDI: 000100000000044e\n RBP: 0000000000000900 R08: 0000000000000000 R09: ffffed1186289350\n R10: 0000000000000003 R11: ffffed1186289350 R12: dffffc0000000000\n R13: 000100000000040e R14: 0000000000000000 R15: ffff888155e02160\n FS:  0000000000000000(0000) GS:ffff888c31440000(0000) knlGS:0000000000000000\n CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033\n CR2: 00005600cb70a5b8 CR3: 0000000a2c014005 CR4: 00000000003706e0\n DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000\n DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400\n Call Trace:\n  \u003cIRQ\u003e\n  inet_frag_destroy+0xa9/0x150\n  call_timer_fn+0x2d/0x180\n  run_timer_softirq+0x4fe/0xe70\n  __do_softirq+0x197/0x5a0\n  irq_exit_rcu+0x1de/0x200\n  sysvec_apic_timer_interrupt+0x6b/0x80\n  \u003c/IRQ\u003e\n\nwhen act_ct temporarily stores an IP fragment, restoring the skb qdisc cb\nresults in putting random data in FRAG_CB(), and this causes those \"wild\"\nmemory accesses later, when the rbtree is purged. Never overwrite the skb\ncb in case tcf_ct_handle_fragments() returns -EINPROGRESS.(CVE-2021-47014)\n\nIn the Linux kernel, the following vulnerability has been resolved:\n\nudp: skip L4 aggregation for UDP tunnel packets\n\nIf NETIF_F_GRO_FRAGLIST or NETIF_F_GRO_UDP_FWD are enabled, and there\nare UDP tunnels available in the system, udp_gro_receive() could end-up\ndoing L4 aggregation (either SKB_GSO_UDP_L4 or SKB_GSO_FRAGLIST) at\nthe outer UDP tunnel level for packets effectively carrying and UDP\ntunnel header.\n\nThat could cause inner protocol corruption. If e.g. the relevant\npackets carry a vxlan header, different vxlan ids will be ignored/\naggregated to the same GSO packet. Inner headers will be ignored, too,\nso that e.g. TCP over vxlan push packets will be held in the GRO\nengine till the next flush, etc.\n\nJust skip the SKB_GSO_UDP_L4 and SKB_GSO_FRAGLIST code path if the\ncurrent packet could land in a UDP tunnel, and let udp_gro_receive()\ndo GRO via udp_sk(sk)-\u003egro_receive.\n\nThe check implemented in this patch is broader than what is strictly\nneeded, as the existing UDP tunnel could be e.g. configured on top of\na different device: we could end-up skipping GRO at-all for some packets.\n\nAnyhow, that is a very thin corner case and covering it will add quite\na bit of complexity.\n\nv1 -\u003e v2:\n - hopefully clarify the commit message(CVE-2021-47036)\n\nIn the Linux kernel, the following vulnerability has been resolved:\n\nmedia: pvrusb2: fix use after free on context disconnection\n\nUpon module load, a kthread is created targeting the\npvr2_context_thread_func function, which may call pvr2_context_destroy\nand thus call kfree() on the context object. However, that might happen\nbefore the usb hub_event handler is able to notify the driver. This\npatch adds a sanity check before the invalid read reported by syzbot,\nwithin the context disconnection call stack.(CVE-2023-52445)\n\nIn the Linux kernel, the following vulnerability has been resolved:\n\nblock: add check that partition length needs to be aligned with block size\n\nBefore calling add partition or resize partition, there is no check\non whether the length is aligned with the logical block size.\nIf the logical block size of the disk is larger than 512 bytes,\nthen the partition size maybe not the multiple of the logical block size,\nand when the last sector is read, bio_truncate() will adjust the bio size,\nresulting in an IO error if the size of the read command is smaller than\nthe logical block size.If integrity data is supported, this will also\nresult in a null pointer dereference when calling bio_integrity_free.(CVE-2023-52458)\n\nIn the Linux kernel, the following vulnerability has been resolved:\n\nnet: usb: smsc75xx: Fix uninit-value access in __smsc75xx_read_reg\n\nsyzbot reported the following uninit-value access issue:\n\n=====================================================\nBUG: KMSAN: uninit-value in smsc75xx_wait_ready drivers/net/usb/smsc75xx.c:975 [inline]\nBUG: KMSAN: uninit-value in smsc75xx_bind+0x5c9/0x11e0 drivers/net/usb/smsc75xx.c:1482\nCPU: 0 PID: 8696 Comm: kworker/0:3 Not tainted 5.8.0-rc5-syzkaller #0\nHardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011\nWorkqueue: usb_hub_wq hub_event\nCall Trace:\n __dump_stack lib/dump_stack.c:77 [inline]\n dump_stack+0x21c/0x280 lib/dump_stack.c:118\n kmsan_report+0xf7/0x1e0 mm/kmsan/kmsan_report.c:121\n __msan_warning+0x58/0xa0 mm/kmsan/kmsan_instr.c:215\n smsc75xx_wait_ready drivers/net/usb/smsc75xx.c:975 [inline]\n smsc75xx_bind+0x5c9/0x11e0 drivers/net/usb/smsc75xx.c:1482\n usbnet_probe+0x1152/0x3f90 drivers/net/usb/usbnet.c:1737\n usb_probe_interface+0xece/0x1550 drivers/usb/core/driver.c:374\n really_probe+0xf20/0x20b0 drivers/base/dd.c:529\n driver_probe_device+0x293/0x390 drivers/base/dd.c:701\n __device_attach_driver+0x63f/0x830 drivers/base/dd.c:807\n bus_for_each_drv+0x2ca/0x3f0 drivers/base/bus.c:431\n __device_attach+0x4e2/0x7f0 drivers/base/dd.c:873\n device_initial_probe+0x4a/0x60 drivers/base/dd.c:920\n bus_probe_device+0x177/0x3d0 drivers/base/bus.c:491\n device_add+0x3b0e/0x40d0 drivers/base/core.c:2680\n usb_set_configuration+0x380f/0x3f10 drivers/usb/core/message.c:2032\n usb_generic_driver_probe+0x138/0x300 drivers/usb/core/generic.c:241\n usb_probe_device+0x311/0x490 drivers/usb/core/driver.c:272\n really_probe+0xf20/0x20b0 drivers/base/dd.c:529\n driver_probe_device+0x293/0x390 drivers/base/dd.c:701\n __device_attach_driver+0x63f/0x830 drivers/base/dd.c:807\n bus_for_each_drv+0x2ca/0x3f0 drivers/base/bus.c:431\n __device_attach+0x4e2/0x7f0 drivers/base/dd.c:873\n device_initial_probe+0x4a/0x60 drivers/base/dd.c:920\n bus_probe_device+0x177/0x3d0 drivers/base/bus.c:491\n device_add+0x3b0e/0x40d0 drivers/base/core.c:2680\n usb_new_device+0x1bd4/0x2a30 drivers/usb/core/hub.c:2554\n hub_port_connect drivers/usb/core/hub.c:5208 [inline]\n hub_port_connect_change drivers/usb/core/hub.c:5348 [inline]\n port_event drivers/usb/core/hub.c:5494 [inline]\n hub_event+0x5e7b/0x8a70 drivers/usb/core/hub.c:5576\n process_one_work+0x1688/0x2140 kernel/workqueue.c:2269\n worker_thread+0x10bc/0x2730 kernel/workqueue.c:2415\n kthread+0x551/0x590 kernel/kthread.c:292\n ret_from_fork+0x1f/0x30 arch/x86/entry/entry_64.S:293\n\nLocal variable ----buf.i87@smsc75xx_bind created at:\n __smsc75xx_read_reg drivers/net/usb/smsc75xx.c:83 [inline]\n smsc75xx_wait_ready drivers/net/usb/smsc75xx.c:968 [inline]\n smsc75xx_bind+0x485/0x11e0 drivers/net/usb/smsc75xx.c:1482\n __smsc75xx_read_reg drivers/net/usb/smsc75xx.c:83 [inline]\n smsc75xx_wait_ready drivers/net/usb/smsc75xx.c:968 [inline]\n smsc75xx_bind+0x485/0x11e0 drivers/net/usb/smsc75xx.c:1482\n\nThis issue is caused because usbnet_read_cmd() reads less bytes than requested\n(zero byte in the reproducer). In this case, 'buf' is not properly filled.\n\nThis patch fixes the issue by returning -ENODATA if usbnet_read_cmd() reads\nless bytes than requested.(CVE-2023-52528)\n\nIn the Linux kernel, the following vulnerability has been resolved:\n\nwifi: wfx: fix possible NULL pointer dereference in wfx_set_mfp_ap()\n\nSince 'ieee80211_beacon_get()' can return NULL, 'wfx_set_mfp_ap()'\nshould check the return value before examining skb data. So convert\nthe latter to return an appropriate error code and propagate it to\nreturn from 'wfx_start_ap()' as well. Compile tested only.(CVE-2023-52593)\n\nIn the Linux kernel, the following vulnerability has been resolved:\n\njfs: fix slab-out-of-bounds Read in dtSearch\n\nCurrently while searching for current page in the sorted entry table\nof the page there is a out of bound access. Added a bound check to fix\nthe error.\n\nDave:\nSet return code to -EIO(CVE-2023-52602)\n\nIn the Linux kernel, the following vulnerability has been resolved:\n\nUBSAN: array-index-out-of-bounds in dtSplitRoot\n\nSyzkaller reported the following issue:\n\noop0: detected capacity change from 0 to 32768\n\nUBSAN: array-index-out-of-bounds in fs/jfs/jfs_dtree.c:1971:9\nindex -2 is out of range for type 'struct dtslot [128]'\nCPU: 0 PID: 3613 Comm: syz-executor270 Not tainted 6.0.0-syzkaller-09423-g493ffd6605b2 #0\nHardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 09/22/2022\nCall Trace:\n \u003cTASK\u003e\n __dump_stack lib/dump_stack.c:88 [inline]\n dump_stack_lvl+0x1b1/0x28e lib/dump_stack.c:106\n ubsan_epilogue lib/ubsan.c:151 [inline]\n __ubsan_handle_out_of_bounds+0xdb/0x130 lib/ubsan.c:283\n dtSplitRoot+0x8d8/0x1900 fs/jfs/jfs_dtree.c:1971\n dtSplitUp fs/jfs/jfs_dtree.c:985 [inline]\n dtInsert+0x1189/0x6b80 fs/jfs/jfs_dtree.c:863\n jfs_mkdir+0x757/0xb00 fs/jfs/namei.c:270\n vfs_mkdir+0x3b3/0x590 fs/namei.c:4013\n do_mkdirat+0x279/0x550 fs/namei.c:4038\n __do_sys_mkdirat fs/namei.c:4053 [inline]\n __se_sys_mkdirat fs/namei.c:4051 [inline]\n __x64_sys_mkdirat+0x85/0x90 fs/namei.c:4051\n do_syscall_x64 arch/x86/entry/common.c:50 [inline]\n do_syscall_64+0x3d/0xb0 arch/x86/entry/common.c:80\n entry_SYSCALL_64_after_hwframe+0x63/0xcd\nRIP: 0033:0x7fcdc0113fd9\nCode: ff ff c3 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 40 00 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 \u003c48\u003e 3d 01 f0 ff ff 73 01 c3 48 c7 c1 c0 ff ff ff f7 d8 64 89 01 48\nRSP: 002b:00007ffeb8bc67d8 EFLAGS: 00000246 ORIG_RAX: 0000000000000102\nRAX: ffffffffffffffda RBX: 0000000000000000 RCX: 00007fcdc0113fd9\nRDX: 0000000000000000 RSI: 0000000020000340 RDI: 0000000000000003\nRBP: 00007fcdc00d37a0 R08: 0000000000000000 R09: 00007fcdc00d37a0\nR10: 00005555559a72c0 R11: 0000000000000246 R12: 00000000f8008000\nR13: 0000000000000000 R14: 00083878000000f8 R15: 0000000000000000\n \u003c/TASK\u003e\n\nThe issue is caused when the value of fsi becomes less than -1.\nThe check to break the loop when fsi value becomes -1 is present\nbut syzbot was able to produce value less than -1 which cause the error.\nThis patch simply add the change for the values less than 0.\n\nThe patch is tested via syzbot.(CVE-2023-52603)\n\nIn the Linux kernel, the following vulnerability has been resolved:\n\nFS:JFS:UBSAN:array-index-out-of-bounds in dbAdjTree\n\nSyzkaller reported the following issue:\n\nUBSAN: array-index-out-of-bounds in fs/jfs/jfs_dmap.c:2867:6\nindex 196694 is out of range for type 's8[1365]' (aka 'signed char[1365]')\nCPU: 1 PID: 109 Comm: jfsCommit Not tainted 6.6.0-rc3-syzkaller #0\nHardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 08/04/2023\nCall Trace:\n \u003cTASK\u003e\n __dump_stack lib/dump_stack.c:88 [inline]\n dump_stack_lvl+0x1e7/0x2d0 lib/dump_stack.c:106\n ubsan_epilogue lib/ubsan.c:217 [inline]\n __ubsan_handle_out_of_bounds+0x11c/0x150 lib/ubsan.c:348\n dbAdjTree+0x474/0x4f0 fs/jfs/jfs_dmap.c:2867\n dbJoin+0x210/0x2d0 fs/jfs/jfs_dmap.c:2834\n dbFreeBits+0x4eb/0xda0 fs/jfs/jfs_dmap.c:2331\n dbFreeDmap fs/jfs/jfs_dmap.c:2080 [inline]\n dbFree+0x343/0x650 fs/jfs/jfs_dmap.c:402\n txFreeMap+0x798/0xd50 fs/jfs/jfs_txnmgr.c:2534\n txUpdateMap+0x342/0x9e0\n txLazyCommit fs/jfs/jfs_txnmgr.c:2664 [inline]\n jfs_lazycommit+0x47a/0xb70 fs/jfs/jfs_txnmgr.c:2732\n kthread+0x2d3/0x370 kernel/kthread.c:388\n ret_from_fork+0x48/0x80 arch/x86/kernel/process.c:147\n ret_from_fork_asm+0x11/0x20 arch/x86/entry/entry_64.S:304\n \u003c/TASK\u003e\n================================================================================\nKernel panic - not syncing: UBSAN: panic_on_warn set ...\nCPU: 1 PID: 109 Comm: jfsCommit Not tainted 6.6.0-rc3-syzkaller #0\nHardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 08/04/2023\nCall Trace:\n \u003cTASK\u003e\n __dump_stack lib/dump_stack.c:88 [inline]\n dump_stack_lvl+0x1e7/0x2d0 lib/dump_stack.c:106\n panic+0x30f/0x770 kernel/panic.c:340\n check_panic_on_warn+0x82/0xa0 kernel/panic.c:236\n ubsan_epilogue lib/ubsan.c:223 [inline]\n __ubsan_handle_out_of_bounds+0x13c/0x150 lib/ubsan.c:348\n dbAdjTree+0x474/0x4f0 fs/jfs/jfs_dmap.c:2867\n dbJoin+0x210/0x2d0 fs/jfs/jfs_dmap.c:2834\n dbFreeBits+0x4eb/0xda0 fs/jfs/jfs_dmap.c:2331\n dbFreeDmap fs/jfs/jfs_dmap.c:2080 [inline]\n dbFree+0x343/0x650 fs/jfs/jfs_dmap.c:402\n txFreeMap+0x798/0xd50 fs/jfs/jfs_txnmgr.c:2534\n txUpdateMap+0x342/0x9e0\n txLazyCommit fs/jfs/jfs_txnmgr.c:2664 [inline]\n jfs_lazycommit+0x47a/0xb70 fs/jfs/jfs_txnmgr.c:2732\n kthread+0x2d3/0x370 kernel/kthread.c:388\n ret_from_fork+0x48/0x80 arch/x86/kernel/process.c:147\n ret_from_fork_asm+0x11/0x20 arch/x86/entry/entry_64.S:304\n \u003c/TASK\u003e\nKernel Offset: disabled\nRebooting in 86400 seconds..\n\nThe issue is caused when the value of lp becomes greater than\nCTLTREESIZE which is the max size of stree. Adding a simple check\nsolves this issue.\n\nDave:\nAs the function returns a void, good error handling\nwould require a more intrusive code reorganization, so I modified\nOsama's patch at use WARN_ON_ONCE for lack of a cleaner option.\n\nThe patch is tested via syzbot.(CVE-2023-52604)",
						References: []string{
							"https://www.openeuler.org/en/security/safety-bulletin/detail.html?id=openEuler-SA-2024-1349",
							"https://www.openeuler.org/en/security/cve/detail.html?id=CVE-2023-52604",
							"https://nvd.nist.gov/vuln/detail/CVE-2023-52604",
						},
						Severity: types.SeverityHigh,
					},
				},
				{
					Key:   []string{"vulnerability-id", "openEuler-SA-2024-1349"},
					Value: map[string]interface{}{},
				},
			},
		},
		{
			name:    "sad path (dir doesn't exist)",
			dir:     filepath.Join("testdata", "badPath"),
			wantErr: "no such file or directory",
		},
		{
			name:    "sad path (failed to decode)",
			dir:     filepath.Join("testdata", "sad"),
			wantErr: "failed to decode openEuler CVRF JSON",
		},

	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := NewVulnSrc()
			vulnsrctest.TestUpdate(t, vs, vulnsrctest.TestUpdateArgs{
				Dir:        tt.dir,
				WantValues: tt.wantValues,
				WantErr:    tt.wantErr,
			})
		})
	}
}


func TestVulnSrc_Get(t *testing.T) {
	tests := []struct {
		name     string
		fixtures []string
		version  string
		pkgName  string
		dist     Distribution
		want     []types.Advisory
		wantErr  string
	}{
		{
			name:     "happy path 1",
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			version:  "22.03-LTS-SP2",
			pkgName:  "perf",
			want: []types.Advisory{
				{
					VulnerabilityID: "openEuler-SA-2024-1349",
					FixedVersion:    "5.10.0-153.48.0.126",
				},
			},
		},
		{
			name:     "happy path 2",
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			version:  "22.03-LTS-SP2",
			pkgName:  "perf-debuginfo",
			want: []types.Advisory{
				{
					VulnerabilityID: "openEuler-SA-2024-1349",
					FixedVersion:    "5.10.0-153.48.0.126",
				},
			},
		},
		{
			name:     "no advisories are returned",
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			version:  "23.09",
			pkgName:  "perf",
			want:     nil,
		},
		{
			name:     "GetAdvisories returns an error",
			fixtures: []string{"testdata/fixtures/sad.yaml"},
			version:  "22.03-LTS-SP2",
			pkgName:  "perf",
			wantErr:  "failed to unmarshal advisory JSON",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := NewVulnSrc()
			vulnsrctest.TestGet(t, vs, vulnsrctest.TestGetArgs{
				Fixtures:   tt.fixtures,
				WantValues: tt.want,
				Release:    tt.version,
				PkgName:    tt.pkgName,
				WantErr:    tt.wantErr,
			})
		})
	}
}

func TestSeverityFromThreat(t *testing.T) {
	testCases := map[string]types.Severity{
		"Low":       types.SeverityLow,
		"Medium":    types.SeverityMedium,
		"High": 	 types.SeverityHigh,
		"Critical":  types.SeverityCritical,
		"":          types.SeverityUnknown,
		"None":      types.SeverityUnknown,
	}
	for k, v := range testCases {
		assert.Equal(t, v, severityFromThreat(k))
	}
}

func TestGetOSVersion(t *testing.T) {
	testCases := []struct {
		inputPlatformCPE    string
		expectedOsVersion string
	}{
		{
			inputPlatformCPE:  "cpe:/a:openEuler:openEuler:22.03-LTS-SP2",
			expectedOsVersion: "openEuler-22.03-LTS-SP2",
		},
		{
			inputPlatformCPE:  "cpe:/a:openEuler:openEuler:20.03-LTS",
			expectedOsVersion: "openEuler-20.03-LTS",
		},
		{
			inputPlatformCPE:  "cpe:/a:openEuler:openEuler:21.03",
			expectedOsVersion: "openEuler-21.03",
		},
		{
			inputPlatformCPE:  "cpe:/a:openEuler:openEuler:20.03-LTS-LTS-SP4",
			expectedOsVersion: "",
		},
		{
			inputPlatformCPE:  "cpe:/a:openEuler:23.09",
			expectedOsVersion: "",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.inputPlatformCPE, func(t *testing.T) {
			actual := getOSVersion(tc.inputPlatformCPE)
			assert.Equal(t, tc.expectedOsVersion, actual, fmt.Sprintf("input data: %s", tc.inputPlatformCPE))
		})
	}
}
