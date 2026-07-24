package resolver

import "testing"

func TestParsePodUID(t *testing.T) {
	tests := []struct {
		name   string
		cgroup string
		want   string
		wantOK bool
	}{
		{
			name:   "systemd v2 burstable (underscores)",
			cgroup: "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod3f8e3c4d_1a2b_4c5d_8e9f_0a1b2c3d4e5f.slice/cri-containerd-abc123.scope",
			want:   "3f8e3c4d-1a2b-4c5d-8e9f-0a1b2c3d4e5f",
			wantOK: true,
		},
		{
			name:   "cgroupfs v1 besteffort (dashes)",
			cgroup: "11:memory:/kubepods/besteffort/pod3f8e3c4d-1a2b-4c5d-8e9f-0a1b2c3d4e5f/abc123def456",
			want:   "3f8e3c4d-1a2b-4c5d-8e9f-0a1b2c3d4e5f",
			wantOK: true,
		},
		{
			name:   "guaranteed qos systemd",
			cgroup: "0::/kubepods.slice/kubepods-podaaaaaaaa_bbbb_cccc_dddd_eeeeeeeeeeee.slice/cri-o-xyz.scope",
			want:   "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			wantOK: true,
		},
		{
			name:   "contiguous 32 hex (no separators)",
			cgroup: "0::/kubepods.slice/kubepods-pod3f8e3c4d1a2b4c5d8e9f0a1b2c3d4e5f.slice/crio-xyz.scope",
			want:   "3f8e3c4d-1a2b-4c5d-8e9f-0a1b2c3d4e5f",
			wantOK: true,
		},
		{
			name:   "multi-line v1 file, uid on one subsystem line",
			cgroup: "12:pids:/\n11:memory:/kubepods/burstable/pod11112222-3333-4444-5555-666677778888/deadbeef\n10:cpu:/",
			want:   "11112222-3333-4444-5555-666677778888",
			wantOK: true,
		},
		{
			name:   "uppercase hex normalized to lowercase",
			cgroup: "0::/kubepods.slice/kubepods-podAAAABBBB_CCCC_DDDD_EEEE_FFFF00001111.slice/x.scope",
			want:   "aaaabbbb-cccc-dddd-eeee-ffff00001111",
			wantOK: true,
		},
		{
			name:   "no pod segment (host process)",
			cgroup: "0::/system.slice/sshd.service",
			want:   "",
			wantOK: false,
		},
		{
			name:   "empty",
			cgroup: "",
			want:   "",
			wantOK: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ParsePodUID(tt.cgroup)
			if ok != tt.wantOK || got != tt.want {
				t.Fatalf("ParsePodUID() = %q,%v want %q,%v", got, ok, tt.want, tt.wantOK)
			}
		})
	}
}
