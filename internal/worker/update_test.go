package worker

import (
	"os"
	"strings"
	"testing"
)

// TestReplaceFlagValue 覆盖 -c/-token 的四种写法与缺失场景：
// 自更新重启必须用"当前生效"的连接配置，否则迁移后重启会带着旧参数。
func TestReplaceFlagValue(t *testing.T) {
	cases := []struct {
		name string
		args []string
		flag string
		val  string
		want []string
	}{
		{
			name: "separate value",
			args: []string{"-c", "old:10240", "-proxy"},
			flag: "c", val: "new:10240",
			want: []string{"-c=new:10240", "-proxy"},
		},
		{
			name: "equals form",
			args: []string{"-c=old:10240", "-token=oldtok"},
			flag: "c", val: "new:10240",
			want: []string{"-c=new:10240", "-token=oldtok"},
		},
		{
			name: "double dash",
			args: []string{"--token", "oldtok"},
			flag: "token", val: "newtok",
			want: []string{"-token=newtok"},
		},
		{
			name: "missing flag is appended",
			args: []string{"-proxy"},
			flag: "token", val: "newtok",
			want: []string{"-proxy", "-token=newtok"},
		},
		{
			name: "value containing dashes/colons survives",
			args: []string{"-c", "1.2.3.4:10240", "-daemon"},
			flag: "c", val: "[::1]:10240",
			want: []string{"-c=[::1]:10240", "-daemon"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := replaceFlagValue(tc.args, tc.flag, tc.val)
			if strings.Join(got, " ") != strings.Join(tc.want, " ") {
				t.Fatalf("replaceFlagValue(%v, %s, %s) = %v, want %v", tc.args, tc.flag, tc.val, got, tc.want)
			}
		})
	}
}

// TestReplaceFlagValueEmptyValueKeepsArgs 空值（未配置 token）不得改写，
// 否则会把 -token 抹成空串导致启动失败。
func TestReplaceFlagValueEmptyValueKeepsArgs(t *testing.T) {
	args := []string{"-c", "keep:10240", "-token", "keep"}
	if got := replaceFlagValue(args, "token", ""); strings.Join(got, " ") != strings.Join(args, " ") {
		t.Fatalf("empty value must not rewrite args: %v", got)
	}
}

// TestRestartArgsUsesCurrentConfig 迁移（handleReconfigure）之后重启，
// 参数里的 -c/-token 必须是新 controller，而不是原始启动参数。
func TestRestartArgsUsesCurrentConfig(t *testing.T) {
	orig := os.Args
	defer func() { os.Args = orig }()
	os.Args = []string{"/usr/bin/worker", "-c", "old-ctrl:10240", "-token", "old-token", "-daemon"}

	w := &Worker{}
	w.setReconfigure("new-ctrl:10240", "new-token")

	args := w.restartArgs()
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "old-ctrl") || strings.Contains(joined, "old-token") {
		t.Fatalf("restart args still carry stale controller/token: %v", args)
	}
	if !containsArg(args, "-c=new-ctrl:10240") {
		t.Fatalf("restart args missing current controller: %v", args)
	}
	if !containsArg(args, "-token=new-token") {
		t.Fatalf("restart args missing current token: %v", args)
	}
	// 其他参数（-daemon 等）必须保留
	if !containsArg(args, "-daemon") {
		t.Fatalf("restart args dropped unrelated flags: %v", args)
	}
}

// TestRestartArgsRoundTrip 验证 Windows 换身流程经环境变量传递参数后
// 能原样还原（正式路径进程拿不到原进程内存，只能靠 env 传递）。
func TestRestartArgsRoundTrip(t *testing.T) {
	orig := os.Args
	defer func() { os.Args = orig }()
	os.Args = []string{"/usr/bin/worker", "-c", "old:1", "-token", "old"}

	w := &Worker{}
	w.setReconfigure("new-ctrl:10240", "new-token")
	args := w.restartArgs()

	t.Setenv("BLACKOUT_UPDATE_ARGS", encodeRestartArgs(args))
	got := restartArgsFromEnv()
	if strings.Join(got, " ") != strings.Join(args, " ") {
		t.Fatalf("env round-trip mismatch: got %v, want %v", got, args)
	}
}

// TestRestartArgsFromEnvFallback 环境变量缺失/损坏时回退命令行
func TestRestartArgsFromEnvFallback(t *testing.T) {
	orig := os.Args
	defer func() { os.Args = orig }()
	os.Args = []string{"/usr/bin/worker", "-c", "cli:1"}

	t.Setenv("BLACKOUT_UPDATE_ARGS", "")
	if got := restartArgsFromEnv(); strings.Join(got, " ") != "-c cli:1" {
		t.Fatalf("missing env must fall back to os.Args, got %v", got)
	}
	t.Setenv("BLACKOUT_UPDATE_ARGS", "{not json")
	if got := restartArgsFromEnv(); strings.Join(got, " ") != "-c cli:1" {
		t.Fatalf("corrupt env must fall back to os.Args, got %v", got)
	}
}

func containsArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}
