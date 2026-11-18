package main

// mihomo 内核进程的生命周期：崩了必须能被发现，不能继续往死端口上发连接。

import (
	"os"
	"os/exec"
	"testing"
)

func TestMihomoAddrHidesDeadProcess(t *testing.T) {
	m := newMihomoMgr("/nonexistent/mihomo", t.TempDir())
	p := &mihomoProc{
		name: "us", port: 20001, done: make(chan struct{}),
		cmd: &exec.Cmd{Process: &os.Process{Pid: 1}},
	}
	m.procs["us"] = p

	if got := m.Addr("us"); got != "127.0.0.1:20001" {
		t.Fatalf("进程活着时应返回地址，得到 %q", got)
	}
	if !m.Running()["us"] {
		t.Fatal("Running 应为 true")
	}

	// 内核被 OOM 杀掉之后：地址必须变空，否则每条连接都去 connect 一个没人
	// 监听的端口，等满超时才报错——整条出口的域名集体超时。
	p.dead = true
	if got := m.Addr("us"); got != "" {
		t.Fatalf("内核已退出还返回 %q，调用方会去连死端口", got)
	}
	if m.Running()["us"] {
		t.Fatal("内核已退出，Running 应报 false")
	}

	// 没有记录的出口
	if got := m.Addr("nope"); got != "" {
		t.Fatalf("不存在的出口返回了 %q", got)
	}
}
