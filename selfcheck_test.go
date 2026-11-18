package main

import "testing"

// 公网网关 + 目标是网关域名/IP -> 判为自连接，杜绝死循环。
func TestSelfTargetPublicGateway(t *testing.T) {
	s := &snipSvc{cfg: &Config{GatewayIP: "104.251.233.131", Domain: "kfc.example.com"}}
	if !s.isSelfTarget("kfc.example.com", nil) {
		t.Fatal("网关域名自身应判为自连接目标")
	}
	if !s.isSelfTarget("104.251.233.131", nil) {
		t.Fatal("网关公网 IP 自身应判为自连接目标")
	}
	if s.isSelfTarget("youtube.com", nil) {
		t.Fatal("无解析结果时不应误判")
	}
}

// 回环/私网网关（e2e 测试、本地调试）必须跳过防护，
// 否则假 DNS 把所有域名指向 127.0.0.1 时会把正常转发误杀。
func TestSelfTargetSkipsPrivateGateway(t *testing.T) {
	s := &snipSvc{cfg: &Config{GatewayIP: "127.0.0.1", Domain: "kfc.example.com"}}
	if s.isSelfTarget("127.0.0.1", nil) {
		t.Fatal("回环网关应跳过自连接防护")
	}
}
