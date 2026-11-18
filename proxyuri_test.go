package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func mustParse(t *testing.T, uri string) ProxyNode {
	t.Helper()
	n, err := ParseProxyURI(uri)
	if err != nil {
		t.Fatalf("解析 %q 失败: %v", uri, err)
	}
	return n
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestParseSS(t *testing.T) {
	// 新格式：base64(userinfo)@host:port
	n := mustParse(t, "ss://"+b64("aes-256-gcm:pass123")+"@1.2.3.4:8388#hk")
	if n.Kind() != "ss" || n["server"] != "1.2.3.4" || n["port"] != 8388 {
		t.Fatalf("字段不对: %v", n)
	}
	if n["cipher"] != "aes-256-gcm" || n["password"] != "pass123" {
		t.Fatalf("凭据不对: %v", n)
	}

	// 旧格式：整段 base64
	n2 := mustParse(t, "ss://"+b64("chacha20-ietf-poly1305:pw@5.6.7.8:9999")+"#tag")
	if n2["server"] != "5.6.7.8" || n2["port"] != 9999 || n2["password"] != "pw" {
		t.Fatalf("旧格式解析不对: %v", n2)
	}

	// 明文 userinfo 也要认
	n3 := mustParse(t, "ss://aes-128-gcm:plain@9.9.9.9:8388")
	if n3["password"] != "plain" {
		t.Fatalf("明文凭据不对: %v", n3)
	}
}

func TestParseVMess(t *testing.T) {
	payload := map[string]any{
		"v": "2", "ps": "test", "add": "example.com", "port": "443",
		"id": "uuid-1234", "aid": "0", "scy": "auto", "net": "ws",
		"host": "cdn.example.com", "path": "/ws", "tls": "tls", "sni": "cdn.example.com",
	}
	raw, _ := json.Marshal(payload)
	n := mustParse(t, "vmess://"+base64.StdEncoding.EncodeToString(raw))
	if n.Kind() != "vmess" || n["server"] != "example.com" || n["port"] != 443 {
		t.Fatalf("字段不对: %v", n)
	}
	if n["uuid"] != "uuid-1234" || n["alterId"] != 0 {
		t.Fatalf("凭据不对: %v", n)
	}
	if n["tls"] != true || n["servername"] != "cdn.example.com" {
		t.Fatalf("TLS 字段不对: %v", n)
	}
	ws, ok := n["ws-opts"].(map[string]any)
	if !ok || ws["path"] != "/ws" {
		t.Fatalf("ws 选项不对: %v", n["ws-opts"])
	}
}

func TestParseVLESSReality(t *testing.T) {
	uri := "vless://uuid-abc@1.1.1.1:443?security=reality&pbk=PUBKEY&sid=ab12&fp=chrome" +
		"&sni=www.example.com&flow=xtls-rprx-vision&type=grpc&serviceName=gsvc#n"
	n := mustParse(t, uri)
	if n["uuid"] != "uuid-abc" || n["flow"] != "xtls-rprx-vision" {
		t.Fatalf("vless 字段不对: %v", n)
	}
	if n["tls"] != true || n["servername"] != "www.example.com" {
		t.Fatalf("TLS 字段不对: %v", n)
	}
	ro, ok := n["reality-opts"].(map[string]any)
	if !ok || ro["public-key"] != "PUBKEY" || ro["short-id"] != "ab12" {
		t.Fatalf("reality 参数不对: %v", n["reality-opts"])
	}
	grpc, ok := n["grpc-opts"].(map[string]any)
	if !ok || grpc["grpc-service-name"] != "gsvc" {
		t.Fatalf("grpc 参数不对: %v", n["grpc-opts"])
	}
}

func TestParseTrojanWS(t *testing.T) {
	n := mustParse(t, "trojan://secret@2.2.2.2:8443?sni=a.example.com&type=ws&path=%2Fws&host=a.example.com#t")
	if n.Kind() != "trojan" || n["password"] != "secret" || n["port"] != 8443 {
		t.Fatalf("字段不对: %v", n)
	}
	if n["sni"] != "a.example.com" && n["servername"] != "a.example.com" {
		t.Fatalf("sni 不对: %v", n)
	}
	ws, ok := n["ws-opts"].(map[string]any)
	if !ok || ws["path"] != "/ws" {
		t.Fatalf("ws 参数不对: %v", n["ws-opts"])
	}
}

func TestParseHysteria2(t *testing.T) {
	n := mustParse(t, "hysteria2://pw@3.3.3.3:443?sni=b.example.com&obfs=salamander&obfs-password=ob&insecure=1#h")
	if n.Kind() != "hysteria2" || n["password"] != "pw" || n["sni"] != "b.example.com" {
		t.Fatalf("字段不对: %v", n)
	}
	if n["obfs"] != "salamander" || n["obfs-password"] != "ob" {
		t.Fatalf("obfs 不对: %v", n)
	}
	if n["skip-cert-verify"] != true {
		t.Fatalf("insecure 未生效: %v", n)
	}
}

func TestParseTUICAndAnyTLS(t *testing.T) {
	n := mustParse(t, "tuic://uuid-x:pw@4.4.4.4:443?sni=c.example.com#t")
	if n.Kind() != "tuic" || n["uuid"] != "uuid-x" || n["password"] != "pw" {
		t.Fatalf("tuic 字段不对: %v", n)
	}
	m := mustParse(t, "anytls://pw2@5.5.5.5:8443?sni=d.example.com#a")
	if m.Kind() != "anytls" || m["password"] != "pw2" || m["port"] != 8443 {
		t.Fatalf("anytls 字段不对: %v", m)
	}
}

func TestParseNaive(t *testing.T) {
	// naive 落到 http + TLS：服务端就是标准 CONNECT 代理。
	n := mustParse(t, "naive+https://u:p@naive.example.com:8443?sni=sni.example.com#n")
	if n.Kind() != "http" {
		t.Fatalf("naive 应落到 http 类型，实际 %v", n.Kind())
	}
	if n["server"] != "naive.example.com" || n["port"] != 8443 {
		t.Fatalf("地址不对: %v", n)
	}
	if n["username"] != "u" || n["password"] != "p" {
		t.Fatalf("凭据不对: %v", n)
	}
	if n["tls"] != true || n["sni"] != "sni.example.com" {
		t.Fatalf("TLS 字段不对: %v", n)
	}
	// http outbound 认 sni，不认 servername；写错了 mihomo 会静默用服务器地址。
	if _, bad := n["servername"]; bad {
		t.Fatalf("不该写 servername: %v", n)
	}
	// 纯 TCP 隧道，必须显式声明不支持 UDP。
	if n["udp"] != false {
		t.Fatalf("naive 不该开 udp: %v", n["udp"])
	}

	// 简写 naive:// 默认 443，不给 sni 时用主机名。
	m := mustParse(t, "naive://a:b@h.example.com")
	if m["port"] != 443 || m["sni"] != "h.example.com" {
		t.Fatalf("默认值不对: %v", m)
	}

	// 指纹参数要透传，naive 的伪装效果一半靠这个。
	f := mustParse(t, "naive+https://x:y@fp.example.com:443?fp=chrome")
	if f["fingerprint"] != "chrome" {
		t.Fatalf("fingerprint 未透传: %v", f)
	}

	// allowInsecure 要映射成 mihomo 的 skip-cert-verify。
	s := mustParse(t, "naive+https://x:y@self.example.com:443?allowInsecure=1")
	if s["skip-cert-verify"] != true {
		t.Fatalf("allowInsecure 未生效: %v", s)
	}

	// QUIC 传输没有对应实现，要明确报错而不是静默降级。
	if _, err := ParseProxyURI("naive+quic://u:p@h.example.com:443"); err == nil {
		t.Fatal("naive+quic 应当报错")
	}
}

func TestParseSocksAndHTTP(t *testing.T) {
	n := mustParse(t, "socks5://user:pass@6.6.6.6:1080")
	if n.Kind() != "socks5" || n["username"] != "user" || n["password"] != "pass" {
		t.Fatalf("socks5 字段不对: %v", n)
	}
	m := mustParse(t, "http://u:p@7.7.7.7:8080")
	if m.Kind() != "http" || m["port"] != 8080 {
		t.Fatalf("http 字段不对: %v", m)
	}
	if _, has := m["tls"]; has {
		t.Error("http 不该带 tls")
	}
}

func TestParseBadURI(t *testing.T) {
	bad := []string{
		"", "ftp://1.2.3.4:21", "ss://不是base64", "vmess://" + b64("not json"),
		"vless://uuid@1.1.1.1:443?security=reality", // 缺 pbk
	}
	for _, u := range bad {
		if _, err := ParseProxyURI(u); err == nil {
			t.Errorf("%q 应该解析失败", u)
		}
	}
}

func TestParseSnell(t *testing.T) {
	// v6：PSK 12–255 字节，UDP 从 v3 起才有，这里应该默认开。
	n := mustParse(t, "snell://psk-1234567890@sn.example.com:8443?version=6")
	if n.Kind() != "snell" {
		t.Fatalf("类型不对: %v", n)
	}
	if n["server"] != "sn.example.com" || n["port"] != 8443 || n["psk"] != "psk-1234567890" {
		t.Fatalf("地址或凭据不对: %v", n)
	}
	if n["version"] != 6 || n["udp"] != true {
		t.Fatalf("版本或 udp 不对: %v", n)
	}
	if _, has := n["mode"]; has {
		t.Error("没写 mode 就不该出现，交给 mihomo 用 default")
	}

	// mode 只 v6 认，取值必须和服务端一致。
	m := mustParse(t, "snell://psk-1234567890@h:443?version=6&mode=unshaped&reuse=1")
	if m["mode"] != "unshaped" || m["reuse"] != true {
		t.Fatalf("v6 的 mode / reuse 不对: %v", m)
	}

	// v4 + obfs 是老组合，字段要落到 mihomo 的 obfs-opts。
	o := mustParse(t, "snell://psk-1234567890@h:443?version=4&obfs=http&obfs-host=cdn.example.com")
	opts, ok := o["obfs-opts"].(ProxyNode)
	if !ok || opts["mode"] != "http" || opts["host"] != "cdn.example.com" {
		t.Fatalf("obfs-opts 不对: %v", o)
	}
	if o["udp"] != true {
		t.Error("v4 应支持 UDP")
	}

	// 不写 version 按 4 走（机场主流）；v5 服务端兼容 v4 客户端，归一成 4。
	if d := mustParse(t, "snell://psk-1234567890@h"); d["version"] != 4 || d["port"] != 443 {
		t.Fatalf("默认值不对: %v", d)
	}
	if v5 := mustParse(t, "snell://psk-1234567890@h:443?version=5"); v5["version"] != 4 {
		t.Fatalf("v5 应归一成 v4: %v", v5)
	}

	// psk 也可以只放 query。
	if qq := mustParse(t, "snell://h:443?psk=psk-1234567890&version=4"); qq["psk"] != "psk-1234567890" {
		t.Fatalf("query 里的 psk 没取到: %v", qq)
	}

	// percent 编码的 psk 要解回原文，否则握手用的密钥是错的。
	if e := mustParse(t, "snell://a%40b%2Fc%3Dd12345@h:443?version=4"); e["psk"] != "a@b/c=d12345" {
		t.Fatalf("psk 未解码: %v", e)
	}

	// v1 没有 UDP，声明了也得拒。
	if _, err := ParseProxyURI("snell://psk-1234567890@h:443?version=1&udp=1"); err == nil {
		t.Error("v1 + udp 应该报错")
	}
}

func TestParseSnellRejects(t *testing.T) {
	cases := []struct{ uri, want string }{
		{"snell://@h:443", "缺少 PSK"},
		{"snell://h:443", "缺少 PSK"},
		{"snell://psk-1234567890@h:443?version=7", "不支持"},
		{"snell://short@h:443?version=6", "12–255"},
		{"snell://psk-1234567890@h:443?version=6&obfs=http", "不支持 obfs"},
		{"snell://psk-1234567890@h:443?version=6&mode=fast", "mode 只能"},
	}
	for _, c := range cases {
		_, err := ParseProxyURI(c.uri)
		if err == nil {
			t.Errorf("%q 应该解析失败", c.uri)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q 的错误信息应含 %q，实际 %q", c.uri, c.want, err.Error())
		}
	}
}

func TestSnellIsProxyLink(t *testing.T) {
	if linkKind("snell://psk@h:443") != "snell" {
		t.Errorf("linkKind 应识别 snell，实际 %q", linkKind("snell://psk@h:443"))
	}
	if !isProxyLink("snell://psk@h:443") {
		t.Error("snell 链接应交给 mihomo")
	}
}
