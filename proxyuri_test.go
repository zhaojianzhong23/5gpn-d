package main

import (
	"encoding/base64"
	"encoding/json"
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
