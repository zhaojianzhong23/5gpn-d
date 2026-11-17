#!/usr/bin/env bash
# 生成 iOS DoT 描述文件，输出到 stdout。
# 用法：bash scripts/make-profile.sh dot.example.com [203.0.113.10]
set -euo pipefail

DOMAIN="${1:?用法: make-profile.sh <DoT域名> [网关IP]}"
IP="${2:-}"
U1="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen)"
U2="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen)"

ADDR_BLOCK=""
if [[ -n "$IP" ]]; then
    ADDR_BLOCK="        <key>ServerAddresses</key>
        <array><string>${IP}</string></array>"
fi

cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>DNSSettings</key>
      <dict>
        <key>DNSProtocol</key>
        <string>TLS</string>
        <key>ServerName</key>
        <string>${DOMAIN}</string>
${ADDR_BLOCK}
      </dict>
      <key>PayloadType</key>
      <string>com.apple.dnsSettings.managed</string>
      <key>PayloadIdentifier</key>
      <string>com.dotmux.dns.${U1}</string>
      <key>PayloadUUID</key>
      <string>${U1}</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>PayloadDisplayName</key>
      <string>dotmux DoT (${DOMAIN})</string>
    </dict>
  </array>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadIdentifier</key>
  <string>com.dotmux.profile.${U2}</string>
  <key>PayloadUUID</key>
  <string>${U2}</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
  <key>PayloadDisplayName</key>
  <string>dotmux</string>
  <key>PayloadDescription</key>
  <string>加密 DNS 分流网关</string>
</dict>
</plist>
EOF
