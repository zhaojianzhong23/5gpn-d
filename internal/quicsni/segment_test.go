package quicsni

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"testing"
)

// 编码一个无符号 varint（RFC 9000 §16），支持到 2 字节，够测试用。
func encVarint(v int) []byte {
	switch {
	case v < 64:
		return []byte{byte(v)}
	case v < 16384:
		return []byte{0x40 | byte(v>>8), byte(v)}
	default:
		panic("encVarint: 测试值超过 2 字节 varint 范围")
	}
}

// 把一个 CRYPTO 帧（0x06 + offset + length + data）编码成帧字节。
func cryptoFrame(offset int, data []byte) []byte {
	f := []byte{0x06}
	f = append(f, encVarint(offset)...)
	f = append(f, encVarint(len(data))...)
	f = append(f, data...)
	return f
}

// sealInitialWithPN 是 sealInitial 的可指定包号版本，避免两个分片用同一个包号。
func sealInitialWithPN(t *testing.T, version uint32, vp quicVersion, dcid, frames []byte, pn byte) []byte {
	t.Helper()
	const pnLen = 4
	hdrLen := 1 + 4 + 1 + len(dcid) + 1 + 1 + 2 + pnLen
	if pad := 1200 - (hdrLen + len(frames) + 16); pad > 0 {
		frames = append(append([]byte(nil), frames...), make([]byte, pad)...)
	}
	length := pnLen + len(frames) + 16
	hdr := []byte{0xc0 | vp.initialType<<4 | (pnLen - 1)}
	hdr = binary.BigEndian.AppendUint32(hdr, version)
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, 0, 0) // SCID 长度 0、token 长度 0
	hdr = append(hdr, 0x40|byte(length>>8), byte(length)) // length
	pnOffset := len(hdr)
	hdr = append(hdr, 0, 0, 0, pn)

	key, iv, hp := deriveClientInitialKeys(vp, dcid)
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	nonce := append([]byte(nil), iv...)
	nonce[len(nonce)-1] ^= pn
	pkt := aead.Seal(append([]byte(nil), hdr...), nonce, frames, hdr)

	hpBlock, _ := aes.NewCipher(hp)
	var mask [16]byte
	hpBlock.Encrypt(mask[:], pkt[pnOffset+4:pnOffset+20])
	pkt[0] ^= mask[0] & 0x0f
	for i := 0; i < pnLen; i++ {
		pkt[pnOffset+i] ^= mask[1+i]
	}
	return pkt
}

// TestClientHelloSplitAcrossInitials 复现 Chrome/Cronet 后量子密钥交换：
// ClientHello 被拆成两个 CRYPTO 分片、分装进两个 Initial 数据报。Decoder 必须
// 在第一个包返回「未完整」，收到第二个包后按 offset 拼出完整 ClientHello 并
// 还原出 example.com。这正是 dotmux 旧实现（首包解析失败即丢弃）会失败的场景。
func TestClientHelloSplitAcrossInitials(t *testing.T) {
	// 从 RFC 9001 权威向量取出明文 CRYPTO 数据。
	plain, _, err := decryptInitial(rfcPacket(t))
	if err != nil {
		t.Fatal(err)
	}
	// 从明文帧序列里提取 CRYPTO 负载（跳过帧头），即完整 ClientHello 字节。
	// 明文的第一个有效帧就是 CRYPTO：type(0x06) + offset + len + data。
	if len(plain) < 3 || plain[0] != 0x06 {
		t.Fatalf("RFC 明文首帧不是 CRYPTO: %x", plain[:min(8, len(plain))])
	}
	offN, n1, ok1 := readVarint(plain[1:])
	lenN, n2, ok2 := readVarint(plain[1+n1:])
	if !ok1 || !ok2 { t.Fatal("CRYPTO 帧头 varint 解析失败") }
	if offN != 0 || n1 == 0 || n2 == 0 {
		t.Fatalf("CRYPTO 帧头异常: off=%d n1=%d n2=%d", offN, n1, n2)
	}
	head := 1 + n1 + n2
	hello := plain[head : head+int(lenN)]
	if len(hello) != int(lenN) {
		t.Fatalf("CRYPTO 数据截断: have %d want %d", len(hello), lenN)
	}

	// 拆成两半，分别放 offset 0 和 offset=len(half)。
	half := len(hello) / 2
	dcid := mustHex(t, "8394c8f03e515708")
	p1 := sealInitialWithPN(t, 0x00000001, versionV1, dcid, cryptoFrame(0, hello[:half]), 1)
	p2 := sealInitialWithPN(t, 0x00000001, versionV1, dcid, cryptoFrame(half, hello[half:]), 2)

	d := NewDecoder()
	// 第一个包：还差一半，必须返回未完整且不报错。
	sni, ok, err := d.Feed(p1)
	if err != nil {
		t.Fatalf("第一片解析报错: %v", err)
	}
	if ok || sni != "" {
		t.Fatalf("第一片不应还原出 SNI: sni=%q ok=%v", sni, ok)
	}
	// 第二个包：拼齐，还原出 example.com。
	sni, ok, err = d.Feed(p2)
	if err != nil {
		t.Fatalf("第二片解析报错: %v", err)
	}
	if !ok || sni != "example.com" {
		t.Fatalf("跨包拼接后 SNI=%q ok=%v, want example.com", sni, ok)
	}
	if d.Packets() != 2 {
		t.Fatalf("应记录 2 个 Initial 包, got %d", d.Packets())
	}
}

// TestOutOfOrderSegments 分片乱序到达（先 offset=half 后 offset=0）也要能拼出。
func TestOutOfOrderSegments(t *testing.T) {
	plain, _, err := decryptInitial(rfcPacket(t))
	if err != nil {
		t.Fatal(err)
	}
	_, n1, ok1 := readVarint(plain[1:])
	lenN, n2, ok2 := readVarint(plain[1+n1:])
	if !ok1 || !ok2 { t.Fatal("CRYPTO 帧头 varint 解析失败") }
	head := 1 + n1 + n2
	hello := plain[head : head+int(lenN)]
	half := len(hello) / 2
	dcid := mustHex(t, "8394c8f03e515708")

	d := NewDecoder()
	// 先到后半段：assemble 从 offset 0 起拼不出，未完整。
	if _, ok, err := d.Feed(sealInitialWithPN(t, 1, versionV1, dcid, cryptoFrame(half, hello[half:]), 1)); err != nil || ok {
		t.Fatalf("仅后半段不应成功: ok=%v err=%v", ok, err)
	}
	// 再到前半段：两段都在，拼齐。
	sni, ok, err := d.Feed(sealInitialWithPN(t, 1, versionV1, dcid, cryptoFrame(0, hello[:half]), 2))
	if err != nil || !ok || sni != "example.com" {
		t.Fatalf("乱序拼接 SNI=%q ok=%v err=%v", sni, ok, err)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
