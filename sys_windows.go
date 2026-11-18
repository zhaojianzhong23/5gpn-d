//go:build windows

package main

// raiseFdLimit 在 Windows 上没有 RLIMIT_NOFILE 这一套，
// 这里留空只是为了本机能 vet/test；正式部署目标是 linux。
func raiseFdLimit() {}

// acquireLock 在 Windows 上不参与单实例保护：
// 开发机上跑测试不需要锁，也不该因为 /run 不存在而报错。
// 真要跑服务，请在 linux 上跑，那边的 flock 实现才是有效的那份。
func acquireLock(cfgPath string) error { return nil }
