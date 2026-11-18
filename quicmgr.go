package main

import "sync"

// quicMgr 管 QUIC 中继的运行时启停。
//
// 为什么要能热开关：改完配置重启服务，会把所有 TCP 连接和 DoT 会话一起断掉，
// 而调这个开关往往只是想试试 QUIC 对自己这条链路有没有用。热开关只影响
// UDP 443，手机上正在跑的 TCP 连接一条都不会断。
type quicMgr struct {
	cfg   *Config
	rules func() *RuleSet
	dyn   *Dyn

	mu    sync.Mutex
	relay *quicRelay
}

func newQUICMgr(cfg *Config, rules func() *RuleSet, dyn *Dyn) *quicMgr {
	return &quicMgr{cfg: cfg, rules: rules, dyn: dyn}
}

// Running 报告中继当前是否真的在跑。
func (m *quicMgr) Running() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.relay != nil && !m.relay.closed.Load()
}

// Start 起中继。已经在跑就直接返回 —— 连点两下按钮不该启出第二个监听，
// 那会立刻撞上 UDP 端口被占用。
func (m *quicMgr) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.relay != nil && !m.relay.closed.Load() {
		return nil
	}
	r, err := startQUIC(m.cfg, m.rules, m.dyn)
	if err != nil {
		return err
	}
	m.relay = r
	return nil
}

// Stop 停中继，没在跑时是空操作。
func (m *quicMgr) Stop() error {
	m.mu.Lock()
	r := m.relay
	m.relay = nil
	m.mu.Unlock()
	if r == nil {
		return nil
	}
	return r.Close()
}

// Toggle 按「当前状态取反」开关，并写回配置。
// 先确认启停成功再落盘：这样 config 里的 enabled 永远等于真实状态，
// 不会出现「配置说开着、进程里其实没跑」这种下次重启才发现的错位。
func (m *quicMgr) Toggle() (bool, error) {
	on := !m.Running()
	if on {
		if err := m.Start(); err != nil {
			return false, err
		}
	} else if err := m.Stop(); err != nil {
		return false, err
	}
	if err := m.dyn.SetQUICEnabled(on); err != nil {
		return on, err
	}
	return on, nil
}

// Set 显式开关，语义同 Toggle。Start/Stop 都是幂等的，重复调到同一个状态
// 不会出错，只是会多写一次配置文件。
func (m *quicMgr) Set(on bool) error {
	if on {
		if err := m.Start(); err != nil {
			return err
		}
	} else if err := m.Stop(); err != nil {
		return err
	}
	return m.dyn.SetQUICEnabled(on)
}
