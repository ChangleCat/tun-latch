# TunLatch

macOS 上独立于代理客户端运行的 TUN 出口保护工具，使用 Rust、系统 PF 和终端界面。

当前开发目标为 **代理 UID 兼容模式**：可信 TUN 承接普通流量，在批准物理链路上允许已批准 socket UID 的 TCP/UDP，以保留代理规则模式直连；其他未授权直连阻断。当前用户选择 UID 0，因此同条件的其他 root socket 也可直连，不能承诺仅代理程序或所有业务隐藏真实出口。该方向尚未实现；UID 不是 PID/签名身份，实际节点 IP/端口不会硬编码。

**当前交付是可运行的只读工程框架，尚未提供防泄漏保护。** `tunlatchd` 仅提供网卡发现与状态查询，始终报告保护未知；不会访问 `/dev/pf`、调用 `pfctl`、更改路由或安装启动项。请使用普通用户运行。

## 构建与试运行

需要 macOS、Rustup 和 Xcode Command Line Tools。仓库固定 Rust 1.99.1 / Edition 2024，并提交 `Cargo.lock`。当前实测环境为 Apple Silicon、macOS 26.6.2；更低系统版本和 Intel 尚未实测，不声明最低兼容系统版本。`rust-version` 暂与固定工具链一致，不承诺支持更早的 Rust。

```sh
cargo build --workspace --locked
cargo run -p tunlatch -- config check examples/config.toml
```

在同一个终端中创建仅自己可访问的临时目录，然后启动观察服务：

```sh
TUNLATCH_RUNTIME_DIR=$(mktemp -d /tmp/tunlatch.XXXXXX)
printf '%s\n' "$TUNLATCH_RUNTIME_DIR"
cargo run -p tunlatchd -- --runtime-dir "$TUNLATCH_RUNTIME_DIR"
```

在另一个终端中，将下面的路径替换为上一步打印出的完整路径：

```sh
cargo run -p tunlatch -- status --runtime-dir /tmp/tunlatch.XXXXXX --json
cargo run -p tunlatch -- tui --runtime-dir /tmp/tunlatch.XXXXXX
```

TUI 优先展示候选 TUN，支持 `↑` / `↓`、`j` / `k` 和翻页键浏览全部网卡；`q` / `Esc` / `Ctrl-C` 退出、`r` 刷新，每 2 秒获取一次状态。后台不可用或刷新失败后清除上次快照并显示错误。关闭 TUI 不会停止后台。前台后台服务用 `Ctrl-C` 或 `SIGTERM` 结束，等待在途请求及已开始的原生枚举退出后清理自己创建的 socket。

服务不会覆盖已有 `control.sock`。若服务被 `SIGKILL` 导致路径残留，先确认原服务已结束，再手动移除该临时目录内的 socket；不要删除仍在运行的服务端点。当前目录只存放开发 socket，删除它不涉及 PF 恢复或停用。

## 结构与依赖方向

```text
crates/
  tunlatch-core/      纯领域模型、版本化配置校验、期望/已提交/观测状态
  tunlatch-platform/  macOS 边界：原生双栈网卡快照、受限文件读取、PF 能力状态
  tunlatch-ipc/       有界 JSON 帧、协议版本、同用户凭据校验、私有 socket 生命周期
  tunlatchd/          服务循环、并发上限、任务监督、超时与信号退出
  tunlatch/           普通用户 CLI、Ratatui TUI、离线配置校验
```

`core` 不依赖系统、异步运行时和界面。`platform`、`ipc` 分别依赖 `core`；两个入口按职责组合它们。TUI 不执行特权操作；目前 IPC 只接受 `status`，未知操作和字段均被拒绝。PF 适配接口当前只返回 `backend_not_implemented`，避免用模拟成功填补系统能力。

候选网卡的发现不授予信任：`utun` 名称只用于展示提示，网卡索引、地址和名称不能作为持久身份。当前没有可被反序列化伪造的“可信 TUN”对象，也没有默认直连例外。

## 当前能力与后续工作

| 范围 | 当前状态 |
| --- | --- |
| 固定工具链、工作区、lint、锁文件、CI、依赖检查策略 | 已建立 |
| 普通用户服务 → 有界 Unix Socket → CLI / TUI | 可运行，只读 |
| 网卡快照 | 原生 `getifaddrs`，保留 IPv4、IPv6 和 IPv6 scope；不是路由或身份验证 |
| 配置 | CLI 保留严格 v1 校验；`core::policy` 已实现有界 v2 草稿、显式迁移、规范化/摘要和条件规则判定；不持久化、不应用 |
| PF、已有连接约束、必要直连例外 | 待原型与实机验证 |
| 绑定领域模型 | 已实现候选/未受信报告/关联/确认分型，确认与刷新必须核对新采集序号及 FD 实例；没有实际可信 TUN 或 PF 资格 |
| 网络事件、平台身份采集、自动恢复 | 待实现 |
| 特权授权、原子持久化、LaunchDaemon、安装卸载、离线解锁 | 待设计与实现 |

下一步先完成 PF 能力验证：socket user 的双栈 TCP/UDP、unknown/其他 UID 对照及撤销后的旧连接，连同 anchor 实际执行顺序与共存、事务、启用引用和接口复用。确认这些机制后再接入保护启停，不以 UI 或模型测试替代内核与物理出口证据。当前 v2 草稿模型没有 UID 授权；后续将通过独立受保护策略接入，文件导入不能生成批准。

`tunlatch-core` 的 v2 配置和绑定 API 是无系统副作用的领域模型。普通规则的允许只返回
`NeedsEgressAuthorization`，直连例外仅是候选；一致的采集报告不等于真实平台事实。
`EnforcementQualifiedBinding` 当前不可安全构造。原有 CLI/IPC 未接入这些新能力，仍报告保护未知。

PF 实验准备工具可用普通用户运行：

```sh
cargo run -p tunlatch-platform --example pf_lab --locked -- plan
TUNLATCH_LAB_DIR=$(mktemp -d /tmp/tunlatch-pf-lab.XXXXXX)
cargo run -p tunlatch-platform --example pf_lab --locked -- prepare "$TUNLATCH_LAB_DIR"
"$TUNLATCH_LAB_DIR/pf-lab" recover
```

工具只生成候选计划、规则文本和独立准备程序；`recover` 默认也只展示计划。
**所有实机请求均被拒绝，即使提供两个 opt-in 标志也不会执行 PF。当前没有可用的实机恢复包。**
固定 anchor 名称、标签、收据或模拟测试均不证明内核资源归属；完整预检、可信程序部署、
有界进程监督、接口复用、状态选择、引用和流量采集仍须补齐，实机操作另行审核。

贡献约定见 [AGENTS.md](AGENTS.md)，完整工程检查见 [CI 配置](.github/workflows/ci.yml)，安全边界见 [SAFETY.md](SAFETY.md)。本地 `docs/` 保存需求、调研和编码指导，按已有 `.gitignore` 设置保留为本地资料；本 README 记录可随代码交付的架构与能力边界。

许可证：[GPL-3.0](LICENSE)。
