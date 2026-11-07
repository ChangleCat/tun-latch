# TunLatch

macOS 上独立于代理客户端运行的 TUN 出口保护工具，使用 Rust、系统 PF 和终端界面。

当前开发目标为 **代理 UID 兼容模式**：可信 TUN 承接普通流量，在批准物理链路上允许已批准 socket UID 的 TCP/UDP，以保留代理规则模式直连；其他未授权直连阻断。当前用户选择 UID 0，因此同条件的其他 root socket 也可直连，不能承诺仅代理程序或所有业务隐藏真实出口。该方向尚未实现；UID 不是 PID/签名身份，实际节点 IP/端口不会硬编码。

**当前交付是可运行的观察服务、离线配置工具和可选模拟控制，尚未提供防泄漏保护。** `tunlatchd` 始终报告实际保护未知；不会访问 `/dev/pf`、调用 `pfctl`、更改路由或安装启动项。请使用普通用户运行。

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
cargo run -p tunlatch -- status --runtime-dir /tmp/tunlatch.XXXXXX --network-details --json
cargo run -p tunlatch -- tui --runtime-dir /tmp/tunlatch.XXXXXX
```

TUI 优先展示候选 TUN，支持 `↑` / `↓`、`j` / `k` 和翻页键浏览全部网卡；`q` / `Esc` / `Ctrl-C` 退出、`r` 刷新，每 2 秒获取一次状态。后台不可用或刷新失败后清除上次快照并显示错误。关闭 TUI 不会停止后台。前台后台服务用 `Ctrl-C` 或 `SIGTERM` 结束，等待在途请求及已开始的原生枚举退出后清理自己创建的 socket。

普通 `status` 保持已有响应格式，旧 CLI/TUI 也能继续查询新服务。`--network-details` 显式请求带扫描代次和采集方式的扩展结果；JSON 包含 `status` 和 `network_observation` 两部分，需支持该操作的服务。

服务以只接收的原生路由套接字监听网络变化，合并通知后触发重扫，并每 2 秒做一次完整性重扫。受监控快照在发布和再次取用时核对已处理的通知与订阅状态，从扫描开始计算有效期，系统睡眠计入这段时间。订阅失败后状态查询返回错误。通知可能滞留在内核队列或无声丢失，真实睡眠唤醒的通知覆盖仍待验证。退出会请求停止并等待通知线程回收。

可显式检查一个 PID 的最小信息，或增加有上限的 FD/control 元数据采集：

```sh
cargo run -p tunlatch -- identity inspect --pid 12345 --json
cargo run -p tunlatch -- identity inspect --pid 12345 --fd-details --json
```

将 PID 替换为实际选择的进程。采集前后核对 PID、UID、出生时间、FD 列表和 socket 元数据；不可读、截断、变化或不支持的结构布局均返回失败。`complete_raw` 仅表示两次有限的原始采样匹配，TUN 归属、已载入映像和实际保护仍为未知/未认证。CLI 省略内核 opaque 值和非 control socket 端点。当前已核对的采集布局限 Apple Silicon；普通观察入口仍拒绝 root。单次管理员只读诊断另有专用程序和受保护暂存流程，见 [操作者步骤](scripts/README.md#单次管理员身份只读采集)，不能直接 sudo 构建目录中的程序。

也可将明确选定的进程与预期的 40 位十六进制 CDHash 作动态核验：

```sh
cargo run -p tunlatch -- identity check-image --pid 12345 --cdhash 00112233445566778899aabbccddeeff00112233 --json
```

示例 PID 和指纹均须替换。这条命令通过系统的运行代码对象检查固定 CodeDirectory 条件，不读取程序路径或将磁盘文件摘要当运行身份；匹配返回成功，不匹配或无法检查返回非零。指纹来自调用者，不代表发布者可信或管理员批准；ad-hoc 签名也没有发布者认证。检查禁止网络访问，因此不做在线撤销/公证检查。进程出生信息在前后复核，但不能排除中间 `exec` 或复用；3 秒预算在系统调用返回后检查，不能中断系统调用。结果不提供整镜像 SHA-256、TUN 归属、持续身份或放行资格，原管理员采集入口也未因此扩权。

另有[受控 TUN 映射实验](scripts/README.md#受控-tun-映射实验)工具，默认仅输出计划。本机一次自持接口的名称/control unit/进程 FD 对照及关闭后点查询已通过，操作者确认联网正常。实际运行会创建一个内核可能自动启用的临时接口，必须另行具体批准；该单次样本不认证现有代理或提供出口保护。

服务不会覆盖已有 `control.sock`。若服务被 `SIGKILL` 导致路径残留，先确认原服务已结束，再手动移除该临时目录内的 socket；不要删除仍在运行的服务端点。当前目录只存放开发 socket，删除它不涉及 PF 恢复或停用。

## 离线配置与模拟控制

`config check` 同时支持旧版配置和配置草稿；草稿的导入预览和规范化导出不会改变后台配置或生成管理员批准：

```sh
cargo run -p tunlatch -- config import-preview draft.toml --current current.toml
cargo run -p tunlatch -- config export draft.toml exported.toml
```

导出默认拒绝覆盖，明确指定 `--overwrite` 才替换已有普通文件。输入拒绝符号链接、非普通文件和超限内容。旧版配置需通过已有领域 API 显式迁移后才能导入或导出，工具不会悄悄迁移。

可将离线策略草稿编译为有界、确定的 PF 候选预览：

```sh
cargo run -p tunlatch -- config compile-preview examples/policy.toml --json
```

当前编译范围是出口资格尚未就绪时的阻断候选：双栈默认出口阻断、固定回环出站放行，普通规则按既定优先级保留选择条件，普通 allow 在此阶段也只生成阻断候选。未经独立授权的直连例外和不能精确表示的条件会被拒绝。输出分开显示源策略摘要与候选摘要，始终标记不可加载、无授权和实际保护未知；命令不调用 PF，也不处理已有连接状态。停用意图只产生空的 unmanaged 候选，不执行全局停用或清空。

普通用户可在私有目录运行持久化模拟，再从新的进程检查恢复线索。

```sh
TUNLATCH_JOURNAL_DIR=$(mktemp -d /tmp/tunlatch-journal.XXXXXX)
cargo run -p tunlatch -- config journal-preview examples/policy.toml --state-dir "$TUNLATCH_JOURNAL_DIR" --json
cargo run -p tunlatch -- config journal-status --state-dir "$TUNLATCH_JOURNAL_DIR" --json
```

日志通过一次原子替换保存草稿与意图，记录有效载荷上限为 64 KiB。写入完成后，提交和独立读回在内存模型中进行。重新打开时会复核草稿和摘要，从未知状态开始核查。损坏或未完成的记录会保留以供检查。

`config verify-capture` 读取已有的 PF 采集文件，报告捕获时的启用状态、根规则调用和可用计数，并与候选规则文本对照。结果为 `unknown` 或 `mismatch`，退出码为非零。

```sh
cargo run -p tunlatch -- config verify-capture examples/policy.toml --capture-dir /path/to/capture --anchor tunlatch --json
```

要演练完整控制流程，在新的私有目录启动 `tunlatchd --simulation`：

```sh
TUNLATCH_SIM_DIR=$(mktemp -d /tmp/tunlatch-simulation.XXXXXX)
printf '%s\n' "$TUNLATCH_SIM_DIR"
cargo run -p tunlatchd -- --runtime-dir "$TUNLATCH_SIM_DIR" --simulation
```

在另一个终端使用打印出的目录：

```sh
cargo run -p tunlatch -- simulate --runtime-dir /tmp/tunlatch-simulation.XXXXXX status
cargo run -p tunlatch -- simulate --runtime-dir /tmp/tunlatch-simulation.XXXXXX set enabled --operation-id 1 --expected-generation 0
```

这条路径实际经过 CLI、本地 socket、协调器、内存后端和独立读取核验。响应明确标为模拟；普通 `status` 仍显示实际保护未知、未托管。普通观察服务拒绝模拟请求。同一进程内相同操作 ID 和内容可重试，不同内容或过时代次被拒绝；最多保留 256 个受理操作，满后拒绝新操作。重启会丢失模拟历史，它不提供管理员授权、持久化或真实 PF 恢复。

## 结构与依赖方向

```text
crates/
  tunlatch-core/      纯领域模型、版本化配置校验、期望/已提交/观测状态
  tunlatch-platform/  macOS 边界：原生双栈网卡快照、受限文件读取、PF 能力状态
  tunlatch-ipc/       有界 JSON 帧、协议版本、同用户凭据校验、私有 socket 生命周期
  tunlatchd/          服务循环、并发上限、任务监督、超时与信号退出
  tunlatch/           普通用户 CLI、Ratatui TUI、离线配置校验
```

`core` 不依赖系统、异步运行时和界面。`platform`、`ipc` 分别依赖 `core`；两个入口按职责组合它们。TUI 不执行特权操作；IPC 接受状态查询及显式启用的隔离模拟请求，未知操作和字段均被拒绝。PF 适配接口当前只返回 `backend_not_implemented`。

候选网卡的发现不授予信任：`utun` 名称只用于展示提示，网卡索引、地址和名称不能作为持久身份。当前没有可被反序列化伪造的“可信 TUN”对象，也没有默认直连例外。

## 当前能力与后续工作

| 范围 | 当前状态 |
| --- | --- |
| 固定工具链、工作区、lint、锁文件、CI、依赖检查策略 | 已建立 |
| 普通用户服务 → 有界 Unix Socket → CLI / TUI | 可运行，只读 |
| 网卡快照 | 原生 `getifaddrs`，保留 IPv4、IPv6 和 IPv6 scope；不是路由或身份验证 |
| 配置 | CLI 校验、草稿差异预览与规范化导出已接入；不导入批准、不应用后台策略 |
| 模拟控制闭环 | 显式启用后经真实本地通信提交、去重、核验和查询；内存后端无系统副作用 |
| PF 候选编译 | 离线 CLI 生成未就绪时的双栈阻断候选与独立摘要。授权放行与真实提交后端待完成 |
| 提交与恢复生命周期 | 状态机已接入普通用户私有记录、模拟提交与独立读回。系统存储部署和 PF 执行待验证 |
| PF 采集核对 | 可读取已有采集文件并报告捕获差异、缺项与过期。实机读回与执行位置验证待完成 |
| PF、已有连接约束、必要直连例外 | 待原型与实机验证 |
| 绑定领域模型 | 已实现候选/关联/确认分型，明确区分 CDHash 与完整镜像摘要，确认与刷新核对类别、内容、新采集序号及 FD 实例；没有实际可信 TUN 或 PF 资格 |
| UID 出口领域模型 | 独立候选、规范摘要、一次性确认检查、撤销替换及当前范围/UID/协议/族判定；只检查报告一致性，不产生实际管理员或 PF 权限 |
| 实验进程监督 | 固定无 PF 子程序的启动、限量输入/输出、超时/取消和直接子进程回收已通过普通用户测试；未回收任务保留记录，另有操作者只读系统查询入口；尚未接入特权写入和 PF 变更入口 |
| 网络观察 | 原生路由通知触发及周期重扫已接入；仅提供失效提示，不证明事件完整或接口实例持续隔离 |
| 原始身份采集 | 选定 PID 的出生/UID、固定上限 FD/control 双采样已实现；本机 root 代理的原始 control 样本已采得，已载入映像与具体 TUN 归属仍未验证 |
| 特权授权、原子持久化、LaunchDaemon、安装卸载、离线解锁 | 待设计与实现 |

下一步先补齐 PF 实验的安全准备，再验证 socket user 的双栈 TCP/UDP、unknown/其他 UID 对照及撤销后的旧连接，连同 anchor 实际执行顺序与共存、事务、启用引用和接口复用。确认这些机制后再接入保护启停，不以 UI 或模型测试替代内核与物理出口证据。`core::egress` 已提供独立 UID 候选和确认模型，实际受保护存储、管理员认证和应用仍待接入；文件导入不能生成批准。

`tunlatch-core` 的配置草稿、绑定和 UID API 是无系统副作用的领域模型。普通规则的允许只返回
`NeedsEgressAuthorization`，直连例外仅是候选；一致的采集报告不等于真实平台事实。
UID 匹配只返回带代次、范围实例及期限的条件要求。系统维护候选参与校验和确认摘要，其报文判定尚未实现。
`EnforcementQualifiedBinding` 和 `EnforcementAuthorization` 当前均不可安全构造。原有 CLI/IPC 未接入这些新能力，仍报告保护未知。

PF 实验准备工具可用普通用户运行：

```sh
cargo run -p tunlatch-platform --example pf_lab --locked -- plan
TUNLATCH_LAB_DIR=$(mktemp -d /tmp/tunlatch-pf-lab.XXXXXX)
cargo run -p tunlatch-platform --example pf_lab --locked -- prepare "$TUNLATCH_LAB_DIR"
"$TUNLATCH_LAB_DIR/pf-lab" recover
```

工具只生成候选计划、规则文本和独立准备程序；`recover` 默认也只展示计划。
**`pf_lab` 的所有实机请求均被拒绝，即使提供两个 opt-in 标志也不会执行 PF。当前没有覆盖真实出口阻断的合格恢复包。**
固定 anchor 名称、标签、收据或模拟测试均不证明内核资源归属；完整预检、可信程序部署、
特权进程监督接入、接口复用、状态选择、引用和流量采集仍须补齐，实机操作另行审核。

贡献约定见 [AGENTS.md](AGENTS.md)，完整工程检查见 [CI 配置](.github/workflows/ci.yml)，安全边界见 [SAFETY.md](SAFETY.md)。本地 `docs/` 保存需求、调研和编码指导，按已有 `.gitignore` 设置保留为本地资料；本 README 记录可随代码交付的架构与能力边界。

许可证：[GPL-3.0](LICENSE)。

操作者在本机可运行 `./scripts/pf-lab-preflight.sh`，通过固定系统工具采集只读 PF 前态。项目程序仍用普通用户运行，不调整网络或加载规则；步骤和数据边界见 [scripts/README.md](scripts/README.md)。

独立的人工实验脚本还可准备单次启用引用及未挂接规则槽的暂存/清空；这些动作需要具体实验许可，项目服务仍无PF写入能力。`pf-lab-rule.py`默认仅展示计划，不启用PF、不添加根调用，恢复只替换本次filter为空。完整当前启动回执下的人工接管不能外推成自动故障恢复、UID或出口防泄漏资格。
