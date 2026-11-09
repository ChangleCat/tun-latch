# 本机诊断与受控实验

## 单次管理员身份只读采集

`identity-readonly.py` 用于当前机器上一项受审查的开发诊断：读取一个明确选择的进程的 PID、UID、出生时间、FD 类型及 kernel-control 注册信息。它不会更改 PF、网络、代理或启动项，也不会读取进程命令行、环境、配置、连接端点或输出内核 opaque 值。结果仍是原始采样，不能据此授信 TUN 或宣称已保护。

先由开发者构建并独立审阅 `identity_readonly`，把该确切二进制的 SHA-256 固定到脚本；当前摘要对应本机已审阅构建。构建不同或字节变化时脚本会拒绝，须重新审阅，不能用命令行提供另一个摘要。不要直接 sudo `target` 中的程序，也不要 sudo 整个 Python 脚本。

在本机 Terminal 的同一个终端中执行，PID 应为明确选择的目标：

```sh
/usr/bin/sudo -v && /usr/bin/python3 scripts/identity-readonly.py collect --pid 12345
```

认证必须由本机系统处理；sudo 缓存可能与终端关联，不能假设在另一个终端认证后本程序就能使用。脚本的后续命令固定使用非交互 sudo，不接收或转发密码。当前机器若只运行一个 sing-box，可用 `--pid "$(/usr/bin/pgrep -x sing-box)"`；空值或多个 PID 会在任何特权操作前被拒绝。

脚本核对源字节、静态系统依赖、受保护父链后，在 `/private/var/root/tunlatch-identity.XXXXXXXX` 新建0700目录。只把已审查字节复制为 root 单链接0500副本并复核摘要；启动/PID记录0600，采样前一次性标记，不能在 run 时换目标。随后仅执行该私有副本的 `--pid` 读取。这里的暂存与固定摘要不构成生产安装或抗同UID篡改的授权机制；仅用于当前人工开发诊断。

控制器在核查无ACL的系统临时目录下新建 `/private/tmp/tunlatch-identity-result.*` 私有目录，保存0600的 `result.json`，并打印路径。`complete_raw` 和退出码0必须同时成立；不完整结果也保存，但返回非零。普通用户路径绝不传入 root 命令。结束后可只回复完成，由开发者直接读取本机结果。

中断、超时、超限或错误时保留结果文件与终端打印的本次 root 目录，不自动重试已标记采样，也不清理来源不明的进程或目录。只有本次临时程序与记录被创建，没有需要撤销的网络变更；停止操作即可，现有代理继续按原方式运行。结果阶段可能是 `started`、`prepared` 或具体采样诊断，均不得把缺失结果解释为成功。

普通权限验证，不运行 sudo：

```sh
/usr/bin/python3 -m unittest discover -s scripts -p 'test_identity_readonly.py' -v
cargo test -p tunlatch-platform --test tunnel_identity --example identity_readonly --locked
```

## 单次管理员同窗诊断

`identity-correlate.py` 读取一个明确选择的 root 进程。它在 FD 采样前后对照预期 CDHash，再核对两次接口扫描。`candidate` 表示观察到一个与 control unit 推导相符的接口，归属和实际保护仍为未知。此工具使用独立的辅助程序与会话目录。它只读取进程和接口信息，无需断网，也不创建接口、修改 PF 或安装服务。

先运行 `plan` 查看范围。执行时替换示例 PID 和 CDHash，使用准备时选定的目标。预期 CDHash 可取自所选磁盘文件的 `codesign -dv --verbose=4` 输出，实际运行映像由辅助程序核对。构建产物必须与控制器内经审查的摘要一致。

```sh
/usr/bin/python3 scripts/identity-correlate.py plan
/usr/bin/sudo -v && /usr/bin/python3 scripts/identity-correlate.py collect \
  --pid 12345 --cdhash 00112233445566778899aabbccddeeff00112233 --ack READ-ONE-PROXY
```

认证和采样在同一个 Terminal 完成。`collect` 将已核对的辅助程序暂存到 root 私有目录，绑定本次启动、模式、PID、预期 CDHash 和构建摘要，执行前写入一次性标记。控制器会打印普通用户可读的私有 `result.json` 路径。`unavailable` 会带固定原因并退出非零。遇到中断、超时、目标变化或摘要错误时，保留输出和会话路径，先核对结果再决定是否另开采样。

## 受控 TUN 映射实验

`utun-mapping.py` 默认只显示计划，不提权或创建接口：

```sh
/usr/bin/python3 scripts/utun-mapping.py plan
```

实机动作需另行明确批准：独立 helper 新建并持有一个由内核分配编号的测试 utun，从自持 FD 直接查询接口名和 control unit，对照自身原始采样，再关闭该 FD 并观察后态。连接时内核可能自动把接口置为 UP，清理可能异步，系统/其他网络管理程序的反应尚未实测。程序不主动设置地址、路由或接口 flags，不发包、不改 PF，也不操作现有代理或 TUN。

在当前 Mac 旁保存工作、确认原联网正常，并批准上述一次动作后，才在自己的同一个终端运行一次：

```sh
/usr/bin/sudo -v && /usr/bin/python3 scripts/utun-mapping.py collect --ack CREATE-ONE-TEST-UTUN
```

操作器只暂存经独立审查且固定摘要的程序到新建 root 私有目录，绑定本次启动/实验模式和一次性执行标记；不要直接 sudo 构建目录中的 helper 或整个脚本。结果保存在普通用户私有目录并打印路径。原身份只读脚本的固定构建与行为不变。

helper 创建前启动约6秒的自停线程，超时只请求终止它自身；不接受外部 PID、不停止代理，不承诺硬时限或资源已经回收。错误、中断或超时不自动重试。`complete` 只表示本次映射观察完整；close 成功或名称缺失不等于全局恢复，接口仍可见可能是异步清理或名称复用，不能按名字清理。

仍在执行时可在原终端按 Ctrl-C。若网络异常持续，先在 v2rayN 自己的界面重启原来的 TUN/代理；仍无法联网时，保存工作后重启 Mac，再启动原代理。脚本不会自动重启服务或系统，不执行全局 PF 或路由恢复命令。该实验不认证 sing-box 的实际接口，也不验证防泄漏。

普通用户检查不运行实机动作：

```sh
cargo test -p tunlatch-platform --example utun_mapping --locked
/usr/bin/python3 -m unittest discover -s scripts -p 'test_utun_mapping.py' -v
```

本机 Apple Silicon/macOS 26.6.2 的一次执行已完成：自持 FD 的接口名、peer unit 和原始 control 采样一致；close 正常返回后，后续 FD 与接口名点查询均为 absent，操作者确认联网正常。这只验证本次受控样本，不推广到现有代理、名称复用或 PF，也不授权自动重复执行。

## 本机PF只读预检

在Mac本机Terminal中，以普通用户从仓库根目录运行：

```sh
./scripts/pf-lab-preflight.sh
```

不要sudo整个脚本。脚本先构建普通用户release工具，显示固定清单和文件快照摘要；输入`READONLY`确认后，由系统sudo提示管理员验证。项目程序不升权。只读查询使用固定sudo/env/pfctl系统路径，读取根规则/NAT、anchor目录、接口、info和引用，再重读根规则/NAT、引用和anchor目录。对首次目录中的至多16个校验通过的literal名称，逐一读取rules/nat/Tables，总计至多58次，不调用已实测出错的全局通配递归。它不加载/清理规则、不启停PF、不清连接、不取放token、不抓包、不发送探针、不调整代理/接口/路由。

每条查询3秒执行预算、1秒回收预算、64KiB合计输出上限。sudo正常返回按其等待固定命令的契约处理；取消/超时/信号不证明命令树已回收，认证/传输/枚举异常会停止。完整回收后返回的pfctl错误逐项记失败，继续其它独立只读项收集诊断；有一项失败则整批incomplete，不把失败规则集当空。原生OS调用无硬实时抢占保证。该路径只用于读取，不构成特权PF写入或恢复入口。

输出留在新建的`/tmp/tunlatch-pf-readonly.XXXXXX`目录，0700目录、0600文件，并拒绝非空目录或非空ACL。`summary.json`不含原始规则/地址/引用token；原始query文件留在本机，先只提供打印的目录路径即可。`captured_requires_review`只表示采集完整，仍需审阅；`incomplete`或错误时保留目录和终端输出，不清理PF。系统工具文件快照不可读取时明确记unavailable，不另行提权获取或宣称身份已核验。

本步骤没有需要撤销的网络变更。真正会改PF的实验必须另行提供准确动作、时限、前态和已核验的独立离线恢复脚本；恢复不能依赖联网、下载、编译或本聊天，不以全局disable/flush恢复连通。

直接运行 `pf_lab_readonly collect` 前，须在同一个终端先执行 `/usr/bin/sudo -v`，再以普通用户运行采集程序。采集器的固定查询使用非交互sudo，不会自行弹出密码提示；凭据缓存过期时会记录 `sudo: a password is required` 并返回失败，后接 `&&` 的实验程序不会启动。每次现场刷新采集都先验证，不依赖prepare时留下的缓存；不要sudo整个项目程序。

本机已观察到全局递归查询在退出码0时报DIOCGETRULES错误；程序现在检查stderr。只把实测的两行ALTQ缺失提示作为保留的提示，额外错误仍失败。目录拒绝通配符/穿越/重复/缺父节点/超量，前后目录须一致；一致也不证明没有ABA或拥有写入权限。

## 单次启用引用工具

`pf-lab-reference.py` 是另一个**需具体批准**的在场操作工具，不是只读采集器。不要 sudo 整个程序。`prepare`建立root私有记录目录并保存本次启动身份；`status`核对恢复入口；`acquire`要求新鲜完整且没有实际规则/表的采集、已确认的独占窗口和 `ENABLE-ONCE`，才通过系统pfctl执行一次 `-E`。这会启用当前已加载PF，不能当作没有网络影响。

另一个Terminal中的`release`仅从本次root保护记录读取完整回执，校验当前启动，并由操作者输入 `TAKEOVER-AND-RELEASE`批准逐项接管，才执行一次对应 `-X`。不从全局引用表挑token，不全局disable/flush，不加载/移除规则，不改服务/接口/路由。系统script直接记录原始输出，释放尝试以独占mkdir防重复；日志刷新不是内核操作与磁盘的原子提交。

这是前台人工流程，不提供十秒硬期限或命令树自动回收。中断、未知、缺回执、跨启动和已有释放尝试均停止，不猜测或重试；它只覆盖完整回执时的人工恢复。完整恢复/实际阻断仍未通过，也不开放W07。恢复只用已经存在的本地Python标准库和系统工具，不需要网络或编译。

本地规划中的完整步骤保存在未跟踪的 `docs/development-plan-2026-11-02/experiments/reference-only.md`。发布给其他环境前仍需重新审阅本机前态和操作窗口，不能照搬历史快照。

普通权限检查（不运行sudo或PF内核操作）：

```sh
/usr/bin/python3 -m unittest discover -s scripts -p 'test_pf_lab_reference.py' -v
```

## 未挂接规则槽及独立恢复

`pf-lab-rule.py`默认只打印计划。它为另一项需单独批准的人工实验准备`prepare/status/stage/recover`入口：在PF停用、引用0及连续独占窗口下，把四条固定回环TCP/UDP规则暂存到全新顶层`tunlatch-lab-<本次随机后缀>`，**不增加根调用、不接入com.apple/*、不启用PF**。端口55000只是固定候选数据，本阶段不绑定端口或收发流量。

root只运行系统mktemp、sysctl、script、tee、stat、ls、cat、test、mkdir及pfctl；项目Python始终普通用户。候选/空恢复文件冻结于本次root私有目录，固定`-a 本次literal -R -o none -f 本次保护文件`只替换本次filter，不使用全局或父级flush/reload，不取放引用、不清state、不改接口/路由。普通`-n -v`解析器提供规范输出供后态完整比较。

提交包装命令正常返回后，脚本核对输出与 root 私有的 `stage.txt` 逐字节相同，再保存 `stage-returned.sha256`。摘要绑定会话、启动身份和原始回执。`--stop-after-submit` 在保存该记录后、首次查询 PF 后态前退出。`recover` 在提示接管前和实际清空前都核对正常返回记录，缺少记录、内容不匹配或中途变化时保留现场。保存的 `stage.txt` 可能在提交运行中已经出现，不能单独用于接管。

正常返回记录只反映固定包装命令的结果。操作者仍须确认原写入者已结束且独占窗口连续，并核对当前启动、保护数据、根 filter/NAT、目录及本次规则或空态。恢复只替换本次 filter 为空。未知内容、其他 NAT/表/子目录、重复尝试或来源不明时保留现场。空 anchor 元数据可能保留。

规则槽有“不存在”和“存在且为空/非空”之分。先核对根下非递归清单与完整递归清单一致，缺失的名字记录为namespace absent，不向不存在的槽读取内容，也不伪造为空规则输出；已有槽必须直接读取filter/NAT/表/子目录，任何查询错误仍失败。恢复结果`payload_absent`表示本次载荷已移除；`filter_empty`只在直接读为空时为true，namespace absent时为null，不宣称删除了所有内核对象。

`resume-before-submit`仅接续有完整保护前态、`stage-once/baseline-ready`存在、但`load-intent`、提交/清空回执和恢复/关闭记录全部不存在的首次提交。它需要新鲜且与原保护前态相同的采集，不删除或重置标记；一旦记录过提交意图，便不能用它重放。它处理提交前预检适配故障，不是失败后的自动PF重试。

新会话在 root 私有目录保存提交前后、清空前后的规则槽观察。记录包含本次核验读取的规则、PF 状态和引用输出，并区分槽不存在和直接读为空。`--stop-after-submit` 仍在读取后态前退出，恢复入口单独记录清空前的观察。操作前先设置一次性意图标记，再写入、回读记录并重新检查 PF。记录失败时停止，不重试。清空后的记录失败时不生成关闭回执。单次回读无法证明记录已经落盘，也不能把观察作为清理授权。

这仍不是自动所有权、可信后台恢复或阻断恢复资格；没有硬期限、未知命令树回收或断电原子性保证。完整W05/W07及UID/出口测试仍需后续证据。完整本机步骤保存在未跟踪的 `docs/development-plan-2026-11-02/experiments/unattached-rule.md`。

```sh
/usr/bin/python3 scripts/pf-lab-rule.py plan
/usr/bin/python3 -m unittest discover -s scripts -p 'test_pf_lab*.py' -v
```

### 核对已关闭会话的保存回执

`pf-lab-rule-evidence.py` 只读取一个已关闭规则槽会话中的固定记录。它检查文件属性与固定候选，输出摘要、回执分类和历史关闭记录。旧会话的正常返回记录可以缺席，摘要会显示 `not_recorded`。阶段观察只输出状态、文件长度和摘要，实际读取的规则、PF 状态和引用输出留在 root 私有目录。`absent` 是当时根据两份目录清单作出的判断，阶段观察未保存这两份清单。旧会话缺少清空前观察时，`consistent_with_matching_nonempty_pre_clear` 仅表示保存的回执与已审查的恢复流程一致。这个推断依赖回执确由该流程生成。工具无法认证当时实际执行的源码，也无法用阶段记录独立证明规则与当时解析器的输出一致。

在同一 Terminal 认证后，用已关闭会话的实际目录替换示例路径。

```sh
/usr/bin/sudo -v && /usr/bin/python3 scripts/pf-lab-rule-evidence.py \
  /var/root/tunlatch-pf-rule.XXXXXXXX --ack READ-SAVED-PF-RECEIPTS
```

这一步只检查保存的文件，无需断网。若读取失败，保留终端提示与原始会话即可。

## 同步规则槽的首次管理员预检

`pf-lab-sync.py` 默认打印计划。首次管理员测试只验证固定发布版 helper 的受保护部署、启动身份和实际 PF 只读查询。`prepare` 在全新的 `/private/var/root/tunlatch-pf-sync` 中保存已核对的 helper 和启动记录，再调用只读入口。`status` 可以独立复查。项目 Python 仍以普通用户运行。

```sh
/usr/bin/python3 scripts/pf-lab-sync.py plan
/usr/bin/sudo -v && /usr/bin/python3 scripts/pf-lab-sync.py prepare
/usr/bin/python3 scripts/pf-lab-sync.py status
```

首次预检应得到 `phase=preflight_ready` 和 `anchor=not_allocated`。它不会占用规则槽或开始暂存期限。准备失败或超时后保留固定目录。若已成功暂存 helper，可以用 `status` 只读检查；`prepare` 会拒绝已有目录。实际 PF 写入需要针对具体范围另行批准。

已安装过本项目指定的旧预检构建时，用 `replace-preflight`。它只接受当前启动、旧摘要、目录内恰好两个部署文件及稳定的 `preflight_ready`，将旧目录整体移入同一文件系统上的 root 私有归档，再部署新构建并只读复查。失败时保留旧归档和现有固定目录，终端会给出归档路径。

```sh
/usr/bin/sudo -v && /usr/bin/python3 scripts/pf-lab-sync.py replace-preflight
/usr/bin/python3 scripts/pf-lab-sync.py status
```

当前规则核对会接受固定四条规则的等价地址及端口显示。其余活动规则报告为 `unrecognized` 并拒绝清空。后续获准的写入实验可通过 `capture-unknown` 保存一次受保护的原始观察，该动作仅查询 PF。

获准的单槽实验由本机忽略目录 `docs/.pf-lab-sync/` 保存批准、暂存尝试及正常返回记录。脚本核对已部署 helper、当前启动和预检基线。暂存启动后，记录原样保留。若缺少同一槽的正常返回，操作脚本只允许只读状态检查和符合条件的未知证据采集。启用本机单次批准后，脚本会拒绝重新部署或替换 helper。

正常完成的同步单槽试验可用 `pf-lab-sync-evidence.py audit` 核对受保护的阶段观察、已关闭日志和当前只读状态。使用同一启动的现有部署，在本机终端认证后以普通用户运行脚本。输出只有摘要和阶段信息，原始规则留在 root 私有目录。

```sh
/usr/bin/sudo -v && /usr/bin/python3 scripts/pf-lab-sync-evidence.py audit
```

## 同步写入者异常退出的独立预检

`pf-lab-sync-fault.py` 先确认前一次试验已关闭、原槽缺席，再将本次已核对构建部署到独立的 `/private/var/root/tunlatch-pf-sync-fault`，并只读确认相同 PF 基线。旧部署和审计记录保留。以普通用户在同一终端执行。

```sh
/usr/bin/python3 scripts/pf-lab-sync-fault.py plan
/usr/bin/sudo -v && /usr/bin/python3 scripts/pf-lab-sync-fault.py prepare
/usr/bin/python3 scripts/pf-lab-sync-fault.py status
```

预检通过时应返回 `preflight_ready` 和 `not_allocated`。实际故障动作在同步提交返回后、发回执前由写入者请求终止自身，父进程须获得 SIGKILL 的直接等待结果及受保护见证。`stage-fault` 和 `recover-fault` 需要单独的本机批准记录，绑定当前启动、已部署构建和基线，并各自要求现场确认。超时、记录缺失、规则不明或旧状态变化时保留现场。等待超时无法确认子进程已退出。

## 根规则读取布局的只读核对

`pf-lab-root-hook-readonly.py plan` 查看本机候选操作。经精确构建审查后，`prepare` 在固定私有目录独占暂存 helper，然后立即执行只读核对。`check` 复用同一启动的受保护副本执行同一核对。脚本本身保持普通用户权限，使用已认证的管理员终端启动固定系统工具和 helper。

`readback_matched` 表示两次系统根规则显示相同，原生读取的条数、顺序、规则类别和调用名与显示相符。结果附根规则摘要。规则票据、owner、修改请求的运行时布局、挂接生效和真实流量需要各自的证据。写请求在此入口一律拒绝。

## TCP 与 UDP 对端预检

`pf_lab_peer` 是普通用户实验辅助程序。两端使用同一组数字地址、端口、协议和一次性 nonce。接收端报告 `ready` 后可启动发送端。发送端的 `completed` 表示收到了匹配的回显。超时或不一致均失败，保护状态始终为 `not_evaluated`。实机外部地址须来自已确认的受控实验环境。

可先在本机用回环脚本检查 IPv4 与 IPv6 各自的 TCP 和 UDP 收发。脚本默认只打印计划，带确认参数时才绑定回环端口并交换 nonce。

```sh
cargo build -p tunlatch-platform --example pf_lab_peer --release --locked
/usr/bin/python3 scripts/pf-lab-peer-loopback.py --ack RUN-LOOPBACK-PROBE
```

四项均成功时输出 `loopback_checked`。失败时会报告地址族、协议、出错端、退出状态，以及可取得的阶段和系统错误码。回环结果只验证对端程序的收发和记录，物理出口、跨 UID、抓包和 PF 匹配需要独立验证。

`pf-lab-peer-batch.py` 把四种组合并行收发。两端都需构建上面的 `pf_lab_peer`。向两端提供同一份 JSON，顶层 `cases` 包含四项，每项有 `family`（`ipv4` 或 `ipv6`）、`protocol`（`tcp` 或 `udp`）、`source`、`destination` 和 `nonce`。地址须为具体数字 `IP:端口`，IPv6 使用方括号。每项使用不同的 32 位小写十六进制 nonce。每轮使用新 nonce 和独立流。

先以 `--role receiver` 或 `--role sender` 只查看计划。仅在确认对端及地址范围后加 `--ack RUN-CONTROLLED-PEER-BATCH`。接收端四项就绪后输出 `ready`，此时发送端可用同一计划启动。任一交换失败时记录 `incomplete` 或 `unavailable`。这些结果用于收发对照，PF 判定始终为 `not_evaluated`。

可将四条待阻断流的端点写成同样的 `cases` 文件，省略 `nonce`，以 `--prepare-controls` 一次生成 `before`、`blocked`、`after` 三组计划。准备命令只向标准输出写 JSON。前后对照保持相同源 IP 和目的端点，使用独立源端口和 nonce。将同一输出用于两端，以 `--phase before`、`--phase blocked` 或 `--phase after` 选择对应组。生成阶段无需打开 socket，端口能否绑定由执行阶段验证。

对端可使用标准 Python 3 接收器。将 `pf-lab-peer-portable.py` 和 `pf-lab-peer-batch.py` 放在同一目录，与发送端使用同一份计划和同一 `--phase`，并在对端确认范围后传入 `--ack RUN-CONTROLLED-PEER-BATCH`。接收端结果报告脚本与计划校验器的摘要。本机 Rust 发送端与便携接收端已完成四路回环互通，仍需受控环境验证外部链路。
