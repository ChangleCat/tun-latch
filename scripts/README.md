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

本地规划中的完整步骤：`docs/development-plan-2026-11-02/experiments/reference-only.md`。发布给其他环境前仍需重新审阅本机前态和操作窗口，不能照搬历史快照。

普通权限检查（不运行sudo或PF内核操作）：

```sh
/usr/bin/python3 -m unittest discover -s scripts -p 'test_pf_lab_reference.py' -v
```

## 未挂接规则槽及独立恢复

`pf-lab-rule.py`默认只打印计划。它为另一项需单独批准的人工实验准备`prepare/status/stage/recover`入口：在PF停用、引用0及连续独占窗口下，把四条固定回环TCP/UDP规则暂存到全新顶层`tunlatch-lab-<本次随机后缀>`，**不增加根调用、不接入com.apple/*、不启用PF**。端口55000只是固定候选数据，本阶段不绑定端口或收发流量。

root只运行系统mktemp、sysctl、script、tee、stat、ls、cat、test、mkdir及pfctl；项目Python始终普通用户。候选/空恢复文件冻结于本次root私有目录，固定`-a 本次literal -R -o none -f 本次保护文件`只替换本次filter，不使用全局或父级flush/reload，不取放引用、不清state、不改接口/路由。普通`-n -v`解析器提供规范输出供后态完整比较。

`--stop-after-submit`只在系统提交命令返回后退出普通控制程序，留下root保护意图；不声称在内核begin/commit内部中断。新进程的recover不依赖丢失的提交回执，须核对当前启动、保护数据、根filter/NAT、目录及本次规则/空态，并由操作者确认原写入者已结束、窗口连续后逐项接管。恢复只替换本次filter为空；未知内容、其他NAT/表/子目录、重复尝试或来源不明时保留现场。空anchor元数据可能保留，程序如实记录，不猜测删除或声称所有内核对象消失。

规则槽有“不存在”和“存在且为空/非空”之分。先核对根下非递归清单与完整递归清单一致，缺失的名字记录为namespace absent，不向不存在的槽读取内容，也不伪造为空规则输出；已有槽必须直接读取filter/NAT/表/子目录，任何查询错误仍失败。恢复结果`payload_absent`表示本次载荷已移除；`filter_empty`只在直接读为空时为true，namespace absent时为null，不宣称删除了所有内核对象。

`resume-before-submit`仅接续有完整保护前态、`stage-once/baseline-ready`存在、但`load-intent`、提交/清空回执和恢复/关闭记录全部不存在的首次提交。它需要新鲜且与原保护前态相同的采集，不删除或重置标记；一旦记录过提交意图，便不能用它重放。它处理提交前预检适配故障，不是失败后的自动PF重试。

这仍不是自动所有权、可信后台恢复或阻断恢复资格；没有硬期限、未知命令树回收或断电原子性保证。完整W05/W07及UID/出口测试仍需后续证据。完整本机步骤见本地`docs/development-plan-2026-11-02/experiments/unattached-rule.md`。

```sh
/usr/bin/python3 scripts/pf-lab-rule.py plan
/usr/bin/python3 -m unittest discover -s scripts -p 'test_pf_lab*.py' -v
```
