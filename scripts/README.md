# 本机PF只读预检

在Mac本机Terminal中，以普通用户从仓库根目录运行：

```sh
./scripts/pf-lab-preflight.sh
```

不要sudo整个脚本。脚本先构建普通用户release工具，显示固定清单和文件快照摘要；输入`READONLY`确认后，由系统sudo提示管理员验证。项目程序不升权。只读查询使用固定sudo/env/pfctl系统路径，读取根规则/NAT、anchor目录、接口、info和引用，再重读根规则/NAT、引用和anchor目录。对首次目录中的至多16个校验通过的literal名称，逐一读取rules/nat/Tables，总计至多58次，不调用已实测出错的全局通配递归。它不加载/清理规则、不启停PF、不清连接、不取放token、不抓包、不发送探针、不调整代理/接口/路由。

每条查询3秒执行预算、1秒回收预算、64KiB合计输出上限。sudo正常返回按其等待固定命令的契约处理；取消/超时/信号不证明命令树已回收，认证/传输/枚举异常会停止。完整回收后返回的pfctl错误逐项记失败，继续其它独立只读项收集诊断；有一项失败则整批incomplete，不把失败规则集当空。原生OS调用无硬实时抢占保证。该路径只用于读取，不构成特权PF写入或恢复入口。

输出留在新建的`/tmp/tunlatch-pf-readonly.XXXXXX`目录，0700目录、0600文件，并拒绝非空目录或非空ACL。`summary.json`不含原始规则/地址/引用token；原始query文件留在本机，先只提供打印的目录路径即可。`captured_requires_review`只表示采集完整，仍需审阅；`incomplete`或错误时保留目录和终端输出，不清理PF。系统工具文件快照不可读取时明确记unavailable，不另行提权获取或宣称身份已核验。

本步骤没有需要撤销的网络变更。真正会改PF的实验必须另行提供准确动作、时限、前态和已核验的独立离线恢复脚本；恢复不能依赖联网、下载、编译或本聊天，不以全局disable/flush恢复连通。

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

首次写入前和恢复时均直接读取本次filter/NAT/表/子目录；目录未列出目标不能当作空filter，直接读取错误也不能被目录结果掩盖。结果只记录目录是否列出名称，不据此断言内核对象不存在。

这仍不是自动所有权、可信后台恢复或阻断恢复资格；没有硬期限、未知命令树回收或断电原子性保证。完整W05/W07及UID/出口测试仍需后续证据。完整本机步骤见本地`docs/development-plan-2026-11-02/experiments/unattached-rule.md`。

```sh
/usr/bin/python3 scripts/pf-lab-rule.py plan
/usr/bin/python3 -m unittest discover -s scripts -p 'test_pf_lab*.py' -v
```
