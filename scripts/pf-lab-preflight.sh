#!/bin/sh
# Operator entrypoint: ordinary user only. No PF writes, probes, capture or network changes.
set -eu
umask 077

if [ "$(/usr/bin/id -u)" -eq 0 ]; then
    printf '%s\n' '请直接用普通用户运行此脚本，不要 sudo 整个脚本。' >&2
    exit 1
fi
if [ "$#" -ne 0 ]; then
    printf '%s\n' '此脚本不接受参数、外部命令或 PF 规则。' >&2
    exit 1
fi

SCRIPT_DIR=$(CDPATH= cd -P -- "$(dirname -- "$0")" && pwd -P)
REPO_DIR=$(CDPATH= cd -P -- "$SCRIPT_DIR/.." && pwd -P)
cd -- "$REPO_DIR"

printf '%s\n' '步骤 1/3：以普通用户构建只读工具。'
cargo build -p tunlatch-platform --example pf_lab_readonly --release --locked
TOOL="$REPO_DIR/target/release/examples/pf_lab_readonly"
"$TOOL" plan
/usr/bin/shasum -a 256 "$TOOL"

printf '\n%s\n' '本次仅用系统 sudo/env/pfctl 执行上面清单：10 项基础，加至多 16 个 anchor 的逐项读取，最多 58 次。'
printf '%s\n' '不会加载/清理规则、启停 PF、增减引用、清连接、抓包或调整代理/接口/路由。'
printf '%s\n' '原始输出留在本机私有目录，包含的规则/引用 token 不会显示在汇总里。'
printf '%s' '确认执行这些只读查询请输入 READONLY（其它输入退出）：'
IFS= read -r ANSWER
if [ "$ANSWER" != READONLY ]; then
    printf '%s\n' '已退出，未执行 PF 查询。'
    exit 0
fi

printf '\n%s\n' '步骤 2/3：由你在系统 sudo 提示中输入管理员密码。'
# Authenticate with the trusted system program. The project binary remains unprivileged.
/usr/bin/sudo -v
OUTPUT_DIR=$(/usr/bin/mktemp -d /tmp/tunlatch-pf-readonly.XXXXXX)
/bin/chmod 700 "$OUTPUT_DIR"

printf '\n%s\n' '步骤 3/3：采集只读快照；遇到超时/输出超限/权限错误立即停止后续查询。'
if "$TOOL" collect --output "$OUTPUT_DIR"; then
    printf '\n%s\n' '采集完成，仍需审阅；这不是 PF 可行性或防泄漏通过。'
else
    printf '\n%s\n' '采集未完成。请保留目录；不执行任何清理或重试覆盖。' >&2
    printf '目录：%s\n' "$OUTPUT_DIR" >&2
    exit 1
fi
printf '只需先提供汇总文件：%s/summary.json\n' "$OUTPUT_DIR"
printf '%s\n' '原始 query-*.json 暂时留在本机，不必全部发出。'
