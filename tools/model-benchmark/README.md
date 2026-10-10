# 模型额度和能力实测工具

需要 Node.js 24 和运行中的本地 Sub2API，管理员测试接口须支持 prompt 与 usage 遥测。工具沿用系统代理、OAuth 凭据和模型映射，不导出密钥。结果写入被 Git 忽略的 `output/`。

管理员用户名从本地配置的 `ADMIN_EMAIL` 读取，密码从 `ADMIN_PASSWORD` 读取；未提供用户名时默认 `admin`，也可以用 `--admin` 指定用户名。用户名和密码都不会写入报告。

六模型、六个不同账号并行，每账号一个请求：

```powershell
node tools/model-benchmark/cli.mjs --serve --minutes 120
```

指定一个账号，测试 GPT-5.5：

```powershell
node tools/model-benchmark/cli.mjs --serve --accounts 3 --models gpt-5.5 --minutes 30 --out output/gpt55-test
```

打开 http://127.0.0.1:8091 看实时报告，5 秒刷新。单账号按钮可启动后续测试，每次自动创建新的结果子目录。新建输出目录中的 `STOP` 文件或点击停止，在当前请求结束后停止。`--resume` 读取断点，保留原开始时间和时限；已完成任务不会被再次运行。`--secrets` 可指定含 ADMIN_PASSWORD 的本地配置，`--admin` 指定管理员名；配置不进入报告。`--idle --serve` 只启动工具页面。`node --test tools/model-benchmark/test.mjs` 验证统计和分类。

报告 `report.html` 包括汇总、评分细项、原始答案、每次请求用量、耗时、首 token 延迟、实际上游模型、额度响应头与前后快照。`checkpoint.json` 为完整机器可读原始证据；HTML 展示每条输出前 12000 字符，JSON 保留全文。`node tools/model-benchmark/finalize.mjs output/model-benchmark` 生成增强报告与 `summary.json`。

输入和输出分别汇总，上游输出 token 可能包含推理，推理不可重复计入总量。没有 usage 不估算。基础 12 题与进阶 10 题各测一次，不是 IQ 测试；需要标准基准时可扩展题库并多次重复。进阶题含自动机计数、背包、组合数、递推、同余、TSP、逻辑、路径和 Python 语义，参考值由本地确定性算法计算。quota_exhausted 表示明确额度信号；rate_limited 只表示限流。时限、网络、未授权、不支持模型和输出截断均不能证明总额度耗尽。

测试持续消耗已选择账号的可用额度；遇到限制停止，不切换账号或等待重置。GPT-Reserve 的请求 ID 暂用 gpt-reserve，当前系统目录缺少该条目，报告保留实际探测结果，不保证该 ID 是有效模型。

如果长请求已有可见输出，但超时或流中断，后续请求逐次减半输出目标（最低 100 行），争取获得完整 usage。未提供 usage 的请求仍标记缺失。`--resume --continue-stopped` 可在原时限内继续被手动停止或因临时错误结束的模型，完整保留已有记录；此时目标调整为 300 行，明确额度耗尽的模型不会重新运行。
