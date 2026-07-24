# Zapata unidbg Normalized Trace 优化方案

本文记录 zapata fork 后续 `NormalizedTrace` 的新开发方案。当前目标不是重新做一套 text trace，也不是在 unidbg 内生成 `trace.db`，而是在 unidbg 侧提供高速、结构化、后端无关的 runtime trace 事实流。

`trace.db`、`ir.db`、`ssa.db` 的构建统一放在 VMP-Lift 中完成。这样后续 QBDI、unidbg、真实设备或其他执行后端都可以接入同一条 VMP-Lift ingestion pipeline。

## 1. 分层边界

| 层 | 职责 | 不负责 |
|---|---|---|
| unidbg fork / `unidbg-api` | 采集真实 runtime 事实，安装 code/read/write hook，输出 normalized trace artifact | 生成 `trace.db`，识别 VM/VIP/opcode，做 taint、SSA、handler clustering |
| VMPark-unidbg / 其他 runner | 加载 APK/SO，调用目标入口，选择 module/range/profile，写 runner config/status/corpus 外壳 | 手写底层 hook，做 VMP 语义分析 |
| VMP-Lift Rust | 消费 unidbg/QBDI normalized trace，编译 `trace.db`，生成 IR/SSA，做 classify、bytecode-access、taint、oracle diff | 运行 unidbg，依赖 runner 内部实现 |

核心原则：unidbg 只采事实；VMP-Lift 才做数据库化和分析。

## 2. xfxfxiaofeng trace 加速方案评估

xfxfxiaofeng 的 trace 加速方案对 text trace 热路径做了有效优化，值得吸收，但它不是最终上限。它解决的是“把可读 trace 打得更快”，而我们要解决的是“把大规模机器可消费 trace 采得更快”。

应吸收的点：

- 异步写日志，hook 线程不直接打文件。
- 大块缓冲，批量 flush，减少 IO 调用次数。
- instruction decode cache，避免每条指令重复 Capstone decode。
- 静态 instruction 信息预计算，包括 mnemonic、operand、reg access、branch/call flags。
- pending instruction 模型，把 memory access 和 register writes 归并到对应 instruction。
- module-name 动态过滤，目标模块未加载时允许先配置名称，加载后自动命中。
- SvcMemory 噪声过滤，避免 unidbg 内部 trampoline 污染 trace。
- symbol/PLT/SVC/JNI 解析缓存，避免重复查符号。

不应照搬的点：

- 不把 hexdump/text line 作为核心数据格式。
- 不在热路径默认启用 JNI/libc/syscall 高级格式化。
- 不把函数语义解析和 VMP trace 采集合并成一个不可分 profile。
- 不让 `trace.db` 编译逻辑进入 unidbg。
- 不为了 text 输出保留大量 `String.format`、`PrintStream`、嵌套字符串拼接。

更高级的方向：

- 缓存 typed instruction metadata，而不是缓存预格式化文本。
- 写出 normalized event 或 binary chunk，而不是写出 text trace 再二次解析。
- 用 profile 控制采集预算，让 instruction、memory、register、call semantic 独立开关。
- unidbg 输出保持后端中立，VMP-Lift 负责把 unidbg/QBDI trace 统一编译成 `trace.db`。

## 3. 新版目标

新版 `NormalizedTrace` 需要同时满足两个场景：

- Debug/audit：保留 JSONL，可读、可抽样、可回归测试。
- Data pipeline：输出低对象分配、低格式化成本的 normalized trace artifact，供 VMP-Lift 编译成 `trace.db`。

第一阶段仍可输出 JSONL，但热路径不能继续依赖 `LinkedHashMap -> JSON.toJSONString`。JSONL writer 应改为 typed streaming writer。后续可以新增 binary chunk writer，但 binary chunk 仍只是 trace artifact，不是 `trace.db`。

## 4. Trace Profile

保留原有 `Level` 概念，但新增更清晰的 profile，用于控制性能预算。

| Profile | 采集内容 | 用途 |
|---|---|---|
| `FAST_PC` | pc、size、machine code，可选 module/file offset | 快速定位热路径和目标范围 |
| `FAST_MEM` | instruction metadata + memory addr/size/value limit | bytecode fetch/decrypt、context access |
| `REG_DELTA` | instruction metadata + selected register delta | VIP、key、state register 识别 |
| `FULL_JSONL` | 完整 normalized JSONL | 审计、调试、回归测试 |
| `CALL_SEMANTIC` | call target、svc no、raw args，可选 JNI/libc parser | 边界语义辅助，不默认启用 |
| `DB_HOT` | typed/binary trace chunks | 大规模 pipeline 输入，由 VMP-Lift 编译 `trace.db` |

`FULL_JSONL` 不应作为大规模默认模式。VMP/OLLVM 大 trace 默认应使用 `FAST_MEM` 或 `REG_DELTA`，需要完整审计时再升到 `FULL_JSONL`。

## 5. Hook 安装策略

### 5.1 Code hook

优先使用精确 range hook：

- 如果 runner 已持有 `Module`，直接安装到 `[module.base, module.base + module.size)` 或更窄函数范围。
- 如果 runner 只有 module name，允许先注册 module-name filter；模块加载后缓存 `Module` 并切换到 range 判断。
- 不建议默认全进程 code hook。确实需要全局追踪时必须显式配置 profile 和 max events。

### 5.2 Memory hook

memory hook 默认不应全局打开。优先顺序：

- 明确 bytecode/payload/context range。
- target module range。
- runner 指定 heap/stack/scratch range。
- 最后才是全局 memory hook，并必须配合 `maxEvents`、`memoryValueLimit` 和 noise filter。

### 5.3 Noise filter

默认跳过：

- unidbg `SvcMemory` trampoline 区域。
- runner 明确标记的 framework/internal ranges。
- 非目标 module 的 instruction，除非 profile 需要 call boundary。

## 6. Instruction Decode Cache

吸收 xfxfxiaofeng 的 L1/L2 cache 思路，但缓存 typed metadata。

缓存项建议包含：

```text
address
size
machine_code
mnemonic_id
operand_text_id
reg_read_ids
reg_write_ids
branch_kind
call_kind
static_flags
```

L1 使用按 PC hash 的数组缓存，L2 使用 bounded map。发生地址冲突时从 L1 驱逐到 L2。

SMC 策略：

- 默认不开强 SMC 校验，避免每条指令都 `mem_read` 抵消 cache 收益。
- `smcDetect=true` 时记录 machine code 并校验。
- 一旦发现某 page 有 SMC，只对该 page 开启强校验。
- 对 known writable/executable page 可主动提高校验等级。

## 7. Pending Instruction 聚合

当前 code hook 在指令执行前触发，所以 register writes 和 memory access 都应通过 pending instruction 模型归并。

流程：

1. 当前 code hook 触发，读取 selected registers 作为当前 before snapshot。
2. flush 上一条 pending instruction：用当前 snapshot 计算上一条 register delta，并附带上一条期间捕获的 memory accesses。
3. 解码或读取当前 instruction cache，创建新的 pending instruction。
4. memory read/write hook 触发时，把 access 追加到当前 pending instruction。
5. session close 时 flush 最后一条 pending instruction，并标记最后一条 delta 不完整。

收益：

- memory access 不再作为孤立 event 散落。
- instruction、register delta、memory access 的关联更稳定。
- event 数量下降，VMP-Lift ingestion 更简单。

保留兼容：writer 可以选择输出聚合 instruction event，也可以为了兼容输出独立 memory event。但内部采集模型应以聚合为准。

## 8. Register Capture

寄存器采集应从 `Map<String, String>` 热路径迁移为 typed snapshot。

建议实现：

- selected register 编译成 `int[] regIds` 和 `String[] regNames`。
- snapshot 使用 `long[] values`。
- delta 使用 index + old/new/current value，不在 hook 内构造字符串 map。
- JSONL writer 在最终序列化时再把值格式化成 hex。
- binary chunk writer 直接写 reg index/value。

默认寄存器集合：

```text
arm64 fast: x0-x15, sp, pc, nzcv
arm64 full: x0-x30, sp, pc, nzcv
arm32 full: r0-r12, sp, lr, pc, cpsr
```

vector registers 默认关闭，后续按 profile 单独打开。

## 9. Memory Capture

memory access 内部结构应保留 typed 字段：

```text
access_kind: read|write
pc
address
size
value_len
value_bytes
region_id
module_id
flags
```

热路径要求：

- 不使用 `String.format`。
- 不使用 `ByteBuffer.allocate` 格式化 write value。
- write value 小于等于 8 字节时直接按 little-endian 写入 scratch buffer。
- read value 只读取 `min(size, memoryValueLimit)`。
- value 读取失败只记录 metadata 和 diagnostic counter，不抛出到 hook 外。

JSONL 中仍可表现为：

```json
{
  "access": "read",
  "address": "0x72002000",
  "size": 1,
  "value_hex": "7f"
}
```

但这是 writer 层格式，不是 hook 热路径格式。

## 10. Writer 设计

writer 分两层：

- `NormalizedTraceEventSink`：接收 typed event，不关心输出格式。
- `JsonlTraceWriter` / `BinaryTraceWriter`：负责具体落盘。

JSONL writer 第一阶段优化：

- 手写 streaming JSON writer，替代 per-event `LinkedHashMap` 和 `JSON.toJSONString`。
- 使用大块 `StringBuilder` 或 `char[]` buffer。
- 异步 writer thread 批量落盘。
- 按 chunk size rotate，避免单文件过大。

Binary writer v0.1：

- `TraceOutputFormat` 支持 `JSONL`、`BINARY`、`BOTH`。
- `BINARY` 输出 `trace.<case_id>.000.bin`，格式名为 `zapata-trace-bin-v0.1`。
- 文件头写 `ZTRC` magic、version、backend、case_id。
- event record 写 instruction/memory typed rows。
- instruction record 覆盖 pc、module、file_offset、symbol、instruction bytes、mnemonic、operands、branch target、register writes、memory accesses。
- memory record 覆盖 pc、module、file_offset、access kind、address、size、value bytes。
- 当前 v0.1 为 append-only typed chunks；string table、module table 和 chunk rotation 后续再做，不进入热路径契约破坏。
- `BOTH` 用于 parity gate：JSONL 保持 debug/audit，binary 作为 VMP-Lift `trace.db` ingestion 优先输入。
- 输出仍是 trace artifact，由 VMP-Lift ingestion 编译成 `trace.db`。

Binary writer v0.2：

- 格式名为 `zapata-trace-bin-v0.2`，文件名为 `trace.<case_id>.<chunk>.bin`。
- 支持按 `maxEventFileBytes` / `maxEvents` chunk rotation；runner 在 `trace_corpus.json` 中为每个 chunk 输出一条 `trace_files` 记录。
- 每个 chunk 独立携带 string table、module table、register table，避免后续 chunk 的 interned strings 污染已关闭 chunk。
- event record 中 module、symbol、mnemonic、operand、instruction bytes、register name 使用 table id，减少重复字符串落盘。
- v0.2 event 热路径使用 varuint 收紧 table id、operand count、register count、memory count、memory size 和 memory value length；PC、address、register value 仍使用 64-bit 固定宽字段。
- header 包含 magic/version/chunk index、event counters、event/table offsets、file size、CRC32 字段和 reserved 字段；VMP-Lift importer 会校验 magic/version、file size 和 offset 单调性。
- memory value length 使用 `len + 1` varuint，`0` 表示无 value；register writes 使用 varuint register id + u64 value。
- `trace.<case_id>.meta.json` 汇总所有 chunks 的 event count、bytes、checksum 和全局 counters。
- `DB_HOT` / 大规模 `full` trace 默认应走 binary artifact；JSONL 保留为 audit/debug 和 `BOTH` parity gate。

当前回归数据：

- `pbkdf2_sha256` full binary v0.2：`904787` events、`904753` instructions、`91491` branches、`317128` memory reads、`145517` memory writes、`1527865` register writes。
- 单 chunk binary v0.2 固定宽版本约 `82.6MB`；varuint 收紧后约 `55.9MB`；同一 case 的 v0.1 binary 曾约 `133.7MB`。
- VMP-Lift `trace db-build` 已能从 v0.2 binary 构建 `trace.db`，rows=`904787`，diagnostics=[]；varuint debug build 转换约 `34.5s`。
- rotation smoke：`max-events=5000`、`max-event-file-bytes=200000` 生成 3 个 v0.2 chunks，VMP-Lift db-build rows=`5000`。
- parity gate：`trace-output both` + VMP-Lift `trace compare-formats` 已验证 v0.2 JSONL/binary counters matched，mismatches=[]。

## 11. Symbol / Call Semantic

symbol 和 call semantic 有价值，但默认不能拖慢 VMP hot trace。

策略：

- 默认只记录 call target、return address、svc number、raw args。
- symbol 解析使用 bounded cache。
- JNI/libc/syscall parser 放入 `CALL_SEMANTIC` profile。
- parser 失败不得影响 instruction/memory trace。
- 复杂语义解析优先离线放到 VMP-Lift，除非必须依赖 runtime object 状态。

可吸收 xfxfxiaofeng 的能力：

- PLT stub 解析。
- SvcMemory symbol 解析。
- JNIEnv offset 识别。
- libc/JNI/syscall raw arg helper。

但这些能力需要 profile gating，不默认进入 `FAST_MEM` 或 `REG_DELTA`。

## 12. Artifact 契约

unidbg session 输出：

```text
events.<case_id>.<chunk>.jsonl       # debug/audit profile
trace.<case_id>.<chunk>.bin          # ztrace binary artifact
trace.<case_id>.meta.json            # binary artifact metadata
normalized_trace_session.json
```

runner 输出：

```text
trace_run_config.json
trace_run_status.json
trace_corpus.json
trace_index.json
trace_summary.json
report.md
```

`trace_corpus.json` 只引用 trace artifacts 和 session metadata。VMP-Lift 根据这些 artifacts 生成 `trace.db`。

必须保持后端中立字段：

- backend name: `unidbg`、`qbdi`、future backend。
- module name/base/size/file offset。
- instruction pc/size/bytes/mnemonic/operands。
- register delta。
- memory access。
- optional call semantic。

## 13. VMP-Lift 契约

VMP-Lift 负责：

- 读取 unidbg JSONL/binary trace artifacts。
- 读取 QBDI trace artifacts。
- 统一 normalize backend 差异。
- 编译 `trace.db`。
- 继续生成 `ir.db`、`ssa.db`。
- 做 VM/VIP/opcode、bytecode-access、handler clustering、taint、SSA、oracle diff。

unidbg 不负责：

- `trace.db` schema。
- mmap layout。
- IR/SSA 数据模型。
- VMP 专用分析逻辑。

## 14. 开发顺序

第一批优化：

- 修正 session close 顺序：flush pending instruction，写 summary，最后关闭 writer 资源。
- 引入 async batch writer。
- 引入 instruction decode typed cache。
- 把 memory read/write 归并到 pending instruction。
- 加 SvcMemory skip。
- 加 module-name dynamic filter。
- 减少 hook 热路径 `LinkedHashMap`、`ArrayList`、`JSON.toJSONString`。

第二批优化：

- register snapshot 改为 `long[]`。
- memory value formatting 改为 scratch buffer。
- symbol/cache/call semantic profile 化。
- JSONL chunk rotate。
- 增加采集 counters 和 dropped reason。

第三批优化：

- 新增 binary trace artifact writer。
- VMP-Lift 新增 unidbg binary ingestion。
- VMP-Lift 同时接入 QBDI trace ingestion。
- 在 VMP-Lift 内统一编译 `trace.db`。

## 15. 验收标准

| Gate | 期望 |
|---|---|
| API | 外部 runner 仍主要调用 `NormalizedTraceInstaller.install` 和 `NormalizedTraceConfig` |
| 性能 | instruction decode cache 命中后不重复 Capstone decode |
| IO | hook 线程不直接同步写大文件 |
| memory | read/write access 能归并到对应 instruction |
| registers | selected delta 可用，默认不采 vector |
| filtering | 支持 module/range-first，避免默认全进程 trace |
| artifacts | unidbg 输出 JSONL/binary trace artifact，不输出 `trace.db` |
| compatibility | 现有 `traceCode/traceRead/traceWrite` 不破坏 |
| VMP-Lift | unidbg/QBDI trace 都能进入同一 ingestion pipeline |

## 16. 最终定位

`NormalizedTrace` 是 zapata unidbg fork 的长期 runtime capture API。它负责把 unidbg 执行期间的真实事实高速采出来，并以 normalized artifact 交给 runner 和 VMP-Lift。

后续所有数据库化、跨后端合流和 VMP 分析都放在 VMP-Lift。unidbg 侧只继续优化采集性能、过滤能力、artifact 稳定性和 backend 事实完整性。
