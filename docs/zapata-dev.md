# Zapata unidbg Normalized Trace 设计计划

本文记录 zapata fork 中一次性沉淀的通用 trace 能力设计。目标是后续 `VMPark-unidbg`、其他 app VMP 样本 runner、外部产品分析 runner 都复用同一套 API，不再为每个项目重复改 unidbg trace 逻辑。

## 1. 背景与目标

当前 unidbg 已有 `traceCode`、`traceRead`、`traceWrite`、`AssemblyCodeDumper`、`TraceMemoryHook` 和 listener API，但它们主要服务于调试打印，不提供稳定的机器可消费 trace artifact。

当前 `VMPark-unidbg` 自己实现了 `TraceWriter` 和 `TraceHook`，但只输出 instruction PC/bytes，`mnemonic=unknown`，没有寄存器 delta，也没有 memory read/write value。这个物料不足以支撑 VMP-Lift 的 no-manifest 路线：VIP、rolling key、opcode/operand fetch/decrypt、handler clustering 和 bounded taint 都需要寄存器与内存访问事实。

本次改造目标：在 unidbg fork 的 `unidbg-api` 中提供通用 Normalized Trace API，一次性覆盖 instruction trace、register snapshot/delta、memory read/write trace、JSONL writer、过滤、限流和 artifact metadata。上层 runner 只负责加载样本和调用目标函数。

## 2. 分层边界

| 层 | 职责 | 不负责 |
|---|---|---|
| unidbg fork / `unidbg-api` | 真实 runtime 事实采集、hook 安装、register/memory/code event 规范化、JSONL 输出 | VMP/VIP/opcode 语义判断、VMPark 专用逻辑 |
| VMPark-unidbg / 其他 runner | CLI 参数、加载 APK/SO、调用 JNI_OnLoad/entry、选择 module/range/filter、写 runner status/config | 手写底层 CodeHook/ReadHook/WriteHook |
| VMP-Lift Rust | 消费 normalized trace，做 classify、bytecode-access、handler clustering、bounded taint、oracle diff | 运行 unidbg 或依赖 runner 内部实现 |

核心原则：unidbg 只采事实；VMP-Lift 才做分析。

## 3. 新增包与公开 API

新增 Java package：

```text
unidbg-api/src/main/java/com/github/unidbg/trace/
```

建议新增类：

| 类 | 公开性 | 职责 |
|---|---|---|
| `NormalizedTraceConfig` | public | trace 配置，包含 case/module/range/register/memory/output/max-events 等 |
| `NormalizedTraceSession` | public | session handle，安装/卸载 hooks，flush/close，暴露 counters/diagnostics |
| `NormalizedTraceInstaller` | public | 静态入口，按 config 安装 code/read/write hooks |
| `NormalizedTraceWriter` | public 或 package-private | JSONL writer，seq、chunk、event serialization |
| `NormalizedTraceEvent` | package-private 或 public POJO | event model，避免散落 Map 构造 |
| `NormalizedTraceRegisters` | package-private | ARM64/ARM32 register selection、snapshot、delta |
| `NormalizedTraceMemory` | package-private | memory event capture/value formatting |
| `NormalizedTraceModuleResolver` | package-private | module name、file offset、range 归属解析 |
| `NormalizedTraceCounters` | public | events/instructions/branches/memory/register counters |

外部使用示例：

```java
NormalizedTraceConfig config = NormalizedTraceConfig.builder()
    .caseId("case_0")
    .outputDir(new File("out/trace"))
    .backendName("unidbg")
    .targetModule(module)
    .traceRange(module.base, module.base + module.size)
    .level(NormalizedTraceConfig.Level.FULL)
    .selectedArm64Registers(NormalizedTraceConfig.arm64GprAll())
    .memoryValueLimit(16)
    .maxEvents(5_000_000L)
    .build();

try (NormalizedTraceSession session = NormalizedTraceInstaller.install(emulator, config)) {
    symbol.call(emulator, arg0, arg1);
}
```

也允许更轻量：

```java
NormalizedTraceSession session = NormalizedTraceInstaller.install(emulator, config);
try {
    module.callFunction(emulator, offset, args);
} finally {
    session.close();
}
```

## 4. Trace Level

支持分级采集，避免默认 full trace 过慢或过大。

| Level | instruction | registers | memory metadata | memory value | 用途 |
|---|---|---|---|---|---|
| `OFF` | no | no | no | no | runner 只加载样本，不采 trace |
| `INSTRUCTION` | yes | no | no | no | PC/bytes/mnemonic/operands 基础覆盖 |
| `REGISTERS` | yes | selected delta | no | no | VIP/key/context 初步识别 |
| `MEMORY` | yes | no | yes | optional | bytecode range/fetch evidence |
| `FULL` | yes | selected delta | yes | yes | no-manifest VMP 分析默认推荐 |

`VMPark-unidbg` 后续 CLI 可映射为：

```text
--trace-level off|instruction|registers|memory|full
```

## 5. 输出 artifact

unidbg API 只负责 JSONL event 文件和 session summary；runner 负责最终 corpus/config/status 外壳。

建议 unidbg session 输出：

```text
events.<case_id>.000.jsonl
events.<case_id>.001.jsonl       # 后续按 chunk size rotate，可第一版不实现 rotate
normalized_trace_session.json
```

`normalized_trace_session.json`：

```json
{
  "schema_version": "0.1",
  "kind": "normalized_trace_session",
  "status": "closed",
  "case_id": "case_0",
  "event_files": [
    {
      "path": "events.case_0.000.jsonl",
      "format": "jsonl",
      "event_schema": "trace_event.v0.1",
      "status": "collected",
      "compression": "none"
    }
  ],
  "summary": {
    "events": 123,
    "instructions": 100,
    "branches": 12,
    "memory_reads": 8,
    "memory_writes": 3,
    "register_writes": 75,
    "dropped_events": 0,
    "malformed_events": 0
  },
  "diagnostics": []
}
```

Runner 读取这个 summary，再写 VMP-Lift 需要的 `trace_corpus.json`、`trace_index.json`、`trace_summary.json`。

## 6. Event Schema

event 必须兼容 VMP-Lift `docs/trace-format.md`。

### 6.1 Instruction Event

```json
{
  "seq": 1,
  "thread_id": "main",
  "kind": "instruction",
  "pc": "0x70001000",
  "module": "libtarget.so",
  "file_offset": "0x1000",
  "symbol": "sub_1000",
  "instruction": {
    "bytes": "e00300aa",
    "mnemonic": "mov",
    "operands": ["x0", "x0"]
  },
  "registers": {
    "reads": {},
    "writes": {
      "x0": "0x1",
      "pc": "0x70001004"
    }
  },
  "memory": [],
  "branch": null,
  "backend": {
    "name": "unidbg",
    "raw_kind": "code_hook"
  }
}
```

### 6.2 Memory Read Event

```json
{
  "seq": 2,
  "thread_id": "main",
  "kind": "memory_read",
  "pc": "0x70001004",
  "module": "libtarget.so",
  "file_offset": "0x1004",
  "memory": [
    {
      "access": "read",
      "address": "0x72002000",
      "size": 1,
      "value_hex": "7f",
      "region": null,
      "module": null,
      "symbol": null,
      "taint": [],
      "note": null
    }
  ],
  "backend": {
    "name": "unidbg",
    "raw_kind": "read_hook"
  }
}
```

### 6.3 Memory Write Event

```json
{
  "seq": 3,
  "thread_id": "main",
  "kind": "memory_write",
  "pc": "0x70001008",
  "module": "libtarget.so",
  "file_offset": "0x1008",
  "memory": [
    {
      "access": "write",
      "address": "0x73003000",
      "size": 8,
      "value_hex": "1122334455667788",
      "region": null,
      "module": null,
      "symbol": null,
      "taint": [],
      "note": null
    }
  ],
  "backend": {
    "name": "unidbg",
    "raw_kind": "write_hook"
  }
}
```

### 6.4 Branch Event

第一版可以不单独输出 branch event；但 instruction event 应尽量填 `branch`。

可通过 mnemonic 粗判：`b`、`bl`、`blr`、`br`、`ret`、`cbz`、`cbnz`、`tbz`、`tbnz`、`b.cond`。target 能从 Capstone operand 中解析则填，无法解析则只填 mnemonic evidence。

```json
"branch": {
  "taken": true,
  "target": "0x70002000",
  "fallthrough": "0x70001004",
  "condition_registers": ["nzcv"]
}
```

如果 target/taken 不可靠，优先不填，避免伪造。

## 7. Register Capture 设计

### 7.1 ARM64 第一版寄存器集合

默认 selected set：

```text
x0-x30, sp, pc, nzcv
```

性能模式：

```text
x0-x15, sp, pc, nzcv
```

后续可选 vector：

```text
q0-q31
```

但 vector 默认关闭，避免 trace 膨胀。

### 7.2 Delta 策略

unidbg `CodeHook` 在指令执行前触发。为了输出上一条指令的 after-state，采用 pending instruction 模型：

1. 当前 code hook 触发，读取当前 selected register snapshot。
2. 如果存在上一条 pending instruction，则用当前 snapshot 与上一条 before snapshot 比较，得到上一条的 `registers.writes`，然后写出上一条 instruction event。
3. 反汇编当前 instruction，保存为新的 pending instruction，并记录当前 before snapshot。
4. session close 时 flush 最后一条 pending instruction；最后一条没有可靠 after snapshot，可以输出空 writes，并在 diagnostics 标记 `last_instruction_delta_unavailable`。

优点：

- 不需要单步执行后 hook。
- 不依赖 Capstone `regsAccess` 的完整性。
- 能稳定得到 VIP/key/context 的实际变化。

局限：

- 写但值不变的寄存器不会出现在 delta 中。
- 最后一条 instruction 的 writes 不可靠。

### 7.3 Reads 策略

第一版 reads 可选：

- 默认 `reads={}`。
- 如果 Capstone `regsAccess()` 可用，则对 `regsRead` 读取 before snapshot 值填入 `reads`。
- reads 失败不得影响 trace，记录 diagnostic。

### 7.4 寄存器名

JSON 使用小写 canonical name：

```text
x0..x30, sp, pc, nzcv, w0..w30 only when instruction explicitly exposes W register and value is 32-bit
```

为了分析稳定，建议 delta 主要输出 `xN` 64-bit 视图；如果 Capstone reads 中出现 `wN`，可以同时输出 `wN` 或规范化为 `xN` 并保留低 32-bit value。第一版优先统一成 `xN`。

## 8. Memory Capture 设计

使用 backend hook：

```java
backend.hook_add_new(ReadHook, begin, end, user);
backend.hook_add_new(WriteHook, begin, end, user);
```

第一版 memory event 独立输出，不强行附着到 instruction event。通过 memory event 的 `pc` 与相邻 seq 关联。

读：

- `address`、`size` 来自 hook。
- `value_hex` 通过 `backend.mem_read(address, min(size, memoryValueLimit))` 获取。
- 如果 value 读取失败，保留 metadata，`value_hex=null`，diagnostics 记录。

写：

- hook 参数有 `value`，按 size 格式化为 little-endian hex。
- 如果 size 大于 8 且无法得到完整 bytes，先输出 `value_hex` 为整数截断形式，并加 note。

过滤：

- 第一版允许 memory hook range 默认为 `1..0` 全局，但建议 runner 传 module range 或 payload/range filter。
- 配置支持 `memoryRanges`，避免全进程读写噪音过大。
- `memoryValueLimit` 默认 16；设置 0 表示只采 metadata。

## 9. Instruction Decode 设计

优先复用 `Emulator.disassemble(address, code, false, 1)`：

- code bytes 通过 `backend.mem_read(address, size)`。
- mnemonic 使用 `Instruction.getMnemonic()`。
- operands 使用 `Instruction.getOpStr()` 或 operands API 规范化为字符串数组；若只能获得 opStr，则第一版可输出单元素数组或按逗号切分。
- 反汇编失败时 `mnemonic="unknown"`，`operands=[]`，diagnostics 记录。

不要复用 `AssemblyCodeDumper` 的打印输出作为数据源；它可以作为实现参考，但 normalized trace 应直接构造 JSON event。

## 10. Module / File Offset / Symbol

`NormalizedTraceConfig` 必须允许配置 target module：

```java
.targetModule(module)
```

模块字段：

- `module = module.name` when `address in [module.base, module.base + module.size)`。
- `file_offset = module.virtualMemoryAddressToFileOffset(address - module.base)`，如果返回 `-1`，fallback 为 `address - module.base` 并加 diagnostic。
- `symbol = module.findClosestSymbolByAddress(address, true)` 可选；失败不影响 trace。

如果没有 target module，允许 range-only 模式：

- `module=null`
- `file_offset=null`

## 11. API 配置字段

`NormalizedTraceConfig` 字段建议：

```java
public final class NormalizedTraceConfig {
    public enum Level { OFF, INSTRUCTION, REGISTERS, MEMORY, FULL }

    String caseId;
    File outputDir;
    String backendName;        // default: unidbg
    Level level;
    long maxEvents;
    long maxEventFileBytes;    // future rotation, first version may ignore
    Module targetModule;
    long traceBegin;
    long traceEnd;
    List<AddressRange> memoryRanges;
    List<String> selectedRegisters;
    int memoryValueLimit;
    boolean includeInstructionBytes;
    boolean includeInstructionDecode;
    boolean includeRegisterReads;
    boolean includeRegisterWrites;
    boolean includeMemoryValues;
    boolean stopEmulatorOnMaxEvents;
}
```

Builder 默认：

```text
level=INSTRUCTION
maxEvents=1_000_000
memoryValueLimit=16
includeInstructionBytes=true
includeInstructionDecode=true
includeRegisterReads=false
includeRegisterWrites=true when level includes registers
includeMemoryValues=true when level=FULL
stopEmulatorOnMaxEvents=true
selectedRegisters=arm64GprAll for 64-bit, arm32GprAll for 32-bit
```

## 12. Hook 安装策略

`NormalizedTraceInstaller.install(emulator, config)`：

1. 创建 output dir 和 writer。
2. 如果 level 包含 instruction/register，安装 `CodeHook` 到 `traceBegin..traceEnd`。
3. 如果 level 包含 memory，安装 `ReadHook` / `WriteHook` 到 memory ranges；如果没有 memory ranges，安装全局并依赖 maxEvents/filter。
4. 返回 `NormalizedTraceSession`。

`NormalizedTraceSession.close()`：

1. detach hooks。
2. flush pending instruction。
3. close writer。
4. 写 `normalized_trace_session.json`。

`close()` 必须幂等。

## 13. 性能与安全边界

- JSONL 一行一个 event，不写 JSON array。
- `maxEvents` 必须生效，超过后停止写入；配置允许自动 `emu_stop()`。
- `memoryValueLimit` 控制 value bytes，默认不超过 16。
- 不默认采 vector registers。
- 不默认全局 memory hook，runner 应尽量传 module/payload/range。
- writer 使用 buffered writer。
- 所有 hook 内异常要转为 diagnostics，除非是不可恢复 IO 错误。
- event 序列化不能依赖 Kotlin 或外部 runner 库；放在 `unidbg-api` Java 里，使用已有 fastjson 或手写轻量 JSON writer。

## 14. 与现有 unidbg trace API 的关系

保留现有 API：

- `traceCode`
- `traceRead`
- `traceWrite`
- `AssemblyCodeDumper`
- `TraceMemoryHook`

新增 normalized trace 不替代这些调试 API。它是面向工具链和 VMP-Lift 的稳定 artifact API。

不要改动现有 `TraceHook` 接口语义，避免破坏外部使用者。

## 15. VMPark-unidbg 改造方式

后续 `VMPark-unidbg` 应删除或弱化自己的底层 `hooks/TraceHook.kt`，改为：

```kotlin
val traceConfig = NormalizedTraceConfig.builder()
    .caseId(config.caseId)
    .outputDir(File(config.outDir))
    .targetModule(module)
    .traceRange(module.base, module.base + module.size)
    .level(config.normalizedTraceLevel())
    .maxEvents(config.maxEvents)
    .build()

NormalizedTraceInstaller.install(emulator, traceConfig).use { session ->
    symbol.call(emulator, *args)
}
```

`TraceWriter.kt` 保留：

- `trace_run_config.json`
- `trace_run_status.json`
- `trace_corpus.json`
- `trace_index.json`
- `trace_summary.json`
- `report.md`

但 events 和 session summary 来自 unidbg normalized trace。

## 16. 与 VMP-Lift 的契约

VMP-Lift 期待：

- `trace_corpus.json` 小文件，只引用 chunks。
- `events.*.jsonl` 是 normalized event stream。
- instruction events 可包含 `registers.writes`。
- memory events 必须包含 `pc`、`address`、`size`、可选 `value_hex`。
- large trace 不全量加载。

完成后应能直接跑：

```powershell
vmp-lift trace index trace_corpus.json --out target\trace-index
vmp-lift trace classify --trace trace_corpus.json --out target\trace-classify
vmp-lift trace bytecode-access --trace trace_corpus.json --out target\bytecode-access
```

## 17. 实施步骤

### Step 1: unidbg-api trace package

- 新增 `com.github.unidbg.trace` 包。
- 实现 config/session/writer/installer/counters。
- 实现 ARM64 selected register snapshot/delta。
- 实现 instruction decode event。
- 实现 memory read/write event。
- 先支持 uncompressed JSONL 单 chunk。

### Step 2: 示例和最小测试

- 在 `unidbg-android` 或 `unidbg-api` test/sample 中添加最小 runner 示例。
- 验证 event 文件包含 instruction、register writes、memory read/write。
- Maven build 通过。

### Step 3: VMPark-unidbg 接入

- 更新 libs 为新编译的 `unidbg-api-0.9.10-SNAPSHOT.jar`，必要时同步 `unidbg-android` 和 backend jar。
- `RunnerConfig` 增加/调整 trace level：`off|instruction|registers|memory|full`。
- `VMParkTraceRunner` 使用 `NormalizedTraceInstaller`。
- `TraceWriter` 从 `normalized_trace_session.json` 汇总 event files/counters。

### Step 4: VMP-Lift 消费验证

- 用真实 VMPark 样本生成 full trace。
- 跑 `trace index`，确认 register/memory counters 非零。
- 跑 `trace bytecode-access`，确认能产生 bytecode range、VIP、fetch/decrypt candidates。

## 18. 验收标准

| Gate | 期望 |
|---|---|
| API 稳定 | 外部 runner 只调用 `NormalizedTraceInstaller.install` 和 `NormalizedTraceConfig` |
| instruction | 输出 pc/module/file_offset/bytes/mnemonic/operands |
| registers | 输出 selected register delta，至少 ARM64 `x0-x30/sp/pc/nzcv` |
| memory read | 输出 address/size/value_hex/pc |
| memory write | 输出 address/size/value_hex/pc |
| JSONL | 一行一个 event，不写大 JSON array |
| limit | `maxEvents` 生效，可 stop emulator |
| close | session close detach hooks、flush pending instruction、写 summary |
| compatibility | 现有 `traceCode/traceRead/traceWrite` 不破坏 |
| VMP-Lift | `trace index/classify/bytecode-access` 可直接消费 |

## 19. 暂不做

- 不在 unidbg 中识别 VM/VIP/opcode。
- 不在 unidbg 中做 taint。
- 不在 unidbg 中做 handler clustering。
- 不默认采 vector registers。
- 不默认做 zstd compression。
- 不在第一版做多线程精确 thread id；先统一 `main`，后续可接 ThreadDispatcher 信息。

## 20. 最终定位

这套 trace 是 zapata fork 的长期稳定 runtime capture API。以后所有 VMP 样本 runner 都只依赖它输出 normalized trace，VMP-Lift 只消费统一 schema。unidbg fork 后续不应为每个分析需求继续添加 VMP 专用逻辑；新增分析能力应放在 VMP-Lift。
