## Suricata 规则解析与匹配实现逻辑（架构到细节）

### 总览

- **规则加载与解析**: 从配置读取规则文件，解析规则字符串为内部结构（`Signature`、`SigMatch` 等），并做语义校验与初始化。
- **签名编译与分组**: 将签名按方向、协议、端口与特征进行分组，构建 `SigGroupHead`，并为预过滤/MPM 构建索引与上下文。
- **预过滤与候选集生成**: 利用多模式匹配（MPM）与其它预过滤引擎快速筛选候选规则集合，降低逐条规则检查的成本。
- **检测主循环**: 针对数据包/事务选择合适的规则组，按顺序执行匹配关键字列表，触发告警、阈值、flowbits 等后处理。

---

## 架构模块

### 1) 数据模型与上下文

- **Signature / SigMatch / SigMatchData**: 规则与关键字条件的内部表达。
- **SignatureInitData / Buffer**: 解析期粘性缓冲区（sticky buffer）与关键字列表组织。
- **DetectEngineCtx**: 引擎全局上下文，持有规则、规则组、预过滤配置、MPM 注册信息等。
- **SigGroupHead / SigGroupHeadInitData**: 规则组容器，绑定预过滤引擎与 MPM 上下文，用于高效选择/过滤。

关键结构（节选）：

```300:750:src/detect.h
typedef struct SigMatch_ {
    uint16_t type; /**< match type */
    uint16_t idx; /**< position in the signature */
    SigMatchCtx *ctx; /**< plugin specific data */
    struct SigMatch_ *next;
    struct SigMatch_ *prev;
} SigMatch;

typedef struct SigMatchData_ {
    uint16_t type;   /**< match type */
    bool is_last;    /**< Last element of the list */
    SigMatchCtx *ctx; /**< plugin specific data */
} SigMatchData;

typedef struct SignatureInitDataBuffer_ {
    uint32_t id;  /**< buffer id */
    bool sm_init; /**< initialized by sigmatch ... */
    bool multi_capable;
    bool only_tc;
    bool only_ts;
    SigMatch *head;
    SigMatch *tail;
} SignatureInitDataBuffer;

typedef struct SignatureInitData_ {
    SignatureHook hook;
    uint16_t sm_cnt;
    bool negated;
    bool src_contains_negation;
    bool dst_contains_negation;
    bool has_possible_prefilter;
    uint32_t init_flags;
    AppProto alprotos[SIG_ALPROTO_MAX];
    SigMatch *dsize_sm;
    IPOnlyCIDRItem *cidr_src, *cidr_dst;
    int mpm_sm_list;
    SigMatch *mpm_sm;
    SigMatch *prefilter_sm;
    int list;
    bool list_set;
    DetectEngineTransforms transforms;
    int score;
    const DetectAddressHead *src, *dst;
    struct SigMatch_ *smlists[DETECT_SM_LIST_MAX];
    struct SigMatch_ *smlists_tail[DETECT_SM_LIST_MAX];
    SignatureInitDataBuffer *buffers;
    uint32_t buffer_index;
    uint32_t buffers_size;
    SignatureInitDataBuffer *curbuf;
    uint32_t max_content_list_id;
    bool is_rule_state_dependant;
    /* ... */
} SignatureInitData;

typedef struct Signature_ {
    uint32_t flags;
    enum SignatureType type;
    AppProto alproto;
    /* ... 地址/端口/分类/动作/匹配数组等 ... */
    DetectEngineAppInspectionEngine *app_inspect;
    DetectEnginePktInspectionEngine *pkt_inspect;
    DetectEngineFrameInspectionEngine *frame_inspect;
    SigMatchData *sm_arrays[DETECT_SM_LIST_MAX];
    char *msg;
    char *class_msg;
    DetectReference *references;
    DetectMetadataHead *metadata;
    char *sig_str;
    SignatureInitData *init_data;
    struct Signature_ *next;
} Signature;
```

```950:1161:src/detect.h
typedef struct DetectEngineCtx_ {
    /* ... */
    DetectEngineLookupFlow flow_gh[FLOW_STATES];
    /* sig group array for stats/iteration */
    struct SigGroupHead_ **sgh_array;
    uint32_t sgh_array_cnt;
    uint32_t sgh_array_size;
    /* decoder event sgh when packet proto not set */
    struct SigGroupHead_ *decoder_event_sgh;
    /* app/pkt/frame inspect engine registries */
    DetectEngineAppInspectionEngine *app_inspect_engines;
    DetectEnginePktInspectionEngine *pkt_inspect_engines;
    DetectBufferMpmRegistry *pkt_mpms_list;
    uint32_t pkt_mpms_list_cnt;
    DetectEngineFrameInspectionEngine *frame_inspect_engines;
    DetectBufferMpmRegistry *frame_mpms_list;
    uint32_t frame_mpms_list_cnt;
    /* pre_stream / pre_flow hooks */
    DetectPacketHookFunc PreStreamHook;
    struct SigGroupHead_ *pre_stream_sgh[2];
    DetectPacketHookFunc PreFlowHook;
    struct SigGroupHead_ *pre_flow_sgh;
} DetectEngineCtx;
```

```1588:1666:src/detect.h
typedef struct SigGroupHeadInitData_ {
    MpmStore mpm_store[MPMB_MAX];
    uint8_t *sig_array; /* bit array of sig ids */
    uint32_t sig_size;
    uint8_t protos[256];
    uint32_t direction;
    int score;
    uint32_t max_sig_id;
    MpmCtx **app_mpms; MpmCtx **pkt_mpms; MpmCtx **frame_mpms;
    PrefilterEngineList *pkt_engines; /* ... payload/tx/frame/post_rule */
    SigIntId sig_cnt;
    Signature **match_array;
} SigGroupHeadInitData;

typedef struct SigGroupHead_ {
    uint16_t flags;
    uint16_t filestore_cnt;
    uint32_t id;
    PrefilterEngine *pkt_engines;
    PrefilterEngine *payload_engines;
    PrefilterEngine *tx_engines;
    PrefilterEngine *frame_engines;
    PrefilterEngine *post_rule_match_engines;
    SigGroupHeadInitData *init;
} SigGroupHead;
```

流上绑定的方向性规则组指针：

```468:478:src/flow.h
const struct SigGroupHead_ *sgh_toclient;
const struct SigGroupHead_ *sgh_toserver;
```

### 2) 规则加载与解析

- 从 `suricata.yaml` 读取 `rule-files`，或从命令行指定规则文件。
- 通过解析器将规则字符串拆解为动作、协议、方向、地址端口与选项，逐个关键字构建 `SigMatch` 链，粘性缓冲区粘接 `content/pcre` 等。
- 完成后将 `SigMatch` 列表转为运行期的 `SigMatchData` 数组，填入 `Signature`。

加载入口：

```372:452:src/detect-engine-loader.c
int SigLoadSignatures(DetectEngineCtx *de_ctx, char *sig_file, bool sig_file_exclusive)
{
    /* 读取 rule-files / 命令行文件，逐个调用 ProcessSigFiles 解析与装载 */
}
```

解析阶段关键点：

```100:111:src/detect-parse.c
typedef struct SignatureParser_ {
    char action[DETECT_MAX_RULE_SIZE];
    char protocol[DETECT_MAX_RULE_SIZE];
    char direction[DETECT_MAX_RULE_SIZE];
    char src[DETECT_MAX_RULE_SIZE];
    char dst[DETECT_MAX_RULE_SIZE];
    char sp[DETECT_MAX_RULE_SIZE];
    char dp[DETECT_MAX_RULE_SIZE];
    char opts[DETECT_MAX_RULE_SIZE];
} SignatureParser;
```

```274:283:src/detect-parse.c
SigMatch *SigMatchAlloc(void)
{
    SigMatch *sm = SCCalloc(1, sizeof(SigMatch));
    sm->prev = NULL; sm->next = NULL; return sm;
}
```

```145:172:src/detect-parse.c
int DetectEngineContentModifierBufferSetup(DetectEngineCtx *de_ctx,
        Signature *s, const char *arg, int sm_type, int sm_list,
        AppProto alproto)
{ /* 处理如 http.uri 等粘性缓冲区，将 pmatch 列表中的 content/pcre 迁移到指定 list */ }
```

### 3) 签名编译与分组（SigGroupBuild）

- 规则解析完成后，进入规则分组：按照方向、协议、端口与“分数”将规则划入 `SigGroupHead`，并初始化 MPM/预过滤引擎。
- 分组数据通过 `SigGroupHeadInitData` 维护位图、匹配数组、MPM 容器与预过滤引擎列表。

分组模块（节选）：

```141:156:src/detect-engine-siggroup.c
static SigGroupHead *SigGroupHeadAlloc(const DetectEngineCtx *de_ctx, uint32_t size)
{
    SigGroupHead *sgh = SCCalloc(1, sizeof(SigGroupHead));
    sgh->init = SigGroupHeadInitDataAlloc(size);
    return sgh;
}
```

```109:130:src/detect-engine-siggroup.c
void SigGroupHeadStore(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    if (de_ctx->sgh_array_cnt < de_ctx->sgh_array_size)
        de_ctx->sgh_array[de_ctx->sgh_array_cnt] = sgh;
    else { /* 扩容并存储 */ }
    de_ctx->sgh_array_cnt++;
}
```

### 4) 预过滤与 MPM 集成

- 预过滤框架统一抽象：每个引擎在规则组中注册，运行时接收数据/上下文，向候选集 `pmq.rule_id_array` 填充可能匹配的规则 ID。
- MPM 将各规则的“快速模式（fast pattern）”集中到共享/独立的自动机结构中进行一次性匹配，极大缩小逐条检查的数量。

预过滤核心：

```216:218:src/detect-engine-prefilter.c
void Prefilter(DetectEngineThreadCtx *det_ctx, const SigGroupHead *sgh, Packet *p,
        const uint8_t flags, const SignatureMask mask)
```

事务级预过滤：

```95:106:src/detect-engine-prefilter.c
void DetectRunPrefilterTx(DetectEngineThreadCtx *det_ctx,
        const SigGroupHead *sgh, Packet *p, const uint8_t ipproto,
        const uint8_t flow_flags, const AppProto alproto,
        void *alstate, DetectTransaction *tx)
{
    det_ctx->pmq.rule_id_array_cnt = 0;
    PrefilterEngine *engine = sgh->tx_engines;
    /* 遍历引擎，运行并填充候选 */
}
```

MPM 注册与上下文（节选）：

```246:289:src/detect-engine-mpm.c
void DetectMpmInitializeAppMpms(DetectEngineCtx *de_ctx)
{
    /* 将全局注册的 MPM 列表复制到 de_ctx，并依据共享/独立策略构建 sgh_mpm_context */
}
```

### 5) 检测主循环与匹配流程

步骤概览：

1. 根据包/流状态确定方向、应用协议、解析进度等，初始化 `DetectRunScratchpad`。
2. 为包生成掩码（payload/flow/tcpflags/events 等需求位），执行规则组的预过滤，得到候选规则集合。
3. 遍历候选集合中的 `Signature`，依序执行其 `sm_arrays` 中的关键字 `Match` 函数。
4. 触发告警、阈值与后置 prefilter（flowbits 依赖）等逻辑，处理文件提取等副作用。

选择规则组：

```282:326:src/detect.c
const SigGroupHead *SigMatchSignaturesGetSgh(const DetectEngineCtx *de_ctx,
        const Packet *p)
{
    /* proto==0 且有事件 => decoder_event_sgh
       否则按方向与 L4 协议在 flow_gh 查找端口组对应的 sgh */
}
```

预过滤执行与候选集去重：

```592:610:src/detect.c
static inline void DetectRunPrefilterPkt(...)
{
    PacketCreateMask(p, &p->sig_mask, scratch->alproto, scratch->app_decoder_events);
    Prefilter(det_ctx, scratch->sgh, p, scratch->flow_flags, p->sig_mask);
    if (det_ctx->pmq.rule_id_array_cnt) {
        DetectPrefilterCopyDeDup(de_ctx, det_ctx);
    }
}
```

匹配主循环（逐签名关键字执行）：

```653:700:src/detect.c
static inline uint8_t DetectRulePacketRules(...)
{
    Signature **match_array = det_ctx->match_array;
    while (match_cnt--) {
        const Signature *s = next_s; /* 预取优化 */
        /* 遍历 s->sm_arrays 各列表，调用 sigmatch_table[...].Match */
    }
}
```

运行期初始化（抓取状态、设置方向、解析进度等）：

```919:1016:src/detect.c
static DetectRunScratchpad DetectRunSetup(...)
{
    /* 计算 flow_flags、alproto、是否有 decoder 事件、重置线程上下文计数器等 */
    return pad;
}
```

---

## 关键实现细节

### 粘性缓冲区与关键字链

- `DetectEngineContentModifierBufferSetup` 会在解析期将 `pmatch` 列表中的 `content/pcre` 迁移到指定 `sm_list`，并跟踪 `max_content_list_id` 用于后续优化。
- `SignatureInitData::smlists[DETECT_SM_LIST_*]` 暂存原始 `SigMatch` 链；编译期转化为 `Signature::sm_arrays` 的紧凑数组，便于高速顺序执行。

### IP-only / PD-only / DE-only 判定

- 在编译阶段根据是否存在 payload 关键字、是否仅解码事件关键字、是否仅应用层协议判定，将规则类型优化为 IP-only/PD-only/DE-only，以便走更快路径（如跳过 payload 检查）。

### 预过滤掩码与去重

- `PacketCreateMask` 根据包特性设置 `SIG_MASK_REQUIRE_*` 位，预过滤引擎据此快速排除不满足前置条件的规则。
- 预过滤填充的候选规则 ID 会排序并去重，随后映射到 `Signature** match_array`，严格按内部 ID 顺序匹配，保持确定性与缓存友好性。

### MPM 快速模式

- 全局注册 `DetectBufferMpmRegistry` 描述每个缓冲区/方向的 MPM 配置；引擎实例化时决定共享或独占上下文，降低内存与准备成本。
- 规则的 `content` 中被选为 fast pattern 的子串进入 MPM 自动机；未命中则整批规则被跳过，极大缩小逐条匹配的集合规模。

### 事务/帧级检测

- 除包级 `pkt_engines` 外，还存在 `tx_engines` 与 `frame_engines` 支持应用事务或帧级别的预过滤与匹配，配合 `DetectEngineAppInspectionEngine`/`DetectEngineFrameInspectionEngine` 的缓冲区获取与回调，实现跨层次的检测模型。

---

## 模块交互与调用关系（简要）

- 规则加载: `SigLoadSignatures` → 解析（`detect-parse.c`）→ `Signature`/`SigMatch` 构建。
- 编译构建: `SigGroupBuild` → 规则分组、预过滤引擎与 MPM 初始化、注册。
- 运行检测:
  - 获取规则组: `SigMatchSignaturesGetSgh`
  - 预过滤: `PacketCreateMask` → `Prefilter` → 候选集排序/去重
  - 匹配执行: `DetectRulePacketRules` → 关键字 `Match`
  - 后处理: `PrefilterPostRuleMatch`、阈值/抑制、flowbits 依赖等

---

## 参考代码片段（便于进一步检索）

```260:336:src/detect.c
/* 关键字 Match 执行循环（节选）：*/
while (1) {
    (void)sigmatch_table[smd->type].Match(det_ctx, p, s, smd->ctx);
    if (smd->is_last)
        break;
    smd++;
}
```

```329:336:src/detect.c
static inline void DetectPrefilterCopyDeDup(
        const DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx)
{
    Signature **sig_array = de_ctx->sig_array;
    Signature **match_array = det_ctx->match_array;
    /* 将排序后的 rule_id 映射为 Signature*，并去重 */
}
```

```1:25:src/detect-engine-build.c
/* detect-engine-build.c: 规则属性分析（IP-only/PD-only/DE-only），
 * 需求掩码生成，文件匹配需求聚合等，驱动后续分组与优化。*/
```

---

## 小结

- Suricata 将“规则解析/编译/分组/预过滤/匹配执行”分层解耦，配合强大的 MPM 与事务/帧级缓冲模型，在高吞吐场景下实现精细而高效的检测。
- 数据结构上通过 `SignatureInitData` 过渡期组织，再转化为运行期 `SigMatchData` 紧凑数组，避免解析期开销进入热路径。
- 预过滤引擎以统一接口承载 MPM 与其它条件快速裁剪，`SigGroupHead` 作为规则组调度的核心纽带，将多维条件与上下文统一到一起。

