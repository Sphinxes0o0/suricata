# Suricata 规则系统独立库抽取方案

## 一、可行性分析

### 1.1 技术可行性评估

**可以抽取**，但需要解决以下关键问题：

| 挑战 | 难度 | 解决方案 |
|-----|------|---------|
| 依赖解耦 | ⭐⭐⭐⭐⭐ | 需要重构大量代码，移除对流管理、应用层解析的依赖 |
| 内存管理 | ⭐⭐⭐⭐ | 替换 Suricata 的内存池系统为标准内存管理 |
| 线程模型 | ⭐⭐⭐⭐ | 简化线程模型，提供单线程和多线程两种模式 |
| 配置系统 | ⭐⭐⭐ | 简化 YAML 配置，提供程序化配置接口 |
| API 设计 | ⭐⭐⭐ | 设计稳定、简洁的公共 API |

### 1.2 核心依赖分析

通过源码分析，规则系统的核心依赖包括：

```
必需依赖（必须保留）：
├── 规则解析器 (detect-parse.c)
├── 关键字注册系统 (detect-engine-register.c)
├── MPM 引擎 (util-mpm-*.c)
├── 基础数据结构 (detect.h)
└── 字符串匹配算法 (util-spm-*.c)

可选依赖（可以简化）：
├── 预过滤系统 (detect-engine-prefilter.c)
├── 规则分组 (detect-engine-siggroup.c)
└── 性能分析 (util-profiling-*.c)

需要移除的依赖：
├── 流管理 (flow-*.c)
├── 应用层解析 (app-layer-*.c)
├── 线程管理 (tm-threads.c)
├── 全局配置 (suricata.yaml)
└── 日志系统 (util-debug.c)
```

## 二、独立库架构设计

### 2.1 目标架构

```
libsuricata-rule/
├── include/                      # 公共头文件
│   ├── suricata_rule.h          # 主要 API
│   ├── suricata_rule_types.h    # 数据类型定义
│   └── suricata_rule_config.h   # 配置选项
├── src/
│   ├── core/                    # 核心功能
│   │   ├── rule_parser.c        # 规则解析器
│   │   ├── rule_compiler.c      # 规则编译器
│   │   ├── rule_matcher.c       # 规则匹配器
│   │   └── rule_engine.c        # 执行引擎
│   ├── keywords/                # 关键字实现
│   │   ├── content.c
│   │   ├── pcre.c
│   │   ├── flow.c
│   │   └── ...
│   ├── mpm/                     # 多模式匹配
│   │   ├── ac.c                # Aho-Corasick
│   │   ├── ac-ks.c
│   │   └── hyperscan.c         # 可选
│   ├── utils/                   # 工具函数
│   │   ├── memory.c
│   │   ├── string.c
│   │   └── hash.c
│   └── compat/                  # 兼容层
│       └── suricata_compat.c   # 与原版兼容
├── examples/                    # 示例代码
├── tests/                       # 单元测试
└── CMakeLists.txt              # 构建配置
```

### 2.2 公共 API 设计

```c
// suricata_rule.h - 主要 API

#ifndef SURICATA_RULE_H
#define SURICATA_RULE_H

#include <stdint.h>
#include <stdbool.h>

// 前向声明
typedef struct SuricataRuleEngine SuricataRuleEngine;
typedef struct SuricataRule SuricataRule;
typedef struct SuricataMatch SuricataMatch;

// 匹配结果
typedef struct {
    uint32_t rule_id;
    const char *msg;
    uint32_t priority;
    void *user_data;
} SuricataMatchResult;

// 回调函数
typedef void (*SuricataMatchCallback)(const SuricataMatchResult *result, void *user_data);

// 配置选项
typedef struct {
    bool enable_mpm;           // 启用多模式匹配
    bool enable_prefilter;     // 启用预过滤
    size_t max_rules;          // 最大规则数
    size_t max_pattern_len;    // 最大模式长度
    const char *mpm_algo;      // MPM 算法选择
} SuricataRuleConfig;

// ============ 引擎管理 API ============

// 创建规则引擎
SuricataRuleEngine* suricata_rule_engine_create(const SuricataRuleConfig *config);

// 销毁规则引擎
void suricata_rule_engine_destroy(SuricataRuleEngine *engine);

// ============ 规则管理 API ============

// 加载单条规则
SuricataRule* suricata_rule_load(SuricataRuleEngine *engine, const char *rule_string);

// 从文件加载规则
int suricata_rule_load_file(SuricataRuleEngine *engine, const char *filename);

// 编译规则（优化性能）
int suricata_rule_compile(SuricataRuleEngine *engine);

// 移除规则
int suricata_rule_remove(SuricataRuleEngine *engine, uint32_t rule_id);

// 清空所有规则
void suricata_rule_clear(SuricataRuleEngine *engine);

// ============ 匹配 API ============

// 匹配原始数据包
int suricata_match_packet(
    SuricataRuleEngine *engine,
    const uint8_t *packet_data,
    size_t packet_len,
    SuricataMatchCallback callback,
    void *user_data
);

// 匹配载荷数据
int suricata_match_payload(
    SuricataRuleEngine *engine,
    const uint8_t *payload_data,
    size_t payload_len,
    SuricataMatchCallback callback,
    void *user_data
);

// 匹配带上下文的数据
typedef struct {
    const char *src_ip;
    const char *dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint8_t flags;
} SuricataPacketContext;

int suricata_match_with_context(
    SuricataRuleEngine *engine,
    const uint8_t *data,
    size_t data_len,
    const SuricataPacketContext *context,
    SuricataMatchCallback callback,
    void *user_data
);

// ============ 工具 API ============

// 验证规则语法
bool suricata_rule_validate(const char *rule_string, char *error_buf, size_t error_buf_size);

// 获取规则信息
typedef struct {
    uint32_t id;
    const char *msg;
    const char *classtype;
    uint32_t priority;
} SuricataRuleInfo;

const SuricataRuleInfo* suricata_rule_get_info(const SuricataRule *rule);

// 获取引擎统计
typedef struct {
    size_t total_rules;
    size_t total_patterns;
    size_t memory_usage;
    uint64_t matches_count;
} SuricataEngineStats;

void suricata_engine_get_stats(const SuricataRuleEngine *engine, SuricataEngineStats *stats);

#endif // SURICATA_RULE_H
```

## 三、抽取实施方案

### 3.1 第一阶段：核心模块提取（2-3周）

```bash
# 1. 创建独立项目结构
mkdir libsuricata-rule
cd libsuricata-rule

# 2. 提取核心文件
cp $SURICATA_SRC/src/detect-parse.c src/core/rule_parser.c
cp $SURICATA_SRC/src/detect-engine.c src/core/rule_engine.c
cp $SURICATA_SRC/src/detect.h include/internal/
cp $SURICATA_SRC/src/util-mpm-ac.c src/mpm/

# 3. 移除外部依赖
# 修改文件，移除对 flow、app-layer、thread 的引用
```

**关键任务**：
- [ ] 提取数据结构定义
- [ ] 简化内存管理
- [ ] 移除全局变量
- [ ] 创建独立的错误处理

### 3.2 第二阶段：功能简化（2-3周）

**简化策略**：

1. **规则解析器简化**
```c
// 原版：复杂的多阶段解析
Signature *SigInit(DetectEngineCtx *de_ctx, const char *sigstr);

// 简化版：直接解析
SuricataRule *rule_parse(const char *rule_str) {
    // 1. 基础解析
    // 2. 关键字解析
    // 3. 返回规则对象
}
```

2. **关键字系统简化**
```c
// 保留核心关键字
enum CoreKeywords {
    KW_CONTENT,    // 内容匹配
    KW_PCRE,       // 正则表达式
    KW_NOCASE,     // 忽略大小写
    KW_DEPTH,      // 深度限制
    KW_OFFSET,     // 偏移
    KW_FLOW,       // 基础流属性
    // 移除复杂的应用层关键字
};
```

3. **匹配引擎简化**
```c
// 简化的匹配流程
int simple_match(rule, data, len) {
    // 1. 预过滤（可选）
    if (!prefilter_check(rule, data)) 
        return 0;
    
    // 2. MPM 匹配
    if (mpm_match(rule->mpm_ctx, data, len)) {
        // 3. 精确匹配
        return exact_match(rule, data, len);
    }
    return 0;
}
```

### 3.3 第三阶段：API 封装（1-2周）

创建用户友好的 API 层：

```c
// 实现示例
SuricataRuleEngine* suricata_rule_engine_create(const SuricataRuleConfig *config) {
    SuricataRuleEngine *engine = calloc(1, sizeof(SuricataRuleEngine));
    
    // 初始化 MPM
    if (config->enable_mpm) {
        engine->mpm_ctx = mpm_init(config->mpm_algo);
    }
    
    // 初始化规则存储
    engine->rules = hash_table_create(config->max_rules);
    
    // 注册核心关键字
    register_core_keywords(engine);
    
    return engine;
}

int suricata_rule_load(SuricataRuleEngine *engine, const char *rule_string) {
    // 解析规则
    SuricataRule *rule = parse_rule(rule_string);
    if (!rule) return -1;
    
    // 添加到引擎
    add_rule_to_engine(engine, rule);
    
    // 更新 MPM
    if (engine->mpm_ctx) {
        update_mpm_patterns(engine->mpm_ctx, rule);
    }
    
    return rule->id;
}
```

### 3.4 第四阶段：测试与优化（1-2周）

1. **单元测试**
```c
// test_rule_parser.c
void test_basic_rule_parsing() {
    const char *rule = "alert tcp any any -> any 80 (msg:\"Test\"; content:\"GET\"; sid:1;)";
    SuricataRule *r = parse_rule(rule);
    assert(r != NULL);
    assert(r->id == 1);
    assert(strcmp(r->msg, "Test") == 0);
}
```

2. **性能测试**
```c
// benchmark.c
void benchmark_mpm_performance() {
    // 加载 1000 条规则
    // 测试匹配性能
    // 对比原版 Suricata
}
```

3. **兼容性测试**
```c
// 测试与原版规则的兼容性
void test_suricata_rule_compatibility() {
    // 加载 Suricata 规则文件
    // 验证解析结果
}
```

## 四、使用示例

### 4.1 基础使用

```c
#include <suricata_rule.h>

int main() {
    // 1. 创建引擎
    SuricataRuleConfig config = {
        .enable_mpm = true,
        .enable_prefilter = true,
        .max_rules = 10000,
        .mpm_algo = "ac"
    };
    SuricataRuleEngine *engine = suricata_rule_engine_create(&config);
    
    // 2. 加载规则
    suricata_rule_load_file(engine, "rules.txt");
    
    // 3. 编译优化
    suricata_rule_compile(engine);
    
    // 4. 匹配数据
    uint8_t packet[] = "GET /index.html HTTP/1.1\r\n...";
    suricata_match_packet(engine, packet, sizeof(packet), 
                          match_callback, NULL);
    
    // 5. 清理
    suricata_rule_engine_destroy(engine);
    return 0;
}

void match_callback(const SuricataMatchResult *result, void *user_data) {
    printf("Rule matched: %u - %s\n", result->rule_id, result->msg);
}
```

### 4.2 高级使用

```c
// 带上下文的匹配
SuricataPacketContext ctx = {
    .src_ip = "192.168.1.100",
    .dst_ip = "10.0.0.1",
    .src_port = 54321,
    .dst_port = 80,
    .protocol = IPPROTO_TCP
};

suricata_match_with_context(engine, payload, len, &ctx, 
                            match_callback, NULL);
```

## 五、预期成果

### 5.1 功能对比

| 功能 | 原版 Suricata | 独立库 |
|-----|--------------|--------|
| 规则解析 | ✅ 完整 | ✅ 核心功能 |
| 内容匹配 | ✅ 完整 | ✅ 支持 |
| PCRE | ✅ 完整 | ✅ 支持 |
| 流匹配 | ✅ 完整 | ⚠️ 简化版 |
| 应用层检测 | ✅ 完整 | ❌ 不支持 |
| 文件提取 | ✅ 支持 | ❌ 不支持 |
| 性能 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| 内存占用 | 高 | 低 |
| 易用性 | ⭐⭐ | ⭐⭐⭐⭐⭐ |

### 5.2 性能指标

预期性能（基于 1000 条规则）：
- 规则加载：< 100ms
- 规则编译：< 500ms  
- 匹配延迟：< 1μs/packet (无匹配)
- 内存占用：< 50MB
- 吞吐量：> 1Gbps

### 5.3 适用场景

**适合**：
- 嵌入式 IDS/IPS
- 应用层防火墙
- 内容过滤系统
- 安全网关
- DPI 应用

**不适合**：
- 需要完整应用层解析
- 需要状态跟踪
- 需要文件还原
- 需要加密流量检测

## 六、开发计划

### 时间线（总计 6-10 周）

```
第 1-3 周：核心模块提取
├── Week 1: 项目搭建，提取核心文件
├── Week 2: 移除外部依赖
└── Week 3: 基础功能验证

第 4-6 周：功能简化与重构
├── Week 4: 简化规则解析器
├── Week 5: 实现核心关键字
└── Week 6: 优化匹配引擎

第 7-8 周：API 设计与实现
├── Week 7: 公共 API 实现
└── Week 8: 文档编写

第 9-10 周：测试与发布
├── Week 9: 单元测试与性能测试
└── Week 10: 示例编写与发布准备
```

### 人力需求

- 核心开发：2-3 人
- 测试：1 人
- 文档：1 人

## 七、风险与挑战

### 主要风险

1. **许可证问题**
   - Suricata 使用 GPLv2 许可证
   - 独立库需要遵守相同许可证
   - 商业使用需要注意合规

2. **维护成本**
   - 需要跟踪 Suricata 上游更新
   - 规则语法变化需要同步
   - 安全漏洞需要及时修复

3. **社区接受度**
   - 需要获得社区认可
   - 可能需要贡献回上游

### 应对策略

1. 与 Suricata 社区合作
2. 建立自动化测试体系
3. 定期同步上游更新
4. 建立用户反馈机制

## 八、结论

将 Suricata 规则系统抽取为独立库是**可行的**，但需要：

✅ **技术投入**：6-10周的开发时间，2-3名核心开发人员

✅ **功能取舍**：保留核心规则匹配，舍弃复杂的应用层功能

✅ **API 设计**：提供简洁易用的接口，降低使用门槛

✅ **持续维护**：跟踪上游更新，保持兼容性

**建议**：如果项目需要完整的 Suricata 功能，建议使用原版；如果只需要规则匹配核心功能，且对性能和资源占用有要求，抽取独立库是一个好选择。

## 附录：参考资源

- [Suricata 源码](https://github.com/OISF/suricata)
- [Hyperscan](https://github.com/intel/hyperscan) - 可作为 MPM 引擎替代
- [PCRE2](https://github.com/PCRE2Project/pcre2) - 正则表达式库
- [libnids](https://github.com/MITRECND/libnids) - 类似的网络检测库