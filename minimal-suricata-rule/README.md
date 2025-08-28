# Minimal Suricata Rule Engine POC

这是一个从 Suricata 提取的最小化规则引擎概念验证（POC）。

## 功能特性

✅ **已实现的核心功能**：
- 规则解析（支持基本的 Suricata 规则语法）
- Content 关键字匹配
- 大小写忽略（nocase）
- 偏移和深度限制（offset/depth）
- 多内容匹配
- 协议、地址、端口过滤
- 规则文件加载

✅ **代码特点**：
- 极简实现：~500 行 C 代码
- 零外部依赖：只使用标准 C 库
- 易于理解：清晰的模块划分
- 易于扩展：预留扩展接口

## 目录结构

```
minimal-suricata-rule/
├── include/public/
│   └── minimal_rule.h      # 公共 API 头文件
├── src/core/
│   ├── rule_parser.c       # 规则解析器
│   ├── rule_matcher.c      # 规则匹配引擎
│   └── rule_engine.c       # 引擎管理
├── examples/
│   ├── test_minimal.c      # 简单测试
│   ├── test_with_file.c    # 文件加载测试
│   └── test.rules          # 测试规则文件
├── Makefile                # 构建脚本
└── README.md              # 本文档
```

## 快速开始

### 编译

```bash
# 编译库和示例
make all

# 或者只编译库
make libminimal_rule.a
make libminimal_rule.so
```

### 运行测试

```bash
# 运行简单测试
LD_LIBRARY_PATH=. ./examples/test_minimal

# 运行文件测试
LD_LIBRARY_PATH=. ./examples/test_with_file

# 使用自定义规则文件
LD_LIBRARY_PATH=. ./examples/test_with_file your_rules.txt
```

### 清理

```bash
make clean
```

## API 使用示例

```c
#include "minimal_rule.h"

int main() {
    // 1. 创建引擎
    MinimalRuleEngine *engine = mre_create();
    
    // 2. 加载规则
    mre_add_rule(engine, "alert tcp any any -> any 80 (msg:\"HTTP\"; content:\"GET\"; sid:1;)");
    // 或从文件加载
    mre_load_rules_file(engine, "rules.txt");
    
    // 3. 准备数据包信息
    PacketInfo packet = {
        .data = (uint8_t*)"GET /index.html HTTP/1.1",
        .data_len = 24,
        .src_ip = "192.168.1.1",
        .dst_ip = "10.0.0.1",
        .src_port = 12345,
        .dst_port = 80,
        .protocol = 6  // TCP
    };
    
    // 4. 执行匹配
    mre_match(engine, &packet, match_callback, NULL);
    
    // 5. 清理
    mre_destroy(engine);
    return 0;
}

void match_callback(const MinimalRule *rule, void *user_data) {
    printf("Matched rule %u: %s\n", rule->id, rule->msg);
}
```

## 支持的规则语法

### 基本格式
```
action protocol src_addr src_port -> dst_addr dst_port (options)
```

### 支持的动作
- `alert` - 生成告警
- `drop` - 丢弃数据包
- `pass` - 通过
- `reject` - 拒绝

### 支持的协议
- `tcp`, `udp`, `icmp`, `ip`, `any`

### 支持的关键字
- `msg:"message"` - 规则描述
- `sid:number` - 规则 ID
- `content:"pattern"` - 内容匹配
- `nocase` - 忽略大小写
- `offset:number` - 起始偏移
- `depth:number` - 搜索深度

### 规则示例
```
# Web 攻击检测
alert tcp any any -> any 80 (msg:"SQL Injection"; content:"SELECT"; nocase; sid:1001;)
alert tcp any any -> any 80 (msg:"XSS Attack"; content:"<script>"; sid:1002;)

# 恶意软件检测
alert tcp any any -> any any (msg:"Malware"; content:"malware"; content:"payload"; sid:2001;)
```

## 性能特点

- **内存占用**：极低（< 1MB for 1000 rules）
- **匹配速度**：简单的线性搜索，适合小规模规则集
- **加载速度**：快速（< 1ms for 100 rules）

## 扩展指南

### 添加新关键字

1. 在 `ContentData` 结构中添加字段
2. 在 `parse_options()` 中添加解析逻辑
3. 在 `simple_content_match()` 中实现匹配

### 优化性能

1. **添加 MPM**：集成 Aho-Corasick 算法
2. **规则分组**：按协议/端口预分组
3. **并行匹配**：多线程处理

### 集成到项目

```c
// 作为库使用
gcc -c your_app.c -I/path/to/minimal-suricata-rule/include/public
gcc your_app.o -L/path/to/minimal-suricata-rule -lminimal_rule -o your_app
```

## 与原版 Suricata 对比

| 特性 | 原版 Suricata | Minimal POC |
|-----|--------------|-------------|
| 代码量 | ~500K 行 | ~500 行 |
| 依赖 | 多个库 | 无 |
| 功能 | 完整 | 最小核心 |
| 性能 | 生产级 | 演示级 |
| 内存 | GB 级 | MB 级 |

## 限制

- 不支持复杂的应用层协议解析
- 不支持状态跟踪
- 不支持 PCRE（可扩展）
- 简单的字符串匹配算法
- 无预过滤优化

## 下一步

1. **功能扩展**：
   - 添加 PCRE 支持
   - 实现更多关键字
   - 支持规则变量

2. **性能优化**：
   - 集成 Aho-Corasick
   - 添加预过滤
   - 实现规则分组

3. **生产化**：
   - 完善错误处理
   - 添加日志系统
   - 线程安全支持

## 许可

本 POC 仅供学习研究使用。如需生产使用，请注意 Suricata 的 GPLv2 许可证要求。

## 联系

如有问题或建议，请提交 Issue 或 PR。