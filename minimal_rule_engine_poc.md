# Suricata 最小核心功能提取指南

## 一、最小核心功能定义

### 1.1 最小功能集

最小核心功能应该能够：
1. **解析简单规则**：支持基本的规则语法
2. **内容匹配**：支持 content 关键字
3. **模式匹配**：使用简单的字符串匹配算法
4. **返回结果**：匹配成功时返回规则信息

### 1.2 最小依赖文件

从 Suricata 源码中，我们只需要提取：

```
必需文件（约 10-15 个）：
├── detect-parse.c (简化版)     # 规则解析
├── detect-content.c (简化版)   # content 关键字
├── util-spm-bm.c               # Boyer-Moore 字符串匹配
├── util-hash.c                 # 哈希表
├── util-mem.c                  # 内存管理
└── 基础头文件                   # 数据结构定义
```

## 二、最小化提取实施步骤

### Step 1: 创建项目结构

```bash
#!/bin/bash
# create_minimal_project.sh

mkdir -p minimal-suricata-rule/{src,include,examples,build}
cd minimal-suricata-rule

# 创建目录结构
mkdir -p src/{core,keywords,utils}
mkdir -p include/{internal,public}
```

### Step 2: 提取并简化核心数据结构

创建 `include/public/minimal_rule.h`：

```c
#ifndef MINIMAL_RULE_H
#define MINIMAL_RULE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* ========== 基础数据类型 ========== */

// 规则动作
typedef enum {
    RULE_ACTION_ALERT,
    RULE_ACTION_DROP,
    RULE_ACTION_PASS,
    RULE_ACTION_REJECT
} RuleAction;

// 协议类型
typedef enum {
    RULE_PROTO_TCP = 1,
    RULE_PROTO_UDP = 2,
    RULE_PROTO_ICMP = 4,
    RULE_PROTO_IP = 8,
    RULE_PROTO_ANY = 0xFF
} RuleProtocol;

// 内容匹配选项
typedef struct ContentData_ {
    uint8_t *content;           // 匹配内容
    uint16_t content_len;       // 内容长度
    bool nocase;               // 忽略大小写
    int32_t offset;            // 偏移量
    int32_t depth;             // 深度限制
    struct ContentData_ *next;  // 下一个内容
} ContentData;

// 简化的规则结构
typedef struct MinimalRule_ {
    uint32_t id;                // 规则 ID (sid)
    char *msg;                  // 消息
    RuleAction action;          // 动作
    RuleProtocol protocol;      // 协议
    
    // 简化的地址和端口（字符串形式）
    char *src_addr;
    char *dst_addr;
    char *src_port;
    char *dst_port;
    
    // 内容匹配链表
    ContentData *content_list;
    
    struct MinimalRule_ *next;  // 下一条规则
} MinimalRule;

// 规则引擎
typedef struct MinimalRuleEngine_ {
    MinimalRule *rules;         // 规则链表
    uint32_t rule_count;        // 规则数量
    
    // 简单的统计
    uint64_t packets_checked;
    uint64_t rules_matched;
} MinimalRuleEngine;

/* ========== API 函数 ========== */

// 引擎管理
MinimalRuleEngine* mre_create(void);
void mre_destroy(MinimalRuleEngine *engine);

// 规则加载
MinimalRule* mre_parse_rule(const char *rule_string);
int mre_add_rule(MinimalRuleEngine *engine, const char *rule_string);
int mre_load_rules_file(MinimalRuleEngine *engine, const char *filename);

// 匹配函数
typedef struct {
    const uint8_t *data;
    size_t data_len;
    const char *src_ip;
    const char *dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
} PacketInfo;

typedef void (*MatchCallback)(const MinimalRule *rule, void *user_data);

int mre_match(MinimalRuleEngine *engine, 
              const PacketInfo *packet,
              MatchCallback callback,
              void *user_data);

// 工具函数
void mre_print_rule(const MinimalRule *rule);
void mre_print_stats(const MinimalRuleEngine *engine);

#endif // MINIMAL_RULE_H
```

### Step 3: 实现最小规则解析器

创建 `src/core/rule_parser.c`：

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "minimal_rule.h"

// 简化的规则解析器
// 格式: action proto src_addr src_port -> dst_addr dst_port (options)

static char* trim(char *str) {
    char *start = str;
    char *end;
    
    // 去除开头空白
    while (isspace(*start)) start++;
    
    // 去除结尾空白
    end = start + strlen(start) - 1;
    while (end > start && isspace(*end)) end--;
    *(end + 1) = '\0';
    
    return start;
}

static RuleAction parse_action(const char *action) {
    if (strcmp(action, "alert") == 0) return RULE_ACTION_ALERT;
    if (strcmp(action, "drop") == 0) return RULE_ACTION_DROP;
    if (strcmp(action, "pass") == 0) return RULE_ACTION_PASS;
    if (strcmp(action, "reject") == 0) return RULE_ACTION_REJECT;
    return RULE_ACTION_ALERT; // 默认
}

static RuleProtocol parse_protocol(const char *proto) {
    if (strcmp(proto, "tcp") == 0) return RULE_PROTO_TCP;
    if (strcmp(proto, "udp") == 0) return RULE_PROTO_UDP;
    if (strcmp(proto, "icmp") == 0) return RULE_PROTO_ICMP;
    if (strcmp(proto, "ip") == 0) return RULE_PROTO_IP;
    if (strcmp(proto, "any") == 0) return RULE_PROTO_ANY;
    return RULE_PROTO_ANY; // 默认
}

static int parse_options(MinimalRule *rule, const char *options) {
    char *opts = strdup(options);
    char *token;
    char *saveptr;
    
    token = strtok_r(opts, ";", &saveptr);
    while (token != NULL) {
        char *key, *value;
        char *colon = strchr(token, ':');
        
        if (colon) {
            *colon = '\0';
            key = trim(token);
            value = trim(colon + 1);
            
            // 解析 msg
            if (strcmp(key, "msg") == 0) {
                // 去除引号
                if (value[0] == '"') value++;
                int len = strlen(value);
                if (len > 0 && value[len-1] == '"') value[len-1] = '\0';
                rule->msg = strdup(value);
            }
            // 解析 sid
            else if (strcmp(key, "sid") == 0) {
                rule->id = atoi(value);
            }
            // 解析 content
            else if (strcmp(key, "content") == 0) {
                ContentData *content = calloc(1, sizeof(ContentData));
                
                // 去除引号
                if (value[0] == '"') value++;
                int len = strlen(value);
                if (len > 0 && value[len-1] == '"') value[len-1] = '\0';
                
                content->content_len = strlen(value);
                content->content = malloc(content->content_len);
                memcpy(content->content, value, content->content_len);
                
                // 添加到链表
                content->next = rule->content_list;
                rule->content_list = content;
            }
            // 解析 nocase
            else if (strcmp(key, "nocase") == 0) {
                if (rule->content_list) {
                    rule->content_list->nocase = true;
                }
            }
            // 解析 offset
            else if (strcmp(key, "offset") == 0) {
                if (rule->content_list) {
                    rule->content_list->offset = atoi(value);
                }
            }
            // 解析 depth
            else if (strcmp(key, "depth") == 0) {
                if (rule->content_list) {
                    rule->content_list->depth = atoi(value);
                }
            }
        }
        
        token = strtok_r(NULL, ";", &saveptr);
    }
    
    free(opts);
    return 0;
}

MinimalRule* mre_parse_rule(const char *rule_string) {
    MinimalRule *rule;
    char *str = strdup(rule_string);
    char *p = str;
    char action[32], proto[32], src_addr[64], src_port[32];
    char dst_addr[64], dst_port[32];
    char *options;
    
    // 跳过注释和空行
    p = trim(p);
    if (p[0] == '#' || p[0] == '\0') {
        free(str);
        return NULL;
    }
    
    rule = calloc(1, sizeof(MinimalRule));
    
    // 简单解析：action proto src_addr src_port -> dst_addr dst_port (options)
    // 查找括号中的选项
    options = strchr(p, '(');
    if (options) {
        *options = '\0';
        options++;
        char *end = strrchr(options, ')');
        if (end) *end = '\0';
    }
    
    // 解析规则头部
    if (sscanf(p, "%31s %31s %63s %31s -> %63s %31s", 
               action, proto, src_addr, src_port, dst_addr, dst_port) == 6) {
        rule->action = parse_action(action);
        rule->protocol = parse_protocol(proto);
        rule->src_addr = strdup(src_addr);
        rule->src_port = strdup(src_port);
        rule->dst_addr = strdup(dst_addr);
        rule->dst_port = strdup(dst_port);
        
        // 解析选项
        if (options) {
            parse_options(rule, options);
        }
    } else {
        free(rule);
        rule = NULL;
    }
    
    free(str);
    return rule;
}
```

### Step 4: 实现最小匹配引擎

创建 `src/core/rule_matcher.c`：

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "minimal_rule.h"

// 简单的 Boyer-Moore 字符串搜索
static bool simple_content_match(const uint8_t *data, size_t data_len,
                                 const ContentData *content) {
    if (content->content_len > data_len) {
        return false;
    }
    
    size_t start = content->offset >= 0 ? content->offset : 0;
    size_t end = data_len - content->content_len + 1;
    
    if (content->depth > 0 && start + content->depth < end) {
        end = start + content->depth;
    }
    
    for (size_t i = start; i < end; i++) {
        bool match = true;
        for (size_t j = 0; j < content->content_len; j++) {
            uint8_t d = data[i + j];
            uint8_t c = content->content[j];
            
            if (content->nocase) {
                // 简单的大小写忽略
                if (d >= 'A' && d <= 'Z') d += 32;
                if (c >= 'A' && c <= 'Z') c += 32;
            }
            
            if (d != c) {
                match = false;
                break;
            }
        }
        
        if (match) {
            return true;
        }
    }
    
    return false;
}

// 检查地址匹配（简化版，只支持 "any" 或精确匹配）
static bool check_addr(const char *rule_addr, const char *packet_addr) {
    if (!rule_addr || !packet_addr) return true;
    if (strcmp(rule_addr, "any") == 0) return true;
    if (strcmp(rule_addr, packet_addr) == 0) return true;
    return false;
}

// 检查端口匹配（简化版，只支持 "any" 或精确匹配）
static bool check_port(const char *rule_port, uint16_t packet_port) {
    if (!rule_port) return true;
    if (strcmp(rule_port, "any") == 0) return true;
    
    int port = atoi(rule_port);
    if (port == packet_port) return true;
    
    return false;
}

// 检查协议匹配
static bool check_protocol(RuleProtocol rule_proto, uint8_t packet_proto) {
    if (rule_proto == RULE_PROTO_ANY) return true;
    
    switch (packet_proto) {
        case 6:  // TCP
            return (rule_proto == RULE_PROTO_TCP);
        case 17: // UDP
            return (rule_proto == RULE_PROTO_UDP);
        case 1:  // ICMP
            return (rule_proto == RULE_PROTO_ICMP);
        default:
            return (rule_proto == RULE_PROTO_IP);
    }
}

// 匹配单条规则
static bool match_rule(const MinimalRule *rule, const PacketInfo *packet) {
    // 检查协议
    if (!check_protocol(rule->protocol, packet->protocol)) {
        return false;
    }
    
    // 检查地址和端口
    if (!check_addr(rule->src_addr, packet->src_ip)) return false;
    if (!check_addr(rule->dst_addr, packet->dst_ip)) return false;
    if (!check_port(rule->src_port, packet->src_port)) return false;
    if (!check_port(rule->dst_port, packet->dst_port)) return false;
    
    // 检查所有 content
    ContentData *content = rule->content_list;
    while (content) {
        if (!simple_content_match(packet->data, packet->data_len, content)) {
            return false;
        }
        content = content->next;
    }
    
    return true;
}

// 主匹配函数
int mre_match(MinimalRuleEngine *engine, 
              const PacketInfo *packet,
              MatchCallback callback,
              void *user_data) {
    int matches = 0;
    MinimalRule *rule = engine->rules;
    
    engine->packets_checked++;
    
    while (rule) {
        if (match_rule(rule, packet)) {
            matches++;
            engine->rules_matched++;
            
            if (callback) {
                callback(rule, user_data);
            }
        }
        rule = rule->next;
    }
    
    return matches;
}
```

### Step 5: 实现引擎管理

创建 `src/core/rule_engine.c`：

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "minimal_rule.h"

MinimalRuleEngine* mre_create(void) {
    MinimalRuleEngine *engine = calloc(1, sizeof(MinimalRuleEngine));
    return engine;
}

void mre_destroy(MinimalRuleEngine *engine) {
    if (!engine) return;
    
    MinimalRule *rule = engine->rules;
    while (rule) {
        MinimalRule *next = rule->next;
        
        // 释放规则内容
        free(rule->msg);
        free(rule->src_addr);
        free(rule->dst_addr);
        free(rule->src_port);
        free(rule->dst_port);
        
        // 释放 content 链表
        ContentData *content = rule->content_list;
        while (content) {
            ContentData *next_content = content->next;
            free(content->content);
            free(content);
            content = next_content;
        }
        
        free(rule);
        rule = next;
    }
    
    free(engine);
}

int mre_add_rule(MinimalRuleEngine *engine, const char *rule_string) {
    MinimalRule *rule = mre_parse_rule(rule_string);
    if (!rule) {
        return -1;
    }
    
    // 添加到链表头部
    rule->next = engine->rules;
    engine->rules = rule;
    engine->rule_count++;
    
    return 0;
}

int mre_load_rules_file(MinimalRuleEngine *engine, const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        return -1;
    }
    
    char line[4096];
    int loaded = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        if (mre_add_rule(engine, line) == 0) {
            loaded++;
        }
    }
    
    fclose(fp);
    return loaded;
}

void mre_print_rule(const MinimalRule *rule) {
    printf("Rule ID: %u\n", rule->id);
    printf("  Message: %s\n", rule->msg ? rule->msg : "(none)");
    printf("  Action: %d\n", rule->action);
    printf("  Protocol: %d\n", rule->protocol);
    printf("  Source: %s:%s\n", rule->src_addr, rule->src_port);
    printf("  Destination: %s:%s\n", rule->dst_addr, rule->dst_port);
    
    ContentData *content = rule->content_list;
    while (content) {
        printf("  Content: \"");
        for (int i = 0; i < content->content_len; i++) {
            if (content->content[i] >= 32 && content->content[i] <= 126) {
                printf("%c", content->content[i]);
            } else {
                printf("\\x%02x", content->content[i]);
            }
        }
        printf("\" (nocase:%d, offset:%d, depth:%d)\n", 
               content->nocase, content->offset, content->depth);
        content = content->next;
    }
}

void mre_print_stats(const MinimalRuleEngine *engine) {
    printf("Engine Statistics:\n");
    printf("  Rules loaded: %u\n", engine->rule_count);
    printf("  Packets checked: %lu\n", engine->packets_checked);
    printf("  Rules matched: %lu\n", engine->rules_matched);
}
```

### Step 6: 创建测试示例

创建 `examples/test_minimal.c`：

```c
#include <stdio.h>
#include <string.h>
#include "minimal_rule.h"

// 匹配回调函数
void match_callback(const MinimalRule *rule, void *user_data) {
    printf("[MATCH] Rule %u: %s\n", rule->id, rule->msg);
}

int main() {
    // 创建引擎
    MinimalRuleEngine *engine = mre_create();
    
    // 添加测试规则
    printf("Loading rules...\n");
    mre_add_rule(engine, "alert tcp any any -> any 80 (msg:\"HTTP GET Request\"; content:\"GET\"; sid:1;)");
    mre_add_rule(engine, "alert tcp any any -> any 80 (msg:\"SQL Injection\"; content:\"SELECT\"; nocase; sid:2;)");
    mre_add_rule(engine, "alert tcp any any -> any any (msg:\"Malware Signature\"; content:\"malware\"; content:\"payload\"; sid:3;)");
    
    // 测试数据包 1: HTTP GET
    printf("\n--- Test 1: HTTP GET Request ---\n");
    const char *http_data = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    PacketInfo packet1 = {
        .data = (uint8_t*)http_data,
        .data_len = strlen(http_data),
        .src_ip = "192.168.1.100",
        .dst_ip = "10.0.0.1",
        .src_port = 54321,
        .dst_port = 80,
        .protocol = 6  // TCP
    };
    mre_match(engine, &packet1, match_callback, NULL);
    
    // 测试数据包 2: SQL Injection
    printf("\n--- Test 2: SQL Injection ---\n");
    const char *sql_data = "id=1; select * from users";
    PacketInfo packet2 = {
        .data = (uint8_t*)sql_data,
        .data_len = strlen(sql_data),
        .src_ip = "192.168.1.100",
        .dst_ip = "10.0.0.1",
        .src_port = 54322,
        .dst_port = 80,
        .protocol = 6  // TCP
    };
    mre_match(engine, &packet2, match_callback, NULL);
    
    // 测试数据包 3: Malware
    printf("\n--- Test 3: Malware Payload ---\n");
    const char *malware_data = "This is a malware with dangerous payload";
    PacketInfo packet3 = {
        .data = (uint8_t*)malware_data,
        .data_len = strlen(malware_data),
        .src_ip = "192.168.1.100",
        .dst_ip = "10.0.0.1",
        .src_port = 12345,
        .dst_port = 443,
        .protocol = 6  // TCP
    };
    mre_match(engine, &packet3, match_callback, NULL);
    
    // 打印统计
    printf("\n");
    mre_print_stats(engine);
    
    // 清理
    mre_destroy(engine);
    
    return 0;
}
```

### Step 7: 创建构建脚本

创建 `Makefile`：

```makefile
# Minimal Suricata Rule Engine Makefile

CC = gcc
CFLAGS = -Wall -Wextra -O2 -g -Iinclude/public
LDFLAGS = 

# 源文件
SRCS = src/core/rule_parser.c \
       src/core/rule_matcher.c \
       src/core/rule_engine.c

OBJS = $(SRCS:.c=.o)

# 目标
TARGET_LIB = libminimal_rule.a
TARGET_SO = libminimal_rule.so
EXAMPLE = examples/test_minimal

# 默认目标
all: $(TARGET_LIB) $(TARGET_SO) $(EXAMPLE)

# 静态库
$(TARGET_LIB): $(OBJS)
	ar rcs $@ $^

# 动态库
$(TARGET_SO): $(OBJS)
	$(CC) -shared -o $@ $^

# 示例程序
$(EXAMPLE): examples/test_minimal.c $(TARGET_LIB)
	$(CC) $(CFLAGS) -o $@ $< -L. -lminimal_rule

# 编译规则
%.o: %.c
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

# 运行测试
test: $(EXAMPLE)
	./$(EXAMPLE)

# 清理
clean:
	rm -f $(OBJS) $(TARGET_LIB) $(TARGET_SO) $(EXAMPLE)

.PHONY: all test clean
```

创建 `CMakeLists.txt`（可选）：

```cmake
cmake_minimum_required(VERSION 3.10)
project(MinimalSuricataRule C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -O2")

# 包含目录
include_directories(include/public)

# 源文件
set(SOURCES
    src/core/rule_parser.c
    src/core/rule_matcher.c
    src/core/rule_engine.c
)

# 静态库
add_library(minimal_rule_static STATIC ${SOURCES})
set_target_properties(minimal_rule_static PROPERTIES OUTPUT_NAME minimal_rule)

# 动态库
add_library(minimal_rule_shared SHARED ${SOURCES})
set_target_properties(minimal_rule_shared PROPERTIES OUTPUT_NAME minimal_rule)

# 示例程序
add_executable(test_minimal examples/test_minimal.c)
target_link_libraries(test_minimal minimal_rule_static)

# 测试
enable_testing()
add_test(NAME test_minimal COMMAND test_minimal)
```

## 三、编译和运行

### 3.1 使用 Make 编译

```bash
# 编译
make all

# 运行测试
make test

# 输出示例：
Loading rules...

--- Test 1: HTTP GET Request ---
[MATCH] Rule 1: HTTP GET Request

--- Test 2: SQL Injection ---
[MATCH] Rule 2: SQL Injection

--- Test 3: Malware Payload ---
[MATCH] Rule 3: Malware Signature

Engine Statistics:
  Rules loaded: 3
  Packets checked: 3
  Rules matched: 3
```

### 3.2 使用 CMake 编译

```bash
mkdir build
cd build
cmake ..
make
./test_minimal
```

## 四、扩展指南

### 4.1 添加更多关键字

要添加新的关键字（如 pcre），需要：

1. 在 `ContentData` 结构中添加字段
2. 在解析器中添加关键字处理
3. 在匹配器中实现匹配逻辑

示例：添加 PCRE 支持

```c
// 1. 修改数据结构
typedef struct ContentData_ {
    // ... 现有字段
    char *pcre_pattern;        // PCRE 模式
    void *pcre_compiled;       // 编译后的 PCRE
} ContentData;

// 2. 在解析器中添加
else if (strcmp(key, "pcre") == 0) {
    // 编译 PCRE 模式
    content->pcre_pattern = strdup(value);
    // content->pcre_compiled = pcre_compile(...);
}

// 3. 在匹配器中添加
if (content->pcre_pattern) {
    // 执行 PCRE 匹配
    // if (!pcre_match(...)) return false;
}
```

### 4.2 优化性能

1. **使用 MPM（多模式匹配）**
   - 集成 Aho-Corasick 算法
   - 批量处理多个 content 模式

2. **添加预过滤**
   - 端口快速过滤
   - 协议快速过滤

3. **规则分组**
   - 按协议分组
   - 按端口分组

### 4.3 集成到项目

```c
// 在你的项目中使用
#include "minimal_rule.h"

int main() {
    MinimalRuleEngine *engine = mre_create();
    
    // 加载规则文件
    mre_load_rules_file(engine, "rules.txt");
    
    // 在数据包处理循环中
    while (receive_packet(&packet)) {
        PacketInfo pinfo = {
            .data = packet.payload,
            .data_len = packet.payload_len,
            // ... 填充其他字段
        };
        
        mre_match(engine, &pinfo, handle_alert, NULL);
    }
    
    mre_destroy(engine);
    return 0;
}
```

## 五、总结

这个最小核心功能实现：

✅ **代码量小**：总共约 500-800 行代码
✅ **易于理解**：清晰的模块划分
✅ **可以运行**：提供完整的编译和测试
✅ **易于扩展**：清晰的扩展点

**下一步建议**：
1. 先运行这个 POC，验证基本功能
2. 根据需求逐步添加关键字
3. 优化性能（添加 MPM、预过滤等）
4. 完善错误处理和日志
5. 添加更多测试用例

这个最小实现为您提供了一个坚实的起点，您可以基于此逐步构建更完整的规则引擎。