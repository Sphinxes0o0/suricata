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