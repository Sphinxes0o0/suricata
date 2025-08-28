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