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