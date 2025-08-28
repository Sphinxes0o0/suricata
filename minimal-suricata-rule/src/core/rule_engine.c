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