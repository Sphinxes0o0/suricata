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