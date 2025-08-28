#include <stdio.h>
#include <string.h>
#include "minimal_rule.h"

// 匹配回调函数
void match_callback(const MinimalRule *rule, void *user_data) {
    int *match_count = (int*)user_data;
    if (match_count) (*match_count)++;
    printf("[ALERT] SID:%u - %s\n", rule->id, rule->msg);
}

// 模拟数据包测试
void test_packet(MinimalRuleEngine *engine, const char *desc, 
                 const char *data, const char *src_ip, const char *dst_ip,
                 uint16_t src_port, uint16_t dst_port, uint8_t proto) {
    printf("\n=== Testing: %s ===\n", desc);
    printf("Data: %.50s%s\n", data, strlen(data) > 50 ? "..." : "");
    
    int match_count = 0;
    PacketInfo packet = {
        .data = (uint8_t*)data,
        .data_len = strlen(data),
        .src_ip = src_ip,
        .dst_ip = dst_ip,
        .src_port = src_port,
        .dst_port = dst_port,
        .protocol = proto
    };
    
    mre_match(engine, &packet, match_callback, &match_count);
    
    if (match_count == 0) {
        printf("No rules matched.\n");
    } else {
        printf("Total matches: %d\n", match_count);
    }
}

int main(int argc, char *argv[]) {
    const char *rules_file = "examples/test.rules";
    
    if (argc > 1) {
        rules_file = argv[1];
    }
    
    printf("Minimal Suricata Rule Engine POC\n");
    printf("=================================\n\n");
    
    // 创建引擎
    MinimalRuleEngine *engine = mre_create();
    
    // 加载规则文件
    printf("Loading rules from: %s\n", rules_file);
    int loaded = mre_load_rules_file(engine, rules_file);
    if (loaded < 0) {
        printf("Failed to load rules file!\n");
        mre_destroy(engine);
        return 1;
    }
    printf("Successfully loaded %d rules\n", loaded);
    
    // 测试各种攻击场景
    
    // 1. HTTP GET 请求
    test_packet(engine, "Normal HTTP GET Request",
                "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
                "192.168.1.100", "10.0.0.1", 54321, 80, 6);
    
    // 2. SQL 注入攻击
    test_packet(engine, "SQL Injection Attack",
                "GET /search.php?id=1' UNION SELECT * FROM users-- HTTP/1.1\r\n",
                "192.168.1.100", "10.0.0.1", 54322, 80, 6);
    
    // 3. XSS 攻击
    test_packet(engine, "XSS Attack",
                "POST /comment HTTP/1.1\r\n\r\ncomment=<script>alert('XSS')</script>",
                "192.168.1.100", "10.0.0.1", 54323, 80, 6);
    
    // 4. 恶意软件通信
    test_packet(engine, "Malware Communication",
                "malware beacon data with command execution via cmd.exe",
                "192.168.1.100", "10.0.0.1", 12345, 443, 6);
    
    // 5. PowerShell 攻击
    test_packet(engine, "PowerShell Attack",
                "powershell.exe -encodedCommand SGVsbG8gV29ybGQ=",
                "192.168.1.100", "10.0.0.1", 4444, 4444, 6);
    
    // 6. SSH 暴力破解
    test_packet(engine, "SSH Brute Force",
                "SSH-2.0-OpenSSH_7.4\r\n",
                "192.168.1.100", "10.0.0.1", 55555, 22, 6);
    
    // 7. 正常流量（不应触发）
    test_packet(engine, "Normal Traffic",
                "Hello World! This is normal traffic.",
                "192.168.1.100", "10.0.0.1", 8080, 8080, 6);
    
    // 打印最终统计
    printf("\n=================================\n");
    mre_print_stats(engine);
    
    // 清理
    mre_destroy(engine);
    
    return 0;
}