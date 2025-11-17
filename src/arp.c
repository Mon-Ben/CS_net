#include "arp.h"

#include "ethernet.h"
#include "net.h"

#include <stdio.h>
#include <string.h>
/**
 * @brief 初始的arp包
 *
 * 暂时将 sender_ip 和 sender_mac 设置为 {0}，并在 arp_req/arp_resp 中手动填充，
 * 以避免编译错误，同时假设这两个字段在 arp_pkt_t 中是数组类型。
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type16 = swap16(ARP_HW_ETHER),
    .pro_type16 = swap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = NET_IF_IP,
    .sender_mac = NET_IF_MAC,
    .target_mac = {0}
};

/**
 * @brief arp地址转换表，<ip,mac>的容器
 *
 */
map_t arp_table;

/**
 * @brief arp buffer，<ip,buf_t>的容器
 *
 */
map_t arp_buf;

/**
 * @brief 打印一条arp表项
 *
 * @param ip 表项的ip地址
 * @param mac 表项的mac地址
 * @param timestamp 表项的更新时间
 */
void arp_entry_print(void *ip, void *mac, time_t *timestamp) {
    printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 *
 */
void arp_print() {
    printf("===ARP TABLE BEGIN===\n");
    map_foreach(&arp_table, arp_entry_print);
    printf("===ARP TABLE  END ===\n");
}

/**
 * @brief 发送一个arp请求
 *
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip) {
    // Step1: 初始化缓冲区
    buf_init(&txbuf, 0);
    buf_add_header(&txbuf, sizeof(arp_pkt_t));
    
    // Step2: 填写ARP报头
    arp_pkt_t *pkt = (arp_pkt_t *)txbuf.data;
    memcpy(pkt, &arp_init_pkt, sizeof(arp_pkt_t));
    
    pkt->opcode16 = swap16(ARP_REQUEST);

    memcpy(pkt->target_ip, target_ip, NET_IP_LEN);
    memset(pkt->target_mac, 0, NET_MAC_LEN);
    
    // Step3: 发送ARP报文（广播）
    const uint8_t broadcast_mac[NET_MAC_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    ethernet_out(&txbuf, broadcast_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 发送一个arp响应
 *
 * @param target_ip 目标ip地址 (ARP 请求方 IP)
 * @param target_mac 目标mac地址 (ARP 请求方 MAC)
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac) {
    // Step1: 初始化缓冲区
    buf_init(&txbuf, 0);
    buf_add_header(&txbuf, sizeof(arp_pkt_t));
    
    // Step2: 填写ARP报头
    arp_pkt_t *pkt = (arp_pkt_t *)txbuf.data;
    memcpy(pkt, &arp_init_pkt, sizeof(arp_pkt_t));
    pkt->opcode16 = swap16(ARP_REPLY);
    memcpy(pkt->target_ip, target_ip, NET_IP_LEN);
    memcpy(pkt->target_mac, target_mac, NET_MAC_LEN);
    
    // Step3: 发送ARP报文（单播）
    ethernet_out(&txbuf, target_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址 (上层传来的 Ethernet 源 MAC)
 */
void arp_in(buf_t *buf, uint8_t *src_mac) {
    // Step1: 检查数据长度
    if (buf->len < sizeof(arp_pkt_t)) return;

    arp_pkt_t *pkt = (arp_pkt_t *)buf->data;
    uint16_t opcode = swap16(pkt->opcode16);

    // Step2: 报头检查
    if (swap16(pkt->hw_type16) != ARP_HW_ETHER ||
        swap16(pkt->pro_type16) != NET_PROTOCOL_IP ||
        pkt->hw_len != NET_MAC_LEN ||
        pkt->pro_len != NET_IP_LEN ||
        (opcode != ARP_REQUEST && opcode != ARP_REPLY)) {
        return;
    }

    // Step3: 更新ARP表项
    map_set(&arp_table, pkt->sender_ip, pkt->sender_mac);

    // Step4: 查看缓存情况
    buf_t *pending = (buf_t *)map_get(&arp_buf, pkt->sender_ip);
    if (pending) {
        // 发送缓存的数据包
        ethernet_out(pending, pkt->sender_mac, NET_PROTOCOL_IP);
        // 从map中删除条目（不手动释放buf_t结构）
        map_delete(&arp_buf, pkt->sender_ip);
        return;
    }

    // 判断是否为请求本机的ARP请求
    if (opcode == ARP_REQUEST && !memcmp(pkt->target_ip, net_if_ip, NET_IP_LEN)) {
        arp_resp(pkt->sender_ip, pkt->sender_mac);
    }
}

/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 */
void arp_out(buf_t *buf, uint8_t *ip) {
    // Step1: 查找ARP表
    uint8_t *mac = (uint8_t *)map_get(&arp_table, ip);
    if (mac) {
        ethernet_out(buf, mac, NET_PROTOCOL_IP);
        return;
    }
    
    // Step2: 检查是否已有缓存
    if (map_get(&arp_buf, ip) != NULL) {
        return;//等待回复
    }
    
    // Step3: 缓存数据包并发送ARP请求
    map_set(&arp_buf, ip, buf);
    
    arp_req(ip);
}

void arp_init() {
    // 初始化ARP表
    map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL, NULL);
    
    // 初始化数据包缓存（使用buf_copy作为析构函数）
    map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, NULL, buf_copy);
    
    // 添加协议处理函数
    net_add_protocol(NET_PROTOCOL_ARP, arp_in);
    
    // 发送无偿ARP通告
    arp_req(net_if_ip);
}