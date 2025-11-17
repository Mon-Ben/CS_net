#include "ethernet.h"

#include "arp.h"
#include "driver.h"
#include "ip.h"
#include "utils.h"
#include <string.h>
/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 */
void ethernet_in(buf_t *buf) {
    // Step1: 数据长度检查 - 如果数据长度小于以太网头部长度，丢弃数据包
    if (buf->len < sizeof(ether_hdr_t)) {
        return;
    }
    
    // 获取以太网头部信息
    ether_hdr_t *hdr = (ether_hdr_t *)buf->data;
    uint16_t protocol = swap16(hdr->protocol16);
    uint8_t src_mac[NET_MAC_LEN];
    
    // 保存源MAC地址 - 使用memcpy而不是buf_copy
    memcpy(src_mac, hdr->src, NET_MAC_LEN);
    
    // Step2: 移除以太网包头
    buf_remove_header(buf, sizeof(ether_hdr_t));
    
    // Step3: 向上层传递数据包
    net_in(buf, protocol, src_mac);
}
/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param mac 目标MAC地址
 * @param protocol 上层协议
 */
void ethernet_out(buf_t *buf, const uint8_t *mac, net_protocol_t protocol) {
    // Step1: 数据长度检查与填充 - 如果数据长度不足46字节，填充0
    if (buf->len < ETHERNET_MIN_TRANSPORT_UNIT) {
        buf_add_padding(buf, ETHERNET_MIN_TRANSPORT_UNIT - buf->len);
    }
    
    // Step2: 添加以太网包头
    buf_add_header(buf, sizeof(ether_hdr_t));
    ether_hdr_t *hdr = (ether_hdr_t *)buf->data;
    
    // Step3: 填写目的MAC地址 - 使用memcpy而不是buf_copy
    memcpy(hdr->dst, mac, NET_MAC_LEN);
    
    // Step4: 填写源MAC地址，即本机的MAC地址 - 使用memcpy而不是buf_copy
    memcpy(hdr->src, net_if_mac, NET_MAC_LEN);
    
    // Step5: 填写协议类型protocol（需要转换为大端字节序）
    hdr->protocol16 = swap16(protocol);
    
    // Step6: 发送数据帧
    driver_send(buf);
}
/**
 * @brief 初始化以太网协议
 *
 */
void ethernet_init() {
    buf_init(&rxbuf, ETHERNET_MAX_TRANSPORT_UNIT + sizeof(ether_hdr_t));
}

/**
 * @brief 一次以太网轮询
 *
 */
void ethernet_poll() {
    if (driver_recv(&rxbuf) > 0)
        ethernet_in(&rxbuf);
}
