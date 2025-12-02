#include "udp.h"

#include "icmp.h"
#include "ip.h"

/**
 * @brief udp处理程序表
 *
 */
map_t udp_table;

/**
 * @brief 处理一个收到的udp数据包
 *
 * @param buf 要处理的包
 * @param src_ip 源ip地址
 */
void udp_in(buf_t *buf, uint8_t *src_ip) {
    // Step1：基本长度检查
    if (buf->len < sizeof(udp_hdr_t))
        return; // 包太小丢弃

    udp_hdr_t *hdr = (udp_hdr_t *)buf->data;
    //需要保存源端口
    uint16_t src_p = swap16(hdr->src_port16);
    uint16_t src_d = swap16(hdr->dst_port16);
    uint16_t udp_len = swap16(hdr->total_len16);

    if (udp_len > buf->len)
        return; // 长度域异常，丢弃

    // Step2：校验和检查
    uint16_t recv_sum = hdr->checksum16;
    hdr->checksum16 = 0;

    uint16_t calc_sum = transport_checksum(NET_PROTOCOL_UDP, buf, src_ip, net_if_ip);

    if (recv_sum != 0 && recv_sum != calc_sum)
        return; // 校验和不一致丢弃

    hdr->checksum16 = recv_sum; // 恢复

    udp_handler_t* handle = map_get(&udp_table,&src_d);
    //当找不到对应的函数

    if(!handle)
    {
        buf_add_header(buf,sizeof(ip_hdr_t));
        //端口不可用差错报文
        icmp_unreachable(buf,src_ip,ICMP_CODE_PORT_UNREACH);
    }else{
        //移除udp报头
        buf_remove_header(buf,sizeof(udp_hdr_t));
        (*handle)((uint8_t*)buf->data, buf->len, src_ip, src_p);
    }
}

/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的包
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_out(buf_t *buf, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port) {
    // Step1：添加 UDP 头部（8字节）
    buf_add_header(buf, sizeof(udp_hdr_t));
    udp_hdr_t hdr ;

    // Step2：填写 UDP 首部
    hdr.src_port16 = swap16(src_port);  // 使用 src_port16
    hdr.dst_port16 = swap16(dst_port);  // 使用 dst_port16
    hdr.total_len16 = swap16(buf->len); // 使用 total_len16
    hdr.checksum16 = 0;  // 初始化校验和字段
    memcpy(buf->data, &hdr, sizeof(udp_hdr_t));
    // Step3：计算校验和
    uint16_t cksum = transport_checksum(NET_PROTOCOL_UDP, buf, net_if_ip, dst_ip);
    hdr.checksum16 = cksum;  // 填充校验和
    memcpy(buf->data, &hdr, sizeof(udp_hdr_t));

    // Step4：调用 IP 层发送
    ip_out(buf, dst_ip, NET_PROTOCOL_UDP);
}

/**
 * @brief 初始化udp协议
 *
 */
void udp_init() {
    map_init(&udp_table, sizeof(uint16_t), sizeof(udp_handler_t), 0, 0, NULL, NULL);
    net_add_protocol(NET_PROTOCOL_UDP, udp_in);
}

/**
 * @brief 打开一个udp端口并注册处理程序
 *
 * @param port 端口号
 * @param handler 处理程序
 * @return int 成功为0，失败为-1
 */
int udp_open(uint16_t port, udp_handler_t handler) {
    return map_set(&udp_table, &port, &handler);
}

/**
 * @brief 关闭一个udp端口
 *
 * @param port 端口号
 */
void udp_close(uint16_t port) {
    map_delete(&udp_table, &port);
}

/**
 * @brief 发送一个udp包
 *
 * @param data 要发送的数据
 * @param len 数据长度
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_send(uint8_t *data, uint16_t len, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port) {
    buf_init(&txbuf, len);
    memcpy(txbuf.data, data, len);
    udp_out(&txbuf, src_port, dst_ip, dst_port);
}