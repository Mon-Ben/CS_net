#include "icmp.h"

#include "ip.h"
#include "net.h"

/**
 * @brief 发送icmp响应
 *
 * @param req_buf 收到的icmp请求包
 * @param src_ip 源ip地址
 */
static void icmp_resp(buf_t *req_buf, uint8_t *src_ip) {
    // Step1: 初始化txbuf并复制请求报文（含id和seq）
    size_t total_len = req_buf->len;  // 完全复制请求报文长度
    buf_init(&txbuf, total_len);
    memcpy(txbuf.data, req_buf->data, total_len);
    
    // 修改类型为ECHO_REPLY，清零校验和
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *)txbuf.data;
    icmp_hdr->type = ICMP_TYPE_ECHO_REPLY;
    icmp_hdr->checksum16 = 0;
    
    // Step2: 重新计算校验和（覆盖整个ICMP报文）
    icmp_hdr->checksum16 = checksum16((uint16_t *)txbuf.data, total_len);
    
    // Step3: 发送应答
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip) {
    // Step1: 长度检查（至少包含icmp_hdr_t）
    if (buf->len < sizeof(icmp_hdr_t)) {
        return;  // 丢弃不完整报文
    }
    
    // Step2: 读取类型字段
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *)buf->data;
    
    // Step3: 处理ECHO_REQUEST
    if (icmp_hdr->type == ICMP_TYPE_ECHO_REQUEST) {
        icmp_resp(buf, src_ip);
    }
    // 其他类型（如ECHO_REPLY）无需处理
}

/**
 * @brief 发送icmp不可达
 *
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code) {
    // 提取原始IP首部长度（单位：字节）
    ip_hdr_t *orig_ip_hdr = (ip_hdr_t *)recv_buf->data;
    size_t orig_ip_hdr_len = orig_ip_hdr->hdr_len * 4;  // header length字段值 * 4
    
    // ICMP数据部分长度 = 原始IP首部 + 8字节原始数据
    size_t icmp_data_len = orig_ip_hdr_len + 8;
    size_t total_len = sizeof(icmp_hdr_t) + icmp_data_len;
    
    // Step1: 初始化并填写ICMP首部
    buf_init(&txbuf, total_len);
    
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *)txbuf.data;
    icmp_hdr->type = ICMP_TYPE_UNREACH;
    icmp_hdr->code = code;
    icmp_hdr->checksum16 = 0;
    // id16和seq16字段在差错报文中作为填充（必须为0）
    icmp_hdr->id16 = 0;
    icmp_hdr->seq16 = 0;
    
    // Step2: 复制原始数据并计算校验和
    uint8_t *icmp_data = txbuf.data + sizeof(icmp_hdr_t);
    memcpy(icmp_data, recv_buf->data, orig_ip_hdr_len);              // 原始IP首部
    memcpy(icmp_data + orig_ip_hdr_len, recv_buf->data + orig_ip_hdr_len, 8); // 后续8字节数据
    
    icmp_hdr->checksum16 = checksum16((uint16_t *)txbuf.data, total_len);
    
    // Step3: 发送差错报文
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 初始化icmp协议
 *
 */
void icmp_init() {
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
}