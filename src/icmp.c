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
    // TO-DO
    // Step1 初始化并封装数据
    buf_init(&txbuf, req_buf->len);
    memcpy(txbuf.data + sizeof(icmp_hdr_t), req_buf->data + sizeof(icmp_hdr_t), req_buf->len - sizeof(icmp_hdr_t));
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *)req_buf->data;
    icmp_hdr->type = ICMP_TYPE_ECHO_REPLY;
    icmp_hdr->code = 0;
    icmp_hdr->id16 = ((icmp_hdr_t *)req_buf->data)->id16;
    icmp_hdr->seq16 = ((icmp_hdr_t *)req_buf->data)->seq16;

    // Step2 填写校验和
    icmp_hdr->checksum16 = 0;
    icmp_hdr->checksum16 = checksum16((uint16_t *)txbuf.data, txbuf.len);

    // Step3 发送数据报
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip) {
    // TO-DO
    // Step1 包头检测
    if (buf->len < sizeof(icmp_hdr_t)) {
        return;
    }

    // Step2 查看ICMP类型
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *)buf->data;
    if (icmp_hdr->type == ICMP_TYPE_ECHO_REQUEST) {
        // Step3 回送回显应答
        icmp_resp(buf, src_ip);
    }
}

/**
 * @brief 发送icmp不可达
 *
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code) {
    // TO-DO
    // Step1 初始化并填写包头
    size_t icmp_len = sizeof(icmp_hdr_t) + sizeof(ip_hdr_t) + 8;
    buf_init(&txbuf, icmp_len);
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *)txbuf.data;
    icmp_hdr->type = ICMP_TYPE_UNREACH;
    icmp_hdr->code = code;
    icmp_hdr->id16 = 0;
    icmp_hdr->seq16 = 0;

    // Step2 填写数据与校验和
    memcpy(txbuf.data + sizeof(icmp_hdr_t), recv_buf->data, 8 + sizeof(ip_hdr_t));
    icmp_hdr->checksum16 = 0;
    icmp_hdr->checksum16 = checksum16((uint16_t *)txbuf.data, txbuf.len);

    // Step3 发送数据报
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 初始化icmp协议
 *
 */
void icmp_init() {
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
}