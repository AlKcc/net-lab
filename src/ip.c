#include "net.h"
#include "ip.h"
#include "ethernet.h"
#include "arp.h"
#include "icmp.h"

#define IP_MAX_PAYLOAD_LEN (ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip_hdr_t))

static uint16_t id = 0;

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac) {
    // TO-DO
    // Step1 检查数据包长度
    if (buf->len < sizeof(ip_hdr_t)) {
        return;
    }

    // Step2 进行报头检测
    ip_hdr_t *ip_hdr = (ip_hdr_t *)buf->data;
    if (ip_hdr->version != IP_VERSION_4 || swap16(ip_hdr->total_len16) > buf->len) {
        return;
    }

    // Step3 校验头部校验和
    uint16_t origin_checksum16 = ip_hdr->hdr_checksum16;
    ip_hdr->hdr_checksum16 = 0;
    uint16_t calculated_checksum16 = checksum16((uint16_t *)ip_hdr, ip_hdr->hdr_len * IP_HDR_LEN_PER_BYTE);
    if (origin_checksum16 != calculated_checksum16) {
        return;
    } else {
        ip_hdr->hdr_checksum16 = origin_checksum16;
    }

    // Step4 对比目的IP地址
    if (memcmp(ip_hdr->dst_ip, net_if_ip, sizeof(net_if_ip))) {
        return;
    }

    // Step5 去除填充字段
    if (buf->len > swap16(ip_hdr->total_len16)) {
        buf_remove_padding(buf, buf->len - swap16(ip_hdr->total_len16));
    }

    //Step6 去掉IP报头
    buf_remove_header(buf, ip_hdr->hdr_len * IP_HDR_LEN_PER_BYTE);

    //Step7 向上层传递数据包
    if (net_in(buf, ip_hdr->protocol, ip_hdr->src_ip) == -1) {
        buf_add_header(buf, ip_hdr->hdr_len * IP_HDR_LEN_PER_BYTE);
        icmp_unreachable(buf, ip_hdr->src_ip, ICMP_CODE_PROTOCOL_UNREACH);
    }
    return;
}


/**
 * @brief 处理一个要发送的ip分片
 * 
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf) {
    // TO-DO
    // Step1 增加头部缓存空间
    buf_add_header(buf, sizeof(ip_hdr_t));
    ip_hdr_t *ip_hdr = (ip_hdr_t *)buf->data;

    // Step2 填写头部字段
    ip_hdr->version = IP_VERSION_4;
    ip_hdr->hdr_len = sizeof(ip_hdr_t) / IP_HDR_LEN_PER_BYTE;
    ip_hdr->tos = 0;
    ip_hdr->total_len16 = swap16(buf->len);
    ip_hdr->id16 = swap16(id);
    ip_hdr->flags_fragment16 = swap16((offset / IP_HDR_OFFSET_PER_BYTE) | (mf ? IP_MORE_FRAGMENT : 0));
    ip_hdr->ttl = IP_DEFALUT_TTL;
    ip_hdr->protocol = protocol;
    memcpy(ip_hdr->src_ip, net_if_ip, NET_IP_LEN);
    memcpy(ip_hdr->dst_ip, ip, NET_IP_LEN);

    // Step3 计算并填写校验和
    ip_hdr->hdr_checksum16 = 0;
    ip_hdr->hdr_checksum16 = checksum16((uint16_t *)ip_hdr, sizeof(ip_hdr_t));

    // Step4 发送数据
    arp_out(buf, ip);
}

/**
 * @brief 处理一个要发送的ip数据包
 * 
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */

void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol) {
    // TO-DO
     // Step1 检查数据报包长
    if (buf->len > IP_MAX_PAYLOAD_LEN) {
        // Step2 分片处理
        int offset = 0;
        while (buf->len > IP_MAX_PAYLOAD_LEN) {
            buf_t ip_buf;
            buf_init(&ip_buf, IP_MAX_PAYLOAD_LEN);
            memcpy(ip_buf.data, buf->data, IP_MAX_PAYLOAD_LEN);
            ip_fragment_out(&ip_buf, ip, protocol, id, offset, 1);
            buf_remove_header(buf, IP_MAX_PAYLOAD_LEN);
            offset += IP_MAX_PAYLOAD_LEN;
        }
        if (buf->len > 0) {
            buf_t ip_buf;
            buf_init(&ip_buf, buf->len);
            memcpy(ip_buf.data, buf->data, buf->len);
            ip_fragment_out(&ip_buf, ip, protocol, id, offset, 0);
        }
    } else {
        ip_fragment_out(buf, ip, protocol, id, 0, 0);
    }
    id++;
    return;
}


/**
 * @brief 初始化ip协议
 * 
 */
void ip_init()
{
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}