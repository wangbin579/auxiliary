#ifndef  TC_SESSION_INCLUDED
#define  TC_SESSION_INCLUDED

#include <xcopy.h>
#include <tcpcopy.h>

#define IP_HEADER_LEN sizeof(tc_ip_header_t)
#define TCP_HEADER_MIN_LEN sizeof(tc_tcp_header_t)

#define FAKE_FRAME_LEN (60 + ETHERNET_HDR_LEN)
#define FAKE_MIN_IP_DATAGRAM_LEN (IP_HEADER_LEN + (TCP_HEADER_DOFF_MIN_VALUE << 2))
#define FAKE_IP_TS_DATAGRAM_LEN (IP_HEADER_LEN + (TCP_HEADER_DOFF_TS_VALUE << 2))
#define FAKE_SYN_IP_DATAGRAM_LEN (IP_HEADER_LEN + (TCP_HEADER_DOFF_MSS_VALUE << 2))
#define FAKE_SYN_IP_TS_DATAGRAM_LEN (IP_HEADER_LEN + (TCP_HEADER_DOFF_WS_TS_VALUE << 2))


/* 初始化会话相关数据 */
void init_for_sessions();
/* 销毁会话相关数据 */
void destroy_for_sessions();
/* 处理请求数据包 */
bool process_in(unsigned char *frame);
/* 处理响应数据包 */
bool process_out(unsigned char *packet);
/* 判断请求数据包是否是待复制的数据包 */
bool is_packet_needed(unsigned char *packet);
/* 定期处理，比如输出统计信息，处理掉超时的会话等等 */
void tc_interval_dispose(tc_event_timer_t *evt);
/* 输出统计信息 */
void output_stat();

/* 用户会话状态相关数据，涉及到真实客户端，tcpcopy伪造的客户端，测试服务器三方的关系 */
typedef struct sess_state_machine_s{
    /* 被伪造的用户会话的TCP状态 */
    uint32_t status:8;
    /* 测试服务器对于请求处理是否响应慢的标识 */
    uint32_t resp_slow:1;
    /* 真实客户端是否关闭的标识 */
    uint32_t recv_client_close:1;
    /* 针对被伪造的用户会话,是否已经重传的标识 */
    uint32_t vir_already_retransmit:1;
    /* 针对被伪造的用户会话,是否是新的重传标识，仅用于统计成功重传的次数 */
    uint32_t vir_new_retransmit:1;
    /* 针对被伪造的用户会话，是否处于CLOSING状态，即同时关闭的标识 */
    uint32_t simul_closing:1;
    /* 针对被伪造的用户会话，是否发送了reset数据包给测试服务器或者接受到了测试服务器的reset数据包 */
    uint32_t reset:1;
    /* 针对被伪造的用户会话，是否因为fin数据包，需要把seq加1 */
    uint32_t fin_add_seq:1;
    /* 针对被伪造的用户会话，其会话是否结束的标识 */
    uint32_t sess_over:1;
    /* 被伪造的客户端是否关闭的标识 */
    uint32_t src_closed:1;
    /* 测试服务器是否关闭用户会话的标识 */
    uint32_t dst_closed:1;
    /* 测试服务器滑动窗口是否为慢的标识 */
    uint32_t last_window_full:1;
    /* 是否需要等测试服务器上层应用响应的标识 */
    uint32_t candidate_response_waiting:1;
    /* 纯用户请求的标识（测试服务器上层应用不需要回复请求) */
    uint32_t req_no_resp:1;
    /* 是否是从收到测试服务器上层应用响应后，来发送被缓冲的后续请求的标识 */
    uint32_t send_reserved_from_bak_payload:1;
    /* 针对被伪造的用户会话，因为流量控制而延缓发送的标识 */
    uint32_t delay_sent_flag:1;
    /* 针对被伪造的用户会话，是否在等前面缺失的数据包(主要是由因为分段的数据包无序到达导致的) */
    uint32_t is_waiting_previous_packet:1;
    /* 针对被伪造的用户会话，是否已经发送syn数据包 */
    uint32_t req_syn_ok:1;
    /* 是否在截获到真实客户端fin数据包之前，记录下真实客户端数据包的ack seq */
    uint32_t record_ack_before_fin:1;
    /* 针对真实的客户端，最近被复制的数据包中的ack seq是否有效的标识 */
    uint32_t req_valid_last_ack_sent:1;
    /* 针对被伪造的用户会话，是否半路截获真实用户会话的标识 */
    uint32_t req_halfway_intercepted:1;
    /* 针对被伪造的用户会话，其数据包是否被加上了timestamp的TCP选项 */
    uint32_t timestamped:1;
    /* 是否收到测试服务器syn数据包的标识 */
    uint32_t resp_syn_received:1;
    /* 用户会话候选被删除的标识 */
    uint32_t sess_candidate_erased:1;
    /* 是否存在下一个相同四元组(客户端ip，客户端端口，服务器ip，服务器端口)的会话的标识 */
    uint32_t sess_more:1;
    /* 客户端端口是否被改变的标识 */
    uint32_t port_transfered:1;
    /* 是否需要把目前待发的数据包放入未确认的数据包链表的标识 */
    uint32_t unack_pack_omit_save_flag:1;
    /* 会话过程中，是否收到服务器应用的greet数据包(服务器端先发送payload数据包)的标识 */
    uint32_t resp_greet_received:1;
    /* 会话过程中，是否需要服务器先传递应用数据包的标识 */
    uint32_t need_resp_greet:1;
    /* 是否传递了reset数据包给测试服务器 */
    uint32_t reset_sent:1;
}sess_state_machine_t;

typedef struct session_s{
    /* session的key */
    uint64_t hash_key;

    /* 客户短ip地址(network byte order) */
    uint32_t src_addr;
    /* 测试服务器ip地址(network byte order) */
    uint32_t dst_addr;
    /* 在线服务器ip地址(network byte order) */
    uint32_t online_addr;
    /* 测试服务器tcp针对此会话所能够缓冲的buffer大小 */
    uint32_t srv_window;
    /* 回复测试服务器的timestamp */
    uint32_t ts_ec_r;
    /* 客户端自身的timestamp */
    uint32_t ts_value;
    /* window scale值 */
    uint16_t wscale;
    /* 客户端最初的端口号(network byte order) */
    uint16_t orig_src_port;
    /* 正在被使用的客户端端口号(host byte order) */
    uint16_t src_h_port;
    /* 测试服务器应用的端口号(network byte order) */
    uint16_t dst_port;
    /* 在线服务器应用的端口号(network byte order) */
    uint16_t online_port;
    /* 被伪造的客户端端口号(network byte order) */
    uint16_t faked_src_port;

    /* 发送给测试服务器的ack seq(host byte order) */
    uint32_t vir_ack_seq;
    /* 下一次发送给测试服务器的seq(host byte order) */
    uint32_t vir_next_seq;

    /* 测试服务器针对此会话，回复的最近一次的tcp的ack seq(host byte order) */
    uint32_t resp_last_ack_seq;
    /* 测试服务器针对此会话，回复的最近一次的tcp的seq(host byte order) */
    uint32_t resp_last_seq;

    /* 下面变量针对在线服务器的数据包的特性 */
    /***********************begin************************/
    /* 捕获的在线请求数据包的最近一次的原始syn sequence(network byte order) */
    uint32_t req_last_syn_seq;
    /* 最近发送给测试服务器的带有payload的数据包的原始seq(host byte order) */
    uint32_t req_last_cont_sent_seq;
    /* 最近发送给测试服务器的数据包的原始ack seq(host byte order) */
    uint32_t req_last_ack_sent_seq;
    /* 收到客户端fin数据包之前的最近的ack seq(host byte order) */
    uint32_t req_ack_before_fin;
    /* 最近捕获的来自客户端的ack seq(host byte order) */ 
    uint32_t req_cont_last_ack_seq;
    /* 这次捕获的来自客户端的ack seq(host byte order) */ 
    uint32_t req_cont_cur_ack_seq;
    /***********************end***************************/

    /* 会话的最近一次更新时间（只要有数据包到达，不管从哪一个方向）*/
    time_t   last_update_time;
    /* 会话创建时间 */
    time_t   create_time;
    /* 最近一次接受到测试服务器应用的响应数据包时间 */
    time_t   resp_last_recv_cont_time;
    /* 最近一次发送带有payload的数据包给测试服务器的时间 */
    time_t   req_last_send_cont_time;
    /* 会话状态 */
    sess_state_machine_t sm; 

    /* 客户端请求数据包的ip头部信息的id*/
    uint32_t req_ip_id:16;
    /* 收到测试服务器的重复ack包的数量 */
    uint32_t resp_last_same_ack_num:8;
    /* 发送给测试服务器的数据链路层的源mac地址 */
    unsigned char *src_mac;
    /* 发送给测试服务器的数据链路层的目的mac地址 */
    unsigned char *dst_mac;

    /* 未发送的数据包列表 */
    link_list *unsend_packets;
    /* 下一个具有同样key的session的的数据包列表 */
    link_list *next_sess_packs;
    /* 未被确认的数据包列表 */
    link_list *unack_packets;

}session_t;

#endif   /* ----- #ifndef TC_SESSION_INCLUDED ----- */

