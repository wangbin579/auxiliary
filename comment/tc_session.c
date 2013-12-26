
#include <xcopy.h>
#include <tcpcopy.h>

/* 所有用户会话的table */
static hash_table *sessions_table;
/* 端口变化的table,以便找到原始端口号 */
static hash_table *tf_port_table;


/* 被删除的session的总和 */
static uint64_t leave_cnt            = 0;
/* 因为被过时删除的session的总和 */
static uint64_t obs_cnt              = 0;
/* 捕获到的客户端syn数据包的总和 */
static uint64_t clt_syn_cnt          = 0;
/* 捕获到的客户端数据包的总和 */
static uint64_t captured_cnt         = 0;
/* 捕获到的带有payload的客户端数据包的总和 */
static uint64_t clt_cont_cnt         = 0;
/* 捕获到的被过滤后的客户端数据包的总和 */
static uint64_t clt_packs_cnt        = 0;
/* 发送给测试服务器的数据包的总和 */
static uint64_t packs_sent_cnt       = 0;
/* 发送给测试服务器的fin数据包的总和 */
static uint64_t fin_sent_cnt         = 0;
/* 发送给测试服务器的reset数据包的总和 */
static uint64_t rst_sent_cnt         = 0;
/* 发送给测试服务器的带有payload数据包的总和 */
static uint64_t con_packs_sent_cnt   = 0;
/* 收到来自测试服务器的响应包的总和 */
static uint64_t resp_cnt             = 0;
/* 收到来自测试服务器的带有payload的响应包的总和 */ 
static uint64_t resp_cont_cnt        = 0;
/* 成功和测试服务器建立连接的总和 */
static uint64_t conn_cnt             = 0;
/* 成功重传的总和 */ 
static uint64_t retrans_succ_cnt     = 0;
/* 重传的总和 */ 
static uint64_t retrans_cnt          = 0;
/* 捕获到的客户端重传数据包的总和 */
static uint64_t clt_con_retrans_cnt  = 0;
/* 因为测试服务器提前关闭连接后，重新和测试服务器建立连接的总和 */
static uint64_t recon_for_closed_cnt = 0;
/* 因半途截获session而重新建立连接的总和 */
static uint64_t recon_for_no_syn_cnt = 0;
/* 开始处理有效数据包的时间 */
static time_t   start_p_time         = 0;


/* 判断用户会话是否结束的函数 */
static bool
check_session_over(session_t *s)
{
    if (s->sm.reset) {   
        return true;
    }   

    if (s->sm.sess_over) {   
        return true;
    }   

    return false;
}


/* 裁剪包的内容，使其传递尽可能少的内容给测试服务器 */
static bool
trim_packet(session_t *s, tc_ip_header_t *ip_header,
        tc_tcp_header_t *tcp_header, uint32_t diff)
{
    uint16_t        size_ip, size_tcp, tot_len, cont_len;
    unsigned char  *payload;

    tot_len   = ntohs(ip_header->tot_len);
    size_ip   = ip_header->ihl << 2;
    size_tcp  = tcp_header->doff << 2;
    cont_len  = tot_len - size_tcp - size_ip;

    if (cont_len <= diff) {
        return false;
    }

    ip_header->tot_len = htons(tot_len - diff);
    tcp_header->seq    = htonl(s->vir_next_seq);
    payload = (unsigned char *) ((char *) tcp_header + size_tcp);
    memmove(payload, payload + diff, cont_len - diff);
    tc_log_debug1(LOG_DEBUG, 0, "trim packet:%u", s->src_h_port);

    return true;
}

/* 更新包的timestamp */
static void 
update_timestamp(session_t *s, tc_tcp_header_t *tcp_header)
{
    uint32_t       ts;
    unsigned int   opt, opt_len;
    unsigned char *p, *end;

    p = ((unsigned char *) tcp_header) + TCP_HEADER_MIN_LEN;
    end =  ((unsigned char *) tcp_header) + (tcp_header->doff << 2);  
    while (p < end) {
        opt = p[0];
        switch (opt) {
            case TCPOPT_TIMESTAMP:
                if ((p + 1) >= end) {
                    return;
                }
                opt_len = p[1];
                if ((p + opt_len) <= end) {
                    ts = htonl(s->ts_ec_r);
                    tc_log_debug2(LOG_DEBUG, 0, "set ts reply:%u,p:%u", 
                            s->ts_ec_r, s->src_h_port);
                    bcopy((void *) &ts, (void *) (p + 6), sizeof(ts));
                    ts = EXTRACT_32BITS(p + 2);
                    if (ts < s->ts_value) {
                        tc_log_debug1(LOG_DEBUG, 0, "ts < history,p:%u",
                                s->src_h_port);
                        ts = htonl(s->ts_value);
                        bcopy((void *) &ts, (void *) (p + 2), sizeof(ts));
                    } else {
                        s->ts_value = ts;
                    }
                }
                return;
            case TCPOPT_NOP:
                p = p + 1; 
                break;
            case TCPOPT_EOL:
                return;
            default:
                if ((p + 1) >= end) {
                    return;
                }
                opt_len = p[1];
                if (opt_len < 2) {
                    tc_log_info(LOG_WARN, 0, "opt len:%d", opt_len);
                    return;
                }
                p += opt_len;
                break;
        }    
    }

    return;
}


/*
 * 重传数据包给测试服务器
 */
static void
wrap_retransmit_ip_packet(session_t *s, unsigned char *frame)
{
    int               ret, tcp_opt_len;
    uint16_t          size_ip, tot_len, cont_len;
    unsigned char    *p, *payload, *tcp_opt;
    tc_ip_header_t   *ip_header;
    tc_tcp_header_t  *tcp_header;

    if (frame == NULL) {
        tc_log_info(LOG_ERR, 0, "error frame is null");
        return;
    }

    p = frame + ETHERNET_HDR_LEN;
    ip_header  = (tc_ip_header_t *) p;
    size_ip    = ip_header->ihl << 2;
    tcp_header = (tc_tcp_header_t *) (p + size_ip);

    if (s->sm.timestamped) {
        update_timestamp(s, tcp_header);
    }

    /* 在这里，设置数据包的目的ip地址和目的端口 */
    ip_header->daddr = s->dst_addr;
    tcp_header->dest = s->dst_port;

    tot_len  = ntohs(ip_header->tot_len);
    cont_len = TCP_PAYLOAD_LENGTH(ip_header, tcp_header);

    if (tcp_header->doff > TCP_HEADER_DOFF_MIN_VALUE) {
        tcp_opt_len = (tcp_header->doff - TCP_HEADER_DOFF_MIN_VALUE) << 2;
        if (cont_len > 0) {
            tcp_opt = (unsigned char *) ((char *) tcp_header
                    + (TCP_HEADER_DOFF_MIN_VALUE << 2));
            payload = (unsigned char *) (tcp_opt + tcp_opt_len);
            memmove(tcp_opt, payload, cont_len);
        }
        tot_len = tot_len - tcp_opt_len;
        ip_header->tot_len = htons(tot_len);
        tcp_header->doff = TCP_HEADER_DOFF_MIN_VALUE;
    }
    
    if (cont_len > 0) {
        s->sm.vir_new_retransmit = 1;
        s->resp_last_same_ack_num = 0;
        retrans_cnt++;
    }

    /* 调用tcpcsum，必须先设置为0 */
    tcp_header->check = 0;
    tcp_header->check = tcpcsum((unsigned char *) ip_header,
            (unsigned short *) tcp_header, (int) (tot_len - size_ip));

#if (TCPCOPY_PCAP_SEND)
    ip_header->check = 0;
    ip_header->check = csum((unsigned short *) ip_header,size_ip);
#endif

    tc_log_trace(LOG_NOTICE, 0, TO_BAKEND_FLAG, ip_header, tcp_header);

#if (!TCPCOPY_PCAP_SEND)
    ret = tc_raw_socket_send(tc_raw_socket_out, ip_header, tot_len,
                             ip_header->daddr);
#else
    fill_frame((struct ethernet_hdr *) frame, s->src_mac, s->dst_mac);
    ret = tc_pcap_send(frame, tot_len + ETHERNET_HDR_LEN);
#endif

    if (ret == TC_ERROR) {
        tc_log_trace(LOG_WARN, 0, TO_BAKEND_FLAG, ip_header, tcp_header);
        tc_log_info(LOG_ERR, 0, "send to back error,tot_len is:%d,cont_len:%d",
                    tot_len,cont_len);
        tc_over = SIGRTMAX;
#if (!TCPCOPY_PCAP_SEND)
        tc_raw_socket_out = TC_INVALID_SOCKET;
#endif
    }
}


/*
 * 发送数据包给测试服务器
 */
static void
wrap_send_ip_packet(session_t *s, unsigned char *frame, bool client)
{
    int               ret;
    uint16_t          size_ip, tot_len, cont_len;
    unsigned char    *p;
    p_link_node       ln;
    tc_ip_header_t   *ip_header;
    tc_tcp_header_t  *tcp_header;

    if (frame == NULL) {
        tc_log_info(LOG_ERR, 0, "error frame is null");
        return;
    }

    p = frame + ETHERNET_HDR_LEN;
    ip_header  = (tc_ip_header_t *) p;
    size_ip    = ip_header->ihl << 2;
    tcp_header = (tc_tcp_header_t *) (p + size_ip);

    if (client) {
        s->req_last_ack_sent_seq = ntohl(tcp_header->ack_seq);
        s->sm.req_valid_last_ack_sent = 1;
    }

    if (s->sm.timestamped) {
        update_timestamp(s, tcp_header);
    }

    /* 在这里，设置数据包的目的ip地址和目的端口 */
    ip_header->daddr = s->dst_addr;
    tcp_header->dest = s->dst_port;

    s->vir_next_seq  = ntohl(tcp_header->seq);

    if (tcp_header->syn || tcp_header->fin) {

        if (tcp_header->syn) {
            s->sm.req_valid_last_ack_sent = 0;
            s->sm.status = SYN_SENT;
            s->req_last_syn_seq = tcp_header->seq;
        } else {
            fin_sent_cnt++;
            s->sm.fin_add_seq = 1;
        }
        s->vir_next_seq = s->vir_next_seq + 1;
    } else if (tcp_header->rst) {
        rst_sent_cnt++;
    }

    if (tcp_header->ack) {
        tcp_header->ack_seq = s->vir_ack_seq;
    }

    tot_len  = ntohs(ip_header->tot_len);
    cont_len = TCP_PAYLOAD_LENGTH(ip_header, tcp_header);
    if (cont_len > 0) {

        s->sm.status = SEND_REQ;
        s->req_last_send_cont_time = tc_time();
        s->req_last_cont_sent_seq  = ntohl(tcp_header->seq);
        s->vir_next_seq = s->vir_next_seq + cont_len;
        if (s->sm.unack_pack_omit_save_flag) {
            s->sm.vir_new_retransmit = 1;
        } else {
            con_packs_sent_cnt++;
        }
    } 

    /* 调用tcpcsum，必须先设置为0 */
    tcp_header->check = 0;
    tcp_header->check = tcpcsum((unsigned char *) ip_header,
            (unsigned short *) tcp_header, (int) (tot_len - size_ip));

#if (TCPCOPY_PCAP_SEND)
    ip_header->check = 0;
    ip_header->check = csum((unsigned short *) ip_header,size_ip);
#endif

    tc_log_debug_trace(LOG_DEBUG, 0, TO_BAKEND_FLAG, ip_header, tcp_header);

    packs_sent_cnt++;

    s->req_ip_id = ntohs(ip_header->id);

    if (!s->sm.unack_pack_omit_save_flag) {

        if (cont_len > 0) {
            p = cp_fr_ip_pack(ip_header);
            ln = link_node_malloc(p);
            link_list_append(s->unack_packets, ln);
        }
    } else {
        s->sm.unack_pack_omit_save_flag = 0;
    }

#if (!TCPCOPY_PCAP_SEND)
    ret = tc_raw_socket_send(tc_raw_socket_out, ip_header, tot_len,
                             ip_header->daddr);
#else
    fill_frame((struct ethernet_hdr *) frame, s->src_mac, s->dst_mac);
    ret = tc_pcap_send(frame, tot_len + ETHERNET_HDR_LEN);
#endif

    if (ret == TC_ERROR) {
        tc_log_trace(LOG_WARN, 0, TO_BAKEND_FLAG, ip_header, tcp_header);
        tc_log_info(LOG_ERR, 0, "send to back error,tot_len is:%d,cont_len:%d",
                    tot_len, cont_len);
        tc_over = SIGRTMAX;
#if (!TCPCOPY_PCAP_SEND)
        tc_raw_socket_out = TC_INVALID_SOCKET;
#endif
    }
}


/* 设置通用的tcp和ip头部信息 */
static void 
fill_pro_common_header(tc_ip_header_t *ip_header, tc_tcp_header_t *tcp_header)
{
    /* IPv4 */
    ip_header->version  = 4;
    /* The header length is the number of 32-bit words in the header */
    ip_header->ihl      = IP_HEADER_LEN/4;

    /* don't fragment */
    ip_header->frag_off = htons(IP_DF); 
    /* 
     * sets an upper limit on the number of routers through 
     * which a datagram can pass
     */
    ip_header->ttl      = 64; 
    /* TCP packet */
    ip_header->protocol = IPPROTO_TCP;
    /* window size(you may feel strange here) */
    tcp_header->window  = htons(65535); 
}


/*
 * 构造待发送的reset数据包,以清理测试服务器的tcp资源
 */
static void
send_faked_passive_rst(session_t *s)
{
    unsigned char    *p, frame[FAKE_FRAME_LEN];
    tc_ip_header_t   *f_ip_header;
    tc_tcp_header_t  *f_tcp_header;

    tc_log_debug1(LOG_DEBUG, 0, "send_faked_passive_rst:%u", s->src_h_port);

    memset(frame, 0, FAKE_FRAME_LEN);
    p = frame + ETHERNET_HDR_LEN;

    f_ip_header  = (tc_ip_header_t *) p;
    f_tcp_header = (tc_tcp_header_t *) (p + IP_HEADER_LEN);

    fill_pro_common_header(f_ip_header, f_tcp_header);
    f_ip_header->tot_len  = htons(FAKE_MIN_IP_DATAGRAM_LEN);
    f_ip_header->id       = htons(++s->req_ip_id);
    f_ip_header->saddr    = s->src_addr;

    f_tcp_header->doff    = TCP_HEADER_DOFF_MIN_VALUE;
    f_tcp_header->source  = htons(s->src_h_port);
    f_tcp_header->rst     = 1;
    f_tcp_header->ack     = 1;

    if (s->sm.fin_add_seq) {
        f_tcp_header->seq = htonl(s->vir_next_seq - 1); 
    } else {
        f_tcp_header->seq = htonl(s->vir_next_seq); 
    }

    s->sm.unack_pack_omit_save_flag = 1;

    wrap_send_ip_packet(s, frame, true);
}

#if (!TCPCOPY_SINGLE)
#if (TCPCOPY_DR)

/* 发送路由信息给intercept，以便响应包信息能够返回给相应的tcpcopy */
static bool
send_router_info(session_t *s, uint16_t type)
{
    int                      i, fd;
    bool                     result = false;
    msg_client_t             msg;
    connections_t           *connections;

    memset(&msg, 0, sizeof(msg_client_t));
    msg.client_ip = s->src_addr;
    msg.client_port = s->faked_src_port;
    msg.type = htons(type);
    msg.target_ip = s->dst_addr;
    msg.target_port = s->dst_port;

    /* 发送路由信息给每一个intercept */
    for (i = 0; i < clt_settings.real_servers.num; i++) {

        if (!clt_settings.real_servers.active[i]) {
            continue;
        }

        connections = &(clt_settings.real_servers.connections[i]);
        fd = connections->fds[connections->index];
        connections->index = (connections->index + 1) % connections->num;

        if (fd == -1) {
            tc_log_debug0(LOG_WARN, 0, "sock invalid");
            continue;
        }
        
        if (tc_socket_send(fd, (char *) &msg, MSG_CLIENT_SIZE) == TC_ERROR) {
            tc_log_info(LOG_ERR, 0, "fd:%d, msg client send error", fd);
            if (clt_settings.real_servers.active[i] != 0) {
                clt_settings.real_servers.active[i] = 0;
                clt_settings.real_servers.active_num--;
            }

            continue;
        }
        result = true;
    }

    return result;
}
 
#else

/* 发送路由信息给intercept，以便响应包信息能够返回给相应的tcpcopy */
static bool
send_router_info(session_t *s, uint16_t type)
{
    int                      fd;
    msg_client_t             msg;

    /* 发送路由信息给相应的intercept */
    fd = address_find_sock(s->online_addr, s->online_port);
    if (fd == -1) {
        tc_log_debug0(LOG_WARN, 0, "sock invalid");
        return false;
    }

    memset(&msg, 0, sizeof(msg_client_t));
    msg.client_ip = s->src_addr;
    msg.client_port = s->faked_src_port;
    msg.type = htons(type);
    msg.target_ip = s->dst_addr;
    msg.target_port = s->dst_port;

    if (tc_socket_send(fd, (char *) &msg, MSG_CLIENT_SIZE) == TC_ERROR) {
        tc_log_info(LOG_ERR, 0, "msg client send error");
        return false;
    }

    return true;
}
#endif

#endif


static void
session_rel_dynamic_mem(session_t *s)
{
    uint64_t key;

    leave_cnt++;
    
    if (!check_session_over(s)) {

        /* 清理测试服务器的tcp资源 */
        send_faked_passive_rst(s);
        s->sm.sess_over = 1;
    }

    if (s->sm.port_transfered) {

        key = get_key(s->src_addr, s->faked_src_port);
        if (!hash_del(tf_port_table, key)) {
            tc_log_info(LOG_WARN, 0, "no hash item for port transfer");
        }
        s->sm.port_transfered = 0;
    }

    if (s->unsend_packets != NULL) {
        if (s->unsend_packets->size > 0) {
            tc_log_debug2(LOG_DEBUG, 0, "unsend size when released:%u,p:%u",
                    s->unsend_packets->size, s->src_h_port);
        }
        link_list_clear(s->unsend_packets);
        free(s->unsend_packets);
        s->unsend_packets = NULL;
    }

    if (s->next_sess_packs != NULL) {
        link_list_clear(s->next_sess_packs);
        free(s->next_sess_packs);
        s->next_sess_packs = NULL;
    }

    if (s->unack_packets != NULL) {
        link_list_clear(s->unack_packets);
        free(s->unack_packets);
        s->unack_packets = NULL;
    }

}


/* 初始化用户session表等信息 */
void
init_for_sessions()
{
    sessions_table = hash_create(65536);
    strcpy(sessions_table->name, "session-table");

    tf_port_table  = hash_create(65536);
    strcpy(tf_port_table->name, "transfer port table");
}

/* 销毁session表等相关资源 */
void
destroy_for_sessions()
{
    size_t       i;           
    hash_node   *hn;
    session_t   *s;
    link_list   *list;
    p_link_node  ln, tmp_ln;

    tc_log_info(LOG_NOTICE, 0, "enter destroy_for_sessions");

    if (sessions_table != NULL) {

        for (i = 0; i < sessions_table->size; i++) {

            list = sessions_table->lists[i];
            ln   = link_list_first(list);   
            while (ln) {

                tmp_ln = link_list_get_next(list, ln);
                hn = (hash_node *) ln->data;
                if (hn->data != NULL) {

                    s = hn->data;
                    hn->data = NULL;
                    /* 销毁用户会话的内存 */
                    session_rel_dynamic_mem(s);
                    if (!hash_del(sessions_table, s->hash_key)) {
                        tc_log_info(LOG_ERR, 0, "wrong del");
                    }
                    free(s);
                }
                ln = tmp_ln;
            }
            free(list);
        }

        free(sessions_table->lists);
        free(sessions_table);
        sessions_table = NULL;
    }

    /* 销毁端口映射表 */
    if (tf_port_table != NULL) {
        hash_destroy(tf_port_table);
        free(tf_port_table);
        tf_port_table = NULL;
    }

    tc_log_info(LOG_NOTICE, 0, "leave destroy_for_sessions");

}

/* 初始化用户会话相关数据 */
static void
session_init(session_t *s, int flag)
{
    if (s->unsend_packets) {
        if (s->unsend_packets->size > 0) {
            link_list_clear(s->unsend_packets);
        }

        if (flag == SESS_REUSE) {
            if (s->next_sess_packs != NULL) {
                free(s->unsend_packets);
                s->unsend_packets = NULL;
            }
        }
    } else {
        s->unsend_packets = link_list_create();
    }

    if (s->unack_packets) {
        if (s->unack_packets->size > 0) {
            link_list_clear(s->unack_packets);
        }
    } else {
        s->unack_packets = link_list_create();
    }

    s->create_time      = tc_time();
    s->last_update_time = s->create_time;
    s->resp_last_recv_cont_time = s->create_time;
    s->req_last_send_cont_time  = s->create_time;

    if (flag != SESS_CREATE) {
        memset(&(s->sm), 0, sizeof(sess_state_machine_t));
    }
    s->sm.status  = CLOSED;
    s->resp_last_same_ack_num = 0;
}


/*
 * 目前只支持保留一份后续的具有相同key的用户会话过程
 */
static void
session_init_for_next(session_t *s)
{
    uint64_t    key;
    link_list  *list;

    list = s->next_sess_packs;

    if (s->sm.port_transfered) {
        key = get_key(s->src_addr, s->faked_src_port);
        if (!hash_del(tf_port_table, key)) {
            tc_log_info(LOG_WARN, 0, "no hash item for port transfer");
        }
    }

    session_init(s, SESS_REUSE);

    if (list != NULL) {
        s->unsend_packets  = list;
        s->next_sess_packs = NULL;
    } else {
        s->unsend_packets = link_list_create();
    }
}


/* 创建用户会话所需要的数据结构 */
static session_t *
session_create(tc_ip_header_t *ip_header, tc_tcp_header_t *tcp_header)
{
    session_t               *s;
    ip_port_pair_mapping_t  *test;

    s = (session_t *) calloc(1, sizeof(session_t));
    if (s == NULL) {
        return NULL;
    }

    session_init(s, SESS_CREATE);

    s->src_addr       = ip_header->saddr;
    s->online_addr    = ip_header->daddr;
    s->orig_src_port  = tcp_header->source;
    s->faked_src_port = tcp_header->source;
    s->src_h_port     = ntohs(tcp_header->source);
    s->online_port    = tcp_header->dest;
    test = get_test_pair(&(clt_settings.transfer), 
            s->online_addr, s->online_port);
    s->dst_addr       = test->target_ip;
    s->dst_port       = test->target_port;
#if (TCPCOPY_PCAP_SEND)
    s->src_mac        = test->src_mac;
    s->dst_mac        = test->dst_mac;
#endif
    if (s->src_addr == LOCALHOST && s->dst_addr != LOCALHOST) {
        tc_log_info(LOG_WARN, 0, "src host localost but dst host not");
        tc_log_info(LOG_WARN, 0, "use -c parameter to avoid this warning");
    }

    return s;
}


/* 添加用户会话的数据到session表中去 */
static session_t *
session_add(uint64_t key, tc_ip_header_t *ip_header,
        tc_tcp_header_t *tcp_header)
{
    session_t *s;

    s = session_create(ip_header, tcp_header);
    if (s != NULL) {
        s->hash_key = key;
        if (!hash_add(sessions_table, key, s)) {
            tc_log_info(LOG_ERR, 0, "session item already exist");
        }
    }

    return s;
}


/* 保留包的相关数据到列表中去 */
static void 
save_packet(link_list *list, tc_ip_header_t *ip_header,
        tc_tcp_header_t *tcp_header)
{

    unsigned char *copyed = (unsigned char *) cp_fr_ip_pack(ip_header);
    p_link_node    ln     = link_node_malloc(copyed);

    ln->key = ntohl(tcp_header->seq);
    link_list_append_by_order(list, ln);
    tc_log_debug0(LOG_DEBUG, 0, "save packet");
}


/* 
 * 是否在等待测试服务器端的greet数据包(测试服务器先发送payload数据包)
 */
static inline bool
is_wait_greet(session_t *s, tc_ip_header_t *ip_header,
        tc_tcp_header_t *tcp_header)
{
    uint32_t seq, ack;

    if (s->sm.req_valid_last_ack_sent) {

        ack = ntohl(tcp_header->ack_seq);
        seq = ntohl(tcp_header->seq);

        if (after(ack, s->req_last_ack_sent_seq) && seq == s->vir_next_seq) {
            s->sm.need_resp_greet = 1;
            if (!s->sm.resp_greet_received) {
                tc_log_debug1(LOG_INFO, 0, "it should wait:%u", s->src_h_port);
                return true;
            } else {
                s->sm.need_resp_greet = 0;
                return false;
            }
        }
    }

    if (s->sm.need_resp_greet && !s->sm.resp_greet_received) {
        return true;
    }

    return false;
}

/*
 * 发送缓存的数据包给测试服务器
 */
static int
send_reserved_packets(session_t *s)
{
    int               count = 0, total_cont_sent = 0; 
    bool              need_pause = false, cand_pause = false,
                      omit_transfer = false, need_check_who_close_first = true; 
    uint16_t          size_ip, cont_len;
    uint32_t          cur_ack, server_closed_ack, cur_seq, diff, srv_sk_buf_s;
    link_list        *list;
    p_link_node       ln, tmp_ln;
    unsigned char    *frame;
    tc_ip_header_t   *ip_header;
    tc_tcp_header_t  *tcp_header;

    tc_log_debug2(LOG_DEBUG, 0, "send reserved packs,size:%u, port:%u",
            s->unsend_packets->size, s->src_h_port);

    if (SYN_CONFIRM > s->sm.status) {
        return count;
    }

    srv_sk_buf_s = s->vir_next_seq - s->resp_last_ack_seq;

    tc_log_debug3(LOG_DEBUG, 0, "srv_sk_buf_s:%u, window:%u, p:%u",
            srv_sk_buf_s, s->srv_window, s->src_h_port);
    if (srv_sk_buf_s > s->srv_window) {
        s->sm.delay_sent_flag = 1;
        return count;
    }

    list = s->unsend_packets;
    if (list == NULL) {
        tc_log_info(LOG_WARN, 0, "list is null");
        return count;
    }

    ln = link_list_first(list); 

    while (ln && (!need_pause)) {

        frame = ln->data;
        ip_header  = (tc_ip_header_t *) ((char *) frame + ETHERNET_HDR_LEN);
        size_ip    = ip_header->ihl << 2;
        tcp_header = (tc_tcp_header_t *) ((char *) ip_header + size_ip);

        tc_log_debug_trace(LOG_DEBUG, 0, RESERVED_CLIENT_FLAG,
                ip_header, tcp_header);

        cur_seq    = ntohl(tcp_header->seq);
        if (after(cur_seq, s->vir_next_seq)) {

            /* 需要等待先前的数据包(由于数据包到达的顺序跟发送的顺序可能是不一样的) */
            tc_log_debug0(LOG_DEBUG, 0, "we need to wait prev pack");
            s->sm.is_waiting_previous_packet = 1;
            s->sm.candidate_response_waiting = 0;
            break;
        } else if (before(cur_seq, s->vir_next_seq)) {

            cont_len   = TCP_PAYLOAD_LENGTH(ip_header, tcp_header);
            if (cont_len > 0) {
                tc_log_debug1(LOG_DEBUG, 0, "reserved strange:%u", 
                        s->src_h_port);
                diff = s->vir_next_seq - cur_seq;
                if (!trim_packet(s, ip_header, tcp_header, diff)) {
                    omit_transfer = true;
                }
            } else {
                tcp_header->seq = htonl(s->vir_next_seq);
            }
        }

        if (s->sm.status < SEND_REQ
                && is_wait_greet(s, ip_header, tcp_header))
        {
            break;
        }

        cont_len   = TCP_PAYLOAD_LENGTH(ip_header, tcp_header);
        if (!omit_transfer && cont_len > 0) {

            if (total_cont_sent > MAX_SIZE_PER_CONTINUOUS_SEND) {
                s->sm.delay_sent_flag = 1;
                break;
            }

            srv_sk_buf_s = s->vir_next_seq - s->resp_last_ack_seq + cont_len;
            if (srv_sk_buf_s > s->srv_window) {
                tc_log_debug3(LOG_DEBUG, 0, "srv_sk_buf_s:%u, window:%u, p:%u",
                        srv_sk_buf_s, s->srv_window, s->src_h_port);
                s->sm.delay_sent_flag = 1;
                break;
            }

            cur_ack = ntohl(tcp_header->ack_seq);
            if (cand_pause) {
                if (cur_ack != s->req_last_ack_sent_seq) {
                    break;
                }
            }
            cand_pause = true;
            s->sm.candidate_response_waiting = 1;
            s->sm.send_reserved_from_bak_payload = 0;
        } else if (tcp_header->rst) {

            if (s->sm.resp_slow) {
                break;
            }

            if (s->sm.candidate_response_waiting) {
                break;
            }
            s->sm.reset      = 1;
            omit_transfer = false;
            need_pause    = true;
        } else if (tcp_header->fin) {

            s->sm.recv_client_close = 1;

            if (s->sm.resp_slow) {
                tc_log_debug1(LOG_DEBUG, 0, "resp slow:%u", s->src_h_port);
                break;
            }

            cur_ack = ntohl(tcp_header->ack_seq);
            if (s->sm.candidate_response_waiting) {
                if (cur_ack != s->req_last_ack_sent_seq) {
                    tc_log_debug1(LOG_DEBUG, 0, "wait resp:%u", s->src_h_port);
                    break;
                } else {
                    s->sm.candidate_response_waiting = 0;
                    s->sm.req_no_resp = 1;
                    tc_log_debug1(LOG_DEBUG, 0, "session continue:%u", 
                            s->src_h_port);
                    need_check_who_close_first = false;
                    s->sm.src_closed = 1;
                    s->sm.status |= CLIENT_FIN;
                    tc_log_debug1(LOG_DEBUG, 0, "active close from clt:%u",
                            s->src_h_port);
                }
            }

            need_pause = true;
            if (need_check_who_close_first) {
                tc_log_debug3(LOG_DEBUG, 0, "cur ack:%u, record:%u, p:%u", 
                        cur_ack, s->req_ack_before_fin, s->src_h_port);
                server_closed_ack = s->req_ack_before_fin + 1;
                if (s->req_ack_before_fin == cur_ack || 
                        after(cur_ack, server_closed_ack))
                {
                    /* 判断出客户端先关闭连接 */
                    s->sm.src_closed = 1;
                    s->sm.status |= CLIENT_FIN;
                    tc_log_debug1(LOG_DEBUG, 0, "active close from clt:%u",
                            s->src_h_port);

                } else {
                    /* 判断出在线服务器先关闭连接 */
                    tc_log_debug1(LOG_DEBUG, 0, "server active close:%u", 
                            s->src_h_port);
                    omit_transfer = true;
                }
            }
        } else if (cont_len == 0) {

            tc_log_debug1(LOG_DEBUG, 0, "cont len 0:%u", s->src_h_port);
            if (!s->sm.recv_client_close) {
                cur_ack = ntohl(tcp_header->ack_seq);
                tc_log_debug3(LOG_DEBUG, 0, "ack:%u, record:%u, p:%u", 
                        cur_ack, s->req_ack_before_fin, s->src_h_port);
                if (!s->sm.record_ack_before_fin) {
                    s->sm.record_ack_before_fin = 1;
                    s->req_ack_before_fin = cur_ack;
                    tc_log_debug1(LOG_DEBUG, 0, "record:%u", s->src_h_port);
                } else if (after(cur_ack, s->req_ack_before_fin)) {
                    s->req_ack_before_fin = cur_ack;
                    tc_log_debug1(LOG_DEBUG, 0, "record:%u", s->src_h_port);
                }
            }
            if (s->sm.candidate_response_waiting
                    || s->sm.status != SYN_CONFIRM)
            {
                omit_transfer = true;
            }
        }
        if (!omit_transfer) {

            count++;
            if (s->sm.sess_candidate_erased) {
                s->sm.sess_candidate_erased = 0;
            }

            if (cont_len > 0) {
                s->req_cont_last_ack_seq = s->req_cont_cur_ack_seq;
                s->req_cont_cur_ack_seq  = ntohl(tcp_header->ack_seq);
                total_cont_sent += cont_len;
            }

            wrap_send_ip_packet(s, frame, true);

        }

        tmp_ln = ln;
        ln = link_list_get_next(list, ln);
        link_list_remove(list, tmp_ln);
        free(frame);
        free(tmp_ln);
        omit_transfer = false;
 
    }

    return count;
}


static int 
check_overwhelming(session_t *s, const char *message, 
        int max_hold_packs, int size)
{
    if (size > MAX_UNSEND_THRESHOLD) {
        obs_cnt++;
        tc_log_info(LOG_WARN, 0, "%s:crazy number of packets:%u,p:%u",
                message, size, s->src_h_port);
        return OBSOLETE;
    }

    if (size > max_hold_packs) {
        if (!s->sm.sess_candidate_erased) {
            s->sm.sess_candidate_erased = 1;
            tc_log_info(LOG_WARN, 0, "%s:candidate erased:%u,p:%u",
                message, size, s->src_h_port);
            return CANDIDATE_OBSOLETE;
        }
        obs_cnt++;
        tc_log_info(LOG_WARN, 0, "%s:too many packets:%u,p:%u",
                message, size, s->src_h_port);
        return OBSOLETE;
    }

    return NOT_YET_OBSOLETE;
}


/*
 * 判断用户会话过程是否被卡住了
 */
static bool
is_session_dead(session_t *s)
{
    int    packs_unsend, diff;

    packs_unsend = s->unsend_packets->size;
    diff = tc_time() - s->req_last_send_cont_time;

    /* 如果超过2秒 */
    if (diff > 2) {
        /* 如果缓存的用户会话数据包的个数超过5个 */
        if (packs_unsend > 5) {
            return true;
        }
    }

    return false;
}


static void activate_dead_sessions()
{
    int           i;
    session_t    *s;
    link_list    *list;
    hash_node    *hn;
    p_link_node   ln;

    for (i = 0; i < sessions_table->size; i++) {

        list = sessions_table->lists[i];
        ln   = link_list_first(list);   
        while (ln) {

            hn = (hash_node *) ln->data;
            if (hn->data != NULL) {
                s = hn->data;
                if (s->sm.sess_over) {
                    tc_log_info(LOG_NOTICE, 0, "already del:%u", s->src_h_port);
                }
                if (is_session_dead(s)) {
                    send_reserved_packets(s);
                }
            }
            ln = link_list_get_next(list, ln);
        }
    }
}

/* 判断用户会话过程是否过时了 */
static int
check_session_obsolete(session_t *s, time_t cur, time_t threshold_time,
        time_t keepalive_timeout)
{
    int threshold = 256, result, diff;
    
    /* 如果很久没有收到测试服务器上层应用的响应 */
    if (s->resp_last_recv_cont_time < threshold_time) {
        if (s->unsend_packets->size > 0) {
            /* 存在缓冲数据包 */
            obs_cnt++;
            tc_log_debug2(LOG_DEBUG, 0, "timeout, unsend number:%u,p:%u",
                    s->unsend_packets->size, s->src_h_port);
            return OBSOLETE;
        }  else {
            if (s->sm.status >= SEND_REQ) {
                /* 已经传递过应用请求 */
                if (s->resp_last_recv_cont_time < keepalive_timeout) {
                    /* 超时 */
                    obs_cnt++;
                    tc_log_debug1(LOG_DEBUG, 0, "keepalive timeout ,p:%u", 
                            s->src_h_port);
                    return OBSOLETE;
                } else {
                    tc_log_debug1(LOG_DEBUG, 0, "session keepalive,p:%u",
                            s->src_h_port);
                    return NOT_YET_OBSOLETE;
                }
            } else {
                obs_cnt++;
                tc_log_debug1(LOG_DEBUG, 0, "wait timeout ,p:%u", 
                        s->src_h_port);
                return OBSOLETE;
            }
        }
    }

    diff = cur - s->resp_last_recv_cont_time;
    if (diff < 6) {
        threshold = threshold << 1;
    }

    diff = cur - s->req_last_send_cont_time;
    /* 判断是否这个用户会话是否闲置了很久 */
    if (diff < 30) {
        threshold = threshold << 2;
        if (diff <= 3) {
            /* 如果闲置的时间小于等于3秒，则增大缓存数据包的数量的阈值 */
            threshold = threshold << 4;
        }
        if (s->sm.last_window_full) {
            /* 如果测试服务器相应的tcp缓存区满了，则增大缓存数据包的数量的阈值 */
            threshold = threshold << 2;
        }
    }

    result = check_overwhelming(s, "unsend", threshold, 
            s->unsend_packets->size);
    if (NOT_YET_OBSOLETE != result) {
        return result;
    }

    result = check_overwhelming(s, "unack", threshold, 
            s->unack_packets->size);
    if (NOT_YET_OBSOLETE != result) {
        return result;
    }

    if (s->next_sess_packs) {
        result = check_overwhelming(s, "next session", threshold, 
                s->next_sess_packs->size);
        if (NOT_YET_OBSOLETE != result) {
            return result;
        }
    }

    return NOT_YET_OBSOLETE;
}


/*
 * 处理超时的用户会话
 */
static void
clear_timeout_sessions()
{
    int          result;
    size_t       i;           
    time_t       current, threshold_time, keepalive_timeout;
    link_list   *list;
    hash_node   *hn;
    session_t   *s;
    p_link_node  ln, tmp_ln;

    current = tc_time();
    threshold_time = current - clt_settings.session_timeout;
    keepalive_timeout = current - clt_settings.session_keepalive_timeout;

    tc_log_info(LOG_NOTICE, 0, "session size:%u", sessions_table->total);

    for (i = 0; i < sessions_table->size; i++) {

        list = sessions_table->lists[i];
        if (!list) {
            tc_log_info(LOG_WARN, 0, "list is null in sess table");
            continue;
        }

        ln   = link_list_first(list);   
        while (ln) {
            tmp_ln = link_list_get_next(list, ln);
            hn = (hash_node *) ln->data;
            if (hn->data != NULL) {

                s = hn->data;
                if (s->sm.sess_over) {
                    tc_log_info(LOG_WARN, 0, "wrong, del:%u", 
                            s->src_h_port);
                }
                result = check_session_obsolete(s, current, 
                        threshold_time, keepalive_timeout);
                if (OBSOLETE == result) {
                    hn->data = NULL;
                    session_rel_dynamic_mem(s);
                    if (!hash_del(sessions_table, s->hash_key)) {
                        tc_log_info(LOG_ERR, 0, "wrong del:%u", s->src_h_port);
                    }
                    free(s);
                }
            }
            ln = tmp_ln;
        }
    }
}


/*
 * 处理重传的细节
 * 目前只支持快速重传机制
 */
static bool 
retransmit_packets(session_t *s, uint32_t expected_seq)
{
    bool              need_pause = false, is_success = false;
    uint16_t          size_ip;
    uint32_t          cur_seq;
    link_list        *list;
    p_link_node       ln, tmp_ln;
    unsigned char    *frame;
    tc_ip_header_t   *ip_header;
    tc_tcp_header_t  *tcp_header;

    if (s->sm.status == SYN_SENT) {
        /* 目前对第一次握手数据包不进行重传,目的是为了不影响在线系统 */
        return true;
    }

    list = s->unack_packets;
    ln = link_list_first(list); 

    while (ln && (!need_pause)) {

        frame      = ln->data;
        ip_header  = (tc_ip_header_t *) (frame + ETHERNET_HDR_LEN);
        size_ip    = ip_header->ihl << 2;
        tcp_header = (tc_tcp_header_t *) ((char *) ip_header + size_ip);
        cur_seq    = ntohl(tcp_header->seq);  

        if (!is_success) {
            /* TODO 目前找重传包的机制需要改进 */
            if (cur_seq == expected_seq) {
                /* 找到快速重传的数据包 */
                is_success = true;
                tc_log_info(LOG_NOTICE, 0, "fast retransmit:%u",
                        s->src_h_port);
                wrap_retransmit_ip_packet(s, frame);
                need_pause = true;  
            } else if (before(cur_seq, s->resp_last_ack_seq)) {
                    tmp_ln = ln;
                    ln = link_list_get_next(list, ln);
                    link_list_remove(list, tmp_ln);
                    free(frame);
                    free(tmp_ln);
            } else {
                tc_log_info(LOG_NOTICE, 0, "no retrans pack:%u", s->src_h_port);
                need_pause = true;
            }
        }
    }
    
    return is_success;
}


/*
 * 更新未确认数据包列表
 */
static void
update_retransmission_packets(session_t *s)
{
    uint16_t          size_ip;
    uint32_t          cur_seq;
    link_list        *list;
    p_link_node       ln, tmp_ln;
    unsigned char    *frame;
    tc_ip_header_t   *ip_header;
    tc_tcp_header_t  *tcp_header;

    list = s->unack_packets;
    ln = link_list_first(list); 

    while (ln) {

        frame      = ln->data;
        ip_header  = (tc_ip_header_t *) (frame + ETHERNET_HDR_LEN);
        size_ip    = ip_header->ihl << 2;
        tcp_header = (tc_tcp_header_t *) ((char *) ip_header + size_ip);
        cur_seq    = ntohl(tcp_header->seq);  

        if (before(cur_seq, s->resp_last_ack_seq)) {
            tmp_ln = ln;
            ln = link_list_get_next(list, ln);
            link_list_remove(list, tmp_ln);
            free(frame);
            free(tmp_ln);
        } else {
            break;
        }
    }
}


/*
 * 检测用户会话的缓存的列表，是否存在上层应用的数据没有发出去
 */
static bool
check_reserved_content_left(session_t *s)
{
    uint16_t         size_ip;
    link_list       *list;
    p_link_node      ln;
    unsigned char   *frame;
    tc_ip_header_t  *ip_header;
    tc_tcp_header_t *tcp_header;

    tc_log_debug0(LOG_DEBUG, 0, "check_reserved_content_left");

    list = s->unsend_packets;
    ln = link_list_first(list); 

    while (ln) {
        frame = ln->data;
        ip_header = (tc_ip_header_t *) (frame + ETHERNET_HDR_LEN);
        size_ip = IP_HDR_LEN(ip_header);
        tcp_header = (tc_tcp_header_t *) ((char *) ip_header + size_ip);
        if (TCP_PAYLOAD_LENGTH(ip_header, tcp_header) > 0) {
            return true;
        }
        ln = link_list_get_next(list, ln);
    }
    return false;
}


/*
 * 伪造syn数据包,并发送出去
 */
static void
send_faked_syn(session_t *s, tc_ip_header_t *ip_header,
        tc_tcp_header_t *tcp_header)
{
    unsigned char   *p, frame[FAKE_FRAME_LEN];
    unsigned char   *opt;
    u_short          mss;
    tc_ip_header_t  *f_ip_header;
    tc_tcp_header_t *f_tcp_header;

    memset(frame, 0, FAKE_FRAME_LEN);
    p = frame + ETHERNET_HDR_LEN;
    f_ip_header  = (tc_ip_header_t *) p;
    f_tcp_header = (tc_tcp_header_t *) (p + IP_HEADER_LEN);
    opt = p + IP_HEADER_LEN + sizeof(tc_tcp_header_t);

    fill_pro_common_header(f_ip_header, f_tcp_header);
    f_ip_header->tot_len  = htons(FAKE_SYN_IP_DATAGRAM_LEN);
    f_tcp_header->doff    = TCP_HEADER_DOFF_MSS_VALUE;
    /* For an Ethernet this implies an MSS of up to 1460 bytes.*/
    mss = clt_settings.mss;
    mss = htons(mss);
    /* TCPOPT_MAXSEG flag */
    opt[0] = 2;
    opt[1] = 4;
    bcopy((void *) &mss, (void *) (opt + 2), sizeof(mss));

    s->req_ip_id = ntohs(ip_header->id);
    /* 
     * The identification field uniquely identifies 
     * each datagram sent by a host.
     * We here adopt a naive method
     */
    f_ip_header->id       = htons(s->req_ip_id - 2);

    f_ip_header->saddr    = ip_header->saddr;
    f_ip_header->daddr    = ip_header->daddr;
    f_tcp_header->source  = tcp_header->source;
    f_tcp_header->dest    = tcp_header->dest;
    f_tcp_header->syn     = 1;
    f_tcp_header->seq     = htonl(ntohl(tcp_header->seq) - 1);

    tc_log_debug_trace(LOG_DEBUG, 0, FAKED_CLIENT_FLAG,
            f_ip_header, f_tcp_header);

    wrap_send_ip_packet(s, frame, true);
    s->sm.req_halfway_intercepted = 1;
    s->sm.resp_syn_received = 0;
}

/* 填充timestamp时间戳信息 */
static void 
fill_timestamp(session_t *s, tc_tcp_header_t *tcp_header)
{
    uint32_t         timestamp;
    unsigned char   *opt, *p; 

    p   = (unsigned char *) tcp_header;
    opt = p + sizeof(tc_tcp_header_t);
    opt[0] = 1;
    opt[1] = 1;
    opt[2] = 8;
    opt[3] = 10;
    timestamp = htonl(s->ts_value);
    bcopy((void *) &timestamp, (void *) (opt + 4), sizeof(timestamp));
    timestamp = htonl(s->ts_ec_r);
    bcopy((void *) &timestamp, (void *) (opt + 8), sizeof(timestamp));
    tc_log_debug3(LOG_DEBUG, 0, "fill ts:%u,%u,p:%u", 
            s->ts_value, s->ts_ec_r, s->src_h_port);
}


/*
 * 发送伪造的第三次握手数据包给测试服务器
 */
static void 
send_faked_third_handshake(session_t *s, tc_ip_header_t *ip_header,
        tc_tcp_header_t *tcp_header)
{
    unsigned char    *p, frame[FAKE_FRAME_LEN];
    tc_ip_header_t   *f_ip_header;
    tc_tcp_header_t  *f_tcp_header;
 
    memset(frame, 0, FAKE_FRAME_LEN);
    p = frame + ETHERNET_HDR_LEN;
    f_ip_header  = (tc_ip_header_t *) p;
    f_tcp_header = (tc_tcp_header_t *) (p + IP_HEADER_LEN);
    fill_pro_common_header(f_ip_header, f_tcp_header);

    if (s->sm.timestamped) {
        f_ip_header->tot_len  = htons(FAKE_IP_TS_DATAGRAM_LEN);
        f_tcp_header->doff    = TCP_HEADER_DOFF_TS_VALUE;
        fill_timestamp(s, f_tcp_header);
    } else {
        f_ip_header->tot_len  = htons(FAKE_MIN_IP_DATAGRAM_LEN);
        f_tcp_header->doff    = TCP_HEADER_DOFF_MIN_VALUE;
    }

    f_ip_header->id       = htons(++s->req_ip_id);
    f_ip_header->saddr    = s->src_addr;
    f_ip_header->daddr    = s->online_addr; 
    f_tcp_header->source  = tcp_header->dest;
    f_tcp_header->dest    = s->online_port;
    f_tcp_header->ack     = 1;
    f_tcp_header->seq     = tcp_header->ack_seq;
    
    tc_log_debug_trace(LOG_DEBUG, 0, FAKED_CLIENT_FLAG,
            f_ip_header, f_tcp_header);

    wrap_send_ip_packet(s, frame, false);
}


/*
 * 根据测试服务器的响应包，来伪造ack确认数据包并发送出去
 */
static void 
send_faked_ack(session_t *s, tc_ip_header_t *ip_header, 
        tc_tcp_header_t *tcp_header, bool active)
{
    tc_ip_header_t   *f_ip_header;
    tc_tcp_header_t  *f_tcp_header;
    unsigned char    *p, frame[FAKE_FRAME_LEN];

    memset(frame, 0, FAKE_FRAME_LEN);
    p = frame + ETHERNET_HDR_LEN;
    f_ip_header  = (tc_ip_header_t *) p;
    f_tcp_header = (tc_tcp_header_t *) (p + IP_HEADER_LEN);

    fill_pro_common_header(f_ip_header, f_tcp_header);

    if (s->sm.timestamped) {
        f_ip_header->tot_len  = htons(FAKE_IP_TS_DATAGRAM_LEN);
        f_tcp_header->doff    = TCP_HEADER_DOFF_TS_VALUE;
        fill_timestamp(s, f_tcp_header);
    } else {
        f_ip_header->tot_len  = htons(FAKE_MIN_IP_DATAGRAM_LEN);
        f_tcp_header->doff    = TCP_HEADER_DOFF_MIN_VALUE;
    }

    f_ip_header->id       = htons(++s->req_ip_id);
    f_ip_header->saddr    = ip_header->daddr;
    f_tcp_header->source  = tcp_header->dest;
    f_tcp_header->ack     = 1;
    if (active) {
        /* 主动关闭 */
        f_tcp_header->seq = htonl(s->vir_next_seq);
    } else {
        /* 被动关闭 */
        f_tcp_header->seq = tcp_header->ack_seq;
    }
    s->sm.unack_pack_omit_save_flag = 1;
    wrap_send_ip_packet(s, frame, false);
}

/*
 * 根据测试服务器的响应包，来伪造reset数据包并发送出去
 */
static void 
send_faked_rst(session_t *s, tc_ip_header_t *ip_header,
        tc_tcp_header_t *tcp_header)
{
    uint16_t          cont_len;
    unsigned char     *p, frame[FAKE_FRAME_LEN];
    tc_ip_header_t   *f_ip_header;
    tc_tcp_header_t  *f_tcp_header;

    tc_log_debug2(LOG_DEBUG, 0, "unsend:%u,send faked rst:%u",
            s->unsend_packets->size, s->src_h_port);
   
    tc_log_debug1(LOG_DEBUG, 0, "send faked rst:%u", s->src_h_port);

    memset(frame, 0, FAKE_FRAME_LEN);
    p = frame + ETHERNET_HDR_LEN;
    f_ip_header  = (tc_ip_header_t *) p;
    f_tcp_header = (tc_tcp_header_t *) (p + IP_HEADER_LEN);
    fill_pro_common_header(f_ip_header, f_tcp_header);

    f_ip_header->tot_len  = htons(FAKE_MIN_IP_DATAGRAM_LEN);
    f_ip_header->id       = htons(++s->req_ip_id);
    f_ip_header->saddr    = ip_header->daddr;

    f_tcp_header->doff    = TCP_HEADER_DOFF_MIN_VALUE; 
    f_tcp_header->source  = tcp_header->dest;
    f_tcp_header->rst     = 1;
    f_tcp_header->ack     = 1;

    cont_len = TCP_PAYLOAD_LENGTH(ip_header, tcp_header);

    if (cont_len > 0) {   
        s->vir_ack_seq = htonl(ntohl(tcp_header->seq) + cont_len); 
    } else {
        s->vir_ack_seq = tcp_header->seq;
    }

    f_tcp_header->seq = tcp_header->ack_seq;
    s->sm.unack_pack_omit_save_flag = 1;
    wrap_send_ip_packet(s, frame, false);
    s->sm.reset_sent = 1;
}

/*
 * 伪造第一次握手数据包
 */
static void
fake_syn(session_t *s, tc_ip_header_t *ip_header, 
        tc_tcp_header_t *tcp_header, bool is_hard)
{
#if (!TCPCOPY_SINGLE)
    bool      result;
#endif
    uint16_t  target_port;
    uint64_t  new_key;

    if (is_hard) {
        tc_log_debug1(LOG_DEBUG, 0, "fake syn hard:%u", s->src_h_port);
        while (true) {
            target_port = get_port_by_rand_addition(tcp_header->source);
            s->src_h_port = target_port;
            target_port   = htons(target_port);
            new_key       = get_key(ip_header->saddr, target_port);
            if (hash_find(sessions_table, new_key) == NULL) {
                break;
            } else {
                tc_log_info(LOG_NOTICE, 0, "already exist:%u", s->src_h_port);
            }
        }

        hash_add(tf_port_table, new_key, (void *) (long) s->orig_src_port);
        tcp_header->source = target_port;
        s->faked_src_port  = tcp_header->source;
        s->sm.port_transfered = 1;

    } else {
        tc_log_debug1(LOG_DEBUG, 0, "fake syn with easy:%u", s->src_h_port);
    }
        
#if (!TCPCOPY_SINGLE)
    /* 发送第一次握手数据包过去之前，先传递路由信息 */
    result = send_router_info(s, CLIENT_ADD);
    if (!result) {
        return;
    }
#endif

    send_faked_syn(s, ip_header, tcp_header);

    s->sm.req_syn_ok = 1;
    if (is_hard) {
        recon_for_closed_cnt++;
    } else {
        recon_for_no_syn_cnt++;
    }
}

/* 检测来自测试服务器响应包的ack seq */
static int
check_backend_ack(session_t *s, tc_ip_header_t *ip_header,
         tc_tcp_header_t *tcp_header, uint32_t seq, 
         uint32_t ack, uint16_t cont_len)
{
    bool slide_window_empty = false;

    s->sm.resp_slow = 0;
    /* 如果测试服务器回应的ack seq大于我们所期望的ack seq */
    if (after(ack, s->vir_next_seq)) {
        tc_log_info(LOG_NOTICE, 0, "ack more than vir next seq");
        if (!s->sm.resp_syn_received) {
            send_faked_rst(s, ip_header, tcp_header);
            s->sm.sess_over = 1;
            return DISP_STOP;
        }
        s->vir_next_seq = ack;
    } else if (before(ack, s->vir_next_seq)) {

        /* 如果测试服务器回应的ack seq小于我们所期望的ack seq,说明测试服务器反应慢 */
        s->sm.resp_slow = 1;
        tc_log_debug3(LOG_DEBUG, 0, "bak_ack less than vir_next_seq:%u,%u,p:%u",
                ack, s->vir_next_seq, s->src_h_port);

        if (!s->sm.resp_syn_received) {
            /* 如果所对应的session之前没有接收到第二次握手数据包,就清理此会话过程 */
            send_faked_rst(s, ip_header, tcp_header);
            s->sm.sess_over = 1;
            return DISP_STOP;
        }

        if (s->sm.src_closed && !tcp_header->fin) {
            if (cont_len > 0) {
                send_faked_ack(s, ip_header, tcp_header, true);
            } else {
                send_faked_rst(s, ip_header, tcp_header);
            }
            return DISP_STOP;
        } else {
            /* 判断是否同时关闭连接 */
            if (s->sm.src_closed && tcp_header->fin) {
                s->sm.simul_closing = 1;
            }
        }

        /* 判断测试服务器针对此会话的tcp接收缓冲区是否满了 */
        if (tcp_header->window == 0) {
            tc_log_info(LOG_NOTICE, 0, "slide window zero:%u", s->src_h_port);
            /* 即使满了，也有可能需要重传 */
            if (!s->sm.last_window_full) {
                s->resp_last_ack_seq = ack;
                s->resp_last_seq     = seq;
                s->sm.last_window_full  = 1;
                update_retransmission_packets(s);
            }
            if (cont_len > 0) {
                send_faked_ack(s, ip_header, tcp_header, true);
                return DISP_STOP;
            }

        } else {
            if (s->sm.last_window_full) {
                s->sm.last_window_full = 0;
                s->resp_last_same_ack_num = 0;
                s->sm.vir_already_retransmit = 0;
                slide_window_empty = true;
            }
        }

        if (ack != s->resp_last_ack_seq) {
            s->resp_last_same_ack_num = 0;
            s->sm.vir_already_retransmit = 0;
            return DISP_CONTINUE;
        }

        if (cont_len > 0) {
            /* 如果这次响应包是带有payload的，那么就不需要进行重传检测 */
            s->resp_last_same_ack_num = 0;
            return DISP_CONTINUE;
        }

        /* 判断是否需要重传 */
        if (!tcp_header->fin && seq == s->resp_last_seq
                && ack == s->resp_last_ack_seq)
        {
            s->resp_last_same_ack_num++;
            /* 如果连续接收到重复的确认包，那么就意味着需要快速重传 */
            if (s->resp_last_same_ack_num > 2) {

                tc_log_info(LOG_WARN, 0, "bak lost packs:%u,same ack:%d", 
                        s->src_h_port, s->resp_last_same_ack_num);

                if (!s->sm.vir_already_retransmit) {
                    if (!retransmit_packets(s, ack)) {
                        /* 重传失败，发送reset数据包给测试服务器 */
                        send_faked_rst(s, ip_header, tcp_header);
                        s->sm.sess_over = 1;
                        return DISP_STOP;
                    }
                    s->sm.vir_already_retransmit = 1;
                } else {
                    tc_log_info(LOG_WARN, 0, "omit retransmit:%u",
                            s->src_h_port);
                }

                if (slide_window_empty) {
                    /* 当测试服务器的tcp缓冲区可以接受数据了，发送本会话所缓存的数据包 */
                    send_reserved_packets(s);
                }
                return DISP_STOP;
            }
        }
    }

    return DISP_CONTINUE;
}

/* 获取tcp的options选项 */
static void 
retrieve_options(session_t *s, int direction, tc_tcp_header_t *tcp_header)
{
    uint32_t       ts_value;
    unsigned int   opt, opt_len;
    unsigned char *p, *end;

    p = ((unsigned char *) tcp_header) + TCP_HEADER_MIN_LEN;
    end =  ((unsigned char *) tcp_header) + (tcp_header->doff << 2);  
    while (p < end) {
        opt = p[0];
        switch (opt) {
            case TCPOPT_WSCALE:
                if ((p + 1) >= end) {
                    return;
                }
                opt_len = p[1];
                if ((p + opt_len) > end) {
                    return;
                }
                s->wscale = (uint16_t) p[2];
                p += opt_len;
            case TCPOPT_TIMESTAMP:
                if ((p + 1) >= end) {
                    return;
                }
                opt_len = p[1];
                if ((p + opt_len) > end) {
                    return;
                }
                if (direction == LOCAL) {
                    ts_value = EXTRACT_32BITS(p + 2);
                } else {
                    s->ts_ec_r  = EXTRACT_32BITS(p + 2);
                    ts_value = EXTRACT_32BITS(p + 6);
                    if (tcp_header->syn) {
                        s->sm.timestamped = 1;
                        tc_log_debug1(LOG_DEBUG, 0, "timestamped,p=%u", 
                                s->src_h_port);
                    }
                    tc_log_debug3(LOG_DEBUG, 0, 
                            "get ts(client viewpoint):%u,%u,p:%u", 
                            s->ts_value, s->ts_ec_r, s->src_h_port);
                }
                if (ts_value > s->ts_value) {
                    tc_log_debug1(LOG_DEBUG, 0, "ts > history,p:%u",
                                s->src_h_port);
                    s->ts_value = ts_value;
                }
                p += opt_len;
            case TCPOPT_NOP:
                p = p + 1; 
                break;
            case TCPOPT_EOL:
                return;
            default:
                if ((p + 1) >= end) {
                    return;
                }
                opt_len = p[1];
                p += opt_len;
                break;
        }    
    }

    return;
}

/* 处理来自测试服务器的第二次握手数据包 */
static void
process_back_syn(session_t *s, tc_ip_header_t *ip_header,
        tc_tcp_header_t *tcp_header)
{
    uint16_t size_tcp;

    conn_cnt++;

    size_tcp = tcp_header->doff << 2;

    tc_log_debug2(LOG_DEBUG, 0, "recv syn from back, size tcp:%u, p:%u", 
            size_tcp, s->src_h_port);

    if (size_tcp > TCP_HEADER_MIN_LEN) {
        retrieve_options(s, REMOTE, tcp_header);
        if (s->wscale > 0) {
            tc_log_debug2(LOG_DEBUG, 0, "wscale:%u, p:%u", 
                    s->wscale, s->src_h_port);
        }
    }

    s->sm.resp_syn_received = 1;
    s->sm.status = SYN_CONFIRM;
    s->sm.dst_closed  = 0;
    s->sm.reset_sent  = 0;

    if (s->sm.req_halfway_intercepted) {
        send_faked_third_handshake(s, ip_header, tcp_header);
        send_reserved_packets(s);
    } else {
        send_reserved_packets(s);
    }

}

/* 处理来自测试服务器的fin数据包 */
static void
process_back_fin(session_t *s, tc_ip_header_t *ip_header,
        tc_tcp_header_t *tcp_header)
{
    tc_log_debug1(LOG_DEBUG, 0, "recv fin from back:%u", s->src_h_port);

    s->sm.dst_closed = 1;
    s->sm.candidate_response_waiting = 0;
    s->sm.status  |= SERVER_FIN;
    send_faked_ack(s, ip_header, tcp_header, s->sm.simul_closing?true:false);

    if (!s->sm.src_closed) {
        tcp_header->seq = htonl(ntohl(tcp_header->seq) + 1);
        /* 再次传递reset数据包给测试服务器 */
        send_faked_rst(s, ip_header, tcp_header);
    }
    s->sm.sess_over = 1;
}



/*
 * 处理来自测试服务器的响应包
 * TODO (还未考虑TCP Keepalive情况)
 */
void
process_backend_packet(session_t *s, tc_ip_header_t *ip_header,
        tc_tcp_header_t *tcp_header)
{
    time_t    current;
    uint16_t  size_ip, size_tcp, tot_len, cont_len;
    uint32_t  ack, seq;

    resp_cnt++;

    tc_log_debug_trace(LOG_DEBUG, 0, BACKEND_FLAG, ip_header, tcp_header);

    if ( tcp_header->rst) {
        s->sm.reset_sent = 1;
        s->sm.sess_over = 1;
        tc_log_debug1(LOG_DEBUG, 0, "reset from back:%u", s->src_h_port);
        return;
    }

    seq      = ntohl(tcp_header->seq);
    ack      = ntohl(tcp_header->ack_seq);
    tot_len  = ntohs(ip_header->tot_len);
    size_ip  = ip_header->ihl << 2;
    size_tcp = tcp_header->doff << 2;
    cont_len = tot_len - size_tcp - size_ip;

    current  = tc_time();

    s->srv_window = ntohs(tcp_header->window);
    tc_log_debug3(LOG_DEBUG, 0, "window value:%u,wscale value:%u,p:%u",
            s->srv_window, s->wscale, s->src_h_port);

    if (s->wscale) {
        s->srv_window = s->srv_window << (s->wscale);
    }

    if (s->sm.timestamped) {
        retrieve_options(s, REMOTE, tcp_header);
    }

    if (cont_len > 0) {

        if (s->sm.vir_new_retransmit) {
            retrans_succ_cnt++;
            s->sm.vir_new_retransmit = 0;
        }
        if (seq != s->resp_last_seq || ack != s->resp_last_ack_seq) {
            s->resp_last_same_ack_num = 0;
        }
        s->sm.vir_already_retransmit = 0;
        resp_cont_cnt++;
        s->resp_last_recv_cont_time = current;
        s->vir_ack_seq = htonl(seq + cont_len);
    } else {
        s->vir_ack_seq = tcp_header->seq;
    }

    if (check_backend_ack(s, ip_header, tcp_header, seq, ack, cont_len) 
            == DISP_STOP) {
        s->resp_last_ack_seq = ack;
        s->resp_last_seq     = seq;
        return;
    }

    s->resp_last_seq     = seq;
    s->resp_last_ack_seq = ack;
    update_retransmission_packets(s);

    if (tcp_header->syn) {

        s->vir_ack_seq = htonl(ntohl(s->vir_ack_seq) + 1);
        if (!s->sm.resp_syn_received) {
            process_back_syn(s, ip_header, tcp_header);
        } 
        return;
    } else if (tcp_header->fin) {

        s->vir_ack_seq = htonl(ntohl(s->vir_ack_seq) + 1);
        process_back_fin(s, ip_header, tcp_header);
        return;
    } else if (tcp_header->ack) {

        if (s->sm.src_closed && s->sm.dst_closed) {
            s->sm.sess_over = 1;
            return;
        }
    }

    if (!s->sm.resp_syn_received) {

        /* 如果收到了之前会话过程中的残留的响应包 */
        tc_log_info(LOG_NOTICE, 0, "unbelievable:%u", s->src_h_port);
        tc_log_trace(LOG_NOTICE, 0, BACKEND_FLAG, ip_header, tcp_header);
        /* 清理测试服务器的tcp资源,以便扫清会话障碍 */
        send_faked_rst(s, ip_header, tcp_header);
        s->sm.sess_over = 1;
        return;
    }

    /* 
     * 由于没有解析上层协议内容，
     * 导致无法判断这个带有payload的响应包是否是请求的最后一个响应包 
     */
    if (cont_len > 0) {

        if (s->sm.status < SEND_REQ) {
            if (!s->sm.resp_greet_received) {
                s->sm.resp_greet_received = 1;
                s->sm.need_resp_greet = 0;
            }
        }

        send_faked_ack(s, ip_header, tcp_header, true);

        if (tcp_header->window == 0) {
            /* 如果测试服务器的tcp的缓冲区满了，就返回 */
            return;
        }
            if (s->sm.candidate_response_waiting)
            {
                tc_log_debug0(LOG_DEBUG, 0, "receive back server's resp");
                s->sm.candidate_response_waiting = 0;
                s->sm.status = RECV_RESP;
                s->sm.delay_sent_flag = 0;
                s->sm.send_reserved_from_bak_payload = 1;
                send_reserved_packets(s);
                return;
            }
    } else {
        /* 不带payload的数据包处理过程 */

        if (tcp_header->window == 0) {
            return;
        }

        if (s->sm.delay_sent_flag || s->sm.req_no_resp) {
            tc_log_debug1(LOG_DEBUG, 0, "send delayed packets:%u", s->src_h_port);
            s->sm.delay_sent_flag = 0;
            send_reserved_packets(s);
            return;
        }
    }
}


/* 处理捕获的来自客户端的reset数据包 */
static void
process_client_rst(session_t *s, unsigned char *frame, 
        tc_ip_header_t *ip_header, tc_tcp_header_t *tcp_header)  
{
    uint32_t seq;

    tc_log_debug1(LOG_DEBUG, 0, "reset from client:%u", s->src_h_port);

    if (s->sm.candidate_response_waiting || s->unsend_packets->size > 0) {
        save_packet(s->unsend_packets, ip_header, tcp_header);
        send_reserved_packets(s);
    } else {
        seq = ntohl(tcp_header->seq);   
        if (before(seq, s->vir_next_seq)) {
            tcp_header->seq = htonl(s->vir_next_seq);
        }
        s->sm.unack_pack_omit_save_flag = 1;
        wrap_send_ip_packet(s, frame, true);
        s->sm.reset = 1;
    }
}


/* 处理捕获的来自客户端的第一次握手数据包 */
static void
process_client_syn(session_t *s, unsigned char *frame,
        tc_ip_header_t *ip_header, tc_tcp_header_t *tcp_header)  
{
    s->sm.req_syn_ok = 1;

    wrap_send_ip_packet(s, frame, true);
}

/* 处理捕获的来自客户端的fin数据包 */
static int
process_client_fin(session_t *s, unsigned char *frame,
        tc_ip_header_t *ip_header, tc_tcp_header_t *tcp_header)  
{
    uint16_t cont_len;
    uint32_t cur_ack;

    tc_log_debug1(LOG_DEBUG, 0, "recv fin from clt:%u", s->src_h_port);

    s->sm.recv_client_close = 1;

    if (s->sm.candidate_response_waiting) {
        cur_ack = ntohl(tcp_header->ack_seq);
        if (cur_ack == s->req_last_ack_sent_seq) {
            s->sm.candidate_response_waiting = 0;
            s->sm.req_no_resp = 1;
            tc_log_debug1(LOG_DEBUG, 0, "set candidate resp false :%u", 
                    s->src_h_port);
        }
    }

    cont_len = TCP_PAYLOAD_LENGTH(ip_header, tcp_header);
    if (cont_len > 0) {
        tc_log_debug1(LOG_DEBUG, 0, "fin has content:%u", s->src_h_port);
        return DISP_CONTINUE;
    }

    /* 根据经验 */
    if (s->resp_last_ack_seq == ntohl(tcp_header->seq)) {
        if (s->sm.candidate_response_waiting) {
            save_packet(s->unsend_packets, ip_header, tcp_header);
        } else {
            wrap_send_ip_packet(s, frame, true);
            s->sm.status |= CLIENT_FIN;
            s->sm.src_closed = 1;
        }

    } else {

        if (s->unsend_packets->size == 0) {
            tc_log_debug1(LOG_DEBUG, 0, "fin,set delay send flag:%u", 
                    s->src_h_port);
            s->sm.delay_sent_flag = 1;
        }
        save_packet(s->unsend_packets, ip_header, tcp_header);
    }

    return DISP_STOP;
}


/* 
 * 当测试服务器提前关闭会话过程，需要重新建立会话过程
 */
static void
proc_clt_cont_when_bak_closed(session_t *s, tc_ip_header_t *ip_header,
        tc_tcp_header_t *tcp_header)
{
    uint64_t key;

    if (s->sm.port_transfered) {
        key = get_key(ip_header->saddr, s->faked_src_port);
        if (!hash_del(tf_port_table, key)) {
            tc_log_info(LOG_WARN, 0, "no hash item for port transfer");
        }
    }

    session_init(s, SESS_KEEPALIVE);
    /* 将改变源端口，以绕开timewait问题 */
    fake_syn(s, ip_header, tcp_header, true);
    save_packet(s->unsend_packets, ip_header, tcp_header);

}


/* 检测捕获到的客户端数据包是否需要被缓存住 */
static int 
check_pack_save_or_not(session_t *s, tc_ip_header_t *ip_header,
        tc_tcp_header_t *tcp_header, int *is_new_req)
{
    bool        is_save = false;
    uint32_t    cur_seq;

    *is_new_req  = 0;

    /*
     * 如果之前的带有payload的数据包的ack seq不同于当前带有payload的数据包的ack seq，
     * 那么我们就认为当前的数据包是新的请求的数据包。
     * 尽管这个结论并不一定总是正确，但对于大部分场合，是适用的
     */
    if (s->req_cont_last_ack_seq != s->req_cont_cur_ack_seq) {
        *is_new_req = 1;
        tc_log_debug1(LOG_DEBUG, 0, "it is a new req,p:%u", s->src_h_port);
    }

    if (*is_new_req) {
        cur_seq = ntohl(tcp_header->seq);
        if (after(cur_seq, s->req_last_cont_sent_seq)) {
            is_save =true;
        }
    } else {
        if (s->unsend_packets->size > 0) {
            if (check_reserved_content_left(s)) {
                is_save = true;
            }
        } 
    }

    if (is_save) {
        save_packet(s->unsend_packets, ip_header, tcp_header);
        return DISP_STOP;
    } else {
        return DISP_CONTINUE;
    }
}


/* 检测是否需要等待晚到的数据包 */
static int
check_wait_prev_packet(session_t *s, unsigned char *frame,
        tc_ip_header_t *ip_header, tc_tcp_header_t *tcp_header, 
        uint16_t cont_len)
{
    int       diff;
    uint32_t  cur_seq, retransmit_seq;

    cur_seq = ntohl(tcp_header->seq);

    if (after(cur_seq, s->vir_next_seq)) {

        save_packet(s->unsend_packets, ip_header, tcp_header);
        send_reserved_packets(s);
        return DISP_STOP;
    } else if (cur_seq == s->vir_next_seq) {

        if (s->sm.is_waiting_previous_packet) {
            s->sm.is_waiting_previous_packet = 0;
            s->sm.candidate_response_waiting = 1;
            wrap_send_ip_packet(s, frame, true);
            send_reserved_packets(s);
            return DISP_STOP;
        } else {
            return DISP_CONTINUE;
        }
    } else {

        retransmit_seq = s->vir_next_seq - cont_len;
        if (!after(cur_seq, retransmit_seq)) {
            /* 检测出这是来自客户端的重传的数据包，可以大致判断在线压力的情况 */
            tc_log_debug1(LOG_DEBUG, 0, "retransmit from clt:%u",
                    s->src_h_port);
            if (tcp_header->fin) {
                s->sm.delay_sent_flag = 1;
            }
            clt_con_retrans_cnt++;
        } else {
            diff = s->vir_next_seq - cur_seq;
            if (trim_packet(s, ip_header, tcp_header, diff)) {
                return DISP_CONTINUE;
            }
        }
        return DISP_STOP;
    }
}

/* 检测是否是同一个请求的数据包 */
static int
is_continuous_packet(session_t *s, unsigned char *frame,
        tc_ip_header_t *ip_header, tc_tcp_header_t *tcp_header)
{
    uint32_t cur_seq = ntohl(tcp_header->seq);

    if (s->sm.candidate_response_waiting) {
        if (after(cur_seq, s->req_last_cont_sent_seq)) {
            wrap_send_ip_packet(s, frame, true);
            tc_log_debug0(LOG_DEBUG, 0, "it is a continuous req");
            return DISP_STOP;
        }
    }

    return DISP_CONTINUE;
}

/* 处理客户端数据包的最后一道处理过程 */
static void
process_clt_afer_filtering(session_t *s, unsigned char *frame,
        tc_ip_header_t *ip_header, tc_tcp_header_t *tcp_header, uint16_t len)
{
    if (!s->sm.candidate_response_waiting) {
        if (len > 0) {
            s->sm.candidate_response_waiting = 1;
            s->sm.send_reserved_from_bak_payload = 0;
            wrap_send_ip_packet(s, frame, true);
            return;
        } else if (SYN_CONFIRM == s->sm.status) {
            if (s->vir_next_seq == ntohl(tcp_header->seq)) {
                wrap_send_ip_packet(s, frame, true);
                return;
            }
        }
    }

    tc_log_debug1(LOG_DEBUG, 0, "drop packet:%u", s->src_h_port);
}


/*
 * 处理来自客户端的数据包
 * TODO 
 * 1)未考虑TCP Keepalive featured
 * 2)TCP is always allowed to send 1 byte of data 
 *   beyond the end of a closed window which confuses TCPCopy.
 * 
 */
void
process_client_packet(session_t *s, unsigned char *frame,
        tc_ip_header_t *ip_header, tc_tcp_header_t *tcp_header)
{
    int       is_new_req = 0;
    uint16_t  cont_len;
    uint32_t  srv_sk_buf_s;

    tc_log_debug_trace(LOG_DEBUG, 0, CLIENT_FLAG, ip_header, tcp_header);

    if (s->sm.port_transfered != 0) {
        /* 修改源端口，目的是为多重复制等场合 */
        tcp_header->source = s->faked_src_port;
    } 

    s->src_h_port = ntohs(tcp_header->source);

    /* 判断这个数据包是否是具有同样会话key的下一个会话的数据包 */
    if (s->sm.sess_more) {
        save_packet(s->next_sess_packs, ip_header, tcp_header);
        tc_log_debug1(LOG_DEBUG, 0, "buffer for next session:%u",
                s->src_h_port);
        return;
    }

    if (s->sm.last_window_full) {
        /* 如果测试服务器针对此会话的tcp接收缓冲区满了 */
        save_packet(s->unsend_packets, ip_header, tcp_header);
        return;
    }

    s->online_addr  = ip_header->daddr;
    s->online_port  = tcp_header->dest;

    if (s->sm.status == SYN_SENT) {
        /* 如果还没有收到第二次握手数据包，则缓存住客户端的数据包 */
        save_packet(s->unsend_packets, ip_header, tcp_header);
        return;
    }

    if (tcp_header->rst) {
        /* 处理reset数据包 */
        process_client_rst(s, frame, ip_header, tcp_header);
        return;
    }

    if (tcp_header->syn) {
        /* 处理syn数据包 */
        process_client_syn(s, frame, ip_header, tcp_header);
        return;
    }

    if (tcp_header->fin) {
        /* 处理fin数据包 */
        if (process_client_fin(s, frame, ip_header, tcp_header) == DISP_STOP) {
            return;
        }
    }

    if (!s->sm.recv_client_close) {
        /* 当还没有捕获到客户端的关闭数据包，记录下相关信息 */
        s->req_ack_before_fin = ntohl(tcp_header->ack_seq);
        s->sm.record_ack_before_fin = 1;
        tc_log_debug2(LOG_DEBUG, 0, "record:%u, p:%u",
                s->req_ack_before_fin, s->src_h_port);
    }

    if (!s->sm.req_syn_ok) {
        /* 如果没有机会收到客户端的syn数据包*/
        s->sm.req_halfway_intercepted = 1;
        fake_syn(s, ip_header, tcp_header, false);
        save_packet(s->unsend_packets, ip_header, tcp_header);
        return;
    }

    if (s->sm.status < SEND_REQ && is_wait_greet(s, ip_header, tcp_header)) {
        save_packet(s->unsend_packets, ip_header, tcp_header);
        return;
    }


    cont_len = TCP_PAYLOAD_LENGTH(ip_header, tcp_header);

    if (cont_len > 0) {
        s->req_cont_last_ack_seq = s->req_cont_cur_ack_seq;
        s->req_cont_cur_ack_seq  = ntohl(tcp_header->ack_seq);
        tc_log_debug2(LOG_DEBUG, 0, "cont len:%d,p:%u",
                cont_len, s->src_h_port);
        if (s->sm.dst_closed || s->sm.reset_sent) {
            proc_clt_cont_when_bak_closed(s, ip_header, tcp_header);
            return;
        }

        srv_sk_buf_s = s->vir_next_seq - s->resp_last_ack_seq  + cont_len;
        if (srv_sk_buf_s > s->srv_window) {
            tc_log_debug3(LOG_DEBUG, 0, "wait,srv_sk_buf_s:%u, win:%u, p:%u",
                    srv_sk_buf_s, s->srv_window, s->src_h_port);
            s->sm.delay_sent_flag = 1;
            save_packet(s->unsend_packets, ip_header, tcp_header);
            return;
        }

        /* 检测是否需要缓存住客户端的数据包 */
        if (s->sm.candidate_response_waiting) {
            if (check_pack_save_or_not(s, ip_header, tcp_header, &is_new_req)
                    == DISP_STOP)
            {
                return;
            }
        }

        /* 检测是否需要等待后到的数据包 */
        if (check_wait_prev_packet(s, frame, ip_header, tcp_header, cont_len)
                == DISP_STOP)
        {
            return;
        }

        /* 检测是否是同一个请求的数据包 */
        if (!is_new_req && is_continuous_packet(s, frame, ip_header, tcp_header)
                == DISP_STOP)
        {
            return;
        }

        tc_log_debug0(LOG_DEBUG, 0, "a new request from client");
    }

    /* 后处理过程 */
    process_clt_afer_filtering(s, frame, ip_header, tcp_header, cont_len);
}


void
restore_buffered_next_session(session_t *s)
{
    uint16_t          size_ip;
    p_link_node       ln;
    unsigned char    *frame;
    tc_ip_header_t   *ip_header;
    tc_tcp_header_t  *tcp_header;

    ln     = link_list_first(s->unsend_packets);    
    frame  = (unsigned char *) ln->data;
    link_list_remove(s->unsend_packets, ln);
    ip_header  = (tc_ip_header_t *) (frame + ETHERNET_HDR_LEN);
    size_ip    = ip_header->ihl << 2;
    tcp_header = (tc_tcp_header_t *) ((char *) ip_header + size_ip);

    process_client_packet(s, frame, ip_header,tcp_header);

    free(frame);
    free(ln);
}


/*
 * 对请求数据包进行过滤
 */
bool
is_packet_needed(unsigned char *packet)
{
    bool              is_needed = false;
    uint16_t          size_ip, size_tcp, tot_len, cont_len, header_len, key;
    tc_ip_header_t   *ip_header;
    tc_tcp_header_t  *tcp_header;

    ip_header = (tc_ip_header_t *) packet;

    captured_cnt++;

    /* 检测是否是tcp数据包 */
    if (ip_header->protocol != IPPROTO_TCP) {
        return is_needed;
    }

    size_ip   = ip_header->ihl << 2;
    if (size_ip < 20) {
        tc_log_info(LOG_WARN, 0, "Invalid IP header length: %d", size_ip);
        return is_needed;
    }

    tot_len    = ntohs(ip_header->tot_len);

    tcp_header = (tc_tcp_header_t *) ((char *) ip_header + size_ip);
    size_tcp   = tcp_header->doff << 2;
    if (size_tcp < 20) {
        tc_log_info(LOG_WARN, 0, "Invalid TCP header len: %d bytes,pack len:%d",
                size_tcp, tot_len);
        return is_needed;
    }

    /* 过滤出我们复制所关心的数据包 */
    if (LOCAL == check_pack_src(&(clt_settings.transfer), 
                ip_header->daddr, tcp_header->dest, CHECK_DEST)) {
        if (clt_settings.target_localhost) {
            if (ip_header->saddr != LOCALHOST) {
                tc_log_info(LOG_WARN, 0, "not localhost source ip address");
                return is_needed;
            }
        }
        header_len = size_tcp + size_ip;
        if (tot_len >= header_len) {

            if (clt_settings.percentage) {
                key = 0xFFFF & (tcp_header->source + ip_header->saddr);
                key = ((key & 0xFF00) >> 8) + (key & 0x00FF);
                key = key % 100;
                if (key >= clt_settings.percentage) {
                    return is_needed;
                }
            }
            is_needed = true;
            if (tcp_header->syn) {
                clt_syn_cnt++;
            } else {
                cont_len  = tot_len - header_len;
                if (cont_len > 0) {
                    clt_cont_cnt++;
                }
            }
            clt_packs_cnt++;
        } else {
            tc_log_info(LOG_WARN, 0, "bad tot_len:%d bytes, header len:%d",
                    tot_len, header_len);
        }
    } 

    return is_needed;

}


/*
 * 输出统计日志
 */
void
output_stat()
{
    int       run_time;
    double    ratio;

    if (start_p_time == 0) {
        return;
    }

    tc_log_info(LOG_NOTICE, 0, "active:%u,rel reqs:%llu,obs del:%llu",
            sessions_table->total, leave_cnt, obs_cnt);
    tc_log_info(LOG_NOTICE, 0, "conns:%llu,resp packs:%llu,c-resp packs:%llu",
            conn_cnt, resp_cnt, resp_cont_cnt);
    tc_log_info(LOG_NOTICE, 0, "send Packets:%llu,send content packets:%llu",
            packs_sent_cnt, con_packs_sent_cnt);
    tc_log_info(LOG_NOTICE, 0, "send fin Packets:%llu,send reset packets:%llu",
            fin_sent_cnt, rst_sent_cnt);
    tc_log_info(LOG_NOTICE, 0, "reconnect for closed :%llu,for no syn:%llu",
            recon_for_closed_cnt, recon_for_no_syn_cnt);
    tc_log_info(LOG_NOTICE, 0, "retransmit:%llu", retrans_cnt);
    tc_log_info(LOG_NOTICE, 0, "successful retransmit:%llu", retrans_succ_cnt);
    tc_log_info(LOG_NOTICE, 0, "syn cnt:%llu,all clt packs:%llu,clt cont:%llu",
            clt_syn_cnt, clt_packs_cnt, clt_cont_cnt);
    tc_log_info(LOG_NOTICE, 0, "total client content retransmit:%llu",
            clt_con_retrans_cnt);
    tc_log_info(LOG_NOTICE, 0, "total captured pakcets:%llu", captured_cnt);

    run_time = tc_time() - start_p_time;

    if (run_time > 3) {
        if (resp_cont_cnt == 0) {
            tc_log_info(LOG_NOTICE, 0, "no responses after %d secends",
                        run_time);
        }
        if (sessions_table->total > 0) {
            ratio = 100 * conn_cnt / sessions_table->total;
            if (ratio < 80) {
                tc_log_info(LOG_WARN, 0,
                        "many connections can't be established");
            }
        }
    }

}


void
tc_interval_dispose(tc_event_timer_t *evt)
{
    output_stat();

    clear_timeout_sessions();

    activate_dead_sessions();

    evt->msec = tc_current_time_msec + 5000;
}

/* 原始处理来自测试服务器的数据包 */
bool
process_out(unsigned char *packet)
{
    void              *ori_port;
    uint16_t           size_ip;
    uint64_t           key;
    session_t         *s;
    tc_ip_header_t    *ip_header;
    tc_tcp_header_t   *tcp_header;

    if (start_p_time == 0) {
        start_p_time = tc_time();
    }

    ip_header  = (tc_ip_header_t *) packet;
    size_ip    = ip_header->ihl << 2;
    tcp_header = (tc_tcp_header_t *) ((char *) ip_header + size_ip);


    key = get_key(ip_header->daddr, tcp_header->dest);
    s = hash_find(sessions_table, key);
    if (s == NULL) {
        ori_port = hash_find(tf_port_table, key);
        if (ori_port != NULL) {
            key = get_key(ip_header->daddr, (uint16_t) (long) ori_port);
            s = hash_find(sessions_table, key);
        }
    }

    if (s) {

        s->last_update_time = tc_time();
        process_backend_packet(s, ip_header, tcp_header);
        if (check_session_over(s)) {
            if (s->sm.sess_more) {
                /* 恢复捕获到的同一个会话key的下一个会话过程 */
                session_init_for_next(s);
                tc_log_info(LOG_NOTICE, 0, "init for next sess from bak");
                restore_buffered_next_session(s);
            } else {
                session_rel_dynamic_mem(s);
                if (!hash_del(sessions_table, s->hash_key)) {
                    tc_log_info(LOG_ERR, 0, "wrong del:%u", s->src_h_port);
                }
                free(s);
            }
        }
    } else {
        tc_log_debug_trace(LOG_DEBUG, 0, BACKEND_FLAG, ip_header,
                tcp_header);
        tc_log_debug0(LOG_DEBUG, 0, "no active session for me");
    }


    return true;
}

/* 原始处理来自客户端的数据包 */
bool
process_in(unsigned char *frame)
{
#if (!TCPCOPY_SINGLE)
    bool               result;
#endif
    uint16_t           size_ip;
    uint64_t           key;
    unsigned char     *packet;
    session_t         *s;
    tc_ip_header_t    *ip_header;
    tc_tcp_header_t   *tcp_header;

    if (start_p_time == 0) {
        start_p_time = tc_time();
    }

    packet     = frame + ETHERNET_HDR_LEN;
    ip_header  = (tc_ip_header_t *) packet;
    size_ip    = ip_header->ihl << 2;
    tcp_header = (tc_tcp_header_t *) ((char *) ip_header + size_ip);

    if (clt_settings.factor) {
        /* 改变源端口 */
        tcp_header->source = get_port_from_shift(tcp_header->source,
                clt_settings.rand_port_shifted, clt_settings.factor);
    }
    key = get_key(ip_header->saddr, tcp_header->source);
    if (tcp_header->syn) {

        s  = hash_find(sessions_table, key);
        if (s) {
            /* 检测是否是重复的syn数据包 */
            if (tcp_header->seq == s->req_last_syn_seq) {
                tc_log_debug0(LOG_DEBUG, 0, "duplicate syn");
                return true;
            } else {
                /*
                 * 缓存住下一个同样具有key的会话
                 */
                s->sm.sess_more = 1;
                if (s->next_sess_packs) {
                    if (s->next_sess_packs->size > 0) {
                        link_list_clear(s->next_sess_packs);
                    }
                } else {
                    s->next_sess_packs = link_list_create();
                }
                if (s->next_sess_packs) {
                    tc_log_debug0(LOG_DEBUG, 0, "buffer the new session");
                    save_packet(s->next_sess_packs, ip_header, tcp_header);
                } else {
                    tc_log_info(LOG_WARN, 0, "buffer new session failed");
                }
                return true;
            }
        } else {
            s = session_add(key, ip_header, tcp_header);
            if (s == NULL) {
                return true;
            }
        }

#if (!TCPCOPY_SINGLE)
        result = send_router_info(s, CLIENT_ADD);
        if (result) {
            process_client_packet(s, frame, ip_header, tcp_header);
        }
#else
        process_client_packet(s, frame, ip_header, tcp_header);
#endif

    } else {

        s = hash_find(sessions_table, key);
        if (s) {
            process_client_packet(s, frame, ip_header, tcp_header);
            s->last_update_time = tc_time();
            if (check_session_over(s)) {
                if (s->sm.sess_more) {
                    session_init_for_next(s);
                    tc_log_info(LOG_NOTICE, 0, "init for next from clt");
                    restore_buffered_next_session(s);
                } else {
                    session_rel_dynamic_mem(s);
                    if (!hash_del(sessions_table, s->hash_key)) {
                        tc_log_info(LOG_ERR, 0, "wrong del:%u",
                                s->src_h_port);
                    }
                    free(s);
                }
            }
        } else {
            /* 检测是否需要补充三次握手 */
            if (TCP_PAYLOAD_LENGTH(ip_header, tcp_header) > 0) {
                s = session_add(key, ip_header, tcp_header);
                if (s == NULL) {
                    return true;
                }
                process_client_packet(s, frame, ip_header, tcp_header);
            } else {
                return false;
            }
        }
    }

    return true;
}

