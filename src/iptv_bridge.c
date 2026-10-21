/*
 * iptv_bridge.c - macOS 二合一 IPTV 专网 PPPoE 拨号与 IGMPv2 自动订阅守护桥
 *
 * 功能：
 * 1. 解决 macOS 内核 PPPoE.kext 因局端 LCP 早于 PADS 到达而抢发 PADT 断连的 Bug
 * 2. 直接通过 getifmaddrs() 监听 feth0 内核组播表，自动发送 IGMPv2 Join/Leave（无需外部 Python 脚本）
 *
 * 编译: clang -O2 -Wno-deprecated-declarations src/iptv_bridge.c -lpcap -o iptv_bridge
 * 运行: sudo env IPTV_USER="账号" IPTV_PASS="密码" ./iptv_bridge en0 feth1 <机顶盒MAC>
 */
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <CommonCrypto/CommonDigest.h>

#ifndef BIOCSHDRCMPLT
#define BIOCSHDRCMPLT _IOW('B', 117, u_int)
#endif

enum { ST_INIT = 0, ST_PADI_SENT, ST_PADR_SENT, ST_LCP, ST_AUTH, ST_IPCP, ST_OPEN };

typedef struct {
    uint8_t grp[4];
    double next_report;
    int active;
} mgroup_t;

static pcap_t *p_en0 = NULL, *p_feth = NULL;
static uint8_t stb_mac[6], bras_mac[6], my_ip[4] = {0, 0, 0, 0};
static uint16_t active_sid = 0, last_killed_sid = 0;
static int state = ST_INIT;
static int lcp_rx_ok = 0, lcp_tx_ok = 0, auth_proto = 0xc023;
static uint8_t ipcp_id = 1;
static uint8_t early_lcp[512];
static int early_lcp_len = 0;
static time_t last_action = 0, state_ts = 0, last_echo = 0;
static mgroup_t groups[64];
static int group_count = 0;

static const char *USER_STR = NULL;
static const char *PASS_STR = NULL;

static double now_sec(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec / 1000000.0;
}

static uint16_t csum(const void *buf, int len) {
    const uint16_t *w = (const uint16_t *)buf;
    uint32_t sum = 0;
    while (len > 1) { sum += *w++; len -= 2; }
    if (len == 1) sum += *(const uint8_t *)w;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

static void send_pppoe_disc(const uint8_t *dst, uint8_t code, uint16_t sid, const uint8_t *tags, int tags_len) {
    if (!p_en0) return;
    uint8_t pkt[512];
    memcpy(pkt, dst, 6);
    memcpy(pkt + 6, stb_mac, 6);
    pkt[12] = 0x88; pkt[13] = 0x63;
    pkt[14] = 0x11; pkt[15] = code;
    *(uint16_t *)(pkt + 16) = htons(sid);
    *(uint16_t *)(pkt + 18) = htons(tags_len);
    if (tags_len > 0) memcpy(pkt + 20, tags, tags_len);
    int len = 20 + tags_len;
    if (len < 60) { memset(pkt + len, 0, 60 - len); len = 60; }
    pcap_inject(p_en0, pkt, len);
}

static void send_ppp(uint16_t proto, const uint8_t *payload, int plen) {
    if (!p_en0 || active_sid == 0) return;
    uint8_t pkt[2048];
    memcpy(pkt, bras_mac, 6);
    memcpy(pkt + 6, stb_mac, 6);
    pkt[12] = 0x88; pkt[13] = 0x64;
    pkt[14] = 0x11; pkt[15] = 0x00;
    *(uint16_t *)(pkt + 16) = htons(active_sid);
    *(uint16_t *)(pkt + 18) = htons(plen + 2);
    *(uint16_t *)(pkt + 20) = htons(proto);
    memcpy(pkt + 22, payload, plen);
    int len = 22 + plen;
    if (len < 60) { memset(pkt + len, 0, 60 - len); len = 60; }
    pcap_inject(p_en0, pkt, len);
}

static void send_igmpv2(uint8_t type, const uint8_t *grp) {
    uint8_t ip[32];
    memset(ip, 0, sizeof(ip));
    ip[0] = 0x46; ip[1] = 0xc0;
    *(uint16_t *)(ip + 2) = htons(32);
    *(uint16_t *)(ip + 4) = htons(0x1357);
    ip[8] = 1; ip[9] = 2;
    memcpy(ip + 12, my_ip, 4);
    if (type == 0x16) memcpy(ip + 16, grp, 4);
    else { ip[16] = 224; ip[17] = 0; ip[18] = 0; ip[19] = 2; }
    ip[20] = 0x94; ip[21] = 0x04; ip[22] = 0x00; ip[23] = 0x00;
    *(uint16_t *)(ip + 10) = csum(ip, 24);

    ip[24] = type; ip[25] = 0x00;
    memcpy(ip + 28, grp, 4);
    *(uint16_t *)(ip + 26) = csum(ip + 24, 8);
    send_ppp(0x0021, ip, 32);
}

static void cleanup_and_exit(int sig) {
    if (state == ST_OPEN && active_sid != 0) {
        for (int i = 0; i < group_count; i++) {
            send_igmpv2(0x17, groups[i].grp);
        }
    }
    if (active_sid != 0) {
        send_pppoe_disc(bras_mac, 0xa7, active_sid, NULL, 0);
        printf("[*] 退出前已退订频道并发送 PADT 注销会话 0x%04x\n", active_sid);
    }
    exit(0);
}

static void send_lcp_req(void) {
    uint8_t req[] = { 0x01, 0x01, 0x00, 0x0e, 0x01, 0x04, 0x05, 0xd4, 0x05, 0x06, 0x14, 0x11, 0x7c, 0xc5 };
    send_ppp(0xc021, req, sizeof(req));
    last_action = time(NULL);
}

static void send_pap_req(void) {
    uint8_t pkt[256];
    int ulen = (int)strlen(USER_STR), plen = (int)strlen(PASS_STR);
    int total = 6 + ulen + plen;
    pkt[0] = 0x01; pkt[1] = 0x01;
    *(uint16_t *)(pkt + 2) = htons(total);
    pkt[4] = ulen; memcpy(pkt + 5, USER_STR, ulen);
    pkt[5 + ulen] = plen; memcpy(pkt + 6 + ulen, PASS_STR, plen);
    send_ppp(0xc023, pkt, total);
    last_action = time(NULL);
    printf("[>] 已发送 PAP 认证请求...\n");
}

static void send_ipcp_req(uint8_t id) {
    uint8_t req[10] = { 0x01, id, 0x00, 0x0a, 0x03, 0x06, my_ip[0], my_ip[1], my_ip[2], my_ip[3] };
    send_ppp(0x8021, req, sizeof(req));
    last_action = time(NULL);
}

// 直接监听 macOS 内核 feth0 组播成员表并发送 IGMPv2 Join/Leave
static void sync_feth_memberships(const char *ifname) {
    unsigned int idx = if_nametoindex(ifname);
    if (idx == 0) return;
    struct ifmaddrs *ifmap = NULL, *ifma;
    if (getifmaddrs(&ifmap) != 0) return;

    for (int i = 0; i < group_count; i++) groups[i].active = 0;
    double now = now_sec();

    for (ifma = ifmap; ifma != NULL; ifma = ifma->ifma_next) {
        if (!ifma->ifma_name || !ifma->ifma_addr) continue;
        if (ifma->ifma_name->sa_family != AF_LINK || ifma->ifma_addr->sa_family != AF_INET) continue;
        struct sockaddr_dl *sdl = (struct sockaddr_dl *)ifma->ifma_name;
        if (sdl->sdl_index != idx) continue;
        struct sockaddr_in *sin = (struct sockaddr_in *)ifma->ifma_addr;
        const uint8_t *g = (const uint8_t *)&sin->sin_addr.s_addr;
        if (g[0] != 239) continue;

        int found = -1;
        for (int i = 0; i < group_count; i++) {
            if (memcmp(groups[i].grp, g, 4) == 0) { found = i; break; }
        }
        if (found >= 0) {
            groups[found].active = 1;
            if (now >= groups[found].next_report) {
                send_igmpv2(0x16, g);
                groups[found].next_report = now + 25.0;
            }
        } else if (group_count < 64) {
            memcpy(groups[group_count].grp, g, 4);
            groups[group_count].active = 1;
            groups[group_count].next_report = now + 1.5;
            group_count++;
            send_igmpv2(0x16, g);
            printf("[>] 频道订阅 Join: %d.%d.%d.%d\n", g[0], g[1], g[2], g[3]);
        }
    }
    freeifmaddrs(ifmap);

    for (int i = 0; i < group_count; ) {
        if (!groups[i].active) {
            send_igmpv2(0x17, groups[i].grp);
            printf("[<] 频道退订 Leave: %d.%d.%d.%d\n",
                   groups[i].grp[0], groups[i].grp[1], groups[i].grp[2], groups[i].grp[3]);
            groups[i] = groups[group_count - 1];
            group_count--;
        } else {
            i++;
        }
    }
}

static void reset_to_wait(void) {
    if (active_sid != 0) {
        send_pppoe_disc(bras_mac, 0xa7, active_sid, NULL, 0);
        active_sid = 0;
    }
    state = ST_PADI_SENT;
    last_action = time(NULL);
    state_ts = time(NULL);
}

static void handle_lcp(const uint8_t *p, int len) {
    if (len < 4) return;
    uint8_t code = p[0];
    uint16_t l = ntohs(*(uint16_t *)(p + 2));
    if (l > len) l = len;

    if (code == 1) {
        int idx = 4;
        while (idx + 2 <= l) {
            uint8_t otype = p[idx], olen = p[idx + 1];
            if (olen < 2 || idx + olen > l) break;
            if (otype == 3 && olen >= 4) auth_proto = ntohs(*(uint16_t *)(p + idx + 2));
            idx += olen;
        }
        uint8_t ack[512];
        memcpy(ack, p, l);
        ack[0] = 2;
        send_ppp(0xc021, ack, l);
        lcp_rx_ok = 1;
        printf("[+] 已确认局端 LCP 请求 (认证: 0x%04x)\n", auth_proto);
    } else if (code == 2) {
        lcp_tx_ok = 1;
        printf("[+] 局端已确认本机 LCP 请求\n");
    } else if (code == 5) {
        uint8_t ack[64];
        int alen = l < 64 ? l : 64;
        memcpy(ack, p, alen);
        ack[0] = 6;
        send_ppp(0xc021, ack, alen);
        printf("[-] 收到局端 LCP 断开请求，3 秒后重拨...\n");
        reset_to_wait();
        return;
    } else if (code == 9 && l >= 8) {
        uint8_t rep[64];
        int rlen = l < 64 ? l : 64;
        memcpy(rep, p, rlen);
        rep[0] = 10;
        uint32_t magic = htonl(0x14117cc5);
        memcpy(rep + 4, &magic, 4);
        send_ppp(0xc021, rep, rlen);
        return;
    }

    if ((state == ST_LCP || state == ST_AUTH) && lcp_rx_ok && lcp_tx_ok) {
        state = ST_AUTH;
        state_ts = time(NULL);
        if (auth_proto == 0xc023) send_pap_req();
    }
}

int main(int argc, char *argv[]) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IOLBF, 0);

    USER_STR = getenv("IPTV_USER");
    PASS_STR = getenv("IPTV_PASS");
    if (argc < 4 || !USER_STR || !PASS_STR) {
        fprintf(stderr, "用法: sudo env IPTV_USER=账号 IPTV_PASS=密码 %s <物理网卡> <feth1> <机顶盒MAC>\n", argv[0]);
        return 1;
    }

    signal(SIGINT, cleanup_and_exit);
    signal(SIGTERM, cleanup_and_exit);
    signal(SIGHUP, cleanup_and_exit);

    char errbuf[PCAP_ERRBUF_SIZE];
    sscanf(argv[3], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &stb_mac[0], &stb_mac[1], &stb_mac[2], &stb_mac[3], &stb_mac[4], &stb_mac[5]);

    p_en0 = pcap_create(argv[1], errbuf);
    pcap_set_snaplen(p_en0, 2048);
    pcap_set_promisc(p_en0, 1);
    pcap_set_timeout(p_en0, 1);
    pcap_set_immediate_mode(p_en0, 1);
    pcap_activate(p_en0);
    pcap_setnonblock(p_en0, 1, errbuf);

    p_feth = pcap_create(argv[2], errbuf);
    pcap_set_snaplen(p_feth, 2048);
    pcap_set_promisc(p_feth, 1);
    pcap_set_timeout(p_feth, 1);
    pcap_set_immediate_mode(p_feth, 1);
    pcap_activate(p_feth);
    pcap_setnonblock(p_feth, 1, errbuf);

    u_int one = 1;
    ioctl(pcap_fileno(p_en0), BIOCSHDRCMPLT, &one);
    ioctl(pcap_fileno(p_feth), BIOCSHDRCMPLT, &one);

    int fd_en0 = pcap_get_selectable_fd(p_en0);
    int fd_feth = pcap_get_selectable_fd(p_feth);
    int max_fd = (fd_en0 > fd_feth ? fd_en0 : fd_feth) + 1;
    double last_igmp_check = 0;

    printf("[*] 二合一 IPTV 专网守护桥已启动 (%s <-> %s, 拨号MAC: %s)\n", argv[1], argv[2], argv[3]);

    while (1) {
        time_t now = time(NULL);
        double dnow = now_sec();

        if (state != ST_OPEN && state != ST_INIT && state != ST_PADI_SENT && now - state_ts >= 8) {
            printf("[-] 握手超时，清理会话并重拨...\n");
            reset_to_wait();
        }

        if (state == ST_INIT || (state == ST_PADI_SENT && now - last_action >= 3)) {
            group_count = 0;
            uint8_t bcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
            uint8_t tags[] = { 0x01, 0x01, 0x00, 0x00 };
            send_pppoe_disc(bcast, 0x09, 0x0000, tags, sizeof(tags));
            state = ST_PADI_SENT;
            last_action = now;
            state_ts = now;
            printf("[>] 已发送 PADI 寻呼广播...\n");
        } else if (state == ST_LCP && now - last_action >= 2) {
            if (!lcp_tx_ok) send_lcp_req();
        } else if (state == ST_AUTH && auth_proto == 0xc023 && now - last_action >= 2) {
            send_pap_req();
        } else if (state == ST_IPCP && now - last_action >= 2) {
            send_ipcp_req(ipcp_id);
        } else if (state == ST_OPEN) {
            if (dnow - last_igmp_check >= 0.15) {
                sync_feth_memberships("feth0");
                last_igmp_check = dnow;
            }
            if (now - last_echo >= 20) {
                uint8_t echo[] = { 0x09, 0x01, 0x00, 0x08, 0x14, 0x11, 0x7c, 0xc5 };
                send_ppp(0xc021, echo, sizeof(echo));
                last_echo = now;
            }
        }

        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(fd_en0, &fds);
        FD_SET(fd_feth, &fds);
        struct timeval tv = {0, 20000};
        select(max_fd, &fds, NULL, NULL, &tv);

        struct pcap_pkthdr *h;
        const u_char *d;

        while (pcap_next_ex(p_en0, &h, &d) == 1) {
            if (h->caplen < 20) continue;
            if (memcmp(d, stb_mac, 6) != 0 || memcmp(d + 6, stb_mac, 6) == 0) continue;
            uint16_t etype = ntohs(*(uint16_t *)(d + 12));

            if (etype == 0x8863) {
                uint8_t code = d[15];
                uint16_t sid = ntohs(*(uint16_t *)(d + 16));
                uint16_t plen = ntohs(*(uint16_t *)(d + 18));
                if (code == 0x07 && state == ST_PADI_SENT) {
                    memcpy(bras_mac, d + 6, 6);
                    uint8_t rtags[256];
                    int rlen = 0, idx = 20;
                    while (idx + 4 <= (int)h->caplen && idx < 20 + plen) {
                        uint16_t t = ntohs(*(uint16_t *)(d + idx));
                        uint16_t l = ntohs(*(uint16_t *)(d + idx + 2));
                        if (t == 0x0101 || t == 0x0103 || t == 0x0104 || t == 0x0110) {
                            if (rlen + 4 + l <= (int)sizeof(rtags)) {
                                memcpy(rtags + rlen, d + idx, 4 + l);
                                rlen += 4 + l;
                            }
                        }
                        idx += 4 + l;
                    }
                    send_pppoe_disc(bras_mac, 0x19, 0x0000, rtags, rlen);
                    state = ST_PADR_SENT;
                    state_ts = time(NULL);
                    early_lcp_len = 0;
                    last_action = time(NULL);
                    printf("[+] 收到局端 PADO，已发送 PADR 请求会话...\n");
                } else if (code == 0x65 && (state == ST_PADR_SENT || state == ST_LCP)) {
                    active_sid = sid;
                    state = ST_LCP;
                    state_ts = time(NULL);
                    lcp_rx_ok = lcp_tx_ok = 0;
                    printf("[+] 收到局端 PADS (会话 0x%04x)，开始 LCP 协商...\n", active_sid);
                    send_lcp_req();
                    if (early_lcp_len > 0) {
                        handle_lcp(early_lcp, early_lcp_len);
                        early_lcp_len = 0;
                    }
                } else if (code == 0xa7 && sid == active_sid && active_sid != 0) {
                    printf("[-] 收到局端 PADT 断开，3 秒后自动重拨...\n");
                    active_sid = 0;
                    reset_to_wait();
                }
            } else if (etype == 0x8864 && h->caplen >= 22) {
                uint16_t sid = ntohs(*(uint16_t *)(d + 16));
                uint16_t pproto = ntohs(*(uint16_t *)(d + 20));
                int plen = ntohs(*(uint16_t *)(d + 18)) - 2;
                if (plen > (int)h->caplen - 22) plen = h->caplen - 22;
                const uint8_t *p = d + 22;

                if (state == ST_PADR_SENT && pproto == 0xc021 && plen > 0 && plen <= (int)sizeof(early_lcp)) {
                    memcpy(early_lcp, p, plen);
                    early_lcp_len = plen;
                    printf("[!] 捕获并缓存提前于 PADS 到达的 LCP 报文 (会话 0x%04x)...\n", sid);
                    continue;
                }
                if (sid != active_sid) {
                    if (sid != 0 && sid != last_killed_sid) {
                        send_pppoe_disc(d + 6, 0xa7, sid, NULL, 0);
                        last_killed_sid = sid;
                        printf("[!] 清理残留旧会话 0x%04x (已发送 PADT)\n", sid);
                    }
                    continue;
                }

                if (pproto == 0xc021) {
                    handle_lcp(p, plen);
                } else if (pproto == 0xc023 && plen >= 4) {
                    if (p[0] == 2) {
                        printf("[+] PAP 认证通过！正在获取专网 IP...\n");
                        state = ST_IPCP;
                        state_ts = time(NULL);
                        ipcp_id = 1;
                        send_ipcp_req(ipcp_id);
                    } else if (p[0] == 3) {
                        printf("[-] PAP 认证被拒，清理后 3 秒重拨...\n");
                        reset_to_wait();
                    }
                } else if (pproto == 0xc223 && plen >= 5 && p[0] == 1) {
                    uint8_t cid = p[1], vlen = p[4];
                    uint8_t md5_in[256], md5_out[16], resp[256];
                    int pass_len = (int)strlen(PASS_STR), user_len = (int)strlen(USER_STR);
                    md5_in[0] = cid;
                    memcpy(md5_in + 1, PASS_STR, pass_len);
                    memcpy(md5_in + 1 + pass_len, p + 5, vlen);
                    CC_MD5(md5_in, 1 + pass_len + vlen, md5_out);
                    int rtot = 5 + 16 + user_len;
                    resp[0] = 2; resp[1] = cid;
                    *(uint16_t *)(resp + 2) = htons(rtot);
                    resp[4] = 16;
                    memcpy(resp + 5, md5_out, 16);
                    memcpy(resp + 21, USER_STR, user_len);
                    send_ppp(0xc223, resp, rtot);
                } else if (pproto == 0xc223 && plen >= 4 && p[0] == 3) {
                    state = ST_IPCP;
                    state_ts = time(NULL);
                    ipcp_id = 1;
                    send_ipcp_req(ipcp_id);
                } else if (pproto == 0x8021 && plen >= 4) {
                    uint8_t code = p[0], id = p[1];
                    uint16_t l = ntohs(*(uint16_t *)(p + 2));
                    if (l > plen) l = plen;
                    if (code == 1) {
                        uint8_t ack[256];
                        memcpy(ack, p, l);
                        ack[0] = 2;
                        send_ppp(0x8021, ack, l);
                    } else if (code == 3 || code == 2) {
                        int idx = 4;
                        while (idx + 2 <= l) {
                            uint8_t ot = p[idx], ol = p[idx + 1];
                            if (ol < 2 || idx + ol > l) break;
                            if (ot == 3 && ol == 6) memcpy(my_ip, p + idx + 2, 4);
                            idx += ol;
                        }
                        if (code == 3) {
                            ipcp_id = id + 1;
                            send_ipcp_req(ipcp_id);
                        } else if (code == 2 && my_ip[0] != 0 && state != ST_OPEN) {
                            state = ST_OPEN;
                            last_echo = time(NULL);
                            printf("✅ IPTV 专网拨号成功！内网 IP: %d.%d.%d.%d (已内置 IGMP 自动选台订阅)\n",
                                   my_ip[0], my_ip[1], my_ip[2], my_ip[3]);
                            char cmd[512];
                            snprintf(cmd, sizeof(cmd),
                                     "/sbin/ifconfig feth0 inet %d.%d.%d.%d netmask 255.255.255.0 up && "
                                     "/sbin/route -n delete -net 239.0.0.0/8 >/dev/null 2>&1; "
                                     "/sbin/route -n add -net 239.0.0.0/8 -interface feth0 >/dev/null 2>&1; "
                                     "/usr/bin/killall rtp2httpd >/dev/null 2>&1",
                                     my_ip[0], my_ip[1], my_ip[2], my_ip[3]);
                            system(cmd);
                        }
                    } else if (code == 4) {
                        ipcp_id = id + 1;
                        send_ipcp_req(ipcp_id);
                    }
                } else if (pproto == 0x0021 && state == ST_OPEN && plen >= 20) {
                    uint8_t frame[2048];
                    int ip_pkt_len = ntohs(*(uint16_t *)(p + 2));
                    if (ip_pkt_len > 0 && ip_pkt_len <= plen) plen = ip_pkt_len;
                    if ((p[16] & 0xf0) == 0xe0) {
                        frame[0] = 0x01; frame[1] = 0x00; frame[2] = 0x5e;
                        frame[3] = p[17] & 0x7f; frame[4] = p[18]; frame[5] = p[19];
                    } else {
                        memcpy(frame, stb_mac, 6);
                    }
                    memcpy(frame + 6, bras_mac, 6);
                    frame[12] = 0x08; frame[13] = 0x00;
                    memcpy(frame + 14, p, plen);
                    pcap_inject(p_feth, frame, 14 + plen);
                }
            }
        }

        while (pcap_next_ex(p_feth, &h, &d) == 1) {
            // 排空 feth1 缓冲
        }
    }
    return 0;
}