#!/usr/bin/env python3
"""
macOS 电信 IPTV 机顶盒 PPPoE 明文密码与 MAC 提取工具
用法: sudo python3 extract_pppoe_pass.py --iface en0
"""
import argparse
import os
import struct
from scapy.all import sniff, sendp, get_if_hwaddr

SESSION_ID = 0x1234


def parse_tags(data):
    tags, idx = [], 0
    while idx + 4 <= len(data):
        t_type, t_len = struct.unpack("!HH", data[idx:idx + 4])
        tags.append((t_type, data[idx + 4:idx + 4 + t_len]))
        idx += 4 + t_len
    return tags


def build_tags(tags):
    return b"".join(struct.pack("!HH", t, len(v)) + v for t, v in tags)


def main():
    parser = argparse.ArgumentParser(description="提取 IPTV 机顶盒 PPPoE 账号与明文密码")
    parser.add_argument("-i", "--iface", default="en0", help="监听的物理网卡名称 (默认: en0)")
    args = parser.parse_args()

    my_mac_str = get_if_hwaddr(args.iface)
    my_mac = bytes.fromhex(my_mac_str.replace(":", ""))

    def send_eth(dst_mac, vlan_hdr, eth_type, payload):
        frame = dst_mac + my_mac + vlan_hdr + struct.pack("!H", eth_type) + payload
        sendp(frame, iface=args.iface, verbose=False)

    def handle_pkt(pkt):
        frame = bytes(pkt)
        if len(frame) < 14:
            return
        src_mac = frame[6:12]
        if src_mac == my_mac:
            return

        eth_type = struct.unpack("!H", frame[12:14])[0]
        vlan_hdr, offset = b"", 14
        if eth_type == 0x8100 and len(frame) >= 18:
            vlan_hdr = frame[12:16]
            eth_type = struct.unpack("!H", frame[16:18])[0]
            offset = 18

        if eth_type not in (0x8863, 0x8864):
            return

        raw = frame[offset:]
        src_mac_str = ":".join(f"{b:02x}" for b in src_mac)

        if eth_type == 0x8863 and len(raw) >= 6:
            code, length = raw[1], struct.unpack("!H", raw[4:6])[0]
            in_tags = parse_tags(raw[6:6 + length])
            reply_tags = [(t, v) for (t, v) in in_tags if t in (0x0101, 0x0103, 0x0110)]
            if not any(t == 0x0101 for t, _ in reply_tags):
                reply_tags.insert(0, (0x0101, b""))
            reply_tags.append((0x0102, b"IPTV-BRAS"))

            if code == 0x09:  # PADI -> PADO
                payload = build_tags(reply_tags)
                pado = struct.pack("!BBHH", 0x11, 0x07, 0x0000, len(payload)) + payload
                send_eth(src_mac, vlan_hdr, 0x8863, pado)
                print(f"[1/3] 收到机顶盒 ({src_mac_str}) 拨号寻呼 (PADI)，已回复 PADO...")

            elif code == 0x19:  # PADR -> PADS + LCP Req (PAP)
                payload = build_tags(reply_tags)
                pads = struct.pack("!BBHH", 0x11, 0x65, SESSION_ID, len(payload)) + payload
                send_eth(src_mac, vlan_hdr, 0x8863, pads)
                lcp_req = b"\x01\x01\x00\x08\x03\x04\xc0\x23"
                pppoe_lcp = struct.pack("!BBHH", 0x11, 0x00, SESSION_ID, len(lcp_req) + 2) + b"\xc0\x21" + lcp_req
                send_eth(src_mac, vlan_hdr, 0x8864, pppoe_lcp)
                print(f"[2/3] 机顶盒 ({src_mac_str}) 已请求会话 (PADR)，正在协商 PAP 明文认证...")

        elif eth_type == 0x8864 and len(raw) >= 8:
            pkt_sess = struct.unpack("!H", raw[2:4])[0]
            if pkt_sess != SESSION_ID:
                padt = struct.pack("!BBHH", 0x11, 0xA7, pkt_sess, 0)
                send_eth(src_mac, vlan_hdr, 0x8863, padt)
                return

            ppp_proto = struct.unpack("!H", raw[6:8])[0]
            ppp_data = raw[8:]

            if ppp_proto == 0xC021 and len(ppp_data) >= 4 and ppp_data[0] == 1:
                lcp_id, lcp_len = ppp_data[1], struct.unpack("!H", ppp_data[2:4])[0]
                lcp_ack = struct.pack("!BBH", 2, lcp_id, lcp_len) + ppp_data[4:lcp_len]
                pppoe_ack = struct.pack("!BBHH", 0x11, 0x00, SESSION_ID, len(lcp_ack) + 2) + b"\xc0\x21" + lcp_ack
                send_eth(src_mac, vlan_hdr, 0x8864, pppoe_ack)
                lcp_req = b"\x01\x02\x00\x08\x03\x04\xc0\x23"
                pppoe_lcp = struct.pack("!BBHH", 0x11, 0x00, SESSION_ID, len(lcp_req) + 2) + b"\xc0\x21" + lcp_req
                send_eth(src_mac, vlan_hdr, 0x8864, pppoe_lcp)

            elif ppp_proto == 0xC023 and len(ppp_data) >= 6 and ppp_data[0] == 1:
                u_len = ppp_data[4]
                user = ppp_data[5:5 + u_len].decode("utf-8", errors="ignore")
                p_len = ppp_data[5 + u_len]
                pwd = ppp_data[6 + u_len:6 + u_len + p_len].decode("utf-8", errors="ignore")
                print("\n========================================")
                print("[3/3] 成功提取电信机顶盒 PPPoE 明文信息：")
                print(f"STB_MAC=\"{src_mac_str}\"")
                print(f"IPTV_USER=\"{user}\"")
                print(f"IPTV_PASS=\"{pwd}\"")
                print("========================================\n")
                os._exit(0)

    print(f"[*] 正在监听网卡 {args.iface} (本机 MAC: {my_mac_str})")
    print("[*] 请先拔掉光猫 ITV 口网线，然后将机顶盒断电重启或重新拔插机顶盒网线...")
    sniff(iface=args.iface, prn=handle_pkt, store=0)


if __name__ == "__main__":
    main()