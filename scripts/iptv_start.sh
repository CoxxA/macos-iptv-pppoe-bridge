#!/bin/sh
CONF="/usr/local/etc/iptv.conf"
if [ ! -f "$CONF" ]; then
    echo "错误: 找不到配置文件 $CONF" >&2
    exit 1
fi

. "$CONF"

CUR_MAC=$(/sbin/ifconfig "$PHYS_IF" | /usr/bin/awk '/ether/{print $2}')
if [ "$CUR_MAC" != "$HOST_MAC" ]; then
    /sbin/ifconfig "$PHYS_IF" ether "$HOST_MAC"
fi

for i in $(/usr/bin/seq 1 15); do
    if /sbin/ifconfig "$PHYS_IF" | /usr/bin/grep -q "status: active"; then
        break
    fi
    sleep 1
done

/sbin/ifconfig feth0 destroy 2>/dev/null
/sbin/ifconfig feth1 destroy 2>/dev/null
/sbin/ifconfig feth0 create
/sbin/ifconfig feth1 create
/sbin/ifconfig feth0 peer feth1
/sbin/ifconfig feth0 lladdr "$STB_MAC" up
/sbin/ifconfig feth1 up

export IPTV_USER IPTV_PASS
exec /usr/local/bin/iptv_bridge "$PHYS_IF" feth1 "$STB_MAC"