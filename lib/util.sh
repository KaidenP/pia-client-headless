#!/bin/bash

# Colors
if [[ -t 1 ]]; then
  ncolors=$(tput colors)
  if [[ -n $ncolors && $ncolors -ge 8 ]]; then
    red=$(tput setaf 1) # ANSI red
    green=$(tput setaf 2) # ANSI green
    nc=$(tput sgr0) # No Color
  else
    red=''
    green=''
    nc='' # No Color
  fi
fi

# Only allow script to run as root
if (( EUID != 0 )); then
  echo -e "${red}This script needs to be run as root. Try again with 'sudo $0'${nc}"
  exit 1
fi

if [ ! -f conf/auth.secrets ]; then
  echo -e "${red}Error: conf/auth.secrets file not found. Please create it with your PIA username and password.${nc}"
  exit 1
fi

source conf/auth.secrets
PIA_TOKEN=""

if [[ -z $PIA_USER ]] || [[ -z $PIA_PASS ]]; then
    echo -e "${red}Error: PIA_USER and PIA_PASS must be set in conf/auth.secrets.${nc}"
    exit 1
fi

reset_killswitch() {
    echo -e "${green}Resetting the killswitch...${nc}"
    rm /etc/resolv.conf
    echo "nameserver 8.8.8.8" > /etc/resolv.conf
    echo "nameserver 8.8.4.4" >> /etc/resolv.conf

    iptables -F
    iptables -t nat -F
    iptables -t mangle -F
    iptables -X
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT DROP

    # Allow existing connections to continue
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # Allow local connections
    iptables -A INPUT -i eth0 -s 10.0.0.0/16 -j ACCEPT
    iptables -A OUTPUT -o eth0 -d 10.0.0.0/16 -j ACCEPT
    
    # Allow all loopback traffic
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT

    # Allow VPN traffic
    iptables -A INPUT -i pia -j ACCEPT
    iptables -A OUTPUT -o pia -j ACCEPT

    # Allow outgoing DNS
    iptables -A OUTPUT -p udp --dport 53 -d 8.8.8.8 -j ACCEPT
    iptables -A OUTPUT -p udp --dport 53 -d 8.8.4.4 -j ACCEPT

    # Whitelist Table
    iptables -N piawhitelist
    iptables -A INPUT -j piawhitelist
    iptables -A OUTPUT -j piawhitelist


    # Block all ipv6 traffic
    ip6tables -P INPUT DROP
    ip6tables -P FORWARD DROP
    ip6tables -P OUTPUT DROP
}

get_ip() {
    dig +short "$1" | head -n 1
}

iptables_whitelist_IP() {
    if iptables-save | grep piawhitelist | grep 142.251.33.163; then
        echo -e "${green}IP $1 is already whitelisted.${nc}"
        return
    else
        echo -e "${green}Whitelisting IP $1...${nc}"
        iptables -A piawhitelist -s $1 -j ACCEPT
        iptables -A piawhitelist -d $1 -j ACCEPT
    fi
}

getToken() {
  echo -e "${green}Getting auth token...${nc}"
  ip=$(get_ip www.privateinternetaccess.com)
  iptables_whitelist_IP $ip
  generateTokenResponse=$(curl -s --location --request POST \
    --connect-to "www.privateinternetaccess.com::$ip:" \
    'https://www.privateinternetaccess.com/api/client/v2/token' \
    --form "username=$PIA_USER" \
    --form "password=$PIA_PASS" )

    if [ "$(echo "$generateTokenResponse" | jq -r '.token')" == "" ]; then
        echo -e "${red}Could not authenticate with the login credentials provided!${nc}"
        exit 1
    fi

    echo -e "${green}OK!$nc"
    PIA_TOKEN=$(echo "$generateTokenResponse" | jq -r '.token')
}

getDIP() {
    ip=$(get_ip www.privateinternetaccess.com)
    iptables_whitelist_IP $ip
    generateDIPResponse=$(curl -s --location --request POST \
        --connect-to "www.privateinternetaccess.com::$ip:" \
        'https://www.privateinternetaccess.com/api/client/v2/dedicated_ip' \
        --header 'Content-Type: application/json' \
        --header "Authorization: Token $PIA_TOKEN" \
        --data-raw '{"tokens":["'"$PIA_DIP"'"]}'
    )
    if [ "$(echo "$generateDIPResponse" | jq -r '.[0].status')" != "active" ]; then
        echo -e "${red}Could not validate the dedicated IP token provided!${nc}"
        exit 1
    fi

    echo -e "${green}OK!$nc"

    PIA_WG_IP=$(echo "$generateDIPResponse" | jq -r '.[0].ip')
    PIA_WG_HOST=$(echo "$generateDIPResponse" | jq -r '.[0].cn')
    dipExpiration=$(echo "$generateDIPResponse" | jq -r '.[0].dip_expire')
    dipExpiration=$(date -d @$dipExpiration)
    dipID=$(echo "$generateDIPResponse" | jq -r '.[0].id')

    echo
    echo -e "The hostname of your dedicated IP is ${green}$dipHostname${nc}"
    echo -e "The dedicated IP address is ${green}$dipAddress${nc}"
    echo -e "This dedicated IP is valid until ${green}$dipExpiration${nc}."

    pfCapable="true"
    if [[ $dipID == us_* ]]; then
        pfCapable="false"
        echo This location does not have port forwarding capability.
        exit 1
    fi
}

disableIPv6() {
    sysctl -w net.ipv6.conf.all.disable_ipv6=1
    sysctl -w net.ipv6.conf.default.disable_ipv6=1
}

printServerLatency() {
    serverIP=$1
    regionID=$2
    regionName="$(echo "${@:3}" |
        sed 's/ false//' | sed 's/true/(geo)/')"
    
    iptables_whitelist_IP $serverIP

    time=$(LC_NUMERIC=en_US.utf8 curl -o /dev/null -s \
        --connect-timeout "$MAX_LATENCY" \
        --write-out "%{time_connect}" \
        "http://$serverIP:443")
    if [[ $? -eq 0 ]]; then
        >&2 echo "Got latency ${time}s for region: $regionName"
        echo "$time $regionID $serverIP"
        # Write a list of servers with acceptable latency
        # to /opt/piavpn-manual/latencyList
        echo -e "$time" "$regionID"'\t'"$serverIP"'\t'"$regionName" >> /opt/piavpn-manual/latencyList
    fi
    # Sort the latencyList, ordered by latency
    sort -no /opt/piavpn-manual/latencyList /opt/piavpn-manual/latencyList
}
export -f printServerLatency

get_selected_region_data() {
    regionData="$( echo "$all_region_data" |
        jq --arg REGION_ID "$selectedRegion" -r \
        '.regions[] | select(.id==$REGION_ID)')"
    if [[ -z $regionData ]]; then
        echo -e "${red}The REGION_ID $selectedRegion is not valid.${nc}"
        exit 1
    fi
}

selectServer() {
    if [[ -z $PIA_DIP ]]; then
        MAX_LATENCY=${MAX_LATENCY:-0.1}
        export MAX_LATENCY

        ip=$(get_ip serverlist.piaservers.net)
        iptables_whitelist_IP $ip
        all_region_data=$(curl --connect-to "serverlist.piaservers.net::$ip:" -s "https://serverlist.piaservers.net/vpninfo/servers/v6" | head -1)

        # summarized_region_data="$( echo "$all_region_data" |
        #     jq -r '.regions[] |
        #         .servers.meta[0].ip+" "+.id+" "+.name+" "+(.geo|tostring)' )"

        summarized_region_data="$( echo "$all_region_data" |
            jq -r '.regions[] | select(.port_forward==true) |
            .servers.meta[0].ip+" "+.id+" "+.name+" "+(.geo|tostring)' )" # Only select regions that support port forwarding

        echo -e "Testing regions that respond faster than "${green}$MAX_LATENCY${nc}" seconds:"
        selectedRegion="$(echo "$summarized_region_data" |
            xargs -I{} bash -c 'printServerLatency {}' |
            sort | head -1 | awk '{ print $2 }')"
        if [[ -z $selectedRegion ]]; then
            echo -e "${red}No region responded within ${MAX_LATENCY}s, consider using a higher timeout."
            exit 1
        fi

        get_selected_region_data

        bestServer_meta_IP=$(echo "$regionData" | jq -r '.servers.meta[0].ip')
        bestServer_meta_hostname=$(echo "$regionData" | jq -r '.servers.meta[0].cn')
        PIA_WG_IP=$(echo "$regionData" | jq -r '.servers.wg[0].ip')
        PIA_WG_HOST=$(echo "$regionData" | jq -r '.servers.wg[0].cn')
    fi
}

disconnect() {
    if [ -n "$PIA_POST_DISCONNECT_SCRIPT" ]; then
        echo -e "${green}Running the PIA_POST_DISCONNECT_SCRIPT...${nc}"
        "$PIA_POST_DISCONNECT_SCRIPT"
    fi
    reset_killswitch
    wg-quick down pia
    exit 1
}

PIA_CONF_PATH="/etc/wireguard/pia.conf"
connect() {
    reset_killswitch
    getToken

    if [[ -n $PIA_DIP ]]; then
        getDIP
    else
        selectServer
    fi


    privKey=$(wg genkey)
    export privKey
    pubKey=$( echo "$privKey" | wg pubkey)
    export pubKey

    #iptables_whitelist_domain "${PIA_WG_HOST}"
    iptables_whitelist_IP "${PIA_WG_IP}"

    echo "Trying to connect to the PIA WireGuard API on $PIA_WG_IP..."
    if [[ -z $PIA_DIP ]]; then
        wireguard_json="$(curl -s -G \
            --connect-to "$PIA_WG_HOST::$PIA_WG_IP:" \
            --cacert "ca.rsa.4096.crt" \
            --data-urlencode "pt=${PIA_TOKEN}" \
            --data-urlencode "pubkey=$pubKey" \
            "https://${PIA_WG_HOST}:1337/addKey" )"
    else
        wireguard_json="$(curl -s -G \
            --connect-to "$PIA_WG_HOST::$PIA_WG_IP:" \
            --cacert "ca.rsa.4096.crt" \
            --user "dedicated_ip_$PIA_DIP:$PIA_WG_IP" \
            --data-urlencode "pubkey=$pubKey" \
            "https://$PIA_WG_HOST:1337/addKey" )"
    fi
    export wireguard_json

    if [[ $(echo "$wireguard_json" | jq -r '.status') != "OK" ]]; then
        >&2 echo -e "${red}Server did not return OK. Stopping now.${nc}"
        exit 1
    fi

    echo "Trying to disable a PIA WG connection in case it exists..."
    wg-quick down pia && echo -e "${green}\nPIA WG connection disabled!${nc}"

    cat > ${PIA_CONF_PATH} <<EOF
[Interface]
Address = $(echo "$wireguard_json" | jq -r '.peer_ip')
PrivateKey = $privKey
[Peer]
PersistentKeepalive = 25
PublicKey = $(echo "$wireguard_json" | jq -r '.server_key')
AllowedIPs = 0.0.0.0/0
Endpoint = ${PIA_WG_IP}:$(echo "$wireguard_json" | jq -r '.server_port')
EOF
    trap disconnect SIGINT SIGTERM
    wg-quick up pia || exit 1
    echo -e "${green}The WireGuard interface got created.${nc}"

}

monitor() {
    echo -e "${green}Monitoring the WireGuard interface...${nc}"

    payload_and_signature="$(curl -s -m 5 \
        --connect-to "$PIA_WG_HOST::$PIA_WG_IP:" \
        --cacert "ca.rsa.4096.crt" \
        -G --data-urlencode "token=${PIA_TOKEN}" \
        "https://${PIA_WG_HOST}:19999/getSignature")"
    if [[ $(echo "$payload_and_signature" | jq -r '.status') != "OK" ]]; then
        echo -e "${red}The payload_and_signature variable does not contain an OK status.${nc}"
        disconnect
        exit 1
    fi
    signature=$(echo "$payload_and_signature" | jq -r '.signature')
    payload=$(echo "$payload_and_signature" | jq -r '.payload')
    port=$(echo "$payload" | base64 -d | jq -r '.port')
    expires_at=$(echo "$payload" | base64 -d | jq -r '.expires_at')

    if [ -n "$PIA_POST_CONNECT_SCRIPT" ]; then
        echo -e "${green}Running the PIA_POST_CONNECT_SCRIPT...${nc}"
        "$PIA_POST_CONNECT_SCRIPT" $port
    fi

    while true; do
        bind_port_response="$(curl -Gs -m 5 \
            --connect-to "$PIA_WG_HOST::$PIA_WG_IP:" \
            --cacert "ca.rsa.4096.crt" \
            --data-urlencode "payload=${payload}" \
            --data-urlencode "signature=${signature}" \
            "https://${PIA_WG_HOST}:19999/bindPort")"

        # If port did not bind, just exit the script.
        # This script will exit in 2 months, since the port will expire.
        export bind_port_response
        if [[ $(echo "$bind_port_response" | jq -r '.status') != "OK" ]]; then
            echo -e "${red}The API did not return OK when trying to bind port... Exiting.${nc}"
            disconnect
            exit 1
        fi
        for i in $(seq 1 15); do
            if ping -c 4 8.8.8.8 > /dev/null; then
                sleep 60
            else
                echo -e "${red}No internet connection detected. Disconnecting.${nc}"
                disconnect
                exit 1
            fi
        done
    done
}