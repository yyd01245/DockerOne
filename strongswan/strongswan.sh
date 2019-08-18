#!/bin/bash
set -e

: ${IP_RANGE:=10.11.0}
: ${VPN_USER:=test}
: ${VPN_PASS:=$(pwmake 64)}
: ${VPN_PSK:=test}
: ${P12_PASS:=test.com}
: ${CLIENT_CN:="strongSwan VPN"}
: ${CA_CN:="strongSwan CA"}
: ${STRONGSWAN_PATH:=/usr/local/etc}

echo "1--- $1"
echo "-- $STRONGSWAN_PATH --"
echo "$(grep "all_enable" $STRONGSWAN_PATH/ipsec.conf)"

if [ "$1" = 'ipsec' ]; then

if [ -z "$(grep "all_enable" $STRONGSWAN_PATH/ipsec.conf)" ]; then
  # Get ip address
  DEV=$(route -n |awk '$1=="0.0.0.0"{print $NF }')
  # if [ -z $SERVER_CN ]; then
  # 	SERVER_CN=$(curl -s https://httpbin.org/ip |awk -F\" 'NR==2{print $4}')
  # fi

  if [ -z $SERVER_CN ]; then
    SERVER_CN=$(curl -s https://showip.net/)
  fi

  if [ -z $SERVER_CN ]; then
    SERVER_CN=$(ifconfig $DEV |awk '$3=="netmask"{print $2}')
  fi

  echo "Initialize strongswan"
  if [ "$(ls /key/ |egrep -c "server.crt|server.key|ca.crt|ca.key|client.crt|client.key|strongswan.p12")" -ne 7 ]; then
    #Create certificate
    echo "---- find key ----"
    cd $STRONGSWAN_PATH/ipsec.d
    pki --gen --type rsa --size 4096 --outform pem > ca-key.pem
    chmod 600 ca-key.pem
    pki --self --ca --lifetime 3650 --in ca-key.pem --type rsa --dn "C=CH, O=strongSwan, CN=$CA_CN" --outform pem > ca-cert.pem

    pki --gen --type rsa --size 2048 --outform pem > server-key.pem
    chmod 600 server-key.pem
    pki --pub --in server-key.pem --type rsa | pki --issue --lifetime 3650 --cacert ca-cert.pem --cakey ca-key.pem --dn "C=CH, O=strongSwan, CN=$SERVER_CN" --san $SERVER_CN --flag serverAuth --flag ikeIntermediate --outform pem > server-cert.pem 

    pki --gen --type rsa --size 2048 --outform pem > client-key.pem
    chmod 600 client-key.pem
    pki --pub --in client-key.pem --type rsa | pki --issue --lifetime 3650 --cacert ca-cert.pem --cakey ca-key.pem --dn "C=CH, O=strongSwan, CN=$CLIENT_CN" --outform pem > client-cert.pem

    openssl pkcs12 -export -inkey client-key.pem -in client-cert.pem -name "IPSec's VPN Certificate" -certfile ca-cert.pem -caname "strongSwan CA" -out strongswan.p12 -password "pass:$P12_PASS"

    \cp ca-key.pem $STRONGSWAN_PATH/ipsec.d/private/ca.key
    \cp ca-cert.pem $STRONGSWAN_PATH/ipsec.d/cacerts/ca.crt
    \cp server-key.pem $STRONGSWAN_PATH/ipsec.d/private/server.key
    \cp server-cert.pem $STRONGSWAN_PATH/ipsec.d/certs/server.crt
    \cp client-key.pem $STRONGSWAN_PATH/ipsec.d/private/client.key
    \cp client-cert.pem $STRONGSWAN_PATH/ipsec.d/certs/client.crt
    \cp ca-key.pem /key/ca.key
    \cp ca-cert.pem /key/ca.crt
    \cp server-key.pem /key/server.key
    \cp server-cert.pem /key/server.crt
    \cp client-key.pem /key/client.key
    \cp client-cert.pem /key/client.crt
    \cp strongswan.p12 /key/strongswan.p12

  else
    \cp /key/ca.key $STRONGSWAN_PATH/ipsec.d/private/ca.key
    \cp /key/ca.crt $STRONGSWAN_PATH/ipsec.d/cacerts/ca.crt
    \cp /key/server.key $STRONGSWAN_PATH/ipsec.d/private/server.key
    \cp /key/server.crt $STRONGSWAN_PATH/ipsec.d/certs/server.crt
    \cp /key/client.key $STRONGSWAN_PATH/ipsec.d/private/client.key
    \cp /key/client.crt $STRONGSWAN_PATH/ipsec.d/certs/client.crt
    echo "Certificate already exists, skip"
  fi

	# IPSec configuration file
	cat >$STRONGSWAN_PATH/ipsec.conf <<-END
# all_enable
	config setup
    uniqueids=never 
	conn all_ikev2
    keyexchange=ikev2
    ike=aes128gcm8-sha1-modp1024,aes128-sha1-modp1024,aes128gcm16-prfsha512-ecp521!
    esp=aes128gcm8,aes128-sha1,chacha20poly1305,chacha20poly1305-ecp192,aes128gcm16-prfsha512-ecp521,null-sha1!
    ikelifetime=24h
    dpdaction=clear
    dpddelay=300s
    rekey=no
    left=%defaultroute
    leftsubnet=0.0.0.0/0
    leftauth=pubkey
    leftsendcert=always
    leftid=$SERVER_CN
    leftcert=server.crt
    right=%any
    rightauth=eap-mschapv2
    rightsourceip=$IP_RANGE.128/25
    rightdns=8.8.8.8,8.8.4.4
    rightsendcert=never
    eap_identity=%any
    dpdaction=clear
    mobike=yes
    fragmentation=yes
    auto=add
conn ikev1_xauth_psk
    keyexchange=ikev1
    left=%defaultroute
    leftauth=psk
    leftsubnet=0.0.0.0/0
    right=%any
    rightauth=psk
    rightauth2=xauth
    rightsourceip=$IP_RANGE.128/25
    mobike=yes
    auto=add
	END
	
	
	# strongSwan configuration file
	cat >$STRONGSWAN_PATH/strongswan.conf <<-END
  charon {
    load_modular = yes
    #duplicheck.enable = no
    compress = yes
    plugins {
      include strongswan.d/charon/*.conf
    }
    dns1 = 8.8.8.8
    dns2 = 8.8.4.4
    nbns1 = 8.8.8.8
    nbns2 = 8.8.4.4
	}
	include strongswan.d/*.conf
	END
	
	
	# IPSec auth file
	cat >$STRONGSWAN_PATH/ipsec.secrets <<-END
	: RSA server.key
	: PSK "$VPN_PSK"
	$VPN_USER %any : EAP "$VPN_PASS"
	$VPN_USER %any : XAUTH "$VPN_PASS"
	END
	
	echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
	sysctl -p

	# iptables
	cat > /iptables.sh <<-END
	iptables -t nat -I POSTROUTING -s $IP_RANGE.0/24 -o $DEV -j MASQUERADE
	iptables -I FORWARD -s $IP_RANGE.0/24 -j ACCEPT
	iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
	iptables -I INPUT -p udp -m state --state NEW -m udp --dport 500 -m comment --comment IPSEC -j ACCEPT
	iptables -I INPUT -p udp -m state --state NEW -m udp --dport 4500 -m comment --comment IPSEC -j ACCEPT
	iptables -I INPUT -p udp -m state --state NEW -m udp --dport 1701 -m comment --comment L2TP -j ACCEPT
	iptables -I INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
	END

	echo -e "
	VPN USER: $VPN_USER
	VPN PASS: $VPN_PASS
	VPN PSK: $VPN_PSK
	P12 PASS: $P12_PASS
	SERVER: $SERVER_CN" |tee /key/strongswan.log
else
  echo "strongswan config over"

fi


echo "Start ****"
[ -z "`iptables -S |grep IPSEC`" ] && . /iptables.sh
# exec "$@" &>/dev/null
echo "$@ &>/key/ipsec.log"
exec "$@" &>/key/ipsec.log


else

echo -e "
	Example
			docker run -d --restart always --privileged \\
			-v /docker/strongswan:/key \\
			--network=host \\
			-e VPN_USER=[jiobxn] \\
			-e VPN_PASS=<123456> \\
			-e VPN_PSK=[jiobxn.com] \\
			-e P12_PASS=[jiobxn.com] \\
			-e SERVER_CN=<SERVER_IP> \\
			-e CLIENT_CN=["strongSwan VPN"] \\
			-e CA_CN=["strongSwan CA"] \\
			-e IP_RANGE=[10.11.0] \\
			--hostname strongswan \\
			--name strongswan strongswan
	"
fi
echo "----- over ----"

#IOS Client:
# L2TP: user+pass+psk
# IPSec: user+pass+psk or user+pass+strongswan.p12, Note: Server is SERVER_CN
# IKEv2: user+pass+ca.crt, Note: Remote ID is SERVER_CN, Local ID is user

#Windows Client:
# L2TP: user+pass+psk, --network=host
# IKEv2: user+pass+ca.crt or user+pass+ca.crt+strongswan.p12, Note: Server is SERVER_CN. Certificate manage: certmgr.msc

#Windows 10 BUG:
# C:\Users\admin>powershell               #to PS Console
# PS C:\Users\jiobx> get-vpnconnection    #Show IKEv2 vpn connection name
# PS C:\Users\jiobx> set-vpnconnection "IKEv2-VPN-Name" -splittunneling $false    #Stop split tunneling
# PS C:\Users\jiobx> get-vpnconnection    #list
# PS C:\Users\jiobx> exit