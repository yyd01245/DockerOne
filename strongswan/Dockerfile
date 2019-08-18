FROM centos:latest

ARG LATEST="0"

# RUN yum -y install epel-release; 
# RUN yum -y update; yum -y install strongswan xl2tpd openssl iptables cronie net-tools bash-completion vim libpam0g-dev; yum clean all
# RUN yum -y update; yum -y install xl2tpd openssl iptables cronie net-tools bash-completion vim libpam0g-dev
RUN yum -y update; yum -y install xl2tpd openssl iptables cronie net-tools bash-completion vim libpam0g-dev

RUN yum -y update; yum -y install git automake; yum -y install pam-devel openssl-devel make gcc curl wget gcc-c++; yum install -y libtool
RUN yum -y update; yum -y install pkgconfig libevent perl bzip2;yum clean all


RUN wget https://download.strongswan.org/strongswan-5.8.0.tar.bz2  -O - |tar -xj \
  && cd strongswan-5.8.0 \
  && ./configure --enable-eap-identity --enable-eap-md5 \
  --enable-eap-mschapv2 --enable-eap-tls --enable-eap-ttls --enable-eap-peap  \
  --enable-eap-tnc --enable-eap-dynamic --enable-eap-radius --enable-xauth-eap  \
  --enable-xauth-pam  --enable-dhcp  --enable-openssl  --enable-addrblock --enable-unity  \
  --enable-certexpire --enable-radattr --enable-swanctl --enable-openssl --disable-gmp \
  && make && make install
# RUN yum install -y libsysfs-dev; yum install -y byacc

VOLUME /key

COPY strongswan.sh /strongswan.sh
RUN chmod +x /strongswan.sh

WORKDIR /usr/local/sbin

ENTRYPOINT ["/strongswan.sh"]

EXPOSE 500/udp 4500/udp 1701/udp
CMD ["ipsec", "start", "--nofork"]
# CMD ["bash", "-c", "while true; do sleep 1; done"]

# docker build -t strongswan .
# docker run -d --restart always --privileged -v /docker/strongswan:/key --network=host -e VPN_PASS=123456 --hostname strongswan --name strongswan strongswan
# cat /docker/strongswan/strongswan.log
