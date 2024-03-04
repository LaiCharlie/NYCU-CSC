#!/bin/sh

if [ $(id -u) -ne 0 ]; then
  echo "Root access is required"
  echo "Running with sudo again ..."
  sudo "$0" "$@"
  exit $?
fi

sysctl -w net.ipv4.tcp_timestamps=0

if [ $# -eq 1 ]; then
  if [ "$1" = "server" ]; then
    cfg="s"
  elif [ "$1" = "client" ]; then
    cfg="c"
  else
    echo -n "Enter your config type [s/c]: "
    read cfg
  fi
else
  echo -n "Enter your config type [s/c]: "
  read cfg
fi

auth_alg="hmac(sha1)"
auth_key="0xb1f884fc3bc1b61aa0c7c8bcde3e1b7b"
trunc_size=96

enc_alg="cipher_null"
enc_key=""

victim_ip='172.18.1.1'
server_ip='172.18.100.254'

victim_port=2222
server_port=1111

if [ "$cfg" = "s" ]; then
  reqid1_direction="in"
  reqid2_direction="out"
elif [ "$cfg" = "c" ]; then
  reqid1_direction="out"
  reqid2_direction="in"
else
  exit 1
fi

ip xfrm state deleteall
ip xfrm policy deleteall

ip xfrm state add src $victim_ip dst $server_ip proto esp spi 0x0000c6f8 reqid 1 mode transport auth-trunc "$auth_alg" "$auth_key" $trunc_size enc "$enc_alg" "$enc_key" sel src $victim_ip dst $server_ip proto 6 sport $victim_port dport $server_port
ip xfrm state add src $server_ip dst $victim_ip proto esp spi 0xfb170e3f reqid 2 mode transport auth-trunc "$auth_alg" "$auth_key" $trunc_size enc "$enc_alg" "$enc_key" sel src $server_ip dst $victim_ip proto 6 sport $server_port dport $victim_port
ip xfrm state

ip xfrm policy add src $victim_ip dst $server_ip proto 6 sport $victim_port dport $server_port dir $reqid1_direction ptype main tmpl src $victim_ip dst $server_ip proto esp reqid 1 mode transport
ip xfrm policy add src $server_ip dst $victim_ip proto 6 sport $server_port dport $victim_port dir $reqid2_direction ptype main tmpl src $server_ip dst $victim_ip proto esp reqid 2 mode transport
ip xfrm policy ls
