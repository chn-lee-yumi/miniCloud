#!/usr/bin/env bash
# 需要注意，如果镜像不是cloud镜像，则lxd在启动容器的时候会卡在Starting
usage() {
  echo "Usage: $0 [容器名] [镜像名] [CPU数] [内存大小] [IP] [GATEWAY] [NETMASK] [veth] [用户名(可选)] [密码(可选)] [宿主(可选)]"
  echo "Example: $0 ubuntu1 ubuntu/jammy 2 512MB 10.0.2.10 10.0.2.1 255.255.255.0 veth1 yumi 'ssh-rsa abcdefg'"
  exit 2
}

trap 'exit 3' INT

if [[ -z $4 ]]; then
  usage
fi

name=$1
image=$2/cloud # 自动加/cloud后缀
core=$3
mem=$4
ipaddr=$5
gateway=$6
netmask=$7
veth=$8
if [ $# -eq 11 ]; then
  username=$9
  pubkey=${10}
  target_node=${11}
elif [ $# -eq 9 ]; then # 不创建ssh登录用户，默认创建一个cloud
  username="cloud"
  pubkey="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDSpMvlkRaWzXT1MnNhi/72POCNi6HGxLWFQz8G02pscrkH2BIqzivKA6p6E3MdVw7XN/D/1t+nc49BL5QtbMsCkZ2tD0NRLtAEM1voJVnV+UO6ehV/5gCqdVlf1uwFfQcPoeoABJl0j/+aqAmw6GCE9Prg1jcq7oIc7qGX4L+x548aafiGnSnOzA6Q9LOpK+y92Ah5wGPZVcU0Lc8vU5VDpuAdPyMxNpr/qnyXywIIl1SHacE1Gl0sQZhdId0xk+LGcEITGYynyYPHnbHs8moI2ARW9MM/9k3Esqlg87WwSANTNxwUvqhj8u/iconki8JGTULAJS3wzAX/MhMw7xNtOHKeZa7D2vUJ8JbiYpn6f9RlSYkJnG3qft/VU0fejmnxL2eBGYO7sEEdVsVs1vn0FOmxcqYERde8N5Ldop1OQynopv0y5FnIRdLeUjIuBbHfySf5X7tBv+qSyr3dqKss8fcNhAOw9XNDq/vjwtnJnY0nJx2aSt2OC5M2ndLuots= cloud"
  target_node=$9
fi
#password=`mkpasswd --method=SHA-512 $password`

ubuntu_mirror="apt:
  primary:
    - arches: [default]
      uri: http://mirrors.gdut.edu.cn/ubuntu
"

ubuntu_ports_mirror="apt:
  primary:
    - arches: [default]
      uri: http://mirrors.gdut.edu.cn/ubuntu-ports
"

debian_mirror="apt:
  primary:
    - arches: [default]
      uri: http://mirrors.gdut.edu.cn/debian
"

# TODO: centos

lxc info --target $target_node | grep architectures -A 1 | grep aarch
is_not_aarch64=$?

if [[ $image =~ "ubuntu" && $is_not_aarch64 == 1 ]]; then
  mirror_config=${ubuntu_mirror}
elif [[ $image =~ "ubuntu" && $is_not_aarch64 == 0 ]]; then
  mirror_config=${ubuntu_ports_mirror}
elif [[ $image =~ "debian" ]]; then
  mirror_config=${debian_mirror}
fi

lxc profile copy vm_template $name
lxc profile set $name cloud-init.user-data "#cloud-config
packages: ['openssh-server']
${mirror_config}
users:
  - name: liyumin
    ssh_authorized_keys:
      - ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8FyT+xGDolRFTfAhZtA9XTds+EgzJaetfmBYtp+mxIiE3PUJnMUZs4o9IOM0J+biaaz56Oh1fV8QiZMbdLU9lLh5yvMI3Y7t9IIVvDewJXdafCRpbSjN91XeG5klmyNwANb+p8reQvUDewPiBUGobuMeG4Mh2Eu+vlZ5uSBPSarcfqR5INLi3zLWV8KHMsIuJgI1x9L5jrSNu47SeSuxOqsJto+Ck66t3/MlfTN/VGYhVrPek5LyhfkMMzWpy/QiCZ5A4Kvv1ZkTdahK783edX6vkG4vDD2wJwtsNiBscR1C5T6H/PxOTi7NOFV9MVMEU4v13x10p8kjCTEskm2n9 yumi
    sudo: [\"ALL=(ALL) NOPASSWD:ALL\"]
    shell: /bin/bash
  - name: gregPerlinLi
    ssh_authorized_keys:
      - ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC4OzKqhs6n7MASHWp+8p1NpL46meJLbsOCm23+y9Yeba36fq3kbPrBvu5XVhctL8VPl/ri2L3JMKA/OJUQV1j9hmSZWCN1Xxo+lOJK/a+D+9cT0bFQXjkXgfrowcTShR8ECEkQUStZgJ6VDaBy3Qmu7NerAsJ9exYdukzshhyVQve5NxAXz/KWkW3TnFF5zTlCdjAkwyCPDjCanWP+fE41/vhrml440gllk4RxX6IQvOApLttS3k08CU54w/2kJQ8MVwkaodeELAonI1TcEX4TgpU8tS9WiYfPlRUfw00fqiFgGHdNB6THqIR/vB7Cmz5bQ3VKy5WZ7hWZNOaPnwZ9skHgkFYL/VWvkLPfrrXXmYKdkED6mM6WD3Yc522dj2zDcMiLc2Fjb9AZSu9y+WcHYk3BcRFKX6GVLmcDdBxn/Cs9rvnxfAduH1vpTsSqocwu1/t5bmaeYiTIxoR4T+RTmC5AEkuzLLC8plOyospko0pJEdS+OGJYPn9BrlcTNR0= gregPerlinLi
    sudo: [\"ALL=(ALL) NOPASSWD:ALL\"]
    shell: /bin/bash
  - name: $username
    ssh_authorized_keys:
      - $pubkey
    sudo: [\"ALL=(ALL) NOPASSWD:ALL\"]
    shell: /bin/bash
"
lxc profile set $name cloud-init.network-config "version: 1
config:
  - type: physical
    name: eth0
    subnets:
      - type: static
        ipv4: true
        address: $ipaddr
        netmask: $netmask
        gateway: $gateway
        control: auto
  - type: nameserver
    address: 202.116.128.1
"
lxc profile device set $name eth0 host_name=$veth

if [[ -n $target_node ]]; then
  lxc launch tuna-images:$image $name -p $name --target $target_node --storage miniCloud
else
  lxc launch tuna-images:$image $name -p $name --storage miniCloud
fi

if [[ $? != 0 ]]; then
  exit 3
fi

lxc config set $name limits.cpu $core
lxc config set $name limits.memory $mem
lxc config set $name security.nesting=true # enable docker support
