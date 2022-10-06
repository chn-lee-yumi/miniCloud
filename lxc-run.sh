#!/usr/bin/env bash
# 需要注意，如果镜像不是cloud镜像，则lxd在启动容器的时候会卡在Starting
usage() {
  echo "Usage: $0 [容器名] [镜像名] [CPU数] [内存大小] [IP] [GATEWAY] [NETMASK] [veth] [用户名] [密码] [宿主(可选)]"
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
username=$9
pubkey=${10}
target_node=${11}
#password=`mkpasswd --method=SHA-512 $password`

ubuntu_mirror="apt:
  primary:
    - arches: [default]
      uri: http://mirrors.tuna.tsinghua.edu.cn/ubuntu
"

ubuntu_ports_mirror="apt:
  primary:
    - arches: [default]
      uri: http://mirrors.tuna.tsinghua.edu.cn/ubuntu-ports
"

debian_mirror="apt:
  primary:
    - arches: [default]
      uri: http://mirrors.tuna.tsinghua.edu.cn/debian
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
elif [[ $image =~ "kali" ]]; then
  mirror_config=${kali_mirror}
fi

lxc profile copy vm_template $name
lxc profile set $name cloud-init.user-data "#cloud-config
packages: ['openssh-server']
${mirror_config}
users:
  - name: yumi
    ssh_authorized_keys:
      - ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8FyT+xGDolRFTfAhZtA9XTds+EgzJaetfmBYtp+mxIiE3PUJnMUZs4o9IOM0J+biaaz56Oh1fV8QiZMbdLU9lLh5yvMI3Y7t9IIVvDewJXdafCRpbSjN91XeG5klmyNwANb+p8reQvUDewPiBUGobuMeG4Mh2Eu+vlZ5uSBPSarcfqR5INLi3zLWV8KHMsIuJgI1x9L5jrSNu47SeSuxOqsJto+Ck66t3/MlfTN/VGYhVrPek5LyhfkMMzWpy/QiCZ5A4Kvv1ZkTdahK783edX6vkG4vDD2wJwtsNiBscR1C5T6H/PxOTi7NOFV9MVMEU4v13x10p8kjCTEskm2n9 yumi
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
    address: 114.114.114.114
"
lxc profile device set $name eth0 host_name=$veth

if [[ -n $target_node ]]; then
  lxc launch tuna-images:$image $name -p $name --target $target_node
else
  lxc launch tuna-images:$image $name -p $name
fi

if [[ $? != 0 ]]; then
  exit 3
fi

lxc config set $name limits.cpu $core
lxc config set $name limits.memory $mem
# lxc config device set test1 root size=1GiB
# lxc config device set test1 root limits.read=10MiB

# check if limits.cpu works https://github.com/lxc/lxd/issues/10997
if [[ $core != $(lxc exec $name nproc) ]]; then
  echo "limits.cpu failed, trying to write sys file"
  if [[ $core == 1 ]]; then
    limit_cores=$(($RANDOM % 4))
  elif [[ $core == 2 ]]; then
    random_pool=("0,1" "0,2" "0,3" "1,2" "1,3" "2,3")
    random_pool_num=${#random_pool[*]}
    limit_cores=${random_pool[$((RANDOM % random_pool_num))]}
  fi
  sudo -u cloud ssh $target_node "sudo sh -c 'echo $limit_cores > /sys/fs/cgroup/lxc.payload.$name/cpuset.cpus'"
  if [[ $core == $(lxc exec $name nproc) ]]; then
    echo "set cpu limit success"
  fi
fi
