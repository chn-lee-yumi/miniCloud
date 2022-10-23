## 使用文件作为btrfs分区

```bash
truncate -s 10G /root/lxd_storage.img
mkfs.btrfs /root/lxd_storage.img
```

修改`/etc/fstab`增加内容：

```txt
/root/lxd_storage.img /mnt btrfs defaults,noatime,loop 0 0
```

## 网关访问白名单

```bash
iptables -t nat -A POSTROUTING -s 10.0.2.0/24 -d 114.114.114.114/32  -o eth0 -j SNAT --to-source 10.0.8.12
iptables -t nat -A POSTROUTING -s 10.0.2.0/24 -d 101.6.15.130/32  -o eth0 -j SNAT --to-source 10.0.8.12
```

## 创建VM

```bash
./lxc-run.sh [容器名] [镜像名] [CPU数] [内存大小] [宿主(可选)]
./lxc-run.sh ubuntu1 ubuntu:18.04 2 512MB
```

## 创建和绑定网卡

```bash
lxc config device add [容器名] [容器内网卡名] nic nictype=bridged parent=[网桥名] host_name=[宿主网口名]
lxc config device add ubuntu1 eth0 nic nictype=bridged parent=ovs host_name=vnic1
lxc config device set my-container eth0 [属性]=[值]
```

## 设置初始化配置

```bash
lxc profile copy default vm01
lxc profile set vm01 cloud-init.user-data "#cloud-config
bootcmd:
  - sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
apt:
  primary:
    - arches: [default]
      uri: http://mirrors.tuna.tsinghua.edu.cn/ubuntu
users:
  - name: yumi
    ssh_authorized_keys:
      - ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8FyT+xGDolRFTfAhZtA9XTds+EgzJaetfmBYtp+mxIiE3PUJnMUZs4o9IOM0J+biaaz56Oh1fV8QiZMbdLU9lLh5yvMI3Y7t9IIVvDewJXdafCRpbSjN91XeG5klmyNwANb+p8reQvUDewPiBUGobuMeG4Mh2Eu+vlZ5uSBPSarcfqR5INLi3zLWV8KHMsIuJgI1x9L5jrSNu47SeSuxOqsJto+Ck66t3/MlfTN/VGYhVrPek5LyhfkMMzWpy/QiCZ5A4Kvv1ZkTdahK783edX6vkG4vDD2wJwtsNiBscR1C5T6H/PxOTi7NOFV9MVMEU4v13x10p8kjCTEskm2n9 yumi
    sudo: [\"ALL=(ALL) NOPASSWD:ALL\"]
    shell: /bin/bash
  - name: $username
    lock_passwd: false
    plain_text_passwd: $password
    sudo: [\"ALL=(ALL) NOPASSWD:ALL\"]
    shell: /bin/bash
"
lxc profile set vm01 cloud-init.network-config "version: 1
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
lxc profile device set vm01 eth0 host_name=veth2
```

## 执行命令

```bash
lxc exec [容器名] -- [命令]
lxc exec my-container -- bash
```

