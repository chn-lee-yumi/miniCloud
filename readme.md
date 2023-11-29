# miniCloud

一个迷你云平台，可以创建虚拟机。做这个项目的目的是学习流表的设计和使用，所以功能着重在网络实现上，对于别的功能不大重视，能用就行。

流量使用OVS流表转发。NAT通过iptables实现。流表和配置下发全部通过SSH命令实现。（后续计划使用openflow的方式下发流表）

v2.0版本和v1.0版本相比和有较大改动。完善了一些功能，将virsh改成lxd，后续计划通过模块的方式支持各种后端。

![screenshot](mini_cloud_screenshot.png)

## 部署文档

机器系统使用Ubuntu。然后用ansible进行部署。需要注意`/mnt/`需要为`btrfs`文件系统（计算节点需要此操作）。

在管理节点修改`~/.ssh/config`配置，增加如下内容：

```shell
StrictHostKeyChecking no
```

看看所有TODO，可能有些地方是需要修改的。比如`lxc-run.sh`里面的DNS地址。

节点分四类：`管理节点`、`网关节点`、`计算节点`、`特殊节点`。`特殊节点`目前包含`交换节点`。 目前`管理节点`和`交换节点`可以合并在同一台机器上。

将节点信息写到一个ini中，可以参考`ansible_scripts/server_list_test.ini`和`ansible_scripts/server_list_prod.ini`。

切换到`ansible_scripts`目录下，执行`ansible-playbook -i server_list_test.ini playbook_init_cluster.yml`即可完成部署。

如果遇到部署过程中LXD卡住的情况，先执行`playbook_clean_cluster.yml`，然后重启所有LXD服务器，再执行`playbook_init_cluster.yml`。或者登录卡住的服务器，执行`snap remove lxd --purge`，然后重新执行`playbook_init_cluster.yml`。

要使用前端和API，执行`python3 main.py`即可。

TODO：安装完LXD后机器需要重启，否则cpu限制不生效 https://github.com/lxc/lxd/issues/10997 目前机器重启后流表会丢失，需要手动调API刷新流表。计划后续版本解决这个问题。

## 已知BUG

- 新镜像，第一次启动大概率卡在Starting，容器状态为STOPPED
- 偶尔创建的容器mac地址和volatile.eth0.hwaddr不一致（低概率复现）

## 参考资料

LXD文档：https://linuxcontainers.org/lxd/docs/master/

cloud-init 排查日志：/var/log/cloud-init*

cloud-init文档：https://cloudinit.readthedocs.io/en/latest/topics/examples.html

Ansible文档：https://docs.ansible.com/ansible/latest/getting_started/index.html http://ansible.com.cn/docs/playbooks_best_practices.html

MAC地址：https://en.wikipedia.org/wiki/MAC_address

OVS会`skipping output to input port`，所以虚拟机不会收到自己的广播报文。

```
# 查看虚拟机对应的物理网卡
virsh domiflist 192.168.20.11 | grep 02:6e:1d:4e:69:ef | awk '{print $1}'
```

## 网桥设计

### 宿主

```bash
# vxlan端口
ovs-vsctl add-port br0 {interface} -- set interface {interface} type=vxlan options:local_ip={ip} options:key=flow options:remote_ip=flow
# 到switch的端口
ovs-vsctl add-port br0 {interface} -- set interface {interface} type=vxlan options:remote_ip={ip} options:key=flow
```

### dhcp

```bash
# vxlan端口
ovs-vsctl add-port br0 {interface} -- set interface {interface} type=vxlan options:local_ip={ip} options:key=flow
# 配上网关ip作为dhcp服务器ip
ip addr add {gateway_ip}/{mask} dev br0
```

### switch

```bash
# 与所有宿主的vxlan隧道（用于广播）
ovs-vsctl add-port br0 {interface} -- set interface {interface} type=vxlan options:remote_ip={ip} options:key=flow
```

### 网关

```bash
# vxlan端口
ovs-vsctl add-port br0 {interface} -- set interface {interface} type=vxlan options:local_ip={ip} options:key=flow
# 配上网关ip
ip addr add {gateway_ip}/{mask} dev br0
```

## 流表设计

| table    | priority    | 匹配项                                                | action                                                                                                                                                                                                                                                                                      | 备注                                                   |
|----------|-------------|----------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------|
| table=0  | priority=20 | dl_dst=ff:ff:ff:ff:ff:ff                           | actions="resubmit(,50)"                                                                                                                                                                                                                                                                     | 广播流量                                                 |
| table=0  | priority=10 | dl_dst=00:00:00:00:00:00/01:00:00:00:00:00         | actions="resubmit(,10)"                                                                                                                                                                                                                                                                     | 单播流量                                                 |
| table=0  | priority=10 | dl_dst=01:00:00:00:00:00/01:00:00:00:00:00         | actions="resubmit(,50)"                                                                                                                                                                                                                                                                     | 组播流量                                                 |
| table=0  | priority=0  |                                                    | actions=drop                                                                                                                                                                                                                                                                                | 默认流                                                  |
| table=10 | priority=5  | dl_src={vm_mac},dl_dst=12:00:00:FF:FF:FF           | actions=load:"{gateway_service_ip_hex}->NXM_NX_TUN_IPV4_DST[]",vxlan-int                                                                                                                                                                                                                    | vm到网关的流量(网关mac地址固定为12:00:00:FF:FF:FF)                |
| table=10 | priority=15 | dl_dst={vm_mac}                                    | actions=load:"{subnet_tun_id_hex}->NXM_NX_TUN_ID[]",load:"{vm_host_ip_hex}->NXM_NX_TUN_IPV4_DST[]",vxlan-int                                                                                                                                                                                | 同子网vm到远程vm的流量，填入tun_id和dst后从vxlan-int接口发出去           |
| table=10 | priority=15 | dl_dst={vm_mac}                                    | actions={vm_interface}                                                                                                                                                                                                                                                                      | 同子网vm到本地vm的流量，从对应接口发出去                               |
| table=10 | priority=10 | ip,nw_dst={vm_ip}                                  | actions=mod_dl_src:"12:00:00:FF:FF:FF",mod_dl_dst:"{vm_mac}",load:"{subnet_tun_id_hex}->NXM_NX_TUN_ID[]",load:"{vm_host_ip_hex}->NXM_NX_TUN_IPV4_DST[]",vxlan-int                                                                                                                           | 不同子网vm到远程vm的流量                                       |
| table=10 | priority=10 | ip,nw_dst={vm_ip}                                  | actions=mod_dl_src:"12:00:00:FF:FF:FF",mod_dl_dst:"{vm_mac}",{vm_interface}                                                                                                                                                                                                                 | 不同子网vm到本地vm的流量                                       |
| table=10 | priority=5  |                                                    | actions=local                                                                                                                                                                                                                                                                               | 网关节点，把流量发到本地网桥（然后NAT）                                |
| table=10 | priority=0  |                                                    | actions=drop                                                                                                                                                                                                                                                                                | 默认流                                                  |
| table=50 | priority=20 | arp,arp_tpa={gateway_ip},arp_op=1                  | actions=move:"NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[]",mod_dl_src:"12:00:00:FF:FF:FF",load:"0x02->NXM_OF_ARP_OP[]",move:"NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[]",load:"0x120000FFFFFF->NXM_NX_ARP_SHA[]",move:"NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[]",load:"{gateway_ip_hex}->NXM_OF_ARP_SPA[]",in_port | vm到网关的arp请求（宿主代答）                                    |
| table=50 | priority=20 | arp,arp_tpa={vm_ip},arp_op=1                       | actions=move:"NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[]",mod_dl_src:"{vm_mac}",load:"0x02->NXM_OF_ARP_OP[]",move:"NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[]",load:"{vm_mac_hex}->NXM_NX_ARP_SHA[]",move:"NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[]",load:"{vm_ip_hex}->NXM_OF_ARP_SPA[]",in_port                 | 对vm的arp请求（宿主/网关代答）                                   |
| table=50 | priority=15 | udp,tp_src=68,tp_dst=67,in_port={in_port}          | actions=load:"{subnet_tun_id_hex}->NXM_NX_TUN_ID[]",load:"{dhcp_server_hex}->NXM_NX_TUN_IPV4_DST[]",vxlan-int                                                                                                                                                                               | DHCP报文，发往DHCP服务器                                     |
| table=50 | priority=10 | in_port={in_port}                                  | actions=load:"{subnet_tun_id_hex}->NXM_NX_TUN_ID[]","resubmit(,60)"                                                                                                                                                                                                                         | 根据inport设置tunid                                      |
| table=50 | priority=10 | in_port=vxlan-sw,tun_id={subnet_tun_id_hex}        | actions={out_ports}                                                                                                                                                                                                                                                                         | inport是vxlan则根据tunid发到本地端口                           |
| table=50 | priority=10 | udp,tp_src=68,tp_dst=67,tun_id={subnet_tun_id_hex} | actions={out_ports}                                                                                                                                                                                                                                                                         | DHCP报文，发往本地vm                                        |
| table=50 | priority=0  |                                                    | actions="resubmit(,60)"                                                                                                                                                                                                                                                                     | 默认流                                                  |
| table=60 | priority=0  |                                                    | actions="clone(resubmit(vxlan-sw,50)),vxlan-sw"                                                                                                                                                                                                                                             | 普通节点，复制一个包修改in_port到50表（发到本地的端口），同时发送到switch         |
| table=60 | priority=10 |                                                    | actions=all                                                                                                                                                                                                                                                                                 | switch节点，广播到除入接口外所有接口 (flood其实也行，因为目前端口没有配置no-flood) |

## 流表追踪命令

```shell
ovs-appctl ofproto/trace br0 icmp,dl_src=02:2e:bd:7e:ad:c0,dl_dst=12:16:3e:ad:c6:f6,nw_src=192.168.20.10,nw_dst=114.114.114.114
```