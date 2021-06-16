import copy
import random
import uuid

from sqlalchemy import and_

from db import *
from utils import *

# 目前所有子网共用一台dhcp和一台switch
dhcp_server = "192.168.10.2"
dhcp_server_hex = "0x" + ip_to_hex(dhcp_server)
DB = Database()

# TODO：webconsole(ssh/vnc)。分布式交换机可视化。
# debian nfs启动资料：https://unix.stackexchange.com/questions/420646/mount-root-as-overlayfs http://support.fccps.cz/download/adv/frr/nfs-root/nfs-root.htm#preps
# mtu 1346 使用1300

"""
apt install qemu-kvm libvirt-clients libvirt-daemon-system virtinst openvswitch-switch 
virsh net-define ovs.xml && virsh net-autostart ovs && virsh net-start ovs
【测试机器】
网关节点：
nnode1-az1
nnode1-az2
计算节点：
cnode1-az1
cnode2-az1
cnode1-az2
特殊节点：
snode1-az1
"""

TEMPLATE = {
    # VXLAN端口 注意，如果一个包进来，会优先匹配到有remote_ip=对端ip的接口，如果没有这个接口，才会匹配remote_ip=flow的接口。
    "add-port-vxlan-local": "sudo ovs-vsctl add-port br0 vxlan-int -- set interface vxlan-int type=vxlan options:local_ip={ip} options:key=flow options:remote_ip=flow\n",
    "add-port-vxlan-remote": "sudo ovs-vsctl add-port br0 {interface} -- set interface {interface} type=vxlan options:remote_ip={ip} options:key=flow\n",
    "add-port-internal": "sudo ovs-vsctl add-port br0 {interface} -- set interface {interface} type=internal && sudo ip link set {interface} up\n",
    # "add-port-vxlan-remote-no-flood": """sudo ovs-vsctl add-port br0 {interface} -- set interface {interface} type=vxlan options:remote_ip={ip}\nsudo ovs-ofctl mod-port br0 {interface} no-flood\n""",
    "del-port": "sudo ovs-vsctl del-port br0 {interface}\n",

    # 【table10】
    # vm到网关的流量(网关mac地址固定为12:00:00:FF:FF:FF)
    "add-flow-vm-gateway": """sudo ovs-ofctl add-flow br0 table=10,priority=5,dl_src={vm_mac},dl_dst=12:00:00:FF:FF:FF,actions=load:"{gateway_service_ip_hex}->NXM_NX_TUN_IPV4_DST[]",vxlan-int\n""",
    "del-flow-vm-gateway": """sudo ovs-ofctl del-flows br0 table=10,dl_src={vm_mac},dl_dst=12:00:00:FF:FF:FF\n""",
    # "mod-flow-vm-gateway": """sudo ovs-ofctl mod-flows br0 table=10,priority=20,dl_src={vm_mac},dl_dst=12:00:00:FF:FF:FF,actions=load:"{gateway_manage_ip_hex}->NXM_NX_TUN_IPV4_DST[]",vxlan-int\n""",
    # 到远程vm的流量，填入tun_id和dst后从vxlan-int接口发出去。到本地vm的流量，从对应接口发出去
    "add-flow-vm-remote": """sudo ovs-ofctl add-flow br0 table=10,priority=15,dl_dst={vm_mac},actions=load:"{subnet_tun_id_hex}->NXM_NX_TUN_ID[]",load:"{vm_host_ip_hex}->NXM_NX_TUN_IPV4_DST[]",vxlan-int\n""",
    "add-flow-vm-local": """sudo ovs-ofctl add-flow br0 table=10,priority=15,dl_dst={vm_mac},actions={vm_interface}\n""",
    "add-flow-vm-remote-ip": """sudo ovs-ofctl add-flow br0 table=10,priority=10,ip,nw_dst={vm_ip},actions=mod_dl_src:"12:00:00:FF:FF:FF",mod_dl_dst:"{vm_mac}",load:"{subnet_tun_id_hex}->NXM_NX_TUN_ID[]",load:"{vm_host_ip_hex}->NXM_NX_TUN_IPV4_DST[]",vxlan-int\n""",
    "add-flow-vm-local-ip": """sudo ovs-ofctl add-flow br0 table=10,priority=10,ip,nw_dst={vm_ip},actions=mod_dl_src:"12:00:00:FF:FF:FF",mod_dl_dst:"{vm_mac}",{vm_interface}\n""",
    "del-flow-vm": """sudo ovs-ofctl del-flows br0 table=10,dl_dst={vm_mac}\n""",
    "del-flow-vm-ip": """sudo ovs-ofctl del-flows br0 table=10,ip,nw_dst={vm_ip}\n""",
    # 网关节点 转发流量
    "add-flow-gateway": """sudo ovs-ofctl add-flow br0 table=10,priority=5,actions=local\n""",

    # 【table50】
    # vm的arp请求（宿主代答）
    "add-flow-arp-vm-gateway": """sudo ovs-ofctl add-flow br0 table=50,priority=20,arp,arp_tpa={gateway_ip},arp_op=1,actions=move:"NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[]",mod_dl_src:"12:00:00:FF:FF:FF",load:"0x02->NXM_OF_ARP_OP[]",move:"NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[]",load:"0x120000FFFFFF->NXM_NX_ARP_SHA[]",move:"NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[]",load:"{gateway_ip_hex}->NXM_OF_ARP_SPA[]",in_port\n""",
    # "add-flow-arp-vm-vm": """sudo ovs-ofctl add-flow br0 table=50,priority=20,arp,arp_tpa={vm_ip},arp_op=1,actions=move:"NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[]",mod_dl_src:"{vm_mac}",load:"0x02->NXM_OF_ARP_OP[]",move:"NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[]",load:"{vm_mac_hex}->NXM_NX_ARP_SHA[]",move:"NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[]",load:"{vm_ip_hex}->NXM_OF_ARP_SPA[]",in_port\n""",
    # "add-flow-arp-vm-gratuitous": """sudo ovs-ofctl add-flow br0 table=50,priority=21,arp,arp_tpa={vm_ip},arp_spa={vm_ip},actions=drop\n""",
    "del-flow-arp": """sudo ovs-ofctl del-flows br0 table=50,arp,arp_tpa={ip},arp_op=1\n""",
    # "del-flow-arp-gratuitous": """sudo ovs-ofctl del-flows br0 table=50,arp,arp_tpa={ip},arp_spa={ip}\n""",
    # dhcp报文
    "add-flow-dhcp": """sudo ovs-ofctl add-flow br0 table=50,priority=15,udp,tp_src=68,tp_dst=67,in_port={in_port},actions=load:"{subnet_tun_id_hex}->NXM_NX_TUN_ID[]",load:"{dhcp_server_hex}->NXM_NX_TUN_IPV4_DST[]",vxlan-int\n""",
    # 根据inport设置tunid，resubmit60
    "add-flow-inport-send": """sudo ovs-ofctl add-flow br0 table=50,priority=10,in_port={in_port},actions=load:"{subnet_tun_id_hex}->NXM_NX_TUN_ID[]","resubmit(,60)"\n""",
    "del-flow-inport-send": """sudo ovs-ofctl del-flows br0 table=50,in_port={in_port}\n""",
    # inport是vxlan则根据tunid发到本地端口
    "add-flow-inport-recv": """sudo ovs-ofctl add-flow br0 table=50,priority=10,in_port=vxlan-sw,tun_id={subnet_tun_id_hex},actions={out_ports}\n""",
    "add-flow-dhcp-inport-recv": """sudo ovs-ofctl add-flow br0 table=50,priority=10,udp,tp_src=68,tp_dst=67,tun_id={subnet_tun_id_hex},actions={out_ports}\n""",
    # "mod-flow-inport-recv": """sudo ovs-ofctl mod-flows br0 table=50,priority=10,in_port=vxlan-sw,tun_id={subnet_tun_id_hex},actions={out_ports}\n""",
    "del-flow-inport-recv": """sudo ovs-ofctl del-flows br0 table=50,in_port=vxlan-sw,tun_id={subnet_tun_id_hex}\n""",
    "del-flow-dhcp-inport-recv": """sudo ovs-ofctl del-flows br0 table=50,in_port=vxlan-int,tun_id={subnet_tun_id_hex}\n""",
    # dhcp回复的报文需要设置tunid
    "add-flow-dhcp-tunid": """sudo ovs-ofctl add-flow br0 table=50,priority=12,udp,tp_src=67,tp_dst=68,nw_src={gateway_ip},actions=load:"{subnet_tun_id_hex}->NXM_NX_TUN_ID[]","resubmit(,60)"\n""",

    # 【table60】
    # 广播报文
    # 普通节点，复制一个包修改in_port到50表（发到本地的端口），同时发送到switch。注意resubmit修改的in_port只在resubmit后的那个表有用
    "add-flow-cast": """sudo ovs-ofctl add-flow br0 table=60,priority=0,actions="clone(resubmit(vxlan-sw,50)),vxlan-sw"\n""",
    # switch节点，广播到除入接口外所有接口 (flood其实也行，因为目前端口没有配置no-flood)
    "add-flow-switch": """sudo ovs-ofctl add-flow br0 table=60,priority=10,actions=all\n""",

    # 其它
    "del-flow-br0": "sudo ovs-ofctl del-flows br0\n",  # 清空流表
    "add-flow-normal": """
sudo ovs-ofctl add-flow br0 table=0,priority=20,dl_dst=ff:ff:ff:ff:ff:ff,actions="resubmit(,50)"
sudo ovs-ofctl add-flow br0 table=0,priority=10,dl_dst=00:00:00:00:00:00/01:00:00:00:00:00,actions="resubmit(,10)"
sudo ovs-ofctl add-flow br0 table=0,priority=10,dl_dst=01:00:00:00:00:00/01:00:00:00:00:00,actions="resubmit(,50)"
sudo ovs-ofctl add-flow br0 table=0,priority=0,actions=drop
sudo ovs-ofctl add-flow br0 table=10,priority=0,actions=drop
sudo ovs-ofctl add-flow br0 table=50,priority=0,actions="resubmit(,60)"\n""",  # 默认流表
}

TEMPLATE_CONF = {
    "dhcp_net": "subnet {subnet} netmask {netmask} {{option subnet-mask {netmask}; option routers {gateway}; range {ip_start} {ip_end};}}"
}

for t in TEMPLATE:
    if not TEMPLATE[t].endswith("\n"):
        print("TEMPLATE没弄好！需要以\\n结尾：", t)
        exit(1)


def init_vxlan_tunnel(target_uuid: str, target_type):
    """
    初始化vxlan隧道
    :param target_uuid: 目标uuid
    :param target_type: 目标类型（Gateway/Host/SpecialNode）
    :return:
    """
    if target_type not in [Host, Gateway, SpecialNode]:
        return 0
    # 查询宿主信息
    target = DB.session.query(target_type).filter_by(uuid=target_uuid).first()
    if not target:  # 宿主不存在
        return 1
    # 删除现有vxlan端口
    cmd = """
sudo ip link set mtu 1300 dev br0
ports=`sudo ovs-vsctl list-ports br0`
for port in $ports; do
    if [[ $port =~ ^vxlan-.* ]]; then
        sudo ovs-vsctl del-port br0 $port
    fi
done
sudo ovs-vsctl list-ports br0 | grep vxlan
"""
    # 修改mac地址
    if target_type in [Gateway, SpecialNode]:
        cmd = "sudo ovs-vsctl set bridge br0 other-config:hwaddr=12:00:00:ff:ff:ff\n" + cmd
    code, _, _ = exec_cmd("ssh %s '%s'" % (target.management_ip, cmd))
    if code != 1:  # 发现还有vxlan端口没删除，这不正常
        logger.warning("发现还有vxlan端口没删除，这不正常")
        return 1
    # 重新添加vxlan端口
    cmd = ""
    # 添加vxlan-local
    cmd += TEMPLATE["add-port-vxlan-local"].format(ip=target.service_ip)
    # for _host in get_list_raw(Host):  # 所有节点都会连接所有宿主
    #     if _host.uuid == target_uuid:
    #         continue
    #     cmd += TEMPLATE["add-port-vxlan-no-flood"].format(ip=_host.service_ip, interface="vxlan-" + ip_to_hex(_host.service_ip))
    # if target_type == Host:  # 宿主才需要添加网关/特殊节点
    #     for _host in get_list_raw([Gateway, SpecialNode]):
    #         if "role" in _host.__dict__.keys() and "switch" in _host.role:  # 交换节点
    #             cmd += TEMPLATE["add-port-vxlan"].format(ip=_host.service_ip, interface="vxlan-" + ip_to_hex(_host.service_ip))
    #         else:  # 非交换节点，配置no-flood
    #             cmd += TEMPLATE["add-port-vxlan-no-flood"].format(ip=_host.service_ip, interface="vxlan-" + ip_to_hex(_host.service_ip))
    # 添加到交换节点的vxlan-remote
    if target_type == Host:
        for _host in get_list_raw(SpecialNode):
            if "role" in _host.__dict__.keys() and "switch" in _host.role:  # 交换节点
                cmd += TEMPLATE["add-port-vxlan-remote"].format(ip=_host.service_ip, interface="vxlan-sw")
                break
    # 添加到宿主的vxlan-remote
    if target_type == SpecialNode and "role" in target.__dict__.keys() and "switch" in target.role:  # 交换节点
        for _host in get_list_raw(Host):
            cmd += TEMPLATE["add-port-vxlan-remote"].format(ip=_host.service_ip, interface="vxlan-" + ip_to_hex(_host.service_ip))
    if cmd:
        _, stdout, _ = exec_cmd("ssh %s '%s'" % (target.management_ip, cmd))
        # print(stdout)  # TODO：不好判断有没有完成
    # 刷新流表
    return refresh_flow_table(target_uuid, target_type)


def init_subnet_gateway_ip(target_uuid: str):
    """
    初始化网关节点的子网网关ip
    :param target_uuid: 网关节点uuid
    :return:
    """
    # 查询宿主信息
    target = DB.session.query(Gateway).filter_by(uuid=target_uuid).first()
    if not target:  # 宿主不存在
        target = DB.session.query(SpecialNode).filter_by(uuid=target_uuid).first()
        if not target:  # 宿主不存在
            logger.warning("Gateway/SpecialNode不存在")
            return 1
    # 查询子网信息，拼接命令
    cmd = ""
    subnets = DB.session.query(Subnet).all()
    for subnet in subnets:
        gateway_ip = calc_gateway_ip(subnet.cidr)
        mask = subnet.cidr[-2:]
        cmd += "sudo ip addr add {gateway_ip}/{mask} dev br0\n".format(gateway_ip=gateway_ip, mask=mask)
    # 执行命令
    _, stdout, _ = exec_cmd("ssh %s '%s'" % (target.management_ip, cmd))
    # print(stdout)  # TODO：判断是否执行成功
    return 0


def refresh_flow_table(target_uuid: str, target_type):
    """
    刷新流表（全量更新）
    :param target_uuid: 目标uuid
    :param target_type: 目标类型（Gateway/Host/SpecialNode/PhysicalMachine）
    :return:
    """
    if target_type not in [Host, Gateway, SpecialNode]:  # ...PhysicalMachine
        return 0
    # 查询宿主信息
    target = DB.session.query(target_type).filter_by(uuid=target_uuid).first()
    if not target:  # 宿主不存在
        return 1
    cmd = TEMPLATE["del-flow-br0"]  # 先清空流表
    # # 广播流量相关流表
    # template = "sudo ovs-ofctl add-flow br0 table=0,priority=20,in_port={in_port},dl_dst=ff:ff:ff:ff:ff:ff,actions={out_port}"
    # _, stdout, _ = exec_cmd("ssh %s 'sudo ovs-vsctl list-ports br0 | grep -v vxlan'" % target.management_ip)
    # out_port = "LOCAL,"
    # for port in stdout.strip().split("\n"):
    #     out_port += port + ","
    # # template = "sudo ovs-ofctl add-flow br0 table=0,priority=20,in_port={in_port},dl_dst=ff:ff:ff:ff:ff:ff,actions=FLOOD"
    # host_list = DB.session.query(Host)
    # for _host in host_list:
    #     if target.management_ip == _host.management_ip:
    #         continue
    #     cmd += template.format(in_port="vxlan-" + ip_to_hex(_host.service_ip), out_port=out_port) + "\n"
    # gateway_list = DB.session.query(Gateway)
    # if target_type == Host:
    #     for _host in gateway_list:
    #         cmd += template.format(in_port="vxlan-" + ip_to_hex(_host.service_ip), out_port=out_port) + "\n"
    #     special_node_list = DB.session.query(SpecialNode)
    #     for _host in special_node_list:
    #         if target_type != Host:
    #             continue
    #         cmd += template.format(in_port="vxlan-" + ip_to_hex(_host.service_ip), out_port=out_port) + "\n"
    # VM网关相关流表
    host_vm_port = {}  # 用于"add-flow-inport-recv"  _vm.subnet_uuid : [_vm.interface]
    for _vm in get_list_raw(VirtualMachine):
        # print(_vm.host, target.management_ip)
        # cmd += TEMPLATE["add-flow-arp-vm-vm"].format(vm_ip=_vm.ip, vm_mac=_vm.mac, vm_mac_hex="0x" + _vm.mac.replace(":", ""),
        #                                              vm_ip_hex="0x" + ip_to_hex(_vm.ip))  # arp代答
        # cmd += TEMPLATE["add-flow-arp-vm-gratuitous"].format(vm_ip=_vm.ip)  # 无故arp
        if _vm.host == target.management_ip:  # target_type == Host
            if _vm.power == 1:
                if _vm.subnet_uuid not in host_vm_port:  # 用于"add-flow-inport-recv"
                    host_vm_port[_vm.subnet_uuid] = [_vm.interface]
                else:
                    host_vm_port[_vm.subnet_uuid].append(_vm.interface)
            _gateway = DB.session.query(Gateway).filter_by(management_ip=_vm.gateway).first()
            cmd += TEMPLATE["add-flow-vm-gateway"].format(vm_mac=_vm.mac,
                                                          gateway_service_ip_hex="0x" + ip_to_hex(_gateway.service_ip))  # 虚拟机发往哪个网关的流表
            if _vm.power == 1:
                cmd += TEMPLATE["add-flow-vm-local"].format(vm_mac=_vm.mac, vm_interface=_vm.interface)  # 到vm的流量
                cmd += TEMPLATE["add-flow-vm-local-ip"].format(vm_ip=_vm.ip, vm_mac=_vm.mac, vm_interface=_vm.interface)  # 到vm的流量
                cmd += TEMPLATE["add-flow-inport-send"].format(in_port=_vm.interface,
                                                               subnet_tun_id_hex=get_tun_id(_vm.subnet_uuid))  # 根据in_port设置tun_id
                cmd += TEMPLATE["add-flow-dhcp"].format(in_port=_vm.interface, subnet_tun_id_hex=get_tun_id(_vm.subnet_uuid),
                                                        dhcp_server_hex=dhcp_server_hex)  # dhcp报文
        else:
            cmd += TEMPLATE["add-flow-vm-remote"].format(vm_mac=_vm.mac, subnet_tun_id_hex=get_tun_id(_vm.subnet_uuid),
                                                         vm_host_ip_hex="0x" + ip_to_hex(_vm.host))  # 到vm的流量
            cmd += TEMPLATE["add-flow-vm-remote-ip"].format(vm_ip=_vm.ip, vm_mac=_vm.mac, subnet_tun_id_hex=get_tun_id(_vm.subnet_uuid),
                                                            vm_host_ip_hex="0x" + ip_to_hex(_vm.host))  # 到vm的流量
    for subnet_uuid, out_ports in host_vm_port.items():
        cmd += TEMPLATE["add-flow-inport-recv"].format(subnet_tun_id_hex=get_tun_id(subnet_uuid), out_ports=",".join(out_ports))  # 根据tun_id发到本地端口
    # for _pm in get_list_raw(PhysicalMachine):
    #     if _pm.management_ip == target.management_ip:
    #         cmd += TEMPLATE["add-flow-vm-local"].format(vm_mac=_pm.mac, vm_interface="br0")  # 到vm的流量
    #         cmd += TEMPLATE["add-flow-vm-local-ip"].format(vm_ip=_pm.inner_ip, vm_interface="br0")  # 到vm的流量
    #     else:
    #         cmd += TEMPLATE["add-flow-vm-remote"].format(vm_mac=_pm.mac, subnet_tun_id_hex="0x02",
    #                                                      vm_host_ip_hex="0x" + ip_to_hex(_pm.service_ip))  # 到vm的流量
    #         cmd += TEMPLATE["add-flow-vm-remote-ip"].format(vm_ip=_pm.inner_ip, subnet_tun_id_hex="0x02",
    #                                                         vm_host_ip_hex="0x" + ip_to_hex(_pm.service_ip))  # 到vm的流量
    if target_type == Host:
        # 查询subnet信息，网关ARP代答流表
        subnets = DB.session.query(Subnet).all()
        for subnet in subnets:
            gateway_ip = calc_gateway_ip(subnet.cidr)
            cmd += TEMPLATE["add-flow-arp-vm-gateway"].format(gateway_ip=gateway_ip, gateway_ip_hex="0x" + ip_to_hex(gateway_ip))
        # 广播流量
        cmd += TEMPLATE["add-flow-cast"]
    # if target_type == PhysicalMachine:
    #     # 广播流量
    #     cmd += TEMPLATE["add-flow-cast"]
    if target_type == SpecialNode and "role" in target.__dict__.keys() and "switch" in target.role:  # 交换节点
        cmd += TEMPLATE["add-flow-switch"]
    if target_type == SpecialNode and "role" in target.__dict__.keys() and "dhcp" in target.role:  # DHCP节点
        for subnet in get_list_raw(Subnet):
            cmd += TEMPLATE["add-flow-dhcp-tunid"].format(gateway_ip=IPy.IP(subnet.start + 1).strNormal(), subnet_tun_id_hex=get_tun_id(subnet.uuid))
            cmd += TEMPLATE["add-flow-dhcp-inport-recv"].format(subnet_tun_id_hex=get_tun_id(subnet.uuid),
                                                                out_ports="dhcp-" + ip_to_hex(IPy.IP(subnet.start + 1).strNormal()))
    if target_type == Gateway:
        cmd += TEMPLATE["add-flow-gateway"]
    # 普通流表
    cmd += TEMPLATE["add-flow-normal"]
    # 执行命令
    _, stdout, _ = exec_cmd("ssh %s '%s'" % (target.management_ip, cmd))
    # print(stdout)  # TODO：不好判断有没有完成
    return 0


def add_host(management_ip: str, service_ip: str, az: str, cpu: int, mem: int, init: bool = True):
    """
    添加宿主
    :param management_ip: 宿主管理ip
    :param service_ip: 宿主业务ip
    :param cpu: 宿主机可以分配的CPU（单位：核）
    :param mem: 宿主机可以分配的内存（单位：GB）
    :param init: 是否执行初始化
    :return:
    """
    # 生成一个uuid
    _uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, management_ip))
    # 写入数据库
    DB.session.add(Host(uuid=_uuid, management_ip=management_ip, service_ip=service_ip, az=az, cpu=cpu, mem=mem))
    DB.session.commit()
    # 其他宿主/网关/特殊节点 添加流表和vxlan隧道
    # for _host in get_list_raw([Host, Gateway, SpecialNode]):
    #     if _host.uuid == _uuid:
    #         continue
    #     if "role" in _host.__dict__.keys() and "switch" in _host.role:  # 交换节点
    #         cmd = TEMPLATE["add-port-vxlan"].format(ip=service_ip, interface="vxlan-" + ip_to_hex(service_ip))
    #     else:  # 非交换节点，配置no-flood
    #         cmd = TEMPLATE["add-port-vxlan-no-flood"].format(ip=service_ip, interface="vxlan-" + ip_to_hex(service_ip))
    #     code, _, _ = exec_cmd("ssh %s '%s'" % (_host.management_ip, cmd))
    #     if code:
    #         return 1
    # switch加vxlan隧道
    for _host in get_list_raw(SpecialNode):
        if "role" in _host.__dict__.keys() and "switch" in _host.role:  # 交换节点
            cmd = TEMPLATE["add-port-vxlan-remote"].format(ip=service_ip, interface="vxlan-" + ip_to_hex(service_ip))
            code, _, _ = exec_cmd("ssh %s '%s'" % (_host.management_ip, cmd))
            if code:
                return 1
    # 初始化宿主vxlan隧道
    if init:
        return init_vxlan_tunnel(_uuid, Host)
    return 0


def delete_host(host_uuid: str):
    """
    删除宿主（宿主的网桥/流表不会被清理） TODO: 有vm禁止删除
    :param host_uuid: 宿主的uuid
    :return:
    """
    host = DB.session.query(Host).filter_by(uuid=host_uuid).first()
    if not host:
        return 0
    DB.session.delete(host)
    DB.session.commit()
    # 清理 其他宿主/网关/特殊节点 的流表和vxlan隧道
    # cmd = TEMPLATE["del-port-vxlan"].format(interface="vxlan-" + ip_to_hex(host.service_ip))
    # for _host in get_list_raw([Host, Gateway, SpecialNode]):
    #     code, _, _ = exec_cmd("ssh %s '%s'" % (_host.management_ip, cmd))
    #     if code:
    #         return 1
    for _host in get_list_raw(SpecialNode):
        if "role" in _host.__dict__.keys() and "switch" in _host.role:  # 交换节点
            cmd = TEMPLATE["del-port"].format(interface="vxlan-" + ip_to_hex(host.service_ip))
            code, _, _ = exec_cmd("ssh %s '%s'" % (_host.management_ip, cmd))
            if code:
                return 1
    return 0


def add_special_node(management_ip: str, service_ip: str, role: str, init: bool = True):
    """
    添加特殊节点
    :param management_ip: 宿主管理ip
    :param service_ip: 宿主业务ip
    :param role: 角色
    :param init: 是否执行初始化
    :return:
    """
    # 生成一个uuid
    _uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, management_ip))
    # 写入数据库
    DB.session.add(SpecialNode(uuid=_uuid, management_ip=management_ip, service_ip=service_ip, role=role))
    DB.session.commit()
    # 所有宿主 添加vxlan隧道
    # if "switch" in role:
    #     cmd = TEMPLATE["add-port-vxlan"].format(ip=service_ip, interface="vxlan-" + ip_to_hex(service_ip))
    # else:
    #     cmd = TEMPLATE["add-port-vxlan-no-flood"].format(ip=service_ip, interface="vxlan-" + ip_to_hex(service_ip))
    # for _host in get_list_raw(Host):
    #     code, _, _ = exec_cmd("ssh %s '%s'" % (_host.management_ip, cmd))
    #     if code:
    #         return 1
    # 初始化vxlan隧道
    if init:
        code = init_vxlan_tunnel(_uuid, SpecialNode)
        if code:
            return 1
        return init_subnet_gateway_ip(_uuid)
    return 0


def delete_special_node(special_node_uuid: str):
    """
    删除特殊节点（宿主的网桥/流表不会被清理）
    :param special_node_uuid: 特殊节点的uuid
    :return:
    """
    host = DB.session.query(SpecialNode).filter_by(uuid=special_node_uuid).first()
    if not host:
        return 0
    DB.session.delete(host)
    DB.session.commit()
    # 清理 所有宿主 的流表和vxlan隧道
    # cmd = TEMPLATE["del-port-vxlan"].format(interface="vxlan-" + ip_to_hex(host.service_ip))
    # for _host in get_list_raw(Host):
    #     code, _, _ = exec_cmd("ssh %s '%s'" % (_host.management_ip, cmd))
    #     if code:
    #         return 1
    return 0


def add_gateway(management_ip: str, internet_ip: str, service_ip: str, internet_inner_ip: str,
                bandwidth: int, description: str = "", init: bool = True):
    """
    添加网关
    :param management_ip: 网关管理ip
    :param internet_ip: 网关公网ip
    :param service_ip: 网关业务ip（vxlan隧道的ip）
    :param internet_inner_ip: 网关公网映射的内网ip（例如公有云的EIP，绑定到某台ECS上，
                              则ECS的内网ip就是internet_inner_ip），如果外网ip直接配在网卡上，该参数为空字符串
    :param bandwidth: 网关带宽
    :param description: 网关描述
    :param init: 是否执行初始化
    :return:
    """
    # 生成一个uuid
    _uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, management_ip))
    # 写入数据库
    DB.session.add(Gateway(
        uuid=_uuid, management_ip=management_ip, internet_ip=internet_ip,
        service_ip=service_ip, internet_inner_ip=internet_inner_ip,
        bandwidth=bandwidth, description=description
    ))
    DB.session.commit()
    # 所有宿主 添加vxlan隧道
    # cmd = TEMPLATE["add-port-vxlan-no-flood"].format(ip=service_ip, interface="vxlan-" + ip_to_hex(service_ip))
    # host_list = DB.session.query(Host)
    # for _host in host_list:
    #     code, _, _ = exec_cmd("ssh %s '%s'" % (_host.management_ip, cmd))
    #     if code:
    #         return 1
    # 初始化网桥
    if init:
        code = init_vxlan_tunnel(_uuid, Gateway)
        if code:
            return 1
        return init_subnet_gateway_ip(_uuid)
    return 0


def delete_gateway(gateway_uuid: str):
    """
    删除网关 TODO：如果有vm，禁止删除
    :param gateway_uuid: 网关的uuid
    :return:
    """
    gateway = DB.session.query(Gateway).filter_by(uuid=gateway_uuid).first()
    if not gateway:
        return 0
    # 清理所有子网网关IP
    # cmd = ""
    # subnets = DB.session.query(Subnet).all()
    # for subnet in subnets:
    #     gateway_ip = calc_gateway_ip(subnet.cidr)
    #     cmd += "sudo ip addr del {gateway_ip} dev br0\n".format(gateway_ip=gateway_ip)
    cmd = """ips=\\`sudo ip addr show br0 | grep inet | awk '{print \\$2}'\\`; for ip in \\$ips; do sudo ip addr del \\$ip dev br0; done"""
    _, stdout, _ = exec_cmd("ssh %s \"%s\"" % (gateway.management_ip, cmd))
    # 删除网关
    DB.session.delete(gateway)
    DB.session.commit()
    # 清理 所有宿主 的流表和vxlan隧道
    # cmd = TEMPLATE["del-port-vxlan"].format(interface="vxlan-" + ip_to_hex(gateway.service_ip))
    # host_list = DB.session.query(Host)
    # for _host in host_list:
    #     code, _, _ = exec_cmd("ssh %s '%s'" % (_host.management_ip, cmd))
    #     if code:
    #         return 1
    return 0


# def add_physical_machine(management_ip: str, service_ip: str, inner_ip: str, mac: str, hostname: str, init: bool = True):
#     """
#     添加物理机 TODO: 需要手动配网桥ip，手动添加vxlan
#     :param management_ip: 管理ip
#     :param service_ip: 业务ip
#     :param inner_ip: 内网ip
#     :param mac: mac地址
#     :param hostname: 名字
#     :param init: 是否执行初始化
#     :return:
#     """
#     # 生成一个uuid
#     _uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, management_ip))
#     # 写入数据库
#     DB.session.add(PhysicalMachine(uuid=_uuid, management_ip=management_ip, service_ip=service_ip, inner_ip=inner_ip, mac=mac, hostname=hostname))
#     DB.session.commit()
#     # 给所有机器下发流表
#     cmd = TEMPLATE["add-flow-vm-remote"].format(vm_mac=mac, subnet_tun_id_hex="0x02", vm_host_ip_hex="0x" + ip_to_hex(service_ip))  # 到物理机的流量
#     cmd += TEMPLATE["add-flow-vm-remote-ip"].format(vm_ip=inner_ip, subnet_tun_id_hex="0x02",
#                                                     vm_host_ip_hex="0x" + ip_to_hex(service_ip))  # 到物理机的流量
#     for host in get_list_raw([Host, SpecialNode, PhysicalMachine]):
#         if host.management_ip == management_ip:
#             continue
#         code, _, _ = exec_cmd("ssh %s '%s'" % (host.management_ip, cmd))
#     # 自己全量刷流表
#     # refresh_flow_table(_uuid, PhysicalMachine)
#     # switch加vxlan隧道
#     # for _host in get_list_raw(SpecialNode):
#     #     if "role" in _host.__dict__.keys() and "switch" in _host.role:  # 交换节点
#     #         cmd = TEMPLATE["add-port-vxlan-remote"].format(ip=service_ip, interface="vxlan-" + ip_to_hex(service_ip))
#     #         code, _, _ = exec_cmd("ssh %s '%s'" % (_host.management_ip, cmd))
#     #         if code:
#     #             return 1
#     # TODO: 初始化vxlan隧道
#     # if init:
#     #     code = init_vxlan_tunnel(_uuid, SpecialNode)
#     #     if code:
#     #         return 1
#     #     return init_subnet_gateway_ip(_uuid)
#     return 0


def add_consistent_flow(management_ip: str, service_ip: str, inner_ip: str, mac: str, subnet_uuid: str):
    # 给所有机器下发流表
    cmd = TEMPLATE["add-flow-vm-remote"].format(vm_mac=mac, subnet_tun_id_hex=get_tun_id(subnet_uuid),
                                                vm_host_ip_hex="0x" + ip_to_hex(service_ip))  # 到物理机的流量
    cmd += TEMPLATE["add-flow-vm-remote-ip"].format(vm_ip=inner_ip, vm_mac=mac, subnet_tun_id_hex=get_tun_id(subnet_uuid),
                                                    vm_host_ip_hex="0x" + ip_to_hex(service_ip))  # 到物理机的流量
    for host in get_list_raw([Host, Gateway, SpecialNode]):
        if host.management_ip == management_ip:
            continue
        code, _, _ = exec_cmd("ssh %s '%s'" % (host.management_ip, cmd))
    cmd = TEMPLATE["add-flow-vm-local"].format(vm_mac=mac, vm_interface="br0")
    cmd += TEMPLATE["add-flow-vm-local-ip"].format(vm_ip=inner_ip, vm_mac=mac, vm_interface="br0")
    code, _, _ = exec_cmd("ssh %s '%s'" % (management_ip, cmd))


def create_vm(subnet_uuid: str, gateway_internet_ip: str, flavor: str, hostname: str, az: str = "", vm_ip: str = "", host_ip: str = ""):
    """
    创建虚拟机
    :param subnet_uuid: 子网uuid
    :param gateway_internet_ip: 网关外网ip
    :param flavor: 虚拟机规格
    :param hostname: 虚拟机名字
    :param az: 可用区
    :param host_ip: 宿主管理ip
    :param vm_ip: 虚拟机ip
    :return: 0=OK 1=Failed
    """
    # 检查规格
    if flavor not in ["1C1G", "1C2G", "2C4G", "4C8G", "32C64G"]:
        return "虚拟机规格不正确"
    # 检查名字
    if hostname == "":
        return "请填写虚拟机名字"
    if DB.session.query(VirtualMachine).filter_by(hostname=hostname).first():
        return "虚拟机名字重复"
    # 检查子网
    if not subnet_uuid:
        # subnet_uuid = "d6b72035-5a0c-5ef8-af39-8955e338185b"
        return "没有选择子网"
    subnet = DB.session.query(Subnet).filter_by(uuid=subnet_uuid).first()
    if not subnet:
        return "子网不存在"
    # 检查网关
    gateway = DB.session.query(Gateway).filter_by(internet_ip=gateway_internet_ip).first()
    if not gateway:
        return "没有这个网关！"
    # 检查ip/分配ip
    if vm_ip:  # 指定IP
        vm = DB.session.query(VirtualMachine).filter_by(ip=vm_ip).first()
        if vm:  # ip重复
            return "IP已被使用"
        # 检查IP是否在子网内
        if not (subnet.start + 2) <= IPy.IP(vm_ip).int() <= (subnet.end - 1):
            return "IP不在子网范围内"  # TODO：该功能未自测
    else:
        # 查询子网内有没有空闲的ip
        for ip in range(subnet.start + 6, subnet.end - 1):  # 前5个ip和最后一个ip保留
            ip_str = IPy.IP(ip).strNormal()
            vm = DB.session.query(VirtualMachine).filter_by(ip=ip_str).first()
            if not vm:
                vm_ip = ip_str
                break
        if not vm_ip:  # 没有足够的IP地址
            return "子网内没有足够的IP地址"  # 注：前5个ip和最后一个ip保留，如需使用请手动指定IP地址
    # 根据资源，分配宿主
    if not host_ip:
        if az:
            hosts = DB.session.query(Host).filter_by(az=az)
        else:
            hosts = DB.session.query(Host).all()
        host_dict = {}
        for host in hosts:
            host_dict[host.management_ip] = {"cpu": host.cpu, "mem": host.mem}
        for _vm in DB.session.query(VirtualMachine).all():
            if _vm.host not in host_dict:
                continue
            host_dict[_vm.host]["cpu"] -= int(_vm.flavor.split("C")[0])
            host_dict[_vm.host]["mem"] -= int(_vm.flavor.split("C")[1][:-1])
        host_dict = sorted(host_dict.items(), key=lambda i: i[1]["cpu"], reverse=True)  # 先按CPU降序
        host_dict = sorted(host_dict, key=lambda i: i[1]["mem"], reverse=True)  # 再按内存降序
        if not host_dict:
            return "宿主资源不足"
        target_host = host_dict[0]  # 排序结果形如 [('192.168.10.2', {'cpu': 32, 'mem': 48}), ('192.168.13.2', {'cpu': 11, 'mem': 8})]
        if target_host[1]["cpu"] - int(flavor.split("C")[0]) >= 0 and target_host[1]["mem"] - int(flavor.split("C")[1][:-1]) >= 0:
            host_ip = target_host[0]
        else:
            return "宿主资源不足"
    # 生成一个mac地址 格式：02:xx:xx:xx:xx:xx 本地mac地址范围：https://en.wikipedia.org/wiki/MAC_address#Universal_vs._local
    uniq_mac = 1
    vm_mac = ""
    while uniq_mac:  # 如果生成了重复的mac，则重新生成
        vm_mac = ':'.join(map(lambda x: "%02x" % x,
                              [0x02, random.randint(0x00, 0xff), random.randint(0x00, 0xff),
                               random.randint(0x00, 0xff), random.randint(0x00, 0xff), random.randint(0x00, 0xff)]
                              ))
        uniq_mac = DB.session.query(VirtualMachine).filter_by(mac=vm_mac).first()  # 检查是否有重复mac
    # 生成一个uuid
    vm_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, vm_ip))
    # 写入数据库
    DB.session.add(VirtualMachine(
        uuid=vm_uuid, ip=vm_ip, host=host_ip, gateway=gateway_internet_ip, subnet_uuid=subnet_uuid,
        flavor=flavor, mac=vm_mac, stage="configuring dhcp", power=0, hostname=hostname
    ))
    DB.session.commit()
    vm = DB.session.query(VirtualMachine).filter_by(uuid=vm_uuid).first()
    # 配置dhcp
    code, _, _ = exec_cmd("""ssh %s 'sudo """
                          """echo "host %s { hardware ethernet %s; fixed-address %s; }" """
                          """>> /etc/dhcp/vm.conf && """
                          """sudo systemctl restart isc-dhcp-server'""" % (dhcp_server, vm_ip, vm_mac, vm_ip))
    if code:
        vm.stage += " ERROR"
        DB.session.commit()
        return "配置DHCP时报错"
    vm.stage = "adding flow"
    DB.session.commit()
    # 下发vm网关流表
    cmd = TEMPLATE["add-flow-vm-gateway"].format(vm_mac=vm.mac, gateway_service_ip_hex="0x" + ip_to_hex(gateway.service_ip))  # 虚拟机发往哪个网关的流表
    code, _, _ = exec_cmd("ssh %s '%s'" % (vm.host, cmd))
    if code:
        vm.stage += " ERROR"
        DB.session.commit()
        return "下发vm网关流表时报错"
    vm.stage = "creating machine"
    DB.session.commit()
    # 给所有机器下发vm流表
    cmd = TEMPLATE["add-flow-vm-remote"].format(vm_mac=vm.mac, subnet_tun_id_hex=get_tun_id(vm.subnet_uuid),
                                                vm_host_ip_hex="0x" + ip_to_hex(vm.host))  # 到vm的流量
    cmd += TEMPLATE["add-flow-vm-remote-ip"].format(vm_ip=vm.ip, vm_mac=vm.mac, subnet_tun_id_hex=get_tun_id(vm.subnet_uuid),
                                                    vm_host_ip_hex="0x" + ip_to_hex(vm.host))  # 到vm的流量
    # cmd += TEMPLATE["add-flow-arp-vm-vm"].format(vm_ip=vm.ip, vm_mac=vm.mac, vm_mac_hex="0x" + vm.mac.replace(":", ""),
    #                                              vm_ip_hex="0x" + ip_to_hex(vm.ip))  # arp代答
    # cmd += TEMPLATE["add-flow-arp-vm-gratuitous"].format(vm_ip=vm.ip)  # 无故arp
    for host in get_list_raw([Host, SpecialNode, Gateway]):  # ...PhysicalMachine
        if host.management_ip == host_ip:
            continue
        code, _, _ = exec_cmd("ssh %s '%s'" % (host.management_ip, cmd))
    # 创建虚拟机 TODO：支持多系统镜像
    # code, _, _ = exec_cmd("""ssh %s 'sudo """
    #                       """virt-install --virt-type kvm -n %s -r 4096 --vcpus=2 """
    #                       """--pxe --disk none --network network=ovs,mac=%s,mtu.size=1300,target=vnet_%s --graphics vnc,listen=127.0.0.1 --wait 0"""
    #                       """'""" % (vm.host, vm.ip, vm.mac, ip_to_hex(vm.ip)))
    cpu_num = flavor.split("C")[0]
    mem_num = str(int(flavor.split("C")[1][:-1]) * 1024)  # 单位：MB
    code, _, _ = exec_cmd("""ssh {host} 'sudo """
                          """cp /mnt/ubuntu-template.qcow2 /mnt/{ip}.qcow2 && """
                          """sudo virt-install --virt-type kvm -n {ip} -r {mem} --vcpus={cpu} --boot hd --disk /mnt/{ip}.qcow2 """
                          """--network network=ovs,mac={mac},mtu.size=1300,target=vnet_{ip_hex} --graphics vnc,listen=127.0.0.1 --wait 0"""
                          """'""".format(host=vm.host, ip=vm.ip, ip_hex=ip_to_hex(vm.ip), mac=vm.mac, cpu=cpu_num, mem=mem_num))
    if code:
        vm.stage += " ERROR"
        DB.session.commit()
        return "创建虚拟机时报错"
    _, stdout, _ = exec_cmd("""ssh %s "sudo virsh domiflist %s | grep %s | awk '{print \\$1}'" """ % (vm.host, vm.ip, vm.mac))
    vm.interface = stdout.strip()
    DB.session.commit()
    # 给宿主下发流表
    cmd = TEMPLATE["add-flow-vm-local"].format(vm_mac=vm.mac, vm_interface=vm.interface)  # 这个有延迟，目前没办法在创建虚拟机前就分配好网卡
    cmd += TEMPLATE["add-flow-vm-local-ip"].format(vm_ip=vm.ip, vm_mac=vm.mac, vm_interface=vm.interface)  # 这个有延迟，目前没办法在创建虚拟机前就分配好网卡
    cmd += TEMPLATE["add-flow-inport-send"].format(in_port=vm.interface, subnet_tun_id_hex=get_tun_id(vm.subnet_uuid))  # 根据in_port设置tun_id
    cmd += TEMPLATE["add-flow-dhcp"].format(in_port=vm.interface, subnet_tun_id_hex=get_tun_id(vm.subnet_uuid),
                                            dhcp_server_hex=dhcp_server_hex)  # dhcp
    # cmd += TEMPLATE["add-flow-arp-vm-vm"].format(vm_ip=vm.ip, vm_mac=vm.mac, vm_mac_hex="0x" + vm.mac.replace(":", ""),
    #                                              vm_ip_hex="0x" + ip_to_hex(vm.ip))  # arp代答
    # cmd += TEMPLATE["add-flow-arp-vm-gratuitous"].format(vm_ip=vm.ip)  # 无故arp
    host_vm_port = {}  # 用于"add-flow-inport-recv"  _vm.subnet_uuid : [_vm.interface]
    for _vm in DB.session.query(VirtualMachine).filter_by(host=host_ip):
        if not _vm.interface:
            continue
        if _vm.subnet_uuid not in host_vm_port:  # 用于"add-flow-inport-recv"
            host_vm_port[_vm.subnet_uuid] = [_vm.interface]
        else:
            host_vm_port[_vm.subnet_uuid].append(_vm.interface)
    for subnet_uuid, out_ports in host_vm_port.items():
        cmd += TEMPLATE["add-flow-inport-recv"].format(subnet_tun_id_hex=get_tun_id(subnet_uuid), out_ports=",".join(out_ports))  # 根据tun_id发到本地端口
    code, _, _ = exec_cmd("ssh %s '%s'" % (host_ip, cmd))
    # 更新数据库状态
    vm.stage = "OK"
    vm.power = 1
    DB.session.commit()
    return 0


def delete_vm(vm_uuid: str):
    """
    删除虚拟机
    :param vm_uuid: 虚拟机uuid
    :return:
    """
    vm = DB.session.query(VirtualMachine).filter_by(uuid=vm_uuid).first()
    if not vm:
        return 0
    vm.stage = "shutting down machine"
    DB.session.commit()
    vm = DB.session.query(VirtualMachine).filter_by(uuid=vm_uuid).first()
    # 虚拟机关机
    code, _, _ = exec_cmd("""ssh %s 'sudo virsh destroy %s'""" % (vm.host, vm.ip))
    if code:
        vm.stage += " ERROR"
        DB.session.commit()
        return 1
    vm.stage = "deleting machine"
    vm.power = 0
    DB.session.commit()
    # 删除虚拟机
    code, _, _ = exec_cmd("""ssh %s 'sudo virsh undefine %s && sudo rm /mnt/%s.qcow2'""" % (vm.host, vm.ip, vm.ip))
    if code:
        vm.stage += " ERROR"
        DB.session.commit()
        return 1
    vm.stage = "deleting flow"
    vm.power = 0
    DB.session.commit()
    # 删除宿主的流表
    cmd = TEMPLATE["del-flow-vm-gateway"].format(vm_mac=vm.mac)
    cmd += TEMPLATE["del-flow-vm"].format(vm_mac=vm.mac)
    cmd += TEMPLATE["del-flow-vm-ip"].format(vm_ip=vm.ip)
    cmd += TEMPLATE["del-flow-inport-send"].format(in_port=vm.interface)
    # cmd += TEMPLATE["del-flow-arp"].format(ip=vm.ip)
    # cmd += TEMPLATE["del-flow-arp-gratuitous"].format(ip=vm.ip)
    port_list = []
    for _vm in DB.session.query(VirtualMachine).filter_by(host=vm.host, power=1):
        if _vm.ip == vm.ip:
            continue
        if _vm.subnet_uuid == vm.subnet_uuid:
            port_list.append(_vm.interface)
    if port_list:
        cmd += TEMPLATE["add-flow-inport-recv"].format(subnet_tun_id_hex=get_tun_id(vm.subnet_uuid), out_ports=",".join(port_list))  # 根据tun_id发到本地端口
    else:
        cmd += TEMPLATE["del-flow-inport-recv"].format(subnet_tun_id_hex=get_tun_id(vm.subnet_uuid))
    code, _, _ = exec_cmd("ssh %s '%s'" % (vm.host, cmd))
    if code:
        vm.stage += " ERROR"
        DB.session.commit()
        return 1
    # 删除其它机器的流表
    cmd = TEMPLATE["del-flow-vm"].format(vm_mac=vm.mac)
    cmd += TEMPLATE["del-flow-vm-ip"].format(vm_ip=vm.ip)
    # cmd += TEMPLATE["del-flow-arp"].format(ip=vm.ip)
    # cmd += TEMPLATE["del-flow-arp-gratuitous"].format(ip=vm.ip)
    for host in get_list_raw([Host, SpecialNode, Gateway]):  # ...PhysicalMachine
        if host.management_ip == vm.host:
            continue
        code, _, _ = exec_cmd("ssh %s '%s'" % (host.management_ip, cmd))
    if code:
        vm.stage += " ERROR"
        DB.session.commit()
        return 1
    vm.stage = "deleting dhcp"
    DB.session.commit()
    # 删除DHCP
    code, _, _ = exec_cmd("""ssh %s 'sudo sed -i '"'"'/%s/d'"'"' /etc/dhcp/vm.conf && """
                          """sudo systemctl restart isc-dhcp-server'""" % (dhcp_server, vm.mac))  # 如用ip，小数点需转义
    if code:
        vm.stage += " ERROR"
        DB.session.commit()
        return 1
    DB.session.delete(vm)
    DB.session.commit()
    return 0


def shutdown_vm(vm_uuid: str):
    """
    关闭虚拟机（强制关机）
    :param vm_uuid: 虚拟机uuid
    :return:
    """
    vm = DB.session.query(VirtualMachine).filter_by(uuid=vm_uuid).first()
    if not vm:
        return 0
    vm.stage = "shutting down machine"
    DB.session.commit()
    vm = DB.session.query(VirtualMachine).filter_by(uuid=vm_uuid).first()
    # 虚拟机关机
    code, _, _ = exec_cmd("""ssh %s 'sudo virsh destroy %s'""" % (vm.host, vm.ip))
    if code:
        vm.stage += " ERROR"
        DB.session.commit()
        return 1
    vm.stage = "deleting flow"
    vm.power = 0
    DB.session.commit()
    # 删除宿主的流表
    cmd = TEMPLATE["del-flow-vm-gateway"].format(vm_mac=vm.mac)
    cmd += TEMPLATE["del-flow-vm"].format(vm_mac=vm.mac)
    cmd += TEMPLATE["del-flow-vm-ip"].format(vm_ip=vm.ip)
    cmd += TEMPLATE["del-flow-inport-send"].format(in_port=vm.interface)
    # cmd += TEMPLATE["del-flow-arp"].format(ip=vm.ip)
    # cmd += TEMPLATE["del-flow-arp-gratuitous"].format(ip=vm.ip)
    port_list = []
    for _vm in DB.session.query(VirtualMachine).filter_by(host=vm.host, power=1):
        if _vm.ip == vm.ip:
            continue
        if _vm.subnet_uuid == vm.subnet_uuid:
            port_list.append(_vm.interface)
    if port_list:
        cmd += TEMPLATE["add-flow-inport-recv"].format(subnet_tun_id_hex=get_tun_id(vm.subnet_uuid), out_ports=",".join(port_list))  # 根据tun_id发到本地端口
    else:
        cmd += TEMPLATE["del-flow-inport-recv"].format(subnet_tun_id_hex=get_tun_id(vm.subnet_uuid))
    code, _, _ = exec_cmd("ssh %s '%s'" % (vm.host, cmd))
    if code:
        vm.stage += " ERROR"
        DB.session.commit()
        return 1
    # 删除其它机器的流表
    cmd = TEMPLATE["del-flow-vm"].format(vm_mac=vm.mac)
    cmd += TEMPLATE["del-flow-vm-ip"].format(vm_ip=vm.ip)
    # cmd += TEMPLATE["del-flow-arp"].format(ip=vm.ip)
    # cmd += TEMPLATE["del-flow-arp-gratuitous"].format(ip=vm.ip)
    for host in get_list_raw([Host, SpecialNode, Gateway]):  # ...PhysicalMachine
        if host.management_ip == vm.host:
            continue
        code, _, _ = exec_cmd("ssh %s '%s'" % (host.management_ip, cmd))
    if code:
        vm.stage += " ERROR"
        DB.session.commit()
        return 1
    vm.stage = "SHUTDOWN"
    DB.session.commit()
    return 0


def start_vm(vm_uuid: str):
    """
    虚拟机开机
    :param vm_uuid: 虚拟机uuid
    :return:
    """
    vm = DB.session.query(VirtualMachine).filter_by(uuid=vm_uuid).first()
    if not vm:
        return 0
    vm.stage = "starting machine"
    DB.session.commit()
    code, _, _ = exec_cmd("""ssh %s 'sudo virsh start %s'""" % (vm.host, vm.ip))
    if code:
        vm.stage += " ERROR"
        DB.session.commit()
        return 1
    vm.stage = "adding flow"
    vm.power = 0
    DB.session.commit()
    # 下发vm网关流表
    cmd = TEMPLATE["add-flow-vm-gateway"].format(vm_mac=vm.mac, gateway_service_ip_hex="0x" + ip_to_hex(vm.gateway))  # 虚拟机发往哪个网关的流表
    code, _, _ = exec_cmd("ssh %s '%s'" % (vm.host, cmd))
    if code:
        vm.stage += " ERROR"
        DB.session.commit()
        return "下发vm网关流表时报错"
    # 给所有机器下发vm流表
    cmd = TEMPLATE["add-flow-vm-remote"].format(vm_mac=vm.mac, subnet_tun_id_hex=get_tun_id(vm.subnet_uuid),
                                                vm_host_ip_hex="0x" + ip_to_hex(vm.host))  # 到vm的流量
    cmd += TEMPLATE["add-flow-vm-remote-ip"].format(vm_ip=vm.ip, vm_mac=vm.mac, subnet_tun_id_hex=get_tun_id(vm.subnet_uuid),
                                                    vm_host_ip_hex="0x" + ip_to_hex(vm.host))  # 到vm的流量
    # cmd += TEMPLATE["add-flow-arp-vm-vm"].format(vm_ip=vm.ip, vm_mac=vm.mac, vm_mac_hex="0x" + vm.mac.replace(":", ""),
    #                                              vm_ip_hex="0x" + ip_to_hex(vm.ip))  # arp代答
    # cmd += TEMPLATE["add-flow-arp-vm-gratuitous"].format(vm_ip=vm.ip)  # 无故arp
    for host in get_list_raw([Host, SpecialNode, Gateway]):  # ...PhysicalMachine
        if host.management_ip == vm.host:
            continue
        code, _, _ = exec_cmd("ssh %s '%s'" % (host.management_ip, cmd))
    _, stdout, _ = exec_cmd("""ssh %s "sudo virsh domiflist %s | grep %s | awk '{print \\$1}'" """ % (vm.host, vm.ip, vm.mac))
    vm.interface = stdout.strip()
    DB.session.commit()
    # 给宿主下发流表
    cmd = TEMPLATE["add-flow-vm-local"].format(vm_mac=vm.mac, vm_interface=vm.interface)  # 这个有延迟，目前没办法在创建虚拟机前就分配好网卡
    cmd += TEMPLATE["add-flow-vm-local-ip"].format(vm_ip=vm.ip, vm_mac=vm.mac, vm_interface=vm.interface)  # 这个有延迟，目前没办法在创建虚拟机前就分配好网卡
    cmd += TEMPLATE["add-flow-inport-send"].format(in_port=vm.interface, subnet_tun_id_hex=get_tun_id(vm.subnet_uuid))  # 根据in_port设置tun_id
    cmd += TEMPLATE["add-flow-dhcp"].format(in_port=vm.interface, subnet_tun_id_hex=get_tun_id(vm.subnet_uuid),
                                            dhcp_server_hex=dhcp_server_hex)  # dhcp
    # cmd += TEMPLATE["add-flow-arp-vm-vm"].format(vm_ip=vm.ip, vm_mac=vm.mac, vm_mac_hex="0x" + vm.mac.replace(":", ""),
    #                                              vm_ip_hex="0x" + ip_to_hex(vm.ip))  # arp代答
    # cmd += TEMPLATE["add-flow-arp-vm-gratuitous"].format(vm_ip=vm.ip)  # 无故arp
    host_vm_port = {}  # 用于"add-flow-inport-recv"  _vm.subnet_uuid : [_vm.interface]
    for _vm in DB.session.query(VirtualMachine).filter_by(host=vm.host, power=1):
        if _vm.subnet_uuid not in host_vm_port:  # 用于"add-flow-inport-recv"
            host_vm_port[_vm.subnet_uuid] = [_vm.interface]
        else:
            host_vm_port[_vm.subnet_uuid].append(_vm.interface)
    for subnet_uuid, out_ports in host_vm_port.items():
        cmd += TEMPLATE["add-flow-inport-recv"].format(subnet_tun_id_hex=get_tun_id(subnet_uuid), out_ports=",".join(out_ports))  # 根据tun_id发到本地端口
    code, _, _ = exec_cmd("ssh %s '%s'" % (vm.host, cmd))
    # 更新数据库状态
    vm.stage = "OK"
    vm.power = 1
    DB.session.commit()
    return 0


def reboot_vm(vm_uuid: str):
    """
    重启虚拟机（强制重启）
    :param vm_uuid: 虚拟机uuid
    :return:
    """
    vm = DB.session.query(VirtualMachine).filter_by(uuid=vm_uuid).first()
    if not vm:
        return 0
    vm.stage = "rebooting machine"
    DB.session.commit()
    vm = DB.session.query(VirtualMachine).filter_by(uuid=vm_uuid).first()
    # 虚拟机关机
    code, _, _ = exec_cmd("""ssh %s 'sudo virsh reset %s'""" % (vm.host, vm.ip))
    if code:
        vm.stage += " ERROR"
        DB.session.commit()
        return 1
    vm.stage = "OK"
    vm.power = 1
    DB.session.commit()
    return 0


def create_nat(internet_ip: str, internal_ip: str, external_port: int, internal_port: int, protocol: str):
    """
    创建nat（dnat）
    :param internet_ip: 外网IP
    :param internal_ip: 内网IP
    :param external_port: 外网端口
    :param internal_port: 内网端口
    :param protocol: 协议（tcp/udp）
    :return:
    """
    # TODO：判断internet_ip是否在数据库中，internal_ip是否在云私有网段范围内
    if protocol not in ["udp", "tcp"]:
        return "协议不是udp或tcp"
    if not (1 <= internal_port <= 65535 or 1 <= external_port <= 65535):
        return "端口号不在1~65535内"
    query = DB.session.query(NAT).filter_by(internet_ip=internet_ip, external_port=external_port).first()
    if query:
        return "端口已被使用"
    # 生成一个uuid
    nat_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, "%s.%s.%d.%d.%s" % (internet_ip, internal_ip, external_port, internal_port, protocol)))
    # 写入数据库
    DB.session.add(NAT(
        uuid=nat_uuid, internet_ip=internet_ip, internal_ip=internal_ip,
        external_port=external_port, internal_port=internal_port, protocol=protocol, stage="creating"
    ))
    DB.session.commit()
    nat = DB.session.query(NAT).filter_by(uuid=nat_uuid).first()
    # 获得网关的ip，用于配置iptables
    gateway = DB.session.query(Gateway).filter_by(internet_ip=internet_ip).first()
    gateway_ip = gateway.internet_inner_ip or gateway.internet_ip  # 如果有internet_inner_ip则用，否则就当internet_ip直接配在网卡上
    # 组合成iptables命令
    cmd = "/sbin/iptables -t nat -A PREROUTING -d %s -p %s --dport %d -j DNAT --to-destination %s:%d" % (
        gateway_ip, protocol, external_port, internal_ip, internal_port)
    # 执行命令
    code, _, _ = exec_cmd("""ssh %s 'sudo %s'""" % (gateway.management_ip, cmd))
    if code:
        nat.stage += " ERROR"
        DB.session.commit()
        return "添加iptables规则失败"
    nat.stage = "OK"
    DB.session.commit()
    return None


def delete_nat(nat_uuid: str):
    """
    删除nat（dnat）
    :param nat_uuid: nat的uuid
    :return:
    """
    nat = DB.session.query(NAT).filter_by(uuid=nat_uuid).first()
    if not nat:
        return 0
    nat.stage = "deleting"
    DB.session.commit()
    # 获得网关的ip，用于配置iptables
    gateway = DB.session.query(Gateway).filter_by(internet_ip=nat.internet_ip).first()
    gateway_ip = gateway.internet_inner_ip or gateway.internet_ip  # 如果有internet_inner_ip则用，否则就当internet_ip直接配在网卡上
    # 组合成iptables命令
    cmd = "/sbin/iptables -t nat -D PREROUTING -d %s -p %s --dport %d -j DNAT --to-destination %s:%d" % (
        gateway_ip, nat.protocol, nat.external_port, nat.internal_ip, nat.internal_port)
    # 执行命令
    code, _, _ = exec_cmd("""ssh %s 'sudo %s'""" % (gateway.management_ip, cmd))
    if code:
        nat.stage += " ERROR"
        DB.session.commit()
        return 1
    DB.session.delete(nat)
    DB.session.commit()
    return 0


def set_vm_gateway(vm_uuid: str, gateway_internet_ip: str):
    """
    修改虚拟机网关
    :param vm_uuid: 虚拟机uuid
    :param gateway_internet_ip: 新的网关外网ip
    :return:
    """
    vm = DB.session.query(VirtualMachine).filter_by(uuid=vm_uuid).first()
    gateway = DB.session.query(Gateway).filter_by(internet_ip=gateway_internet_ip).first()
    # 修改流表
    cmd = TEMPLATE["add-flow-vm-gateway"].format(vm_mac=vm.mac, gateway_service_ip_hex="0x" + ip_to_hex(gateway.service_ip))  # 虚拟机发往哪个网关的流表
    code, _, _ = exec_cmd("ssh %s 'sudo %s'" % (vm.host, cmd))
    if code:
        return 1
    return 0


def create_subnet(mask: int, vpc_uuid: str = "test_vpc"):
    """
    创建子网
    :param mask: 掩码位数
    :param vpc_uuid: vpc的uuid
    :return: 0 或 msg
    """
    # 掩码位数校验
    if mask < 22 or mask > 28:
        return "掩码位数不能大于28，不能小于22。特殊需求请联系管理员。"
    # 查询vpc
    vpc = DB.session.query(VPC).filter_by(uuid=vpc_uuid).first()
    # 从头遍历可用的网段（算法略粗暴）
    can_be_allocated = False
    ip = None
    for ip in range(vpc.start, vpc.end, 2 ** (32 - mask)):
        # 判断该ip是否已被使用
        if DB.session.query(Subnet).filter(and_(Subnet.start <= ip, Subnet.end >= ip)).first():
            continue
        # 发现可用ip，设置flag并退出循环
        can_be_allocated = True
        break
    if not can_be_allocated:
        return "没有可用的网段了，请尝试减少掩码位数。"
    # 生成uuid并写入数据库
    subnet_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, "%d.%d.%s" % (ip, mask, vpc_uuid)))
    DB.session.add(Subnet(
        uuid=subnet_uuid, cidr=IPy.IP(ip).strNormal() + "/" + str(mask), start=ip, end=ip + 2 ** (32 - mask) - 1
    ))
    DB.session.commit()
    # 在所有网关节点配上子网网关IP
    gateway_ip = IPy.IP(ip + 1).strNormal()
    cmd = "sudo ip addr add {gateway_ip}/{mask} dev br0\n".format(gateway_ip=gateway_ip, mask=mask)
    gateways = DB.session.query(Gateway).all()
    for gateway in gateways:
        _, stdout, _ = exec_cmd("ssh %s 'sudo %s'" % (gateway.management_ip, cmd))
    # 在dhcp节点添加端口和IP，添加dhcp配置，重启dhcp，添加流表
    interface = "dhcp-" + ip_to_hex(gateway_ip)
    cmd = TEMPLATE["add-port-internal"].format(interface=interface)
    cmd += """sudo sed -i '"'"'/INTERFACESv4/ s/"$/ %s"/'"'"' /etc/default/isc-dhcp-server\n""" % interface
    cmd += "sudo ip addr add {gateway_ip}/{mask} dev {interface}\n".format(gateway_ip=gateway_ip, mask=mask, interface=interface)
    cmd += """echo "%s" >> /etc/dhcp/net.conf\n""" % TEMPLATE_CONF["dhcp_net"].format(
        subnet=IPy.IP(ip).strNormal(), netmask=int_to_mask(mask),
        gateway=IPy.IP(ip + 1).strNormal(),
        ip_start=IPy.IP(ip + 5).strNormal(),  # 保留前5个ip（第一个为网络地址，第二个为网关）
        ip_end=IPy.IP(ip + 2 ** (32 - mask) - 2).strNormal()  # 最后一个为广播地址
    )
    cmd += "sudo systemctl restart isc-dhcp-server\n"
    cmd += TEMPLATE["add-flow-dhcp-inport-recv"].format(subnet_tun_id_hex=get_tun_id(subnet_uuid), out_ports=interface)
    special_nodes = DB.session.query(SpecialNode).all()
    for special_node in special_nodes:
        if "dhcp" in special_node.role:
            _, stdout, _ = exec_cmd("ssh %s sudo '%s'" % (special_node.management_ip, cmd))
    # 在所有宿主添加对应流表
    cmd = TEMPLATE["add-flow-arp-vm-gateway"].format(gateway_ip=gateway_ip, gateway_ip_hex="0x" + ip_to_hex(gateway_ip))
    hosts = DB.session.query(Host).all()
    for host in hosts:
        _, stdout, _ = exec_cmd("ssh %s 'sudo %s'" % (host.management_ip, cmd))
    return 0


def delete_subnet(subnet_uuid: str):
    """
    删除子网
    :param subnet_uuid: 子网的uuid
    :return: 0 或 msg
    """
    # 查询子网
    subnet = DB.session.query(Subnet).filter_by(uuid=subnet_uuid).first()
    if subnet:
        # 检查子网内有没有虚拟机在
        vm = DB.session.query(VirtualMachine).filter_by(subnet_uuid=subnet_uuid).first()
        if vm:
            return "子网内还有虚拟机"
        # 在所有网关节点和交换节点删除子网网关IP
        gateway_ip = calc_gateway_ip(subnet.cidr)
        mask = subnet.cidr[-2:]
        cmd = "sudo ip addr del {gateway_ip}/{mask} dev br0\n".format(gateway_ip=gateway_ip, mask=mask)
        gateways = DB.session.query(Gateway).all()
        for gateway in gateways:
            _, stdout, _ = exec_cmd("ssh %s 'sudo %s'" % (gateway.management_ip, cmd))
        # for _host in get_list_raw(SpecialNode):
        #     if "role" in _host.__dict__.keys() and "switch" in _host.role:  # 交换节点
        #         _, stdout, _ = exec_cmd("ssh %s 'sudo %s'" % (_host.management_ip, cmd))
        # 在所有宿主删除对应流表
        cmd = TEMPLATE["del-flow-arp"].format(ip=gateway_ip)
        hosts = DB.session.query(Host).all()
        for host in hosts:
            _, stdout, _ = exec_cmd("ssh %s 'sudo %s'" % (host.management_ip, cmd))
        # 在dhcp节点删除流表、端口、dhcp配置，重启dhcp
        interface = "dhcp-" + ip_to_hex(gateway_ip)
        cmd = TEMPLATE["del-port"].format(interface=interface)
        cmd += TEMPLATE["del-flow-dhcp-inport-recv"].format(subnet_tun_id_hex=get_tun_id(subnet_uuid))
        cmd += """sudo sed -i '"'"'/INTERFACESv4/ s/ %s//'"'"' /etc/default/isc-dhcp-server\n""" % interface
        cmd += """sudo sed -i '"'"'/%s/d'"'"' /etc/dhcp/net.conf\n""" % gateway_ip
        cmd += "sudo systemctl restart isc-dhcp-server\n"
        special_nodes = DB.session.query(SpecialNode).all()
        for special_node in special_nodes:
            if "dhcp" in special_node.role:
                _, stdout, _ = exec_cmd("ssh %s 'sudo %s'" % (special_node.management_ip, cmd))
        # 清理数据库
        DB.session.delete(subnet)
        DB.session.commit()
    return 0


def get_list(obj):
    """
    获取对象列表
    :param obj: 对象名字（可以是列表）
    :return: 对象属性字典的列表
    """

    def _get_list(_obj):
        _list = []
        _all = DB.session.query(_obj).all()
        for _item in _all:
            _dict = copy.copy(_item.__dict__)
            for _key in list(_item.__dict__.keys()):
                if _key.startswith("_"):
                    del _dict[_key]  # 删除内部属性
            _list.append(_dict)
        return _list

    if type(obj) == list:
        result_list = []
        for o in obj:
            result_list.extend(_get_list(o))
    else:
        result_list = _get_list(obj)
    return result_list


def get_list_raw(obj):
    """
        获取对象列表
        :param obj: 对象名字（可以是列表）
        :return: 对象列表
        """

    def _get_list(_obj):
        return DB.session.query(_obj).all()

    if type(obj) == list:
        result_list = []
        for o in obj:
            result_list.extend(_get_list(o))
    else:
        result_list = _get_list(obj)
    return result_list


if __name__ == '__main__':
    """函数测试"""
    # print(create_subnet(27))
    # print(create_subnet(28))
    # print(delete_subnet("493036d9-90e7-513e-a593-f02488d968c0"))
    # print(delete_subnet("d6b72035-5a0c-5ef8-af39-8955e338185b"))

    # print(delete_host("5a40c9d0-e277-5435-98ab-c0132b22d468"))
    # print(delete_host("d63e7bbf-47aa-5f1d-b2e6-f7b152c8023f"))
    # print(delete_special_node("f86dc9d0-01c9-56a6-bd47-ce6237ee2dd3"))
    # print(delete_gateway("0a0711b9-30d6-5537-a014-634028b53e4b"))
    # print(delete_gateway("14c41856-8367-5dce-ab33-2b42f1e0173e"))

    refresh_flow_table("5a40c9d0-e277-5435-98ab-c0132b22d468", Host)
    refresh_flow_table("d63e7bbf-47aa-5f1d-b2e6-f7b152c8023f", Host)
    refresh_flow_table("c28e7c68-46bc-5b86-8789-a64ae1edb74c", Host)
    refresh_flow_table("f86dc9d0-01c9-56a6-bd47-ce6237ee2dd3", SpecialNode)
    refresh_flow_table("0a0711b9-30d6-5537-a014-634028b53e4b", Gateway)
    refresh_flow_table("14c41856-8367-5dce-ab33-2b42f1e0173e", Gateway)
    # add_consistent_flow("192.168.10.2", "192.168.10.2", "192.168.20.2", "14:00:00:00:00:00", "a09bd8c4-cae7-5914-9011-a4b1c0ecd1ec")

    # print(add_gateway("139.9.62.22", "139.9.62.22", "192.168.11.2", "192.168.0.133", 1, "华为云"))
    # print(add_gateway("119.29.62.52", "119.29.62.52", "192.168.12.2", "10.0.8.12", 5, "腾讯云"))
    # print(add_special_node("192.168.10.2", "192.168.10.2", "switch,dhcp"))
    # print(add_host("192.168.13.2", "192.168.13.2", "AZ-1", 32, 48))
    # print(add_host("192.168.13.3", "192.168.13.3", "AZ-1", 32, 48))
    # print(delete_host("4e981c56-3fff-539b-bb63-f975862a259c"))
    # print(add_host("192.168.14.2", "192.168.14.2", "AZ-2", 128, 256))

    # print(get_list(VirtualMachine))
    # print(get_list(Gateway))
    # create_vm("d6b72035-5a0c-5ef8-af39-8955e338185b", "139.9.62.22", "4C8G", "test10")
    # delete_vm("e7df3677-16b9-5f7f-9cd1-f7d9b035b52a")
    # create_nat("139.9.62.22", "192.168.20.10", 10022, 22, "tcp")
    # delete_nat("54b64d08-4cfa-5418-b12d-effbbd2ca5eb")
    # set_vm_gateway("3a0db673-eb15-55af-a7ab-ce4604a1d2ab", "119.29.62.52")
    # set_vm_gateway("3a0db673-eb15-55af-a7ab-ce4604a1d2ab", "139.9.62.22")

    # print(delete_subnet("09d3695f-ab9f-5647-b10d-7e348f74c629"))

    pass

"""
流表追踪
ovs-appctl ofproto/trace br0 icmp,dl_src=02:2e:bd:7e:ad:c0,dl_dst=12:16:3e:ad:c6:f6,nw_src=192.168.20.10,nw_dst=114.114.114.114
"""
