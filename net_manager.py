import IPy

from database import db, Gateway, SpecialNode, Host, Subnet, VirtualMachine, NAT
from utils import exec_cmd, calc_gateway_ip, ip_to_hex, get_tun_id, get_list_raw, logger

TEMPLATE = {
    # VXLAN端口 注意，如果一个包进来，会优先匹配到有remote_ip=对端ip的接口，如果没有这个接口，才会匹配remote_ip=flow的接口。
    "add-port-vxlan-local": "sudo ovs-vsctl add-port br0 vxlan-int -- set interface vxlan-int type=vxlan options:local_ip={ip} options:key=flow options:remote_ip=flow\n",
    "add-port-vxlan-remote": "sudo ovs-vsctl add-port br0 {interface} -- set interface {interface} type=vxlan options:remote_ip={ip} options:key=flow\n",
    "add-port-internal": "sudo ovs-vsctl add-port br0 {interface} -- set interface {interface} type=internal && sudo ip link set {interface} up\n",
    "del-port": "sudo ovs-vsctl del-port br0 {interface}\n",

    # 【table10】
    # vm到网关的流量(网关mac地址固定为12:00:00:FF:FF:FF)
    "add-flow-vm-gateway": """sudo ovs-ofctl add-flow br0 table=10,priority=5,dl_src={vm_mac},dl_dst=12:00:00:FF:FF:FF,actions=load:"{gateway_service_ip_hex}->NXM_NX_TUN_IPV4_DST[]",vxlan-int\n""",
    "del-flow-vm-gateway": """sudo ovs-ofctl del-flows br0 table=10,dl_src={vm_mac},dl_dst=12:00:00:FF:FF:FF\n""",
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
    "add-flow-arp-vm": """sudo ovs-ofctl add-flow br0 table=50,priority=20,arp,arp_tpa={vm_ip},arp_op=1,actions=move:"NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[]",mod_dl_src:"{vm_mac}",load:"0x02->NXM_OF_ARP_OP[]",move:"NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[]",load:"{vm_mac_hex}->NXM_NX_ARP_SHA[]",move:"NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[]",load:"{vm_ip_hex}->NXM_OF_ARP_SPA[]",in_port\n""",
    "del-flow-arp": """sudo ovs-ofctl del-flows br0 table=50,arp,arp_tpa={ip},arp_op=1\n""",
    # 根据inport设置tunid，resubmit60
    "add-flow-inport-send": """sudo ovs-ofctl add-flow br0 table=50,priority=10,in_port={in_port},actions=load:"{subnet_tun_id_hex}->NXM_NX_TUN_ID[]","resubmit(,60)"\n""",
    "del-flow-inport-send": """sudo ovs-ofctl del-flows br0 table=50,in_port={in_port}\n""",
    # inport是vxlan则根据tunid发到本地端口
    "add-flow-inport-recv": """sudo ovs-ofctl add-flow br0 table=50,priority=10,in_port=vxlan-sw,tun_id={subnet_tun_id_hex},actions={out_ports}\n""",
    "del-flow-inport-recv": """sudo ovs-ofctl del-flows br0 table=50,in_port=vxlan-sw,tun_id={subnet_tun_id_hex}\n""",

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
    target = db.session.query(target_type).filter_by(uuid=target_uuid).first()
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
    target = db.session.query(Gateway).filter_by(uuid=target_uuid).first()
    if not target:  # 宿主不存在
        target = db.session.query(SpecialNode).filter_by(uuid=target_uuid).first()
        if not target:  # 宿主不存在
            logger.warning("Gateway/SpecialNode不存在")
            return 1
    # 查询子网信息，拼接命令
    cmd = ""
    subnets = db.session.query(Subnet).all()
    for subnet in subnets:
        gateway_ip = calc_gateway_ip(subnet.cidr)
        mask = subnet.cidr[-2:]
        cmd += "sudo ip addr add {gateway_ip}/{mask} dev br0\n".format(gateway_ip=gateway_ip, mask=mask)
    # 执行命令
    if subnets:
        _, stdout, _ = exec_cmd("ssh %s '%s'" % (target.management_ip, cmd))
        # print(stdout)  # TODO：判断是否执行成功
    return 0


def refresh_flow_table(target_uuid: str, target_type):
    """
    刷新流表（全量更新）
    :param target_uuid: 目标uuid
    :param target_type: 目标类型（Gateway/Host/SpecialNode）
    :return:
    """
    if target_type not in [Host, Gateway, SpecialNode]:
        return 0
    # 查询宿主信息
    target = db.session.query(target_type).filter_by(uuid=target_uuid).first()
    if not target:  # 宿主不存在
        return 1
    cmd = TEMPLATE["del-flow-br0"]  # 先清空流表
    # VM网关相关流表
    host_vm_port = {}  # 用于"add-flow-inport-recv"  _vm.subnet_uuid : [_vm.interface]
    for _vm in get_list_raw(VirtualMachine):
        # print(_vm.host, target.management_ip)
        if _vm.host == target.management_ip:  # target_type == Host
            if _vm.power == 1:
                if _vm.subnet_uuid not in host_vm_port:  # 用于"add-flow-inport-recv"
                    host_vm_port[_vm.subnet_uuid] = [_vm.interface]
                else:
                    host_vm_port[_vm.subnet_uuid].append(_vm.interface)
            _gateway = db.session.query(Gateway).filter_by(management_ip=_vm.gateway).first()
            cmd += TEMPLATE["add-flow-vm-gateway"].format(vm_mac=_vm.mac,
                                                          gateway_service_ip_hex="0x" + ip_to_hex(_gateway.service_ip))  # 虚拟机发往哪个网关的流表
            if _vm.power == 1:
                cmd += TEMPLATE["add-flow-vm-local"].format(vm_mac=_vm.mac, vm_interface=_vm.interface)  # 到vm的流量
                cmd += TEMPLATE["add-flow-vm-local-ip"].format(vm_ip=_vm.ip, vm_mac=_vm.mac, vm_interface=_vm.interface)  # 到vm的流量
                cmd += TEMPLATE["add-flow-inport-send"].format(in_port=_vm.interface,
                                                               subnet_tun_id_hex=get_tun_id(_vm.subnet_uuid))  # 根据in_port设置tun_id
        else:
            cmd += TEMPLATE["add-flow-vm-remote"].format(vm_mac=_vm.mac, subnet_tun_id_hex=get_tun_id(_vm.subnet_uuid),
                                                         vm_host_ip_hex="0x" + ip_to_hex(_vm.host))  # 到vm的流量
            cmd += TEMPLATE["add-flow-vm-remote-ip"].format(vm_ip=_vm.ip, vm_mac=_vm.mac, subnet_tun_id_hex=get_tun_id(_vm.subnet_uuid),
                                                            vm_host_ip_hex="0x" + ip_to_hex(_vm.host))  # 到vm的流量
        cmd += TEMPLATE["add-flow-arp-vm"].format(vm_ip=_vm.ip, vm_mac=_vm.mac, vm_ip_hex="0x" + ip_to_hex(_vm.ip),
                                                  vm_mac_hex="0x" + _vm.mac.replace(":", ""))  # vm的arp代答
    for subnet_uuid, out_ports in host_vm_port.items():
        cmd += TEMPLATE["add-flow-inport-recv"].format(subnet_tun_id_hex=get_tun_id(subnet_uuid), out_ports=",".join(out_ports))  # 根据tun_id发到本地端口
    if target_type == Host:
        # 查询subnet信息，网关ARP代答流表
        subnets = db.session.query(Subnet).all()
        for subnet in subnets:
            gateway_ip = calc_gateway_ip(subnet.cidr)
            cmd += TEMPLATE["add-flow-arp-vm-gateway"].format(gateway_ip=gateway_ip, gateway_ip_hex="0x" + ip_to_hex(gateway_ip))
        # 广播流量
        cmd += TEMPLATE["add-flow-cast"]
    if target_type == SpecialNode and "role" in target.__dict__.keys() and "switch" in target.role:  # 交换节点
        cmd += TEMPLATE["add-flow-switch"]
    if target_type == Gateway:
        cmd += TEMPLATE["add-flow-gateway"]
    # 普通流表
    cmd += TEMPLATE["add-flow-normal"]
    # 执行命令
    _, stdout, _ = exec_cmd("ssh %s '%s'" % (target.management_ip, cmd))
    # print(stdout)  # TODO：不好判断有没有完成
    return 0


def add_host(service_ip: str, _uuid: str, init: bool):
    """添加宿主"""
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


def delete_host(host: Host):
    """删除宿主"""
    for _host in get_list_raw(SpecialNode):
        if "role" in _host.__dict__.keys() and "switch" in _host.role:  # 交换节点
            cmd = TEMPLATE["del-port"].format(interface="vxlan-" + ip_to_hex(host.service_ip))
            code, _, _ = exec_cmd("ssh %s '%s'" % (_host.management_ip, cmd))
            if code:
                return 1
    return 0


def add_special_node(_uuid: str, init: bool):
    """添加特殊节点"""
    if init:
        # 初始化vxlan隧道
        code = init_vxlan_tunnel(_uuid, SpecialNode)
        if code:
            return 1
        return init_subnet_gateway_ip(_uuid)
    return 0


def delete_special_node(host: SpecialNode):
    """删除特殊节点"""
    # 宿主的网桥/流表不会被清理，什么也不需要做
    return 0


def add_gateway(_uuid: str, init: bool):
    """添加网关"""
    # 初始化网桥
    if init:
        code = init_vxlan_tunnel(_uuid, Gateway)
        if code:
            return 1
        return init_subnet_gateway_ip(_uuid)
    return 0


def delete_gateway(gateway: Gateway):
    """删除网关"""
    # 清理所有子网网关IP
    cmd = """ips=\\`sudo ip addr show br0 | grep inet | awk '{print \\$2}'\\`; for ip in \\$ips; do sudo ip addr del \\$ip dev br0; done"""
    _, stdout, _ = exec_cmd("ssh %s \"%s\"" % (gateway.management_ip, cmd))
    return 0


def create_vm(gateway: Gateway, vm: VirtualMachine, host_ip: str):
    """创建虚拟机"""
    # 下发vm网关流表
    cmd = TEMPLATE["add-flow-vm-gateway"].format(vm_mac=vm.mac, gateway_service_ip_hex="0x" + ip_to_hex(gateway.service_ip))  # 虚拟机发往哪个网关的流表
    code, _, _ = exec_cmd("ssh %s '%s'" % (vm.host, cmd))
    if code:
        vm.stage += " ERROR"
        db.session.commit()
        return "下发vm网关流表时报错"
    # 给所有机器下发vm流表
    cmd = TEMPLATE["add-flow-vm-remote"].format(vm_mac=vm.mac, subnet_tun_id_hex=get_tun_id(vm.subnet_uuid),
                                                vm_host_ip_hex="0x" + ip_to_hex(vm.host))  # 到vm的流量
    cmd += TEMPLATE["add-flow-vm-remote-ip"].format(vm_ip=vm.ip, vm_mac=vm.mac, subnet_tun_id_hex=get_tun_id(vm.subnet_uuid),
                                                    vm_host_ip_hex="0x" + ip_to_hex(vm.host))  # 到vm的流量
    cmd += TEMPLATE["add-flow-arp-vm"].format(vm_ip=vm.ip, vm_mac=vm.mac, vm_ip_hex="0x" + ip_to_hex(vm.ip),
                                              vm_mac_hex="0x" + vm.mac.replace(":", ""))  # vm的arp代答
    for host in get_list_raw([Host, SpecialNode, Gateway]):
        if host.management_ip == host_ip:
            continue
        code, _, _ = exec_cmd("ssh %s '%s'" % (host.management_ip, cmd))
    # 给宿主下发流表
    cmd = TEMPLATE["add-flow-vm-local"].format(vm_mac=vm.mac, vm_interface=vm.interface)
    cmd += TEMPLATE["add-flow-vm-local-ip"].format(vm_ip=vm.ip, vm_mac=vm.mac, vm_interface=vm.interface)
    cmd += TEMPLATE["add-flow-inport-send"].format(in_port=vm.interface, subnet_tun_id_hex=get_tun_id(vm.subnet_uuid))  # 根据in_port设置tun_id
    cmd += TEMPLATE["add-flow-arp-vm"].format(vm_ip=vm.ip, vm_mac=vm.mac, vm_ip_hex="0x" + ip_to_hex(vm.ip),
                                              vm_mac_hex="0x" + vm.mac.replace(":", ""))  # vm的arp代答
    host_vm_port = {}  # 用于"add-flow-inport-recv"  _vm.subnet_uuid : [_vm.interface]
    for _vm in db.session.query(VirtualMachine).filter_by(host=host_ip):
        if not _vm.interface:
            continue
        if _vm.subnet_uuid not in host_vm_port:  # 用于"add-flow-inport-recv"
            host_vm_port[_vm.subnet_uuid] = [_vm.interface]
        else:
            host_vm_port[_vm.subnet_uuid].append(_vm.interface)
    for subnet_uuid, out_ports in host_vm_port.items():
        cmd += TEMPLATE["add-flow-inport-recv"].format(subnet_tun_id_hex=get_tun_id(subnet_uuid), out_ports=",".join(out_ports))  # 根据tun_id发到本地端口
    code, _, _ = exec_cmd("ssh %s '%s'" % (host_ip, cmd))
    return 0


def delete_vm(vm: VirtualMachine):
    """删除虚拟机"""
    # 删除宿主的流表
    cmd = TEMPLATE["del-flow-vm-gateway"].format(vm_mac=vm.mac)
    cmd += TEMPLATE["del-flow-vm"].format(vm_mac=vm.mac)
    cmd += TEMPLATE["del-flow-vm-ip"].format(vm_ip=vm.ip)
    # cmd += TEMPLATE["del-flow-inport-send"].format(in_port=vm.interface) # lxc: 不需要，关机时端口自己消失
    port_list = []
    for _vm in db.session.query(VirtualMachine).filter_by(host=vm.host, power=1):
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
        return 1
    # 删除其它机器的流表
    cmd = TEMPLATE["del-flow-vm"].format(vm_mac=vm.mac)
    cmd += TEMPLATE["del-flow-vm-ip"].format(vm_ip=vm.ip)
    cmd += TEMPLATE["del-flow-arp"].format(ip=vm.ip)
    for host in get_list_raw([Host, SpecialNode, Gateway]):
        if host.management_ip == vm.host:
            continue
        code, _, _ = exec_cmd("ssh %s '%s'" % (host.management_ip, cmd))
    if code:
        return 1
    return 0


def shutdown_vm(vm: VirtualMachine):
    """强制关闭虚拟机"""
    # 删除宿主的流表
    cmd = TEMPLATE["del-flow-vm-gateway"].format(vm_mac=vm.mac)
    cmd += TEMPLATE["del-flow-vm"].format(vm_mac=vm.mac)
    cmd += TEMPLATE["del-flow-vm-ip"].format(vm_ip=vm.ip)
    cmd += TEMPLATE["del-flow-inport-send"].format(in_port=vm.interface)
    port_list = []
    for _vm in db.session.query(VirtualMachine).filter_by(host=vm.host, power=1):
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
        return "流表更新失败"
    # 删除其它机器的流表
    cmd = TEMPLATE["del-flow-vm"].format(vm_mac=vm.mac)
    cmd += TEMPLATE["del-flow-vm-ip"].format(vm_ip=vm.ip)
    cmd += TEMPLATE["del-flow-arp"].format(ip=vm.ip)
    for host in get_list_raw([Host, SpecialNode, Gateway]):
        if host.management_ip == vm.host:
            continue
        code, _, _ = exec_cmd("ssh %s '%s'" % (host.management_ip, cmd))
    if code:
        return "流表更新失败"
    return 0


def start_vm(vm: VirtualMachine):
    """启动虚拟机"""
    # 下发VM网关流表
    gateway = db.session.query(Gateway).filter_by(internet_ip=vm.gateway).first()
    cmd = TEMPLATE["add-flow-vm-gateway"].format(vm_mac=vm.mac, gateway_service_ip_hex="0x" + ip_to_hex(gateway.service_ip))  # 虚拟机发往哪个网关的流表
    code, _, _ = exec_cmd("ssh %s '%s'" % (vm.host, cmd))
    if code:
        return "下发VM网关流表时报错"
    # 给所有机器下发vm流表
    cmd = TEMPLATE["add-flow-vm-remote"].format(vm_mac=vm.mac, subnet_tun_id_hex=get_tun_id(vm.subnet_uuid),
                                                vm_host_ip_hex="0x" + ip_to_hex(vm.host))  # 到vm的流量
    cmd += TEMPLATE["add-flow-vm-remote-ip"].format(vm_ip=vm.ip, vm_mac=vm.mac, subnet_tun_id_hex=get_tun_id(vm.subnet_uuid),
                                                    vm_host_ip_hex="0x" + ip_to_hex(vm.host))  # 到vm的流量
    cmd += TEMPLATE["add-flow-arp-vm"].format(vm_ip=vm.ip, vm_mac=vm.mac, vm_ip_hex="0x" + ip_to_hex(vm.ip),
                                              vm_mac_hex="0x" + vm.mac.replace(":", ""))  # vm的arp代答
    for host in get_list_raw([Host, SpecialNode, Gateway]):
        if host.management_ip == vm.host:
            continue
        code, _, _ = exec_cmd("ssh %s '%s'" % (host.management_ip, cmd))
    # 给宿主下发流表
    cmd = TEMPLATE["add-flow-vm-local"].format(vm_mac=vm.mac, vm_interface=vm.interface)  # 这个有延迟，目前没办法在创建虚拟机前就分配好网卡
    cmd += TEMPLATE["add-flow-vm-local-ip"].format(vm_ip=vm.ip, vm_mac=vm.mac, vm_interface=vm.interface)  # 这个有延迟，目前没办法在创建虚拟机前就分配好网卡
    cmd += TEMPLATE["add-flow-inport-send"].format(in_port=vm.interface, subnet_tun_id_hex=get_tun_id(vm.subnet_uuid))  # 根据in_port设置tun_id
    cmd += TEMPLATE["add-flow-arp-vm"].format(vm_ip=vm.ip, vm_mac=vm.mac, vm_ip_hex="0x" + ip_to_hex(vm.ip),
                                              vm_mac_hex="0x" + vm.mac.replace(":", ""))  # vm的arp代答
    host_vm_port = {}  # 用于"add-flow-inport-recv"  _vm.subnet_uuid : [_vm.interface]
    vm.power = 1  # 设置vm开机，否则下面查询端口的时候就没有此vm
    db.session.commit()
    for _vm in db.session.query(VirtualMachine).filter_by(host=vm.host, power=1):
        if _vm.subnet_uuid not in host_vm_port:  # 用于"add-flow-inport-recv"
            host_vm_port[_vm.subnet_uuid] = [_vm.interface]
        else:
            host_vm_port[_vm.subnet_uuid].append(_vm.interface)
    for subnet_uuid, out_ports in host_vm_port.items():
        cmd += TEMPLATE["add-flow-inport-recv"].format(subnet_tun_id_hex=get_tun_id(subnet_uuid), out_ports=",".join(out_ports))  # 根据tun_id发到本地端口
    code, _, _ = exec_cmd("ssh %s '%s'" % (vm.host, cmd))
    return 0


def reboot_vm(vm: VirtualMachine):
    """重启虚拟机 暂时没有调用"""
    return 0


def create_nat(gateway: Gateway, protocol: str, external_port: int, internal_ip: str, internal_port: int):
    """创建NAT"""
    # 获得网关的ip，用于配置iptables
    gateway_ip = gateway.internet_inner_ip or gateway.internet_ip  # 如果有internet_inner_ip则用，否则就当internet_ip直接配在网卡上
    # 组合成iptables命令
    cmd = "/sbin/iptables -t nat -A PREROUTING -d %s -p %s --dport %d -j DNAT --to-destination %s:%d" % (
        gateway_ip, protocol, external_port, internal_ip, internal_port)
    # 执行命令
    code, _, _ = exec_cmd("""ssh %s 'sudo %s'""" % (gateway.management_ip, cmd))
    if code:
        return "添加iptables规则失败"
    return 0


def delete_nat(nat: NAT, gateway: Gateway):
    """删除NAT"""
    # 获得网关的ip，用于配置iptables
    gateway_ip = gateway.internet_inner_ip or gateway.internet_ip  # 如果有internet_inner_ip则用，否则就当internet_ip直接配在网卡上
    # 组合成iptables命令
    cmd = "/sbin/iptables -t nat -D PREROUTING -d %s -p %s --dport %d -j DNAT --to-destination %s:%d" % (
        gateway_ip, nat.protocol, nat.external_port, nat.internal_ip, nat.internal_port)
    # 执行命令
    code, _, _ = exec_cmd("""ssh %s 'sudo %s'""" % (gateway.management_ip, cmd))
    return code


def set_vm_gateway(vm: VirtualMachine, gateway: Gateway):
    """修改虚拟机网关"""
    # 修改流表
    cmd = TEMPLATE["add-flow-vm-gateway"].format(vm_mac=vm.mac, gateway_service_ip_hex="0x" + ip_to_hex(gateway.service_ip))  # 虚拟机发往哪个网关的流表
    code, _, _ = exec_cmd("ssh %s 'sudo %s'" % (vm.host, cmd))
    return code


def create_subnet(ip: int, mask: int):
    """创建子网"""
    # 在所有网关节点配上子网网关IP
    gateway_ip = IPy.IP(ip + 1).strNormal()
    cmd = "sudo ip addr add {gateway_ip}/{mask} dev br0\n".format(gateway_ip=gateway_ip, mask=mask)
    gateways = db.session.query(Gateway).all()
    for gateway in gateways:
        _, stdout, _ = exec_cmd("ssh %s 'sudo %s'" % (gateway.management_ip, cmd))
    # 在所有宿主添加对应流表
    cmd = TEMPLATE["add-flow-arp-vm-gateway"].format(gateway_ip=gateway_ip, gateway_ip_hex="0x" + ip_to_hex(gateway_ip))
    hosts = db.session.query(Host).all()
    for host in hosts:
        _, stdout, _ = exec_cmd("ssh %s 'sudo %s'" % (host.management_ip, cmd))
    return 0


def delete_subnet(subnet: Subnet):
    """删除子网"""
    # 在所有网关节点和交换节点删除子网网关IP
    gateway_ip = calc_gateway_ip(subnet.cidr)
    mask = subnet.cidr[-2:]
    cmd = "sudo ip addr del {gateway_ip}/{mask} dev br0\n".format(gateway_ip=gateway_ip, mask=mask)
    gateways = db.session.query(Gateway).all()
    for gateway in gateways:
        _, stdout, _ = exec_cmd("ssh %s 'sudo %s'" % (gateway.management_ip, cmd))
    # 在所有宿主删除对应流表
    cmd = TEMPLATE["del-flow-arp"].format(ip=gateway_ip)
    hosts = db.session.query(Host).all()
    for host in hosts:
        _, stdout, _ = exec_cmd("ssh %s 'sudo %s'" % (host.management_ip, cmd))
    return 0
