import copy
import uuid

from sqlalchemy import and_

from config import *
from database import *
from utils import *

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


def add_host(management_ip: str, service_ip: str, az: str, arch: str, performance: int, cpu: int, cpu_alloc_ratio: float, mem: int,
             mem_alloc_ratio: float, tenant: str = "ALL", init: bool = True):
    """
    添加宿主
    :param management_ip: 宿主管理ip
    :param service_ip: 宿主业务ip
    :param az 宿主机所在AZ
    :param arch 宿主机CPU架构
    :param performance 宿主机性能性能标识
    :param cpu: 宿主机可以分配的CPU（单位：核）
    :param cpu_alloc_ratio 宿主机CPU分配比例（如1.5即可以总共分配1.5倍核数）
    :param mem             宿主机的内存（单位：MB）
    :param mem_alloc_ratio 宿主机内存分配比例（如1.5即可以总共分配1.5倍内存）
    :param tenant: 宿主所属租户，ALL表示共享
    :param init: 是否执行初始化
    :return:
    """
    # 生成一个uuid
    _uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, management_ip))
    # 写入数据库
    db.session.add(Host(uuid=_uuid, management_ip=management_ip, service_ip=service_ip, az=az, arch=arch, performance=performance,
                        cpu=cpu, cpu_alloc_ratio=cpu_alloc_ratio, mem=mem, mem_alloc_ratio=mem_alloc_ratio, tenant=tenant))
    db.session.commit()
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
    host = db.session.query(Host).filter_by(uuid=host_uuid).first()
    if not host:
        return 0
    db.session.delete(host)
    db.session.commit()
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
    db.session.add(SpecialNode(uuid=_uuid, management_ip=management_ip, service_ip=service_ip, role=role))
    db.session.commit()
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
    host = db.session.query(SpecialNode).filter_by(uuid=special_node_uuid).first()
    if not host:
        return 0
    db.session.delete(host)
    db.session.commit()
    return 0


def add_gateway(management_ip: str, internet_ip: str, service_ip: str, internet_inner_ip: str,
                bandwidth: int, tenant: str = "ALL", description: str = "", init: bool = True):
    """
    添加网关
    :param management_ip: 网关管理ip
    :param internet_ip: 网关公网ip
    :param service_ip: 网关业务ip（vxlan隧道的ip）
    :param internet_inner_ip: 网关公网映射的内网ip（例如公有云的EIP，绑定到某台ECS上，
                              则ECS的内网ip就是internet_inner_ip），如果外网ip直接配在网卡上，该参数为空字符串
    :param bandwidth: 网关带宽
    :param tenant: 网关所属租户，ALL表示共享网关
    :param description: 网关描述
    :param init: 是否执行初始化
    :return:
    """
    # 生成一个uuid
    _uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, management_ip))
    # 写入数据库
    db.session.add(Gateway(
        uuid=_uuid, management_ip=management_ip, internet_ip=internet_ip,
        service_ip=service_ip, internet_inner_ip=internet_inner_ip,
        bandwidth=bandwidth, tenant=tenant, description=description
    ))
    db.session.commit()
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
    gateway = db.session.query(Gateway).filter_by(uuid=gateway_uuid).first()
    if not gateway:
        return 0
    # 清理所有子网网关IP
    cmd = """ips=\\`sudo ip addr show br0 | grep inet | awk '{print \\$2}'\\`; for ip in \\$ips; do sudo ip addr del \\$ip dev br0; done"""
    _, stdout, _ = exec_cmd("ssh %s \"%s\"" % (gateway.management_ip, cmd))
    # 删除网关
    db.session.delete(gateway)
    db.session.commit()
    return 0


# def add_consistent_flow(management_ip: str, service_ip: str, inner_ip: str, mac: str, subnet_uuid: str):
#     # 给所有机器下发流表
#     cmd = TEMPLATE["add-flow-vm-remote"].format(vm_mac=mac, subnet_tun_id_hex=get_tun_id(subnet_uuid),
#                                                 vm_host_ip_hex="0x" + ip_to_hex(service_ip))  # 到物理机的流量
#     cmd += TEMPLATE["add-flow-vm-remote-ip"].format(vm_ip=inner_ip, vm_mac=mac, subnet_tun_id_hex=get_tun_id(subnet_uuid),
#                                                     vm_host_ip_hex="0x" + ip_to_hex(service_ip))  # 到物理机的流量
#     for host in get_list_raw([Host, Gateway, SpecialNode]):
#         if host.management_ip == management_ip:
#             continue
#         code, _, _ = exec_cmd("ssh %s '%s'" % (host.management_ip, cmd))
#     cmd = TEMPLATE["add-flow-vm-local"].format(vm_mac=mac, vm_interface="br0")
#     cmd += TEMPLATE["add-flow-vm-local-ip"].format(vm_ip=inner_ip, vm_mac=mac, vm_interface="br0")
#     code, _, _ = exec_cmd("ssh %s '%s'" % (management_ip, cmd))


def create_vm(subnet_uuid: str, gateway_internet_ip: str, flavor: str, os: str, instance_name: str,
              az: str, tenant: str, create_user: str, is_enable_ssh: bool,
              username: str = "", pubkey: str = "", vm_ip: str = "", host_ip: str = ""):
    """
    创建虚拟机
    :param subnet_uuid: 子网uuid
    :param gateway_internet_ip: 网关外网ip
    :param flavor: 虚拟机规格
    :param os: 虚拟机系统
    :param instance_name: 虚拟机名字
    :param username: 用户名
    :param pubkey: 公钥
    :param is_enable_ssh: 是否启用ssh登录
    :param az: 可用区
    :param tenant: VM所属租户
    :param create_user: 创建VM的用户
    :param host_ip: 宿主管理ip
    :param vm_ip: 虚拟机ip
    :return: 0=OK 1=Failed
    """
    # 检查用户名
    if is_enable_ssh and username in ["root", "admin"]:
        return "用户名不能为%s，请填入其他用户名。后续在服务器中用sudo切到root。" % username
    # 检查规格
    if flavor not in FLAVORS:
        return "虚拟机规格不正确"
    cpu = FLAVORS[flavor]["cpu"]
    mem = FLAVORS[flavor]["mem"]
    arch = FLAVORS[flavor]["arch"]
    performance = FLAVORS[flavor]["performance"]
    # 检查操作系统
    if os not in OS_LIST:
        return "所选操作系统不支持"
    # 检查名字
    if instance_name == "":
        return "请填写虚拟机名字"
    if db.session.query(VirtualMachine).filter_by(instance_name=instance_name).first():
        return "虚拟机名字重复"
    # 检查子网
    if not subnet_uuid:
        return "没有选择子网"
    subnet = db.session.query(Subnet).filter_by(uuid=subnet_uuid).first()
    if not subnet:
        return "子网不存在"
    # 检查网关
    gateway = db.session.query(Gateway).filter_by(internet_ip=gateway_internet_ip).first()
    if not gateway:
        return "没有这个网关！"
    # 检查ip/分配ip
    if vm_ip:  # 指定IP
        vm = db.session.query(VirtualMachine).filter_by(ip=vm_ip).first()
        if vm:  # ip重复
            return "IP已被使用"
        # 检查IP是否在子网内
        if not (subnet.start + 2) <= IPy.IP(vm_ip).int() <= (subnet.end - 1):
            return "IP不在子网范围内"  # TODO：该功能未自测
    else:
        # 查询子网内有没有空闲的ip
        for ip in range(subnet.start + 6, subnet.end - 1):  # 前5个ip和最后一个ip保留
            ip_str = IPy.IP(ip).strNormal()
            vm = db.session.query(VirtualMachine).filter_by(ip=ip_str).first()
            if not vm:
                vm_ip = ip_str
                break
        if not vm_ip:  # 没有足够的IP地址
            return "子网内没有足够的IP地址"  # 注：前5个ip和最后一个ip保留，如需使用请手动指定IP地址
    # 根据资源，分配宿主
    if not host_ip:
        hosts = db.session.query(Host).filter_by(az=az, arch=arch, performance=performance).all()
        host_dict = {}
        for host in hosts:
            # 忽略非共享宿主和非自己项目的宿主
            if host.tenant != "ALL" and host.tenant != tenant:
                continue
            host_dict[host.management_ip] = {"cpu": host.cpu * host.cpu_alloc_ratio, "mem": host.mem * host.mem_alloc_ratio}
        for _vm in db.session.query(VirtualMachine).all():
            if _vm.host not in host_dict:
                continue
            host_dict[_vm.host]["cpu"] -= FLAVORS[_vm.flavor]["cpu"]
            host_dict[_vm.host]["mem"] -= FLAVORS[_vm.flavor]["mem"]
        host_dict = sorted(host_dict.items(), key=lambda i: i[1]["cpu"], reverse=True)  # 先按CPU降序
        host_dict = sorted(host_dict, key=lambda i: i[1]["mem"], reverse=True)  # 再按内存降序
        if not host_dict:
            return "宿主资源不足"
        target_host = host_dict[0]  # 排序结果形如 [('192.168.10.2', {'cpu': 32, 'mem': 48}), ('192.168.13.2', {'cpu': 11, 'mem': 8})]
        if target_host[1]["cpu"] - cpu >= 0 and target_host[1]["mem"] - mem >= 0:
            host_ip = target_host[0]
        else:
            return "宿主资源不足"
    # 生成一个mac地址 格式：02:xx:xx:xx:xx:xx 本地mac地址范围：https://en.wikipedia.org/wiki/MAC_address#Universal_vs._local
    # uniq_mac = 1
    # vm_mac = ""
    # while uniq_mac:  # 如果生成了重复的mac，则重新生成
    #     vm_mac = ':'.join(map(lambda x: "%02x" % x,
    #                           [0x02, random.randint(0x00, 0xff), random.randint(0x00, 0xff),
    #                            random.randint(0x00, 0xff), random.randint(0x00, 0xff), random.randint(0x00, 0xff)]
    #                           ))
    #     uniq_mac = db.session.query(VirtualMachine).filter_by(mac=vm_mac).first()  # 检查是否有重复mac
    # 生成一个uuid
    vm_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, vm_ip))
    # 写入数据库
    vm_interface = "veth" + ip_to_hex(vm_ip)
    db.session.add(VirtualMachine(
        uuid=vm_uuid, ip=vm_ip, host=host_ip, gateway=gateway_internet_ip, subnet_uuid=subnet_uuid,
        flavor=flavor, stage="creating", power=0, instance_name=instance_name, interface=vm_interface,
        os=os, tenant=tenant, create_user=create_user
    ))
    db.session.commit()
    vm = db.session.query(VirtualMachine).filter_by(uuid=vm_uuid).first()
    db.session.commit()
    # 创建虚拟机
    if not is_enable_ssh:
        username = ""
        pubkey = ""
    if pubkey:
        code, _, _ = exec_cmd("""sudo bash ~/miniCloud/lxc-run.sh %s %s %s %sMB %s %s %s %s %s '%s' %s""" % (
            instance_name, os, cpu, mem,
            vm_ip, IPy.IP(IPy.IP(subnet.cidr).int() + 1).strNormal(), str(IPy.IP(subnet.cidr).netmask()), vm_interface,
            username, pubkey, host_ip))
    else:
        code, _, _ = exec_cmd("""sudo bash ~/miniCloud/lxc-run.sh %s %s %s %sMB %s %s %s %s %s""" % (
            instance_name, os, cpu, mem,
            vm_ip, IPy.IP(IPy.IP(subnet.cidr).int() + 1).strNormal(), str(IPy.IP(subnet.cidr).netmask()), vm_interface, host_ip))
    if code:
        vm.stage += " ERROR"
        db.session.commit()
        return "创建虚拟机时报错"
    _, stdout, _ = exec_cmd("""sudo lxc config get %s volatile.eth0.hwaddr""" % instance_name)
    vm.mac = stdout.strip()
    vm.stage = "adding flow"
    db.session.commit()
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
    # 更新数据库状态
    vm.stage = "OK"
    vm.power = 1
    db.session.commit()
    return 0


def delete_vm(vm_uuid: str):
    """
    删除虚拟机
    :param vm_uuid: 虚拟机uuid
    :return:
    """
    vm = db.session.query(VirtualMachine).filter_by(uuid=vm_uuid).first()
    if not vm:
        return 0
    # 检查有没有nat未删除
    if db.session.query(NAT).filter_by(internal_ip=vm.ip).all():
        return "该虚拟机还有NAT未删除，请删除NAT后再删除虚拟机！"
    vm.stage = "deleting machine"
    db.session.commit()
    vm = db.session.query(VirtualMachine).filter_by(uuid=vm_uuid).first()
    # 删除虚拟机
    code, _, _ = exec_cmd("""ssh %s 'sudo lxc delete --force %s; sudo lxc profile delete %s'""" % (vm.host, vm.instance_name, vm.instance_name))
    if code:
        vm.stage += " ERROR"
        db.session.commit()
        # return 1
    vm.stage = "deleting flow"
    vm.power = 0
    db.session.commit()
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
        vm.stage += " ERROR"
        db.session.commit()
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
        vm.stage += " ERROR"
        db.session.commit()
        return 1
    db.session.delete(vm)
    db.session.commit()
    return 0


def shutdown_vm(vm_uuid: str):
    """
    关闭虚拟机（强制关机）
    :param vm_uuid: 虚拟机uuid
    :return:
    """
    vm = db.session.query(VirtualMachine).filter_by(uuid=vm_uuid).first()
    if not vm or vm.power == 0:
        return 0
    if vm.stage.find("ERROR") >= 0:
        return "VM状态为ERROR，无法启动。如果是新创建的机器，可以删除重新创建试试。"
    vm.stage = "deleting flow"
    db.session.commit()
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
        vm.stage += " ERROR"
        db.session.commit()
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
        vm.stage += " ERROR"
        db.session.commit()
        return 1
    vm.stage = "shutting down machine"
    db.session.commit()
    vm = db.session.query(VirtualMachine).filter_by(uuid=vm_uuid).first()
    # 虚拟机关机
    code, _, _ = exec_cmd("""ssh %s 'sudo lxc stop --force %s'""" % (vm.host, vm.instance_name))
    if code:
        vm.stage += " ERROR"
        db.session.commit()
        return 1
    vm.power = 0
    vm.stage = "SHUTDOWN"
    db.session.commit()
    return 0


def start_vm(vm_uuid: str):
    """
    虚拟机开机
    :param vm_uuid: 虚拟机uuid
    :return:
    """
    vm = db.session.query(VirtualMachine).filter_by(uuid=vm_uuid).first()
    if not vm or vm.power == 1:
        return 0
    if vm.stage.find("ERROR") >= 0:
        return "VM状态为ERROR，无法启动。如果是新创建的机器，可以删除重新创建试试。"
    vm.stage = "starting machine"
    db.session.commit()
    code, _, _ = exec_cmd("""ssh %s 'sudo lxc start %s'""" % (vm.host, vm.instance_name))
    if code:
        vm.stage += " ERROR"
        db.session.commit()
        return 1
    _, stdout, _ = exec_cmd("""sudo lxc config get %s volatile.eth0.hwaddr""" % vm.instance_name)
    vm.mac = stdout.strip()
    vm.stage = "adding flow"
    vm.power = 0
    db.session.commit()
    # 下发vm网关流表
    gateway = db.session.query(Gateway).filter_by(internet_ip=vm.gateway).first()
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
    # 更新数据库状态
    vm.stage = "OK"
    db.session.commit()
    return 0


def reboot_vm(vm_uuid: str):
    """
    重启虚拟机（强制重启） TODO: 适配lxd
    :param vm_uuid: 虚拟机uuid
    :return:
    """
    vm = db.session.query(VirtualMachine).filter_by(uuid=vm_uuid).first()
    if not vm:
        return 0
    vm.stage = "rebooting machine"
    db.session.commit()
    vm = db.session.query(VirtualMachine).filter_by(uuid=vm_uuid).first()
    # 虚拟机关机
    code, _, _ = exec_cmd("""ssh %s 'sudo lxc restart %s'""" % (vm.host, vm.instance_name))
    if code:
        vm.stage += " ERROR"
        db.session.commit()
        return 1
    vm.stage = "OK"
    vm.power = 1
    db.session.commit()
    return 0


def create_nat(internet_ip: str, internal_ip: str, external_port: int, internal_port: int, protocol: str, tenant: str, create_user: str):
    """
    创建nat（dnat）
    :param internet_ip: 外网IP
    :param internal_ip: 内网IP
    :param external_port: 外网端口
    :param internal_port: 内网端口
    :param protocol: 协议（tcp/udp）
    :param tenant: NAT所属租户
    :param create_user: 创建NAT的用户
    :return:
    """
    # TODO：判断internet_ip是否在数据库中，internal_ip是否在云私有网段范围内
    if protocol not in ["udp", "tcp"]:
        return "协议不是udp或tcp"
    if not (1 <= internal_port <= 65535 or 1 <= external_port <= 65535):
        return "端口号不在1~65535内"
    query = db.session.query(NAT).filter_by(internet_ip=internet_ip, external_port=external_port).first()
    if query:
        return "端口已被使用"
    # 生成一个uuid
    nat_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, "%s.%s.%d.%d.%s" % (internet_ip, internal_ip, external_port, internal_port, protocol)))
    # 写入数据库
    db.session.add(NAT(
        uuid=nat_uuid, internet_ip=internet_ip, internal_ip=internal_ip,
        external_port=external_port, internal_port=internal_port,
        tenant=tenant, create_user=create_user, protocol=protocol, stage="creating"
    ))
    db.session.commit()
    nat = db.session.query(NAT).filter_by(uuid=nat_uuid).first()
    # 获得网关的ip，用于配置iptables
    gateway = db.session.query(Gateway).filter_by(internet_ip=internet_ip).first()
    gateway_ip = gateway.internet_inner_ip or gateway.internet_ip  # 如果有internet_inner_ip则用，否则就当internet_ip直接配在网卡上
    # 组合成iptables命令
    cmd = "/sbin/iptables -t nat -A PREROUTING -d %s -p %s --dport %d -j DNAT --to-destination %s:%d" % (
        gateway_ip, protocol, external_port, internal_ip, internal_port)
    # 执行命令
    code, _, _ = exec_cmd("""ssh %s 'sudo %s'""" % (gateway.management_ip, cmd))
    if code:
        nat.stage += " ERROR"
        db.session.commit()
        return "添加iptables规则失败"
    nat.stage = "OK"
    db.session.commit()
    return None


def delete_nat(nat_uuid: str):
    """
    删除nat（dnat）
    :param nat_uuid: nat的uuid
    :return:
    """
    nat = db.session.query(NAT).filter_by(uuid=nat_uuid).first()
    if not nat:
        return 0
    nat.stage = "deleting"
    db.session.commit()
    # 获得网关的ip，用于配置iptables
    gateway = db.session.query(Gateway).filter_by(internet_ip=nat.internet_ip).first()
    gateway_ip = gateway.internet_inner_ip or gateway.internet_ip  # 如果有internet_inner_ip则用，否则就当internet_ip直接配在网卡上
    # 组合成iptables命令
    cmd = "/sbin/iptables -t nat -D PREROUTING -d %s -p %s --dport %d -j DNAT --to-destination %s:%d" % (
        gateway_ip, nat.protocol, nat.external_port, nat.internal_ip, nat.internal_port)
    # 执行命令
    code, _, _ = exec_cmd("""ssh %s 'sudo %s'""" % (gateway.management_ip, cmd))
    if code:
        nat.stage += " ERROR"
        db.session.commit()
        return 1
    db.session.delete(nat)
    db.session.commit()
    return 0


def set_vm_gateway(vm_uuid: str, gateway_internet_ip: str):
    """
    修改虚拟机网关
    :param vm_uuid: 虚拟机uuid
    :param gateway_internet_ip: 新的网关外网ip
    :return:
    """
    vm = db.session.query(VirtualMachine).filter_by(uuid=vm_uuid).first()
    gateway = db.session.query(Gateway).filter_by(internet_ip=gateway_internet_ip).first()
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
    vpc = db.session.query(VPC).filter_by(uuid=vpc_uuid).first()
    # 从头遍历可用的网段（算法略粗暴）
    can_be_allocated = False
    ip = None
    for ip in range(vpc.start, vpc.end, 2 ** (32 - mask)):
        # 判断该ip是否已被使用
        if db.session.query(Subnet).filter(and_(Subnet.start <= ip, Subnet.end >= ip)).first():
            continue
        # 发现可用ip，设置flag并退出循环
        can_be_allocated = True
        break
    if not can_be_allocated:
        return "没有可用的网段了，请尝试减少掩码位数。"
    # 生成uuid并写入数据库
    subnet_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, "%d.%d.%s" % (ip, mask, vpc_uuid)))
    db.session.add(Subnet(
        uuid=subnet_uuid, cidr=IPy.IP(ip).strNormal() + "/" + str(mask), start=ip, end=ip + 2 ** (32 - mask) - 1,
        vpc_uuid=vpc_uuid, tenant=vpc.tenant
    ))
    db.session.commit()
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


def delete_subnet(subnet_uuid: str):
    """
    删除子网
    :param subnet_uuid: 子网的uuid
    :return: 0 或 msg
    """
    # 查询子网
    subnet = db.session.query(Subnet).filter_by(uuid=subnet_uuid).first()
    if subnet:
        # 检查子网内有没有虚拟机在
        vm = db.session.query(VirtualMachine).filter_by(subnet_uuid=subnet_uuid).first()
        if vm:
            return "子网内还有虚拟机"
        # 在所有网关节点和交换节点删除子网网关IP
        gateway_ip = calc_gateway_ip(subnet.cidr)
        mask = subnet.cidr[-2:]
        cmd = "sudo ip addr del {gateway_ip}/{mask} dev br0\n".format(gateway_ip=gateway_ip, mask=mask)
        gateways = db.session.query(Gateway).all()
        for gateway in gateways:
            _, stdout, _ = exec_cmd("ssh %s 'sudo %s'" % (gateway.management_ip, cmd))
        # for _host in get_list_raw(SpecialNode):
        #     if "role" in _host.__dict__.keys() and "switch" in _host.role:  # 交换节点
        #         _, stdout, _ = exec_cmd("ssh %s 'sudo %s'" % (_host.management_ip, cmd))
        # 在所有宿主删除对应流表
        cmd = TEMPLATE["del-flow-arp"].format(ip=gateway_ip)
        hosts = db.session.query(Host).all()
        for host in hosts:
            _, stdout, _ = exec_cmd("ssh %s 'sudo %s'" % (host.management_ip, cmd))
        # 清理数据库
        db.session.delete(subnet)
        db.session.commit()
    return 0


def create_vpc(name: str, cidr: str, tenant: str):
    """
    创建VPC
    :param name: VPC的名字
    :param cidr: VPC的cidr
    :param tenant: VPC所属租户
    :return: 0 或 msg
    """
    vpc_uuid = name
    db.session.add(VPC(
        uuid=vpc_uuid, cidr=cidr, start=IPy.IP(cidr).ip, end=IPy.IP(cidr).ip + IPy.IP(cidr).len() - 1, tenant=tenant
    ))
    db.session.commit()
    return 0


def get_list(obj):
    """
    获取对象列表
    :param obj: 对象名字（可以是列表）
    :return: 对象属性字典的列表
    """

    def _get_list(_obj):
        _list = []
        _all = db.session.query(_obj).all()
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
        return db.session.query(_obj).all()

    if type(obj) == list:
        result_list = []
        for o in obj:
            result_list.extend(_get_list(o))
    else:
        result_list = _get_list(obj)
    return result_list


if __name__ == '__main__':
    """函数测试"""
    from flask import Flask

    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///miniCloud2.db'
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = True
    db.init_app(app)
    with app.app_context():
        db.create_all()

"""
流表追踪
ovs-appctl ofproto/trace br0 icmp,dl_src=02:2e:bd:7e:ad:c0,dl_dst=12:16:3e:ad:c6:f6,nw_src=192.168.20.10,nw_dst=114.114.114.114
"""
