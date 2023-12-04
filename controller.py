import uuid

from sqlalchemy import and_

import net_manager
import plugin_wazuh
from config import *
from database import *
from utils import *

# 堡垒机配置 TODO：提取出来方便配置
ENABLE_JUMP_SERVER = True
if ENABLE_JUMP_SERVER:
    import plugin_jumpserver


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
    # 处理网络相关
    result = net_manager.add_host(service_ip, _uuid, init)
    return result


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
    # 处理网络相关
    result = net_manager.delete_host(host)
    return result


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
    # 处理网络相关
    result = net_manager.add_special_node(_uuid, init)
    return result


def delete_special_node(special_node_uuid: str):
    """
    删除特殊节点
    :param special_node_uuid: 特殊节点的uuid
    :return:
    """
    host = db.session.query(SpecialNode).filter_by(uuid=special_node_uuid).first()
    if not host:
        return 0
    db.session.delete(host)
    db.session.commit()
    # 处理网络相关
    result = net_manager.delete_special_node(host)
    return result


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
    # 处理网络相关
    result = net_manager.add_gateway(_uuid, init)
    return result


def delete_gateway(gateway_uuid: str):
    """
    删除网关 TODO：如果有vm，禁止删除
    :param gateway_uuid: 网关的uuid
    :return:
    """
    gateway = db.session.query(Gateway).filter_by(uuid=gateway_uuid).first()
    if not gateway:
        return 0
    # 删除网关
    db.session.delete(gateway)
    db.session.commit()
    # 处理网络相关
    result = net_manager.delete_gateway(gateway)
    return result


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
    if instance_name.isnumeric():
        return "虚拟机名字不能是纯数字"
    if not instance_name.isalnum():
        return "虚拟机名字只能包含英文和数字"
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
    # 处理网络相关
    result = net_manager.create_vm(gateway, vm, host_ip)
    if result:
        return result
    # 更新数据库状态
    vm.stage = "OK"
    vm.power = 1
    db.session.commit()
    # 写入堡垒机
    if ENABLE_JUMP_SERVER:
        # 自动创建一个SSH的NAT
        nat_port = 10000 + int(vm_ip.split(".")[-1])
        create_nat(gateway_internet_ip, vm_ip, nat_port, 22, "tcp", tenant, "堡垒机")
        plugin_jumpserver.create_assets(vm_uuid, create_user + "-" + instance_name, gateway_internet_ip, nat_port)
        plugin_jumpserver.create_perms(vm_uuid, create_user + "-" + instance_name, create_user)
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
    vm.stage = "deleting NAT"
    db.session.commit()
    # 自动删除所有NAT
    nat_list = db.session.query(NAT).filter_by(internal_ip=vm.ip).all()
    for nat in nat_list:
        code = delete_nat(nat.uuid)
        if code:
            vm.stage += " ERROR"
            db.session.commit()
            return 1
    vm.stage = "deleting machine"
    db.session.commit()
    vm = db.session.query(VirtualMachine).filter_by(uuid=vm_uuid).first()
    # 写入堡垒机
    if ENABLE_JUMP_SERVER:
        plugin_jumpserver.delete_assets(vm_uuid)
        plugin_jumpserver.delete_perms(vm_uuid)
        plugin_wazuh.delete_agent_by_ip(vm.ip)
    # 删除虚拟机
    code, _, _ = exec_cmd("""ssh %s 'sudo lxc delete --force %s; sudo lxc profile delete %s'""" % (vm.host, vm.instance_name, vm.instance_name))
    if code:
        vm.stage += " ERROR"
        db.session.commit()
        # return 1
    vm.stage = "deleting flow"
    vm.power = 0
    db.session.commit()
    # 处理网络相关
    result = net_manager.delete_vm(vm)
    if result:
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
    # 处理网络相关
    result = net_manager.shutdown_vm(vm)
    if result:
        vm.stage += " ERROR"
        db.session.commit()
        return result
    vm.stage = "shutting down machine"
    db.session.commit()
    vm = db.session.query(VirtualMachine).filter_by(uuid=vm_uuid).first()
    # 虚拟机关机
    code, _, _ = exec_cmd("""ssh %s 'sudo lxc stop --force %s'""" % (vm.host, vm.instance_name))
    if code:
        vm.stage += " ERROR"
        db.session.commit()
        return "关机失败"
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
    if not vm or vm.power == 1:  # TODO：可能用户从里面关机了
        return 0
    if vm.stage.find("ERROR") >= 0:
        return "VM状态为ERROR，无法启动。如果是新创建的机器，可以删除重新创建试试。"
    vm.stage = "starting machine"
    db.session.commit()
    code, _, _ = exec_cmd("""ssh %s 'sudo lxc start %s'""" % (vm.host, vm.instance_name))
    if code:
        vm.stage += " ERROR"
        db.session.commit()
        return "VM启动失败"
    _, stdout, _ = exec_cmd("""sudo lxc config get %s volatile.eth0.hwaddr""" % vm.instance_name)
    vm.mac = stdout.strip()
    vm.stage = "adding flow"
    vm.power = 0
    db.session.commit()
    # 处理网络相关
    result = net_manager.start_vm(vm)
    if result:
        vm.stage += " ERROR"
        db.session.commit()
        return result
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
    # 处理网络相关
    gateway = db.session.query(Gateway).filter_by(internet_ip=internet_ip).first()
    result = net_manager.create_nat(gateway, protocol, external_port, internal_ip, internal_port)
    if result:
        nat.stage += " ERROR"
        db.session.commit()
        return result
    nat.stage = "OK"
    db.session.commit()
    return 0


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
    # 处理网络相关
    gateway = db.session.query(Gateway).filter_by(internet_ip=nat.internet_ip).first()
    result = net_manager.delete_nat(nat, gateway)
    if result:
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
    result = net_manager.set_vm_gateway(vm, gateway)
    if result:
        return 1
    return 0


def create_subnet(mask: int, vpc_uuid: str):
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
    # 处理网络相关
    net_manager.create_subnet(ip, mask)
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
        # 处理网络相关
        net_manager.delete_subnet(subnet)
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


if __name__ == '__main__':
    """函数测试"""
    from flask import Flask

    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///miniCloud3.db'
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = True
    db.init_app(app)
    with app.app_context():
        db.create_all()
