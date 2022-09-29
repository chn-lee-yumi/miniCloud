from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Text, Integer, ForeignKey, Float, Boolean

db = SQLAlchemy()


class User(db.Model):
    """
    用户
    属性： name          用户名
          password      密码（加盐后SHA1）
          tenant        所属租户，如有多个租户则用逗号分隔，ALL表示有所有租户的权限
          is_admin      是否管理员（可以看到所有租户）
    """
    __tablename__ = 'User'
    name = Column(Text, primary_key=True)
    password = Column(Text)
    tenant = Column(Text)
    is_admin = Column(Boolean, default=False)


class Tenant(db.Model):
    """
    租户
    属性： name          租户名
    """
    __tablename__ = 'Tenant'
    name = Column(Text, primary_key=True)


class VPC(db.Model):
    """
    VPC
    属性：   cidr    VPC的cidr
            start   十进制ip开始值，用于创建子网时的计算 IPy.IP(cidr).ip
            end     十进制ip结束值，用于创建子网时的计算 IPy.IP(cidr).ip+IPy.IP(cidr).len()-1
            tenant  租户
    """
    __tablename__ = 'VPC'
    uuid = Column(Text, primary_key=True)
    cidr = Column(Text)
    start = Column(Integer)
    end = Column(Integer)
    tenant = Column(Text)


class Subnet(db.Model):
    """
    子网（子网的cidr从vpc里面分配，根据用户需要的掩码位数自动计算合适的cidr，掩码位数限制为24-29）
    属性：   cidr      子网cidr
            start     十进制ip开始值，用于创建子网时的计算 IPy.IP(cidr).ip
            end       十进制ip结束值，用于创建子网时的计算 IPy.IP(cidr).ip+IPy.IP(cidr).len()-1
            vpc_uuid  所属VPC的uuid
            tenant    所属租户
    """
    __tablename__ = 'Subnet'
    uuid = Column(Text, primary_key=True)
    cidr = Column(Text)
    start = Column(Integer)
    end = Column(Integer)
    vpc_uuid = Column(Text, ForeignKey(VPC.uuid))
    tenant = Column(Text)


class VirtualMachine(db.Model):
    """
    虚拟机
    属性：   ip        虚拟机ip
            host      宿主机管理ip
            gateway   网关的internet_ip（不影响流表下发，仅用于查Gateway表）
            subnet_uuid 子网uuid
            flavor    实例类型
            mac       虚拟机mac地址
            interface 虚拟机的网卡名字
            stage     虚拟机初始化/删除进度（"configuring dhcp"->"adding flow"->"creating machine"->"OK"
                                          ->"shutting down machine"->"deleting machine"->"deleting flow"->"deleting dhcp"）
            power     虚拟机电源状态（1=ON，0=OFF）
            instance_name  虚拟机名字
            os 操作系统
            tenant    所属租户
            create_user 创建虚拟机的用户名
    """
    __tablename__ = 'VirtualMachine'
    uuid = Column(Text, primary_key=True)
    ip = Column(Text)
    host = Column(Text)
    gateway = Column(Text)
    subnet_uuid = Column(Text, ForeignKey(Subnet.uuid))
    flavor = Column(Text)
    mac = Column(Text)
    interface = Column(Text)
    stage = Column(Text)
    power = Column(Integer)
    instance_name = Column(Text)
    os = Column(Text)
    tenant = Column(Text)
    create_user = Column(Text)


class Host(db.Model):
    """
    宿主机
    属性：   management_ip   宿主机管理ip（用于SSH连接）
            service_ip      宿主机业务ip（用于与其它宿主或网关通信，例如创建VXLAN隧道）
            az              宿主机所在可用区
            arch            宿主机的CPU架构（如arm，x86）
            performance     宿主机性能标识（使用数字表示，越大性能越好，用于flavor对宿主机的选择）
            cpu             宿主机的CPU（单位：核）
            cpu_alloc_ratio 宿主机CPU分配比例（如1.5即可以总共分配1.5倍核数）
            mem             宿主机的内存（单位：MB）
            mem_alloc_ratio 宿主机内存分配比例（如1.5即可以总共分配1.5倍内存）
            tenant          宿主机所属的租户
    """
    __tablename__ = 'Host'
    uuid = Column(Text, primary_key=True)
    management_ip = Column(Text)
    service_ip = Column(Text)
    az = Column(Text)
    arch = Column(Text)
    performance = Column(Integer)
    cpu = Column(Integer)
    cpu_alloc_ratio = Column(Float)
    mem = Column(Integer)
    mem_alloc_ratio = Column(Float)
    tenant = Column(Text)


class SpecialNode(db.Model):
    """
    特殊节点。如提供DHCP的节点。特殊节点只有宿主机的vxlan隧道。
    属性：   management_ip  特殊节点管理ip（用于SSH连接）
            service_ip     特殊节点业务ip（用于与其它宿主或网关通信，例如创建VXLAN隧道）
            role           角色（switch,dhcp,等等，可以同时拥有多个角色，用逗号分隔）
    """
    __tablename__ = 'SpecialNode'
    uuid = Column(Text, primary_key=True)
    management_ip = Column(Text)
    service_ip = Column(Text)
    role = Column(Text)


class Gateway(db.Model):
    """
    网关
    属性：   management_ip  网关管理ip（用于SSH连接）
            internet_ip    网关公网ip（仅前端显示用，不影响流表下发。暂时只考虑一个Gateway只有一个公网ip，TODO：一个Gateway多个公网IP）
            service_ip     网关业务ip（vxlan隧道的ip）
            internet_inner_ip    网关公网映射的内网ip（例如公有云的EIP，绑定到某台ECS上，
                                 则ECS的内网ip就是internet_inner_ip），如果外网ip直接配在网卡上，该参数为空字符串
            bandwidth      带宽（无限速功能，仅在前端显示。单位：Mbps）
            description    描述（用作备注，在前端显示）
            tenant         网关所属租户
    """
    __tablename__ = 'Gateway'
    uuid = Column(Text, primary_key=True)
    management_ip = Column(Text)
    service_ip = Column(Text)
    internet_ip = Column(Text)
    internet_inner_ip = Column(Text)
    bandwidth = Column(Integer)
    description = Column(Text)
    tenant = Column(Text)


class NAT(db.Model):
    """
    NAT(DNAT)
    属性：   internet_ip      网关的外网ip
            internal_ip      虚拟机内网ip
            external_port    外网端口
            internal_port    内网端口
            protocol         协议（tcp/udp）
            stage            NAT配置进度（"creating"->"OK"->"deleting"）
            tenant           NAT所属租户
            create_user      创建NAT的用户
    """
    __tablename__ = 'NAT'
    uuid = Column(Text, primary_key=True)
    internet_ip = Column(Text)
    internal_ip = Column(Text)
    external_port = Column(Integer)
    internal_port = Column(Integer)
    protocol = Column(Text)
    stage = Column(Text)
    tenant = Column(Text)
    create_user = Column(Text)
