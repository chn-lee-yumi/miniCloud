"""
这个文件定义了数据库和对象模型
"""
# TODO: use Flask-SQLAlchemy? http://www.pythondoc.com/flask-sqlalchemy/quickstart.html
# sqlalchemy参考资料：https://www.cnblogs.com/lsdb/p/9835894.html
from sqlalchemy import Column, Text, Integer, create_engine, ForeignKey
from sqlalchemy.ext.declarative import declarative_base

from sqlalchemy.orm import sessionmaker

Base = declarative_base()  # 先建立基本映射类，后边真正的映射类都要继承它

Cloud_CIDR = "192.168.20.0/22"  # 整个云的网段范围


class VPC(Base):
    """
    VPC
    属性：   cidr    VPC的cidr
            start   十进制ip开始值，用于创建子网时的计算 IPy.IP(cidr).ip
            end     十进制ip结束值，用于创建子网时的计算 IPy.IP(cidr).ip+IPy.IP(cidr).len()-1
    """
    __tablename__ = 'VPC'
    uuid = Column(Text, primary_key=True)
    cidr = Column(Text)
    start = Column(Integer)
    end = Column(Integer)


class Subnet(Base):
    """
    子网（子网的cidr从vpc里面分配，根据用户需要的掩码位数自动计算合适的cidr，掩码位数限制为24-29）
    属性：   cidr    子网cidr
            start   十进制ip开始值，用于创建子网时的计算 IPy.IP(cidr).ip
            end     十进制ip结束值，用于创建子网时的计算 IPy.IP(cidr).ip+IPy.IP(cidr).len()-1
            vpc_uuid  所属VPC的uuid
    """
    __tablename__ = 'Subnet'
    uuid = Column(Text, primary_key=True)
    cidr = Column(Text)
    start = Column(Integer)
    end = Column(Integer)
    vpc_uuid = Column(Text, ForeignKey(VPC.uuid))


# class PhysicalMachine(Base):
#     """
#     虚拟机
#     属性：   management_ip  物理机管理ip（用于SSH连接）
#             service_ip     物理机业务ip（用于与其它宿主或网关通信，例如创建VXLAN隧道）
#             inner_ip       物理机内网ip（网桥的ip）
#             mac            物理机网桥mac地址
#             hostname       物理机名字
#     """
#     __tablename__ = 'PhysicalMachine'
#     uuid = Column(Text, primary_key=True)
#     management_ip = Column(Text)
#     service_ip = Column(Text)
#     inner_ip = Column(Text)
#     mac = Column(Text)
#     hostname = Column(Text)


class VirtualMachine(Base):
    """
    虚拟机
    属性：   ip        虚拟机ip
            host      宿主机管理ip
            gateway   网关管理ip
            subnet_uuid 子网uuid
            flavor    实例类型
            mac       虚拟机mac地址
            interface 虚拟机的网卡名字
            stage     虚拟机初始化/删除进度（"configuring dhcp"->"adding flow"->"creating machine"->"OK"
                                          ->"shutting down machine"->"deleting machine"->"deleting flow"->"deleting dhcp"）
            power     虚拟机电源状态（1=ON，0=OFF）
            hostname  虚拟机名字
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
    hostname = Column(Text)


class Host(Base):
    """
    宿主机
    属性：   management_ip  宿主机管理ip（用于SSH连接）
            service_ip     宿主机业务ip（用于与其它宿主或网关通信，例如创建VXLAN隧道）
            az             宿主机所在可用区
            cpu            宿主机可以分配的CPU（单位：核）
            mem            宿主机可以分配的内存（单位：GB）
    """
    __tablename__ = 'Host'
    uuid = Column(Text, primary_key=True)
    management_ip = Column(Text)
    service_ip = Column(Text)
    az = Column(Text)
    cpu = Column(Integer)
    mem = Column(Integer)


class SpecialNode(Base):
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


class Gateway(Base):
    """
    网关
    属性：   management_ip  网关管理ip（用于SSH连接）
            internet_ip    网关公网ip（暂时只考虑一个Gateway只有一个公网ip，TODO：一个Gateway多个公网IP）
            service_ip     网关业务ip（vxlan隧道的ip）
            internet_inner_ip    网关公网映射的内网ip（例如公有云的EIP，绑定到某台ECS上，
                                 则ECS的内网ip就是internet_inner_ip），如果外网ip直接配在网卡上，该参数为空字符串
            bandwidth      带宽（无限速功能，仅在前端显示。单位：Mbps）
            description    描述（用作备注，在前端显示）
    """
    __tablename__ = 'Gateway'
    uuid = Column(Text, primary_key=True)
    management_ip = Column(Text)
    service_ip = Column(Text)
    internet_ip = Column(Text)
    internet_inner_ip = Column(Text)
    bandwidth = Column(Integer)
    description = Column(Text)


class NAT(Base):
    """
    NAT(DNAT)
    属性：   internet_ip      网关的外网ip
            internal_ip      虚拟机内网ip
            external_port    外网端口
            internal_port    内网端口
            protocol         协议（tcp/udp）
            stage            NAT配置进度（"creating"->"OK"->"deleting"）
    """
    __tablename__ = 'NAT'
    uuid = Column(Text, primary_key=True)
    internet_ip = Column(Text)
    internal_ip = Column(Text)
    external_port = Column(Integer)
    internal_port = Column(Integer)
    protocol = Column(Text)
    stage = Column(Text)


class Database:
    """数据库"""

    def __init__(self):
        """初始化数据库"""
        self.db_path = 'sqlite:///miniCloud.db?check_same_thread=False'
        self.engine = create_engine(self.db_path, echo=True)
        Base.metadata.create_all(self.engine, checkfirst=True)
        self.session = sessionmaker(bind=self.engine)()


if __name__ == '__main__':
    Database()
