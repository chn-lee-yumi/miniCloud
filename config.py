Cloud_CIDR = "10.0.1.0/24"  # 整个云的网段范围
PASSWORD_SALT = "./s%7fS"  # 密码SHA1前加盐

# 虚拟机规格配置
FLAVORS = {
    "a1.small": {
        "performance": 1,
        "cpu": 1,
        "mem": 128,
        "arch": "arm",
    },
    "a2.medium": {
        "performance": 2,
        "cpu": 1,
        "mem": 512,
        "arch": "arm"
    },
    "a2.large": {
        "performance": 2,
        "cpu": 2,
        "mem": 1024,
        "arch": "arm"
    },
    "x2.medium": {
        "performance": 2,
        "cpu": 1,
        "mem": 512,
        "arch": "x86"
    },
    "x2.large": {
        "performance": 2,
        "cpu": 2,
        "mem": 1024,
        "arch": "x86"
    },
}

# 虚拟机系统列表
OS_LIST = ["ubuntu/22.04", "ubuntu/20.04",
           "debian/12", "debian/11",
           "centos/9-Stream", "centos/8-Stream"]
# archlinux fedora gentoo opensuse

# 以下是集群初始化配置，对于已存在数据库的集群无效
special_nodes = []
compute_nodes = []
network_nodes = []
node_infos = {}
