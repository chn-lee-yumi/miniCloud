Cloud_CIDR = "{{ cloud_cidr }}"  # test的VPC网段范围
Cloud_CIDR_2 = "{{ cloud_cidr_2 }}"  # test2的VPC网段范围
PASSWORD_SALT = "./s%7fS"  # 密码SHA1前加盐
CONSOLE_TIMEOUT = 60  # 控制台超时时间

# 虚拟机规格配置
FLAVORS = {
    "a0.tiny": {
        "performance": 0,
        "cpu": 1,
        "mem": 128,
        "arch": "arm"
    },
    "a1.small": {
        "performance": 1,
        "cpu": 1,
        "mem": 512,
        "arch": "arm"
    },
    "a1.medium": {
        "performance": 1,
        "cpu": 2,
        "mem": 1024,
        "arch": "arm"
    },
    "x1.small": {
        "performance": 1,
        "cpu": 1,
        "mem": 512,
        "arch": "x86"
    },
    "x1.medium": {
        "performance": 1,
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
special_nodes = {{groups['special_node']}}
compute_nodes = {{groups['compute_node']}}
network_nodes = {{groups['network_node']}}
node_infos = {{hostvars}}
