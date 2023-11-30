Cloud_CIDR = "{{ cloud_cidr }}"  # VPC网段范围
PASSWORD_SALT = "./s%7fS"  # 密码SHA1前加盐
CONSOLE_TIMEOUT = 600  # 控制台超时时间

# 虚拟机规格配置
FLAVORS = {
    "x1.micro": {
        "performance": 1,
        "cpu": 0.5,
        "mem": 1024,
        "arch": "x86"
    },
    "x1.small": {
        "performance": 1,
        "cpu": 1,
        "mem": 2048,
        "arch": "x86"
    },
    "x1.medium": {
        "performance": 1,
        "cpu": 2,
        "mem": 4096,
        "arch": "x86"
    },
    "x1.large": {
        "performance": 1,
        "cpu": 3,
        "mem": 6144,
        "arch": "x86"
    },
}

# 虚拟机系统列表
OS_LIST = ["ubuntu/22.04", "ubuntu/20.04",
           # "debian/12", "debian/11",  # debian目前镜像有问题
           "centos/9-Stream", "centos/8-Stream"]
# archlinux fedora gentoo opensuse

# 以下是集群初始化配置，对于已存在数据库的集群无效
special_nodes = {{groups['special_node']}}
compute_nodes = {{groups['compute_node']}}
network_nodes = {{groups['network_node']}}
node_infos = {{hostvars}}

# 堡垒机配置 TODO：暂时写死
jms_url = 'https://bastion.gdutnic.com'
KeyID = 'eeea4547-39a4-46af-9b27-ab6a3fb13f87'
SecretID = 'a9074ab8-97ed-4ae8-a9c3-f50c0baa4d64'
