import os

import flask

import config
from controller import *

# 如果已经存在数据库，就跳过初始化
if os.path.exists("miniCloud2.db"):
    print("集群已存在数据库，跳过初始化")
    exit()

print("集群没有数据库，开始初始化")
app = flask.Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///miniCloud2.db'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = True
db.init_app(app)
with app.app_context():
    db.create_all()
    db.session.add(User(name="admin", password=password_hash("admin@miniCloud2"), tenant="ALL", is_admin=True))
    # db.session.add(User(name="test", password=password_hash("test"), tenant="test"))
    # db.session.add(User(name="test2", password=password_hash("test2"), tenant="test,test2"))
    db.session.add(Tenant(name="test"))
    # db.session.add(Tenant(name="test2"))
    print("create_vpc")
    print(create_vpc(name="test_vpc", cidr=Cloud_CIDR, tenant="test"))
    # print(create_vpc(name="test2_vpc", cidr="192.168.1.0/24", tenant="test2"))
    print("add_gateway")
    for node in config.network_nodes:
        node = node_infos[node]
        print(add_gateway(node["inventory_hostname"], node["internet_ip"],
                          node["inventory_hostname"], node["inventory_hostname"],
                          node["bandwidth"], node["description"]))
    print("add_special_node")
    for node in config.special_nodes:
        node = node_infos[node]
        print(add_special_node(node["inventory_hostname"], node["inventory_hostname"], node["role"]))
    print("add_host")
    for node in config.compute_nodes:
        node = node_infos[node]
        print(add_host(node["inventory_hostname"], node["inventory_hostname"], node["az"],
                       node["arch"], node["performance"], node["cpu"], node["cpu_alloc_ratio"],
                       node["mem"], node["mem_alloc_ratio"]))
    print("create_subnet")
    print(create_subnet(26))
