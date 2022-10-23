import copy
import json
import os
import threading
import time
import uuid
from functools import wraps

import simple_websocket
from flask import Flask, session, redirect, url_for, request, jsonify
from flask_sock import Sock
from sqlalchemy import or_

from config import *
from controller import create_vm, delete_vm, start_vm, shutdown_vm, create_nat, delete_nat, create_subnet, delete_subnet, refresh_flow_table
from database import *
from utils import *

app = Flask(__name__)
app.secret_key = b'_5#y212\rfaL"F4aQ8asdfn\xec]/'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///miniCloud2.db'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = True
sock = Sock(app)
db.init_app(app)
console_session_map = {}  # 控制台的连接字典，key为连接id，value为连接空闲时间，超过1分钟就断掉。


def login_required(func):
    """需要先登录的装饰器"""

    @wraps(func)
    def decorated_view(*args, **kwargs):
        if "username" in session:
            return func(*args, **kwargs)
        else:
            return "请先登录", 403

    return decorated_view


def dict_to_list(data: dict, attr: str):
    return list(map(lambda i: i[attr], data))


def get_list(obj):
    """
    获取对象列表
    :param obj: 对象名字（可以是列表）
    :return: 对象属性字典的列表
    """

    def _get_list(_obj):
        _list = []
        _all = db.session.query(_obj).filter(or_(obj.tenant == session['tenant'], obj.tenant == "ALL")).all()
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


def init():
    """初始化数据库"""
    with app.app_context():
        db.create_all()


def read_pipe(p, ws, session_id):
    """从管道中不断读取字符并发送到websocket"""
    buf = b""
    while True:
        out = p.stdout.read(1)
        # print("out", out)
        if not out:  # 读到空就退出线程
            break
        buf += out
        try:  # 处理非utf8字符的问题
            out = buf.decode()
            buf = b""
        except UnicodeDecodeError:
            continue
        try:
            ws.send(out)
            console_session_map[session_id] = time.time()  # 更新session时间
        except simple_websocket.ws.ConnectionClosed:
            break


def monitor_websocket(p, ws, session_id):
    """监控websocket状态，如果websocket已经断开，则kill掉控制台"""
    while time.time() - console_session_map[session_id] < CONSOLE_TIMEOUT:
        time.sleep(1)
    # 超时
    os.system("sudo python3 kill_console.py " + str(p.pid))
    ws.close()


# socket 路由，访问url是： ws://localhost:5000/console
@sock.route('/console/<instance>')
def socket_console(ws, instance):
    """web终端，连接容器"""
    if "username" not in session:
        ws.send("\033[31m请先登录！\033[0m\r\n")
        ws.close()
        return
    vm = db.session.query(VirtualMachine).filter_by(instance_name=instance).first()
    if not vm:
        ws.send("\033[31m虚拟机 %s 不存在！\033[0m\r\n" % instance)
        ws.close()
        return
    user = db.session.query(User).filter_by(name=session["username"]).first()
    if user.tenant != "ALL" and vm.tenant not in user.tenant.split(","):
        ws.send("\033[31m你没有虚拟机所属tenant的权限。\033[0m\r\n")
        ws.close()
        return
    ws.send("\033[33mConnecting to %s...\033[0m\r\n" % instance)
    session_id = uuid.uuid5(uuid.NAMESPACE_DNS, session["username"] + "." + str(time.time()))
    console_session_map[session_id] = time.time()
    cmd = 'python3 -c "import pty; pty.spawn(%s)"' % ["sudo", "-i", "lxc", "exec", instance, "bash"]
    p = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    threading.Thread(target=read_pipe, args=(p, ws, session_id)).start()
    threading.Thread(target=monitor_websocket, args=(p, ws, session_id)).start()
    while True:
        data_recv = ws.receive()
        # print("data_recv", data_recv)
        console_session_map[session_id] = time.time()  # 更新session时间
        p.stdin.write(data_recv.encode())
        p.stdin.flush()


@app.route('/')
def index():
    if 'username' in session:
        return app.send_static_file("index.html")
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = db.session.query(User).filter_by(name=request.form['username']).first()
        if not user:  # 用户不存在
            return "用户不存在"
        password = password_hash(request.form['password'])
        if user.password == password:
            session['username'] = request.form['username']
            if user.tenant == "ALL":
                # 如果有所有tenant的权限，默认取所有tenant的第一个进行显示
                tenant = db.session.query(Tenant).first().name
            else:
                # 如果有多个tenant权限，取第一个进行显示
                tenant = user.tenant.split(',')[0]
            session['tenant'] = tenant
            return redirect(url_for('index'))
        else:
            return "密码错误"
    return app.send_static_file("login.html")


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))


@app.route('/api/user_info')
@login_required
def api_user_info():
    # 返回当前用户信息
    user = db.session.query(User).filter_by(name=session['username']).first()
    if not user:
        return "", 200
    if user.tenant == "ALL":
        tenants = dict_to_list(db.session.query(Tenant).with_entities(Tenant.name).all(), "name")
    else:
        tenants = user.tenant.split(",")
    return jsonify({"name": user.name, "is_admin": user.is_admin, "current_tenant": session['tenant'], "tenants": tenants})


@app.route('/api/change_tenant', methods=['POST'])
@login_required
def api_change_tenant():
    # 修改当前租户
    user = db.session.query(User).filter_by(name=session['username']).first()
    tenants = user.tenant.split(",")
    args = request.get_json()
    if user.tenant != "ALL" and args['tenant'] not in tenants:
        return "用户没有这个tenant的权限", 403
    session['tenant'] = args['tenant']
    return "", 200


@app.route('/api/resources', methods=['GET'])
@login_required
def api_get_resources():
    # 返回AZ列表和各AZ不同flavor可创建的机器数量
    resource_list = []
    az_list = sorted(dict_to_list(db.session.query(Host).with_entities(Host.az).distinct().all(), "az"))
    flavor_list = list(FLAVORS.keys())
    os_list = OS_LIST
    for az in az_list:
        for flavor in FLAVORS:
            remain = 0  # 剩余可创建vm数量
            hosts = db.session.query(Host).filter_by(az=az, arch=FLAVORS[flavor]["arch"], performance=FLAVORS[flavor]["performance"]).all()
            for host in hosts:
                # 忽略非共享宿主和非自己项目的宿主
                if host.tenant != "ALL" and host.tenant != session["tenant"]:
                    continue
                cpu_available = host.cpu * host.cpu_alloc_ratio
                mem_available = host.mem * host.mem_alloc_ratio
                vm_list = db.session.query(VirtualMachine).filter_by(host=host.management_ip).with_entities(VirtualMachine.flavor).all()
                for vm in vm_list:
                    cpu_available -= FLAVORS[vm.flavor]["cpu"]
                    mem_available -= FLAVORS[vm.flavor]["mem"]
                remain += min(cpu_available // FLAVORS[flavor]["cpu"], mem_available // FLAVORS[flavor]["mem"])
            if remain:
                resource_list.append({"az": az, "flavor": flavor, "arch": FLAVORS[flavor]["arch"], "performance": FLAVORS[flavor]["performance"],
                                      "cpu": FLAVORS[flavor]["cpu"], "mem": FLAVORS[flavor]["mem"], "remain": remain})
    return jsonify({"resources": resource_list, "az_list": az_list, "flavor_list": flavor_list, "os_list": os_list})


@app.route('/api/vm', methods=['GET'])
@login_required
def api_get_vm_list():
    vm_list = get_list(VirtualMachine)
    for vm in vm_list:
        vm["az"] = db.session.query(Host).filter_by(management_ip=vm["host"]).first().az
    return jsonify(vm_list)


@app.route('/api/vm', methods=['POST'])
@login_required
def api_create_vm():
    param = request.get_json()
    if param["enableSSH"] and not param["pubkey"].startswith("ssh-rsa "):
        return "公钥需要以ssh-rsa 开头！", 400
    msg = create_vm(
        subnet_uuid=param["subnet"], gateway_internet_ip=param["gateway"], flavor=param["flavor"], os=param["os"],
        instance_name=param["instance_name"], username=param["username"], is_enable_ssh=param["enableSSH"], pubkey=param["pubkey"],
        az=param["az"], tenant=session["tenant"], create_user=session["username"])
    if msg:
        return msg, 500
    return "", 201


@app.route('/api/vm/<vm_uuid>', methods=['DELETE'])
@login_required
def api_delete_vm(vm_uuid):
    vm = db.session.query(VirtualMachine).filter_by(uuid=vm_uuid).first()
    if session["tenant"] != vm.tenant:
        return "vm不在此tenant，请切换到对应tenant再试", 403
    msg = delete_vm(vm_uuid)
    if msg:
        return msg, 500
    return "", 204


@app.route('/api/vm/<vm_uuid>/start', methods=['GET'])
@login_required
def api_start_vm(vm_uuid):
    vm = db.session.query(VirtualMachine).filter_by(uuid=vm_uuid).first()
    if session["tenant"] != vm.tenant:
        return "vm不在此tenant，请切换到对应tenant再试", 403
    msg = start_vm(vm_uuid)
    if msg:
        return msg, 500
    return "", 200


@app.route('/api/vm/<vm_uuid>/shutdown', methods=['GET'])
@login_required
def api_shutdown_vm(vm_uuid):
    vm = db.session.query(VirtualMachine).filter_by(uuid=vm_uuid).first()
    if session["tenant"] != vm.tenant:
        return "vm不在此tenant，请切换到对应tenant再试", 403
    msg = shutdown_vm(vm_uuid)
    if msg:
        return msg, 500
    return "", 200


# @app.route('/api/vm/<vm_uuid>/reboot', methods=['GET'])
# def api_reboot_vm(vm_uuid):
#     vm = db.session.query(VirtualMachine).filter_by(uuid=vm_uuid).first()
#     if session["tenant"] != vm.tenant:
#         return "vm不在此tenant，请切换到对应tenant再试", 403
#     msg = reboot_vm(vm_uuid)
#     if msg:
#         return msg, 500
#     return "", 200


@app.route('/api/gateway', methods=['GET'])
@login_required
def api_get_gateway_list():
    return jsonify(get_list(Gateway))


@app.route('/api/nat', methods=['GET'])
@login_required
def api_get_nat_list():
    return jsonify(get_list(NAT))


@app.route('/api/nat', methods=['POST'])
@login_required
def api_create_nat():
    param = json.loads(request.get_data(as_text=True))
    print(param)
    if not param["internet_ip"] or not param["internal_ip"] or not param["protocol"]:
        return "请填写完整信息！", 400
    if int(param["external_port"]) < 9000 or int(param["external_port"]) > 9999:
        return "端口号可用范围：9000-9999。请勿使用范围外的端口。", 403
    msg = create_nat(internet_ip=param["internet_ip"], internal_ip=param["internal_ip"],
                     external_port=int(param["external_port"]), internal_port=int(param["internal_port"]),
                     protocol=param["protocol"], tenant=session["tenant"], create_user=session["username"])
    if msg:
        return msg, 500
    return "", 201


@app.route('/api/nat/<nat_uuid>', methods=['DELETE'])
@login_required
def api_delete_nat(nat_uuid):
    nat = db.session.query(NAT).filter_by(uuid=nat_uuid).first()
    if session["tenant"] != nat.tenant:
        return "NAT不在此tenant，请切换到对应tenant再试", 403
    if delete_nat(nat_uuid):
        return "failed", 500
    return "", 204


@app.route('/api/subnet', methods=['GET'])
@login_required
def api_get_subnet_list():
    return jsonify(get_list(Subnet))


@app.route('/api/subnet', methods=['POST'])
@login_required
def api_create_subnet():
    param = json.loads(request.get_data(as_text=True))
    # TODO: 支持一个tenant对应多个VPC
    vpc = db.session.query(VPC).filter_by(tenant=session["tenant"]).first()
    msg = create_subnet(int(param["mask"]), vpc.uuid)
    if msg:
        return msg, 500
    return "", 201


@app.route('/api/subnet/<subnet_uuid>', methods=['DELETE'])
@login_required
def api_delete_subnet(subnet_uuid):
    subnet = db.session.query(Subnet).filter_by(uuid=subnet_uuid).first()
    if session["tenant"] != subnet.tenant:
        return "subnet不在此tenant，请切换到对应tenant再试", 403
    msg = delete_subnet(subnet_uuid)
    if msg:
        return msg, 500
    return "", 204


@app.route('/api/refresh_flow_table/host/<ip>', methods=['POST'])
@login_required
def api_refresh_flow_table_host(ip):
    user = db.session.query(User).filter_by(name=session["username"]).first()
    if not user.is_admin:
        return "仅管理员可调用该API", 403
    node = db.session.query(Host).filter_by(management_ip=ip).first()
    msg = refresh_flow_table(node.uuid, Host)
    if msg:
        return msg, 500
    return "", 204


@app.route('/api/refresh_flow_table/gateway/<ip>', methods=['POST'])
@login_required
def api_refresh_flow_table_gateway(ip):
    user = db.session.query(User).filter_by(name=session["username"]).first()
    if not user.is_admin:
        return "仅管理员可调用该API", 403
    node = db.session.query(Gateway).filter_by(management_ip=ip).first()
    msg = refresh_flow_table(node.uuid, Gateway)
    if msg:
        return msg, 500
    return "", 204


# @app.route('/api/route', methods=['PUT'])
# @login_required
# def api_modify_route():
#     param = json.loads(request.get_data(as_text=True))
#     if set_vm_gateway(param["vm_uuid"], param["gateway_internet_ip"]):
#         return "failed", 500
#     return "", 200


if __name__ == '__main__':
    init()
    app.run(port=5000, host="0.0.0.0")
