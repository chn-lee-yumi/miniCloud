import json

from flask import Flask, request, jsonify, session, redirect, url_for

from controller import *

app = Flask(__name__)
app.secret_key = b'_5#y212\rfaL"F4aQ8asdfn\xec]/'

reg_vm_list = []  # vm初始化成功的标记

reboot_script = """
reboot
"""

username = "admin"
password = "admin@miniCloud"


@app.route('/')
def index():
    if 'username' in session:
        return app.send_static_file("index.html")
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form['username'] == username and request.form['password'] == password:
            session['username'] = request.form['username']
            return redirect(url_for('index'))
    return app.send_static_file("login.html")


@app.route('/logout')
def logout():
    # remove the username from the session if it's there
    session.pop('username', None)
    return redirect(url_for('index'))


@app.route('/api/vm', methods=['GET'])
def api_get_vm_list():
    return jsonify(get_list(VirtualMachine))


@app.route('/api/vm', methods=['POST'])
def api_create_vm():
    param = json.loads(request.get_data(as_text=True))
    msg = create_vm(param["subnet"], param["gateway"], param["flavor"], param["hostname"], param["az"])
    if msg:
        return msg, 500
    return "", 201


@app.route('/api/vm/<vm_uuid>', methods=['DELETE'])
def api_delete_vm(vm_uuid):
    msg = delete_vm(vm_uuid)
    if msg:
        return msg, 500
    return "", 204


@app.route('/api/vm/<vm_uuid>/start', methods=['GET'])
def api_start_vm(vm_uuid):
    msg = start_vm(vm_uuid)
    if msg:
        return msg, 500
    return "", 200


@app.route('/api/vm/<vm_uuid>/shutdown', methods=['GET'])
def api_shutdown_vm(vm_uuid):
    msg = shutdown_vm(vm_uuid)
    if msg:
        return msg, 500
    return "", 200


@app.route('/api/vm/<vm_uuid>/reboot', methods=['GET'])
def api_reboot_vm(vm_uuid):
    msg = reboot_vm(vm_uuid)
    if msg:
        return msg, 500
    return "", 200


@app.route('/api/vm/script', methods=['GET'])
def api_vm_script():
    ip = request.remote_addr
    if ip not in reg_vm_list:
        reg_vm_list.append(ip)
        return reboot_script
    return ""


@app.route('/api/gateway', methods=['GET'])
def api_get_gateway_list():
    return jsonify(get_list(Gateway))


@app.route('/api/nat', methods=['GET'])
def api_get_nat_list():
    return jsonify(get_list(NAT))


@app.route('/api/nat', methods=['POST'])
def api_create_nat():
    param = json.loads(request.get_data(as_text=True))
    print(param)
    if int(param["external_port"]) == 22 or int(param["external_port"]) == 80:
        return "Not allowed to use port 22 and 80!", 403
    msg = create_nat(param["internet_ip"], param["internal_ip"], int(param["external_port"]), int(param["internal_port"]), param["protocol"])
    if msg:
        return msg, 500
    return "", 201


@app.route('/api/nat/<nat_uuid>', methods=['DELETE'])
def api_delete_nat(nat_uuid):
    if delete_nat(nat_uuid):
        return "failed", 500
    return "", 204


@app.route('/api/subnet', methods=['GET'])
def api_get_subnet_list():
    return jsonify(get_list(Subnet))


@app.route('/api/subnet', methods=['POST'])
def api_create_subnet():
    param = json.loads(request.get_data(as_text=True))
    msg = create_subnet(int(param["mask"]))
    if msg:
        return msg, 500
    return "", 201


@app.route('/api/subnet/<subnet_uuid>', methods=['DELETE'])
def api_delete_subnet(subnet_uuid):
    msg = delete_subnet(subnet_uuid)
    if msg:
        return msg, 500
    return "", 204


@app.route('/api/route', methods=['PUT'])
def api_modify_route():
    param = json.loads(request.get_data(as_text=True))
    if set_vm_gateway(param["vm_uuid"], param["gateway_internet_ip"]):
        return "failed", 500
    return "", 200


if __name__ == '__main__':
    app.run(port=5000, host="0.0.0.0")
