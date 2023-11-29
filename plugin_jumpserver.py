"""用于配置堡垒机登录，对应文档：https://docs.jumpserver.org/"""
# pip install requests drf-httpsig
import datetime

import requests
from httpsig.requests_auth import HTTPSignatureAuth

from config import jms_url, KeyID, SecretID


def get_auth(KeyID, SecretID):
    signature_headers = ['(request-target)', 'accept', 'date']
    auth = HTTPSignatureAuth(key_id=KeyID, secret=SecretID, algorithm='hmac-sha256', headers=signature_headers)
    return auth


def get_user_info(auth):
    url = jms_url + '/api/v1/users/users/'
    gmt_form = '%a, %d %b %Y %H:%M:%S GMT'
    headers = {
        'Accept': 'application/json',
        'X-JMS-ORG': '00000000-0000-0000-0000-000000000002',
        'Date': datetime.datetime.utcnow().strftime(gmt_form)
    }
    response = requests.get(url, auth=auth, headers=headers)
    print(response.json())
    return response.json()


def create_assets(uuid, name, ip, port):
    print("在堡垒机上创建资产")
    auth = get_auth(KeyID, SecretID)
    url = jms_url + '/api/v1/assets/hosts/'
    gmt_form = '%a, %d %b %Y %H:%M:%S GMT'
    headers = {
        'Accept': 'application/json',
        'X-JMS-ORG': '00000000-0000-0000-0000-000000000002',
        'Date': datetime.datetime.utcnow().strftime(gmt_form),
    }
    data = {
        "id": uuid,
        "name": name,
        "address": ip,
        "platform": 1,  # 1=Linux
        "protocols": [{"name": "ssh", "port": port}, {"name": "sftp", "port": port}],
        "accounts": [{"name": "cloud", "username": "cloud", "template": "058a917a-a78c-477e-88b1-674efb2600c5"}],  # 这个模板从前端手动创建
        "nodes_display": ["/Default/GDUTNIC/网管队云平台"],
    }
    print(data)
    response = requests.post(url, auth=auth, headers=headers, json=data)
    print(response.json())


def create_perms(uuid, name, username):
    print("在堡垒机上创建权限绑定")
    auth = get_auth(KeyID, SecretID)
    url = jms_url + '/api/v1/perms/asset-permissions/'
    user_list = get_user_info(auth)
    user_id = ""
    for user in user_list:
        if user["username"] == username:
            user_id = user["id"]
            break
    if not user_id:
        print("用户不存在：", username)
        return
    gmt_form = '%a, %d %b %Y %H:%M:%S GMT'
    headers = {
        'Accept': 'application/json',
        'X-JMS-ORG': '00000000-0000-0000-0000-000000000002',
        'Date': datetime.datetime.utcnow().strftime(gmt_form),
    }
    data = {
        "id": uuid,
        "name": name,
        "assets": [uuid],
        "users": [user_id],
        "accounts": ["@ALL"],
    }
    print(data)
    response = requests.post(url, auth=auth, headers=headers, json=data)
    print(response.json())


def delete_assets(id):
    print("在堡垒机上删除资产")
    auth = get_auth(KeyID, SecretID)
    url = jms_url + '/api/v1/assets/hosts/' + id + "/"
    gmt_form = '%a, %d %b %Y %H:%M:%S GMT'
    headers = {
        'Accept': 'application/json',
        'X-JMS-ORG': '00000000-0000-0000-0000-000000000002',
        'Date': datetime.datetime.utcnow().strftime(gmt_form),
    }
    response = requests.delete(url, auth=auth, headers=headers)
    print(response.status_code)


def delete_perms(id):
    print("在堡垒机上删除权限绑定")
    auth = get_auth(KeyID, SecretID)
    url = jms_url + '/api/v1/perms/asset-permissions/' + id + "/"
    gmt_form = '%a, %d %b %Y %H:%M:%S GMT'
    headers = {
        'Accept': 'application/json',
        'X-JMS-ORG': '00000000-0000-0000-0000-000000000002',
        'Date': datetime.datetime.utcnow().strftime(gmt_form),
    }
    response = requests.delete(url, auth=auth, headers=headers)
    print(response.status_code)


if __name__ == '__main__':
    # auth = get_auth(KeyID, SecretID)
    # get_user_info(auth)
    create_assets("a63a61a6-8e48-11ee-b79b-53e5304606c5", "测试鸡", "10.21.255.38", '22')
    delete_assets("a63a61a6-8e48-11ee-b79b-53e5304606c5")
