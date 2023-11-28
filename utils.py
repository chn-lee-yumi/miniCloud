import copy
import hashlib
import logging
import subprocess

import IPy

from config import PASSWORD_SALT
from database import db

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)


def exec_cmd(cmd: str):
    """执行shell命令并返回 返回码 stdout stderr"""
    logger.debug("EXEC: " + cmd)
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    process.wait()
    return_code = process.returncode
    stdout = process.stdout.read().decode()
    stderr = process.stderr.read().decode()
    # logger.debug("return code: " + str(return_code))
    if stdout:
        logger.debug("stdout:\n" + stdout)
    if stderr:
        logger.debug("stderr:\n" + stderr)
    if return_code:
        logger.debug("return code: " + str(return_code))
    return return_code, stdout, stderr


def ip_to_hex(ip: str):
    # 返回不带0x的十六进制IP
    return IPy.IP(ip).strHex()[2:]


def calc_gateway_ip(subnet_cidr: str):
    return IPy.IP(IPy.IP(subnet_cidr).ip + 1).strNormal()


def get_tun_id(subnet_uuid: str):
    # TODO：优化一下防止冲突
    return "0x" + subnet_uuid[:6]


def int_to_mask(mask_int):
    bin_arr = ['0' for _ in range(32)]
    for i in range(mask_int):
        bin_arr[i] = '1'
    mask = [''.join(bin_arr[i * 8:i * 8 + 8]) for i in range(4)]
    mask = [str(int(s, 2)) for s in mask]
    return '.'.join(mask)


def sha1(string):
    """
    计算hash
    :param string: 字符串
    :return: 十六进制字符串
    """
    _hash = hashlib.sha1()
    _hash.update(string.encode('utf8'))
    return _hash.hexdigest()


def password_hash(password):
    return sha1(password + PASSWORD_SALT)


def get_list(obj):
    """
    获取对象列表
    :param obj: 对象名字（可以是列表）
    :return: 对象属性字典的列表
    """

    def _get_list(_obj):
        _list = []
        _all = db.session.query(_obj).all()
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


def get_list_raw(obj):
    """
    获取对象列表
    :param obj: 对象名字（可以是列表）
    :return: 对象列表
    """

    def _get_list(_obj):
        return db.session.query(_obj).all()

    if type(obj) == list:
        result_list = []
        for o in obj:
            result_list.extend(_get_list(o))
    else:
        result_list = _get_list(obj)
    return result_list


if __name__ == '__main__':
    print(int_to_mask(26))
