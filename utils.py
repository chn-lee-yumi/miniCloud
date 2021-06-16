import logging
import subprocess

import IPy

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


# def get_tun_id(subnet_gateway: str):
#     # TODO：优化一下防止冲突
#     return "0x" + IPy.IP(subnet_gateway).strHex()[-6:]

def get_tun_id(subnet_uuid: str):
    # TODO：优化一下防止冲突
    return "0x" + subnet_uuid[:6]


def int_to_mask(mask_int):
    bin_arr = ['0' for i in range(32)]
    for i in range(mask_int):
        bin_arr[i] = '1'
    mask = [''.join(bin_arr[i * 8:i * 8 + 8]) for i in range(4)]
    mask = [str(int(s, 2)) for s in mask]
    return '.'.join(mask)


if __name__ == '__main__':
    print(int_to_mask(26))
