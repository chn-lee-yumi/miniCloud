import requests

# TODO：看看密码怎么妥善保存，直接上传github就gg，用conf文件夹？
def get_token():
    req = requests.get("https://10.21.255.32:55000/security/user/authenticate?raw=true", auth=("api-admin", "password"), verify=False)
    # print(req.text)
    return req.text


def list_agents(token):
    req = requests.get("https://10.21.255.32:55000/agents", headers={
        "Authorization": f"Bearer {token}"
    }, verify=False)
    data = req.json()
    # print(data)
    return_dict = {}
    for agent in data["data"]["affected_items"]:
        # print(agent["id"], agent["ip"])
        return_dict[agent["ip"]] = agent["id"]
    return return_dict


def delete_agent(token, agent_id):
    req = requests.delete(f"https://10.21.255.32:55000/agents?pretty=true&older_than=0s&agents_list={agent_id}&status=all", headers={
        "Authorization": f"Bearer {token}"
    }, verify=False)
    # print(req.status_code)


def delete_agent_by_ip(ip):
    token = get_token()
    agents = list_agents(token)
    if ip in agents:
        delete_agent(token, agents[ip])


if __name__ == '__main__':
    token = get_token()
    list_agents(token)
