import random, string, yaml, requests

# 保存到文件
def save_to_file(file_name, content):
    with open(file_name, 'wb') as f:
        f.write(content)

# 获取本地配置文件
def load_local_config(path):
    local_config = None
    try:
        with open(path, 'r', encoding="utf-8") as f:
            local_config = yaml.load(f.read(), Loader=yaml.FullLoader)
    except FileNotFoundError:
        pass
    except yaml.YAMLError:
        pass
    finally:
        return local_config

# 获取网络配置文件
def load_online_config(url):
    online_config = None
    try:
        raw = requests.get(url, timeout=5).content.decode('utf-8')
        online_config = yaml.load(raw, Loader=yaml.FullLoader)
    except requests.exceptions.RequestException:
        pass
    except yaml.YAMLError:
        pass
    finally:
        return online_config

def process_node(node_list, option):
    # Truncate node names longer than 10 characters
    for node in node_list:
        node['name'] = node['name'][:10]

    # Remove nodes with invalid names or insecure configurations
    node_list = [node for node in node_list if
                all(node['name'].find(name) == -1 for name in option['invalid_node_name']) and
                 (not node.get('skip-cert-verify') or option['allow_insecure_node'])]

    # Remove duplicate nodes
    node_counts = {}
    unique_nodes = []
    unique_names = []
    updated_node_list = []
    i = 0
    for node in node_list:
        node_key = (node['type'], node['server'], node['port'], node.get('password'), node.get('uuid'), node.get("ws-opts"))
        if node_key not in unique_nodes:
            while node["name"] in unique_names:
                node["name"] += str(i)
                i += 1
            unique_names.append(node["name"])
            unique_nodes.append(node_key)
            node_counts[node['type']] = node_counts.get(node['type'], 0) + 1
            updated_node_list.append(node)

    return node_counts, updated_node_list


# 将代理添加到配置文件
def add_proxies_to_model(data, model, option):
    if model.get('proxies') is None:
        model['proxies'] = data
    else:
        model['proxies'].extend(data)

    proxy_names = [proxy['name'] for proxy in data]

    for group in model.get('proxy-groups'):
        if group.get('name') not in option['pass_group']:
            if group.get('proxies') is None:
                group['proxies'] = proxy_names
            else:
                group['proxies'].extend(proxy_names)

    words = string.digits + string.ascii_lowercase + string.ascii_uppercase

    if option['secret'] and model.get('secret') is None:
            model['secret'] = "".join(random.choice(words) for _ in range(30))
    if option['authentication'] and model.get('authentication') is None:
        username = "".join(random.choice(words) for _ in range(6))
        userpass = "".join(random.choice(words) for _ in range(30))
        auth = username + ':' + userpass
        auths = []
        auths.append(auth)
        model['authentication']=auths

    return model


# 保存配置文件
def save_config(path, data):
    if len(data['proxies'])==0 :
        return
    if data.get('secret') is not None:
        print('external controller password:{}'.format(data['secret']))
    if data.get('authentication') is not None:
        print('authentication:{}'.format(data['authentication']))

    config = yaml.dump(data, sort_keys=False, default_flow_style=False, encoding='utf-8', allow_unicode=True)
    save_to_file(path, config)

def clash_use_new_config(config_path, clashAuth = None, port = 9090) :
    headers = dict()
    if clashAuth is not None:
        headers['Authorization'] = "Bearer " + clashAuth
    headers['content-type'] = 'application/json'
    url = f'http://127.0.0.1:{port}/configs'
    data = {'path': config_path}
    status = ""
    try:
        status = requests.put(url, json=data, headers=headers)
    except:
        print('clash api连接失败')
        status = -1
    return status

def test_latency(headers, port=9090):
    clash_api_url = f"http://127.0.0.1:{port}/group/♻️ 自动选择/delay?url=https://www.youtube.com/&timeout=5000"
    try:
        requests.get(clash_api_url, headers=headers)
    except:
        print('clash api连接失败')

def del_connections(headers, port=9090):
    clash_api_url = f"http://127.0.0.1:{port}/connections"
    try:
        requests.delete(clash_api_url, headers=headers)
    except:
        print('clash api连接失败')
