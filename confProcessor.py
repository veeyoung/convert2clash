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

def process_dulplicate_invalid_insecure(node_list, option):
    for node in node_list:
        if len(node['name']) > 10:
            node['name'] = node['name'][:10]
    node_num = dict()
    for i in range(len(node_list) - 1, -1, -1):
        if node_list[i].get('name') is None:
            node_list[i]['name'] = str(i)
        if any(node_list[i]['name'].find(name) > -1 for name in option['invalid_node_name']) or \
        ( node_list[i].get('skip-cert-verify') is not None and not option['allow_insecure_node'] ):
            node_list.pop(i)

    #删除重复节点
    origin_len = len(node_list)
    for i in range(origin_len - 1, -1, -1):
        flag = True
        for j in range(i):
            if node_list[j]['name'] == node_list[i]['name']:
                node_list[i]['name'] += str(i)
            if node_list[j]['type'] == node_list[i]['type'] and node_list[j]['server'] == node_list[i]['server'] \
            and node_list[j]['port'] == node_list[i]['port'] and (not option['keep_dulplicate'] or \
            (node_list[j].get('password') == node_list[i].get('password') and node_list[j].get('uuid') == node_list[i].get('uuid'))):
                node_list.pop(i)
                flag = False
                break
        if flag:
            if node_num.get(node_list[i]['type']) is None:
                node_num[node_list[i]['type']] = 1
            else:
                node_num[node_list[i]['type']] += 1

    return node_num

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

def clash_use_new_config(config_path, clashAuth = None, port = 9090, ip = '127.0.0.1') :
    headers = dict()
    if clashAuth is not None:
        headers['Authorization'] = "Bearer " + clashAuth
    headers['content-type'] = 'application/json'
    url = 'http://127.0.0.1:9090/configs'
    data = {'path': config_path}
    status = ""
    try:
        status = requests.put(url, json=data, headers=headers)
    except:
        print('clash api连接失败')
        status = -1
    return status
