import re, base64, urllib.parse
import json

# 针对url的base64解码
def safe_decode(s):
    num = len(s) % 4
    if num:
        s += '=' * (4 - num)
    return base64.urlsafe_b64decode(s)

# v2ray转换成Clash节点
def v2ray_to_clash(node):
    decode_proxy = node[8:]
    if not decode_proxy or decode_proxy.isspace():
        return None
    proxy_str = base64.b64decode(decode_proxy).decode('utf-8')
    proxy_dict = json.loads(proxy_str)
    if proxy_dict.get('ps') is None or proxy_dict.get('add') is None or proxy_dict.get('port') is None \
    or proxy_dict.get('id') is None or proxy_dict.get('aid') is None:
        return None
    
    obj = {
        'name': proxy_dict.get('ps').strip() if proxy_dict.get('ps') else None,
        'type': 'vmess',
        'server': proxy_dict.get('add'),
        'port': int(proxy_dict.get('port')),
        'uuid': proxy_dict.get('id'),
        'alterId': int(proxy_dict.get('aid')),
        'cipher': proxy_dict.get('scy').strip() if proxy_dict.get('scy') else 'auto',
        'network': proxy_dict.get('net'),
        'tls': True if proxy_dict.get('tls') else None,
        'udp': proxy_dict.get('udp')
    }
    if proxy_dict.get('net') == 'ws' :
        ws = {
            'path': proxy_dict.get('path') if proxy_dict.get('path') else '/',
            'headers': {'Host': proxy_dict.get('host') if proxy_dict.get('host') else proxy_dict.get('add')}
        }
        obj['ws-opts'] = ws
    elif proxy_dict.get('net') == 'grpc' :
        grpc = {
            'grpc-service-name': proxy_dict.get('path') if proxy_dict.get('path') else '/',
        }
        obj['grpc-opts'] = grpc
        obj['servername'] = proxy_dict.get('sni')

    for key in list(obj.keys()):
        if obj.get(key) is None:
            del obj[key]

    return obj


# ss转换成Clash节点
def ss_to_clash(node):
    param = node[5:]
    if not param or param.isspace():
        return None
    info = dict()
    if param.find('#') > -1:
        remark = urllib.parse.unquote(param[param.find('#') + 1:])
        info['name'] = remark
        param = param[:param.find('#')]
    info['type'] = 'ss'
    plugin = ''
    if param.find('/?') > -1:
        plugin = urllib.parse.unquote(param[param.find('/?') + 2:])
        param = param[:param.find('/?')]
    if param.find('@') > -1:
        matcher = re.match(r'(.*?)@(.*):(.*)', param)
        if matcher:
            param = matcher.group(1)
            info['server'] = matcher.group(2)
            info['port'] = matcher.group(3)
        else:
            return None
        matcher = re.match(r'(.*?):(.*)', safe_decode(param).decode('utf-8'))
        if matcher:
            info['cipher'] = matcher.group(1)
            info['password'] = matcher.group(2)
        else:
            return None
    else:
        matcher = re.match(r'(.*?):(.*)@(.*):(.*)', safe_decode(param).decode('utf-8'))
        if matcher:
            info['server'] = matcher.group(3)
            info['port'] = matcher.group(4)
            info['cipher'] = matcher.group(1)
            info['password'] = matcher.group(2)
        else:
            return None

    for p in plugin.split(';'):
        key_value = p.split('=')
        if key_value[0] == 'plugin':
            if key_value[1] == 'obfs':
                info['plugin'] = key_value[1]
            else :
                info['plugin'] = None
            info['plugin-opts'] = key_value[1]
        elif key_value[0] == 'obfs':
            info['plugin-opts'] = dict()
            info['plugin-opts']['mode'] = info.get('obfs')
        elif key_value[0] == 'obfs-host':
            info['plugin-opts'] = dict()
            info['plugin-opts']['host'] = info.get('obfs-host')
        else:
            info['plugin'] = None
            info['plugin-opts'] = None

    for key in list(info.keys()):
        if info.get(key) is None:
            del info[key]

    return info


# ssr转换成Clash节点
def ssr_to_clash(node):
    decode_proxy = node[6:]
    if not decode_proxy or decode_proxy.isspace():
        return None
    proxy_str = safe_decode(decode_proxy).decode('utf-8')
    parts = proxy_str.split(':')
    if len(parts) != 6:
        return None
    info = {
        'server': parts[0],
        'port': parts[1],
        'protocol': parts[2],
        'method': parts[3],
        'obfs': parts[4]
    }
    password_params = parts[5].split('/?')
    info['password'] = safe_decode(password_params[0]).decode('utf-8')
    params = password_params[1].split('&')
    for p in params:
        key_value = p.split('=')
        info[key_value[0]] = safe_decode(key_value[1]).decode('utf-8')

    obj = {
        'name': info.get('remarks').strip() if info.get('remarks') else None,
        'type': 'ssr',
        'server': info.get('server'),
        'port': int(info.get('port')),
        'cipher': info.get('method'),
        'password': info.get('password'),
        'obfs': info.get('obfs'),
        'protocol': info.get('protocol'),
        'obfs-param': info.get('obfsparam'),
        'protocol-param': info.get('protoparam'),
        'udp': True
    }
    for key in list(obj.keys()):
        if obj.get(key) is None:
            del obj[key]
    
    return obj


# trojan转换成Clash节点
def trojan_to_clash(node):
    param = node[9:]
    if not param or param.isspace():
        return None
    info = dict()
    if param.find('#') > -1:
        remark = urllib.parse.unquote(param[param.find('#') + 1:])
        info['name'] = remark
        param = param[:param.find('#')]
    info['type'] = 'trojan'
    matcher = re.match(r'(.*?)@(.*):(\d*)', param)
    if matcher:
        info['server'] = matcher.group(2)
        info['port'] = int(matcher.group(3))
        info['password'] = matcher.group(1)
        if param.find('sni') > -1:
            param = param[param.find('sni')+4:]
            if param.find('&') > -1:
                info['sni'] = param[:param.find('&')].strip()
            else:
                info['sni'] = param.strip()
    else:
        return None
    info['skip-cert-verify'] = True if param.find('allowInsecure=1') > -1 else False
    info['udp'] = True
    for key in list(info.keys()):
        if info.get(key) is None:
            del info[key]
    
    return info