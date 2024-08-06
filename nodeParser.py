# Ref:https://github.com/SubConv/SubConv/blob/main/modules/convert/converter.py

import re
import json
import base64
import urllib.parse as urlparse
import random

# 针对url的base64解码
def base64RawURLDecode(encoded):
    return base64.urlsafe_b64decode(
              encoded + "="*(-len(encoded)%4)
    ).decode("utf-8")

# Ref:https://github.com/pypa/distutils/blob/main/distutils/util.py
def strtobool(val):
    """Convert a string representation of truth to true (1) or false (0).

    True values are 'y', 'yes', 't', 'true', 'on', and '1'; false values
    are 'n', 'no', 'f', 'false', 'off', and '0'.  Raises ValueError if
    'val' is anything else.
    """
    if val is None:
        return 0
    val = val.lower()
    if val in ('y', 'yes', 't', 'true', 'on', '1'):
        return 1
    elif val in ('n', 'no', 'f', 'false', 'off', '0'):
        return 0
    else:
        raise ValueError("invalid truth value {!r}".format(val))

def RandUserAgent() -> str:
    with open('userAgents.json') as f:
        return random.choice(json.load(f))

def uniqueName(names: dict, name):
    index = names.get(name)
    if index is None:
        index = 0
        names[name] = index
    else:
        index += 1
        names[name] = index
        name = "%s-%02d" % (name, index)
    return name

def get(content):
    if content is None:
        return ""
    else:
        return content

def handleVShareLink(names: dict, url: urlparse.ParseResult, scheme: str, proxy: dict):
    query = dict(urlparse.parse_qsl(url.query))
    proxy["name"] = uniqueName(names, urlparse.unquote(url.fragment))
    if url.hostname == "":
        raise
    if url.port == "":
        raise
    proxy["type"] = scheme
    proxy["server"] = url.hostname
    proxy["port"] = url.port
    proxy["uuid"] = url.username
    proxy["udp"] = True
    tls = get(query.get("security")).lower()
    if tls.endswith("tls") or tls == "reality":
        proxy["tls"] = True
        fingerprint = get(query.get("fp"))
        if fingerprint == "":
            proxy["client-fingerprint"] = "chrome"
        else:
            proxy["client-fingerprint"] = fingerprint
        alpn = get(query.get("alpn"))
        if alpn != "":
            proxy["alpn"] = alpn.split(",")
    sni = get(query.get("sni"))
    if sni != "":
        proxy["servername"] = sni
    realityPublicKey = get(query.get("pbk"))
    if realityPublicKey != "":
        proxy["reality-opts"] = {
            "public-key": realityPublicKey,
            "short-id": get(query.get("sid"))
        }

    switch = get(query.get("packetEncoding"))
    if switch == "none" or switch == "":
        pass
    elif switch == "packet":
        proxy["packet-addr"] = True
    else:
        proxy["xudp"] = True

    network = get(query.get("type")).lower()
    if network == "":
        network = "tcp"
    fakeType = get(query.get("headerType")).lower()
    if fakeType == "http":
        network = "http"
    elif network == "http":
        network = "h2"
    proxy["network"] = network
    if network == "tcp":
        if fakeType != "none" and fakeType != "":
            headers = {}
            httpOpts = {}
            httpOpts["path"] = "/"

            host = get(query.get("host"))
            if host != "":
                headers["Host"] = str(host)

            method = get(query.get("method"))
            if method != "":
                httpOpts["method"] = method

            path = get(query.get("path"))
            if path != "":
                httpOpts["path"] = str(path)

            httpOpts["headers"] = headers
            proxy["http-opts"] = httpOpts

    elif network == "http":
        headers = {}
        h2Opts = {}
        h2Opts["path"] = "/"
        path = get(query.get("path"))
        if path != "":
            h2Opts["path"] = str(path)
        host = get(query.get("host"))
        if host != "":
            h2Opts["host"] = str(host)
        h2Opts["headers"] = headers
        proxy["h2-opts"] = h2Opts

    elif network == "ws":
        headers = {}
        wsOpts = {}
        headers["User-Agent"] = RandUserAgent()
        headers["Host"] = get(query.get("host"))
        wsOpts["path"] = get(query.get("path"))
        wsOpts["headers"] = headers

        earlyData = get(query.get("ed"))
        if earlyData != "":
            try:
                med = int(earlyData)
            except:
                raise
            wsOpts["max-early-data"] = med
        earlyDataHeader = get(query.get("edh"))
        if earlyDataHeader != "":
            wsOpts["early-data-header-name"] = earlyDataHeader

        proxy["ws-opts"] = wsOpts

    elif network == "grpc":
        grpcOpts = {}
        grpcOpts["grpc-service-name"] = get(query.get("serviceName"))
        proxy["grpc-opts"] = grpcOpts

# ss转换成Clash节点
def ss_to_clash(node):
    param = node
    if not param or param.isspace():
        return None
    info = dict()
    if param.find('#') > -1:
        remark = urlparse.unquote(param[param.find('#') + 1:])
        info['name'] = remark
        param = param[:param.find('#')]
    info['type'] = 'ss'
    plugin = ''
    if param.find('/?') > -1:
        plugin = urlparse.unquote(param[param.find('/?') + 2:])
        param = param[:param.find('/?')]
    if param.find('@') > -1:
        matcher = re.match(r'(.*?)@(.*):(.*)', param)
        if matcher:
            param = matcher.group(1)
            info['server'] = matcher.group(2)
            info['port'] = matcher.group(3)
        else:
            return None
        matcher = re.match(r'(.*?):(.*)', base64RawURLDecode(param))
        if matcher:
            info['cipher'] = matcher.group(1)
            info['password'] = matcher.group(2)
        else:
            return None
    else:
        matcher = re.match(r'(.*?):(.*)@(.*):(.*)', base64RawURLDecode(param))
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
    decode_proxy = node
    if not decode_proxy or decode_proxy.isspace():
        return None
    proxy_str = base64RawURLDecode(decode_proxy)
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
    info['password'] = base64RawURLDecode(password_params[0])
    params = password_params[1].split('&')
    for p in params:
        key_value = p.split('=')
        info[key_value[0]] = base64RawURLDecode(key_value[1])

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

def ConvertsV2Ray(buf):

    try:
        data = buf.decode("utf-8")
    except:
        data = buf

    arr = data.splitlines()

    proxies = []
    names = {}

    for line in arr:
        if line == "":
            continue

        if -1 == line.find("://"):
            continue
        else:
            scheme, body = line.split("://", 1)

        scheme = scheme.lower()
        if scheme == "hysteria":
            try:
                urlHysteria = urlparse.urlparse(line)
            except:
                continue

            query = dict(urlparse.parse_qsl(urlHysteria.query))
            name = uniqueName(names, urlparse.unquote(urlHysteria.fragment))
            hysteria = {}

            hysteria["name"] = name
            hysteria["type"] = scheme
            hysteria["server"] = urlHysteria.hostname
            hysteria["port"] = urlHysteria.port
            hysteria["sni"] = query.get("peer")
            hysteria["obfs"] = query.get("obfs")
            alpn = get(query.get("alpn"))
            if alpn != "":
                hysteria["alpn"] = alpn.split(",")
            hysteria["auth_str"] = query.get("auth")
            hysteria["protocol"] = query.get("protocol")
            up = get(query.get("up"))
            down = get(query.get("down"))
            if up == "":
                up = query.get("upmbps")
            if down == "":
                down = query.get("downmbps")
            hysteria["up"] = up
            hysteria["down"] = down
            hysteria["skip-cert-verify"] = bool(
                strtobool(query.get("insecure")))

            proxies.append(hysteria)
        elif scheme == "hysteria2" or scheme == "hy2":
            # apply f6bf9c08577060bb199c2f746c7d91dd3c0ca7b9 from mihomo
            try:
                urlHysteria2 = urlparse.urlparse(line)
            except:
                continue

            query = dict(urlparse.parse_qsl(urlHysteria2.query))
            name = uniqueName(names, urlparse.unquote(urlHysteria2.fragment))
            hysteria2 = {}

            hysteria2["name"] = name
            hysteria2["type"] = "hysteria2"
            hysteria2["server"] = urlHysteria2.hostname
            port = get(urlHysteria2.port)
            if port != "":
                hysteria2["port"] = int(port)
            else:
                hysteria2["port"] = 443
            obfs = get(query.get("obfs"))
            if obfs != "" and obfs not in ["none", "None"]:
                hysteria2["obfs"] = query.get("obfs")
                hysteria2["obfs-password"] = get(query.get("obfs-password"))
            sni = get(query.get("sni"))
            if sni == "":
                sni = get(query.get("peer"))
            if sni != "":
                hysteria2["sni"] = sni
            hysteria2["skip-cert-verify"] = bool(
                strtobool(query.get("insecure")))
            alpn = get(query.get("alpn"))
            if alpn != "":
                hysteria2["alpn"] = alpn.split(",")
            auth = get(urlHysteria2.username)
            if auth != "":
                hysteria2["password"] = auth
            hysteria2["fingerprint"] = get(query.get("pinSHA256"))
            hysteria2["down"] = get(query.get("down"))
            hysteria2["up"] = get(query.get("up"))

            proxies.append(hysteria2)

        elif scheme == "tuic":
            # A temporary unofficial TUIC share link standard
            # Modified from https://github.com/daeuniverse/dae/discussions/182
            # Changes:
            #   1. Support TUICv4, just replace uuid:password with token
            #   2. Remove `allow_insecure` field
            try:
                urlTUIC = urlparse.urlparse(line)
            except:
                continue

            query = dict(urlparse.parse_qsl(urlTUIC.query))

            tuic = {}
            tuic["name"] = uniqueName(
                names, urlparse.unquote(urlTUIC.fragment))
            tuic["type"] = scheme
            tuic["server"] = urlTUIC.hostname
            tuic["port"] = urlTUIC.port
            tuic["udp"] = True
            password = urlTUIC.password
            if password is not None:
                tuic["uuid"] = urlTUIC.username
                tuic["password"] = password
            else:
                tuic["token"] = urlTUIC.username
            cc = get(query.get("congestion_control"))
            if cc != "":
                tuic["congestion-control"] = cc
            alpn = get(query.get("alpn"))
            if alpn != "":
                tuic["alpn"] = alpn.split(",")
            sni = get(query.get("sni"))
            if sni != "":
                tuic["sni"] = sni
            if query.get("disable_sni") == "1":
                tuic["disable-sni"] = True
            udpRelayMode = get(query.get("udp_relay_mode"))
            if udpRelayMode != "":
                tuic["udp-relay-mode"] = udpRelayMode
            proxies.append(tuic)

        elif scheme == "trojan":
            try:
                urlTrojan = urlparse.urlparse(line)
            except:
                continue

            query = dict(urlparse.parse_qsl(urlTrojan.query))

            name = uniqueName(names, urlparse.unquote(urlTrojan.fragment))
            trojan = {}
            try:
                trojan["name"] = name
                trojan["type"] = scheme
                trojan["server"] = urlTrojan.hostname
                trojan["port"] = urlTrojan.port
                trojan["password"] = urlTrojan.password
            except:
                continue
            if trojan["password"] is None:
                trojan["password"] = urlTrojan.username
            if trojan["password"] is None:
                continue
            trojan["udp"] = True
            trojan["skip-cert-verify"] = bool(
                strtobool(query.get("allowInsecure")))

            sni = get(query.get("sni"))
            if sni != "":
                trojan["sni"] = sni

            alpn = get(query.get("alpn"))
            if alpn != "":
                trojan["alpn"] = alpn.split(",")

            network = get(query.get("type"))
            if network != "":
                network = network.lower()
                trojan["network"] = network

            if network == "ws":
                headers = {}
                wsOpts = {}

                headers["User-Agent"] = RandUserAgent()

                wsOpts["path"] = query.get("path")
                wsOpts["headers"] = headers

                trojan["ws-opts"] = wsOpts

            elif network == "grpc":
                grpcOpts = {}
                grpcOpts["serviceName"] = query.get("serviceName")
                trojan["grpc-opts"] = grpcOpts

            fingerprint = get(query.get("fp"))
            if fingerprint == "":
                trojan["client-fingerprint"] = "chrome"
            else:
                trojan["client-fingerprint"] = fingerprint

            proxies.append(trojan)

        elif scheme == "vless":
            try:
                urlVless = urlparse.urlparse(line)
            except:
                continue

            query = dict(urlparse.parse_qsl(urlVless.query))
            vless = {}
            try:
                handleVShareLink(names, urlVless, scheme, vless)
            except:
                continue
            flow = get(query.get("flow"))
            if flow != "":
                vless["flow"] = str(flow).lower()
            proxies.append(vless)

        elif scheme == "vmess":
            try:
                dcBuf = base64RawURLDecode(body)
            except:
                # Xray VMessAEAD share link
                try:
                    urlVMess = urlparse.urlparse(line)
                except:
                    continue
                query = dict(urlparse.parse_qsl(urlVMess.query))
                vmess = {}
                try:
                    handleVShareLink(names, urlVMess, scheme, vmess)
                except:
                    continue
                vmess["alterId"] = 0
                vmess["cipher"] = "auto"
                encryption = get(query.get("encryption"))
                if encryption != "":
                    vmess["cipher"] = encryption
                proxies.append(vmess)
                continue

            values = {}
            try:
                values = json.loads(dcBuf)
            except:
                continue

            try:
                tempName = values["ps"]
            except:
                continue
            name = uniqueName(names, tempName)
            vmess = {}

            vmess["name"] = name
            vmess["type"] = scheme
            vmess["server"] = values["add"]
            vmess["port"] = values["port"]
            vmess["uuid"] = values["id"]
            alterId = values.get("aid")
            if alterId is not None:
                vmess["alterId"] = alterId
            else:
                vmess["alterId"] = 0
            vmess["udp"] = True
            vmess["xudp"] = True
            vmess["tls"] = False
            vmess["skip-cert-verify"] = False

            vmess["cipher"] = "auto"
            cipher = get(values.get("scy"))
            if cipher != "":
                vmess["cipher"] = cipher

            sni = get(values.get("sni"))
            if sni != "":
                vmess["servername"] = sni

            network = get(values.get("net")).lower()
            if values.get("type") == "http":
                network = "http"
            elif network == "http":
                network = "h2"
            vmess["network"] = network

            tls = values.get("tls")
            if tls is not None:
                tls = str(tls).lower()
                if tls.endswith("tls"):
                    vmess["tls"] = True
                alpn = values.get("alpn")
                if alpn is not None and alpn != "":
                    vmess["alpn"] = alpn.split(",")

            if network == "http":
                headers = {}
                httpOpts = {}
                host = get(values.get("host"))
                if host != "":
                    headers["Host"] = host
                httpOpts["path"] = ["/"]
                path = get(values.get("path"))
                if path != "":
                    httpOpts["path"] = [path]
                httpOpts["headers"] = headers

                vmess["http-opts"] = httpOpts

            elif network == "h2":
                headers = {}
                h2Opts = {}
                host = get(values.get("host"))
                if host != "":
                    headers["Host"] = host
                h2Opts["path"] = get(values.get("path"))
                h2Opts["headers"] = headers

                vmess["h2-opts"] = h2Opts

            elif network == "ws":
                headers = {}
                wsOpts = {}
                wsOpts["path"] = "/"
                host = get(values.get("host"))
                if host != "":
                    headers["Host"] = host
                path = get(values.get("path"))
                if path != "":
                    wsOpts["path"] = path
                wsOpts["headers"] = headers
                vmess["ws-opts"] = wsOpts

            elif network == "grpc":
                grpcOpts = {}
                grpcOpts["grpc-service-name"] = get(values.get("path"))
                vmess["grpc-opts"] = grpcOpts

            proxies.append(vmess)

        elif scheme == "ss":
            try:
                ss = ss_to_clash(body)
                if ss is not None:
                    proxies.append(ss)
            except:
                continue

        elif scheme == "ssr":
            ssr = ssr_to_clash(body)
            if ss is not None:
                proxies.append(ssr)

        elif scheme == "tg":
            try:
                urlTG = urlparse.urlparse(line)
            except:
                continue

            query = dict(urlparse.parse_qsl(urlTG.query))

            tg = {}
            remark = get(query.get("remark"))
            if remark == "":
                remark = get(query.get("remarks"))
            if remark == "":
                remark = urlTG.hostname
            tg["name"] = uniqueName(names, remark)
            tg["type"] = urlTG.hostname
            tg["server"] = get(query.get("server"))
            tg["port"] = str(get(query.get("port")))
            user = get(query.get("user"))
            if user != "":
                tg["username"] = user
            password = get(query.get("pass"))
            if password != "":
                tg["password"] = password

            proxies.append(tg)

        elif scheme == "https":
            try:
                urlHTTPS = urlparse.urlparse(line)
            except:
                continue

            query = dict(urlparse.parse_qsl(urlHTTPS.query))

            if not urlHTTPS.hostname.startswith("t.me"):
                continue

            tg = {}

            remark = get(query.get("remark"))
            if remark == "":
                remark = get(query.get("remarks"))
            if remark == "":
                urlHTTPS.path.strip("/")
            tg["name"] = uniqueName(names, remark)
            tg["type"] = urlHTTPS.path.strip("/")
            tg["server"] = get(query.get("server"))
            tg["port"] = str(get(query.get("port")))
            user = get(query.get("user"))
            if user != "":
                tg["username"] = user
            password = get(query.get("pass"))
            if password != "":
                tg["passwork"] = password

            proxies.append(tg)


    if len(proxies) == 0:
        raise Exception("No valid proxies found")

    return proxies
