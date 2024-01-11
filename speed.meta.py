#!/usr/bin/env python
import os, sys, requests, json
from confProcessor import load_local_config, clash_use_new_config, save_config

if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[2] == '-c':
        config_path = sys.argv[2]
    else:
        config_path = '/home/' + os.getlogin() + '/.config/clash/config.yaml'
    config = load_local_config(config_path)

    if len(sys.argv) == 3 and sys.argv[2] == '-c':
        clash_use_new_config(config_path, clashAuth = config.get('secret'))
        input('测完速按回车继续')

    headers = dict()
    if config.get('secret') is not None:
        headers['Authorization'] = "Bearer " + config['secret']
    headers['content-type'] = 'application/json'
    url_clash_api = "http://127.0.0.1:9090/proxies"
    response_clash = requests.get(url_clash_api,headers = headers)

    latency = dict()
    for i, j in response_clash.json()['proxies'].items():
        if j.get('all') is not None or j['alive'] == False or len(j['history']) == 0:
            continue
        delay = j['history'][-1].get('meanDelay') if j['history'][-1].get('meanDelay') is not None \
        else j['history'][-1].get('delay')
        if delay > 0:
            latency[i] = delay

    # 删除原来的节点
    pass_group = []
    node_list = config['proxies']
    node_names = [node['name'] for node in node_list]
    config['proxies'] = []
    for group in config.get('proxy-groups'):
        if group.get('proxies') is None or node_list[-1]['name'] not in group['proxies']:
            pass_group.append(group['name'])
        else:
            group['proxies'] = [i for i in group['proxies'] if i not in node_names]

    for i in sorted(latency.items(), key=lambda x: x[1]):
        config['proxies'].append(node_list[node_names.index(i[0])])
        for group in config.get('proxy-groups'):
            if group['name'] not in pass_group:
                group['proxies'].append(config['proxies'][-1]['name'])

    save_config(config_path, config)
    clash_use_new_config(config_path, clashAuth = config.get('secret'))
