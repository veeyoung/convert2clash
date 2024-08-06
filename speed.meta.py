#!/usr/bin/env python3
import os
import sys
import argparse
import requests
from utils import load_local_config, clash_use_new_config, save_config
from utils import test_latency

def get_latency(headers, port):
    clash_api_url = f"http://127.0.0.1:{port}/proxies"
    response = requests.get(clash_api_url, headers=headers)

    latency_info = {}
    for proxy_name, proxy_info in response.json()['proxies'].items():
        if proxy_info.get('all') or not proxy_info.get('alive') or not proxy_info.get('history'):
            continue
        delay = proxy_info['history'][-1].get('meanDelay', proxy_info['history'][-1].get('delay', 0))
        if delay > 0:
            latency_info[proxy_name] = delay

    return latency_info

def update_config(config_path, config, latency_info, top_n):
    pass_group = []
    node_list = config['proxies']
    node_names = [node['name'] for node in node_list]
    config['proxies'] = []
    for group in config.get('proxy-groups', []):
        if not group.get('proxies') or node_list[-1]['name'] not in group['proxies']:
            pass_group.append(group['name'])
        else:
            group['proxies'] = [proxy for proxy in group['proxies'] if proxy not in node_names]

    sorted_latency = sorted(latency_info.items(), key=lambda x: x[1])[:top_n]
    for proxy_name, _ in sorted_latency:
        proxy_index = node_names.index(proxy_name)
        config['proxies'].append(node_list[proxy_index])
        for group in config.get('proxy-groups', []):
            if group['name'] not in pass_group:
                group['proxies'].append(proxy_name)

    save_config(config_path, config)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Clash配置自动更新')
    parser.add_argument('-c', '--config', dest='config_path', default='/home/' + os.getlogin() + '/.config/mihomo/config.yaml', help='Clash配置文件的路径')
    parser.add_argument('-t', '--top', dest='top_n', type=int, default=-1, help='保留的前n个代理节点')
    parser.add_argument('-p', '--port', dest='api_port', type=int, default=9090, help='api端口')
    args = parser.parse_args()

    config = load_local_config(args.config_path)
    headers = {'content-type': 'application/json'}
    if config.get('secret'):
        headers['Authorization'] = "Bearer " + config['secret']

    clash_use_new_config(args.config_path, clashAuth=config.get('secret'), port = args.api_port)
    test_latency(headers, port = args.api_port)
    latency_info = get_latency(headers, port = args.api_port)

    update_config(args.config_path, config, latency_info, args.top_n)
    clash_use_new_config(args.config_path, clashAuth=config.get('secret'), port = args.api_port)
    test_latency(headers, port = args.api_port)
