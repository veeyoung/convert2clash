#!/usr/bin/env python
#coding: utf-8
# 说明 : 本脚本提供批量解析v2ray/ss/ssr/trojan/clash为Clash配置文件,仅供学习交流使用.
# https://github.com/celetor/convert2clash
import os, sys, json, base64, datetime
import requests, yaml
import argparse

from nodeParser import *
from confProcessor import *

supported_nodes = ['vmess://', 'ss://', 'ssr://', 'trojan://']


def log(msg):
    time = datetime.datetime.now()
    print('[' + time.strftime('%Y.%m.%d-%H:%M:%S') + '] ' + msg)


# 获取节点:
def get_proxies_recursive(urls):
    if urls is None or urls == '':
        return None
    url_list = urls.split(';')
    headers = {
        'User-Agent': 'Clash'
    }
    proxy_list = list()
    for url in url_list:
        url = url.strip()
        print(url)
        if url.startswith('http'):
            try:
                inputnode = requests.get(url, headers=headers, timeout=5)
                inputnode.encoding = 'unicode'
                inputnode = inputnode.text
            except Exception as r:
                log('获取订阅链接{}失败:{}'.format(url,r))
                continue
        else:
            try:
                with open(url, 'r', encoding="utf-8") as f:
                    inputnode = f.read()
            except FileNotFoundError:
                log('本地节点{}导入失败'.format(url))
                continue

        if not any(inputnode.find(node_type) > -1 for node_type in supported_nodes):
            try:
                yml = yaml.load(inputnode, Loader=yaml.FullLoader)
                tmp_list = yml.get('proxies')
                if tmp_list is None:
                    log('clash节点{}为空,提取失败'.format(url))
                    continue
                proxy_list.extend(tmp_list)
                continue
            except:
                pass
            try:
                inputnode = base64.b64decode(inputnode).decode('utf-8')
            except:
                tmp_list = get_proxies_recursive(inputnode)
                proxy_list.extend(tmp_list)
                continue

        nodes_list = inputnode.splitlines()
        for node in nodes_list:
            name = node[:node.find('://')]
            if name is None:
                continue
            if name == 'vmess':
                clash_node = v2ray_to_clash(node)
            elif name == 'ss':
                clash_node = ss_to_clash(node)
            elif name == 'ssr':
                clash_node = ssr_to_clash(node)
            elif name == 'trojan':
                clash_node = trojan_to_clash(node)
            else:
                continue
            if clash_node is None:
                continue
            proxy_list.append(clash_node)

    return proxy_list


# 程序入口
if __name__ == '__main__':
    args = argparse.ArgumentParser(description = 'convert node to clash format',epilog = 'end ')
    args.add_argument("-S",'--sample', type = str, dest = "sample_path", help = u"sample path")
    args.add_argument("-O", "--output", type = str, dest = "output_path", help = "output config path")
    args = args.parse_args()
    args_dict = args.__dict__

    converter_config = None
    try:
        with open('./config.json', 'r', encoding='utf8') as f:
            converter_config = json.load(f)
    except FileNotFoundError:
        log('程序配置文件未找到')
        sys.exit(1)

    # 配置路径
    sample_path = converter_config['sample_path']
    if args_dict.get('sample_path') is not None:
        sample_path = args_dict['sample_path']

    # 输出路径
    if converter_config.get('output_path') is None or converter_config['output_path'] == 'default':
        output_path = '/home/' + os.getlogin() + '/.config/clash/config.yaml'
    else:
        output_path = converter_config['output_path']
    if args_dict.get('output_path') is not None:
        output_path = args_dict['output_path']
    if converter_config.get('backup') == True and os.path.exists(output_path):
        if not os.path.exists('backup'):
            os.mkdir('backup')
        os.rename(output_path, os.path.join('backup', str(int(datetime.datetime.now().timestamp())) + os.path.basename(output_path)))


    # 获取配置文件
    config_sample = load_local_config(sample_path)
    if config_sample is None:
        log('获取本地配置文件失败')
        config_sample = load_online_config(converter_config.get('sample_url'))
    if config_sample is None:
        log('获取网络配置文件失败')
        sys.exit(1)
    
    input_urls = input('请输入文件名或订阅地址(多个用;隔开):')
    node_list = get_proxies_recursive(input_urls)
    if node_list is None or len(node_list) == 0:
        log('未发现节点')
        sys.exit(0)

    node_num = process_dulplicate_invalid_insecure(node_list, converter_config)

    message = '发现:'
    for k, v in node_num.items():
        message = message + '{}个{}节点,'.format(v, k)
    log(message)

    final_config = add_proxies_to_model(node_list, config_sample, converter_config)
    save_config(output_path, final_config)
    log('成功更新{}个节点'.format(len(node_list)))
    print(f'文件已导出至 {output_path}')
    if args_dict.get('output_path') is None:
        clash_use_new_config(output_path, clashAuth = config_sample.get('secret'))