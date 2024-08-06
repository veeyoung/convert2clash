# convert2clash

#### 说明 : 本项目提供解析ss/ssr/v2ray/trojan/Clash/hysteria/https/tuic/tg/vless为mihomo配置文件的自动化脚本,供学习交流使用.
#### config.json中的参数 :
```json
{
    "invalid_node_name": ["剩余流量", "套餐到期", "距离下次"],
    "pass_group": ["🎯 全球直连", "🛑 全球拦截", "🍃 应用净化"],
    "sample_path": "./samples/sample.yaml",
    "sample_url": "https://github.gogodoge66.eu.org/https://raw.githubusercontent.com/veeyoung/somescripts/main/sample.yaml",
    "output_path": "default",
    "secret": true,
    "authentication": false,
    "allow_insecure_node": true,
    "keep_dulplicate": true,
    "backup": false,
    "use_api": true
}
```
1. invalid_node_name,跳过无效的节点
2. pass_group把节点添加到代理组时跳过的组
3. sample_path,配置文件目录
4. sample_url,配置文件url
5. output_path,输出路径,默认default为/home/user/.config/clash,适用于linux
6. secret,是否添加管理页面api认证,如果配置文件中没有则随机生成
7. authentication,是否添加代理认证,如果没有则随机生成一组
8. allow_insecure_node,是否允许不安全的节点
9. keep_dulplicate是否保存节点相同但用户信息不同的节点,适用于一个机场拥有多个订阅
10. 输出前是否备份原文件,备份到backup文件夹
11. 采用clash api更新配置

#### 使用说明:
     1. 先执行pip install -r requirements.txt
     2. 再运行convertClash.py

#### 功能特点:
    1.支持本地文件和网络订阅，支持base64编码，直接复制的节点链接或者clash配置文件,支持递归解析
    2.订阅或本地文件以;分隔
