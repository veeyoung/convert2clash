# convert2clash

#### 说明 : 本项目提供解析ss/ssr/v2ray/trojan/Clash为Clash配置文件的自动化脚本,供学习交流使用.
#### Robot.py中的参数 :
     1. input_urls=订阅地址或本地文件目录（多个地址;隔开）
     2. output_path=转换成功后文件输出路径 默认输出至当前文件夹的config.yaml中
     3. config_path=来自本地的规则策略 默认选择当前文件的sample.yaml文件
     4. config_url=来自互联网的规则策略 默认值为https://raw.githubusercontent.com/veeyoung/convert2clash/master/sample.yaml
##### 当config_path获取失败，使用config_url的策略。正常情况下只需修改sub_url即可食用。
#### 使用说明:
     1. 先执行pip install -r requirements.txt
     2. 再运行Robot.py 
     
#### 功能特点:
    1.支持本地文件和网络订阅，本地文件支持base64加密，直接复制的节点链接或者clash配置文件
    2.secret字段自动生成随机密码(默认30位)
