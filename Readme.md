## 端口扫描 && 嗅探工具 ##
### 简单介绍 ###
- 这是一款非常简单的集成端口扫描和嗅探的java应用
- 主要分为俩个模块，下面会做介绍
- 由HFUTer制作完成
### 欢迎界面 ###
- 入口界面，包含了进入端口扫描和嗅探界面的Button
- 方式是进行界面Scene的切换
### 端口扫描界面 ###
- 主要功能：
    - 采用多线程方式对用户输入的网址进行端口扫描
    - 导出扫描结果的txt文件。
    - 返回主界面
###  嗅探界面 ###
- 主要功能：
    - 过滤流经网卡的TCP、UDP、ICMP包
    - 通过过滤规则对包进行简单筛选
    - 返回主界面
