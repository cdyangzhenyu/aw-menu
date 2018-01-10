# -*- coding: utf-8 -*-

#    Copyright 2018 Awcloud, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

SETTINGS_FILE = "/var/lib/awstack/reg_config"

LOGFILE = "/var/log/awmenu.log"

RELEASE_FILE = "/etc/aw_release"
HIERA_NET_SETTINGS = "/etc/hiera/networks.yaml"

DEFAULT_LOCK_FILE = "/var/run/awmenu.lock"

PRE_DEPLOYMENT_MODE = "pre"
POST_DEPLOYMENT_MODE = "post"

PUPPET_TYPE_LITERAL = "literal"
PUPPET_TYPE_RESOURCE = "resource"
PUPPET_TYPE_CLASS = "class"

ADMIN_NETWORK_ID = 1

# Awcloud
AWCLOUD_TITLE = u"预配置界面（请使用Up/Down/Left/Right进行选择，退出之前请保存配置。）"
AWCLOUD_FOOTER = u"这里将显示提示信息"
AWCLOUD_MENU = u""
AWCLOUD_WIDGET_CHECK = u"检查"
AWCLOUD_WIDGET_CANCEL = u"取消"
AWCLOUD_WIDGET_APPLY = u"应用"
AWCLOUD_SUCCESS_FOOTER = u"修改成功"
AWCLOUD_CHANGING_FOOTER = u"修改中，请稍等"

# Cloud Role
ROLE_MENU_NAME = u"角色配置"
CLOUD_ROLE_NAME = u"云管"
NON_CLOUD_ROLE_NAME = u"非云管"
ROLE_MENU_HEADER = u"请选择该节点的角色："
MGMT_IP_LABLE = u"云管地址："
MGMT_IP_TOOLTIP = u"请设置云管服务的地址（例如：192.168.1.2）"
MGMT_IP_HEADER = u"请设置云管平台的IP地址："

# Save and Quit
SAVE_QUIT_MENU_NAME = u"退出选项"
SAVE_QUIT_MENU_HEADER = u"友情提示，退出前请记得保存修改："
SAVE_AND_CONTINUE = u"保存并继续"
SAVE_AND_QUIT = u"保存并退出"
QUIT_WITHOUT_SAVE = u"直接退出"
SAVE_QUIT_FOOTER = u"所有的修改都已保存成功"

# Network settings
NETWORK_MENU_HEADER = u"请选择管理网络网卡并进行配置："
NETWORK_MENU_NAME = u"管理网络"
NETWORK_INTERFACE_NAME_LABLE = u"网卡名称："
NETWORK_INTERFACE_NAME_TOOLTIP = u"系统内网卡标识符"
NETWORK_INTERFACE_ENABLE_LABLE = u"是否启用："
NETWORK_IPADDR_LABLE = u"网卡地址："
NETWORK_IPADDR_TOOLTIP = u"请设置IP地址（例如：192.168.1.2）"
NETWORK_NETMASK_LABLE = u"掩码地址："
NETWORK_NETMASK_TOOLTIP = u"请设置掩码地址（例如：255.255.255.0）"
NETWORK_GATEWAY_LABLE = u"默认网关："
NETWORK_GATEWAY_TOOLTIP = u"请设置默认网关（例如：192.168.1.1）"
NETWORK_DNS_LABLE = u"域名解析："
NETWORK_DNS_TOOLTIP = u"请设置DNS（例如：114.114.114.114）"

# System tips
CHECK_TIPS = u"检查数据中..."
ERROR_TIPS = u"发生错误！"
NO_ERROR_TIPS = u"没有错误"
APPLY_SUCCESS_TIPS = u"修改成功"


# ERROR MSG
MGMT_IP_BLANK_ERROR = u"IP地址不能为空！"
MGMT_IP_FORMAT_ERROR = u"IP地址格式不正确！"
NETMASK_FORMAT_ERROR = u"掩码地址不正确！"
GATEWAY_SUBNET_ERROR = u"网关和地址不在一个子网中！"
DUPLICATE_IP_ERROR = u"IP地址重复！"
DUPLICATE_HOST_ERROR = u"IP地址：{0} 冲突！"
