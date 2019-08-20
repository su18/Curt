#!/usr/bin/env python 
# -*- coding: utf-8 -*- 
# @Author : su18
# @Copyright : phoebebuffayfan9527@gmail.com
# @Time  : 2019-07-11 16:40
# @FileName: main.py


import os
from core.checks import check_waf
from core.checks import check_stable
from core.checks import check_dynamic
from core.checks import check_connection
from core.checks import heuristic_check
from core.checks import check_sql_injection
from core.initialize import set_path
from core.initialize import load_boundaries
from core.initialize import load_settings
from core.initialize import load_payloads

# 设置文件路径
set_path(os.getcwd())

# 初始化应用程序设置
load_settings()

# 加载 boundaries
load_boundaries()

# 加载payload
load_payloads()

# 检查页面联通性，首次 get_page 将会作为原始请求页面，存储在 queries 的 original 中
check_connection()

# 检查页面稳定性，请求三次页面，同时计算排除页面动态内容，存储在 byz.original 中
check_stable()

# 检查 WAF
check_waf()

# 检查参数动态性，动态参数存储在 byz.dynamic_params 中
check_dynamic()

# 启发式检测
heuristic_check()

# 注入检测
check_sql_injection()
