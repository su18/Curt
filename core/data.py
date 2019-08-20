#!/usr/bin/env python 
# -*- coding: utf-8 -*- 
# @Author : su18
# @Copyright : phoebebuffayfan9527@gmail.com
# @Time  : 2019-07-11 18:18
# @FileName: data.py

from core.datatype import AttribDict
from plugins.logger import Logger


# 设置路径全局变量
paths = AttribDict()

# 设置配置全局变量
conf = AttribDict()

# 设置请求队列全局变量
queries = {}

# 运行过程所需变量
byz = AttribDict()

# 设置日志
logger = Logger()

# payload 列表
payloads_list = ['boolean_blind.json']
payloads = {}

