#!/usr/bin/env python 
# -*- coding: utf-8 -*- 
# @Author : su18
# @Copyright : phoebebuffayfan9527@gmail.com
# @Time  : 2019-07-11 18:11
# @FileName: initialize.py

import os
import re
import sys
import json
import codecs
from urllib.parse import urlparse
from xml.etree import ElementTree as Et
from core.data import paths
from core.data import logger
from core.data import conf
from core.data import byz
from core.data import payloads_list
from core.data import payloads
from core.datatype import AttribDict


def set_path(root_path):
    """
    设置路径
    :param root_path:
    :return:
    """

    # 设置应用程序主路径
    paths.ROOT_PATH = root_path

    paths.DATA_PATH = os.path.join(paths.ROOT_PATH, "data")

    # 设置配置文件路径
    paths.CONFIG_FILE = os.path.join(paths.ROOT_PATH, "settings.json")

    # 设置 payload、ua、waf 文件路径
    paths.PAYLOADS_PATH = os.path.join(paths.DATA_PATH, "payloads")
    paths.UA_PATH = os.path.join(paths.DATA_PATH, "ua")
    paths.WAF_PATH = os.path.join(paths.DATA_PATH, 'waf')
    paths.WAF_FILE = os.path.join(paths.WAF_PATH, 'waf.json')
    paths.UA_FILES = os.path.join(paths.UA_PATH, "user-agents.txt")

    # 设置边界
    paths.BOUNDARIES = os.path.join(paths.DATA_PATH, "boundaries.xml")


def load_settings():
    """
    加载配置
    :return:
    """
    logger.info("初始化项目配置")
    try:
        with codecs.open(paths.CONFIG_FILE, encoding="utf-8") as config:
            configs = json.loads(config.read())
            parse_result = urlparse(configs.get("target"))

            # 将配置文件写入全局变量
            conf.TARGET = {}
            conf.TARGET['url'] = configs.get("target")
            conf.TARGET['scheme'] = parse_result.scheme
            conf.TARGET['domain'] = parse_result.netloc
            conf.TARGET['path'] = parse_result.path
            conf.TARGET['params'] = parse_result.params
            conf.TARGET['query'] = parse_result.query.split('&')

            conf.TAMPER = configs.get("tamper")
            conf.HOST = configs.get("host")
            conf.HEADER = configs.get("header")
            conf.TECH = configs.get("tech").upper()
            conf.COOKIE = configs.get("cookie")
            conf.CHUNK = configs.get("chunk")
            conf.GZIP_ENCODING = configs.get("gzip_encoding")
            conf.DATA = configs.get("data")
            conf.METHOD = configs.get("method")
            conf.UA = []
            conf.COUNT = 0
            conf.BOUNDARIES = []

            # 初始化全局变量
            byz.dynamic_markings = []
            byz.dynamic_params = []
            byz.injectable_params = []
            byz.original_page = ''

            # 加载随机UA
            with codecs.open(paths.UA_FILES, 'r') as ua_file:
                for line in ua_file.readlines():
                    line = line.strip()
                    conf.UA.append(line)

    except Exception as reason:
        logger.error("加载配置错误：%s" % reason)


def load_boundaries():
    """
    加载 boundaries
    :return:
    """
    doc = Et.parse(paths.BOUNDARIES)
    root = doc.getroot()

    def parse_xml_node(node):
        for element in node.getiterator("boundary"):
            boundary = AttribDict()

            for child in element.getchildren():
                if child.text:
                    values = clean_up_vals(child.text, child.tag)
                    boundary[child.tag] = values
                else:
                    boundary[child.tag] = None

            conf.BOUNDARIES.append(boundary)

    parse_xml_node(root)


def load_payloads():
    """
    加载 payloads 到全局变量中
    :return:
    """
    logger.info("正在加载攻击载荷")
    try:
        for i in payloads_list:
            payload_path = os.path.join(paths.PAYLOADS_PATH, i)
            with codecs.open(payload_path) as file:
                for k, v in json.load(file).items():
                    payloads[k] = v
    except Exception as reason:
        logger.info("加载攻击载荷出错：%s " % reason)
        sys.exit()


def clean_up_vals(text, tag):
    if tag == "clause" and '-' in text:
        text = re.sub(r"(\d+)-(\d+)",
                      lambda match: ','.join(str(_) for _ in range(int(match.group(1)), int(match.group(2)) + 1)), text)
    if tag in ("clause", "where"):
        text = text.split(',')
    if hasattr(text, "isdigit") and text.isdigit():
        text = int(text)
    elif isinstance(text, list):
        count = 0
        for _ in text:
            text[count] = int(_) if _.isdigit() else _
            count += 1
        if len(text) == 1 and tag not in ("clause", "where"):
            text = text[0]
    return text


def show_banner():
    pass
