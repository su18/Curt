#!/usr/bin/env python 
# -*- coding: utf-8 -*- 
# @Author : su18
# @Copyright : phoebebuffayfan9527@gmail.com
# @Time  : 2019-07-11 18:00
# @FileName: connect.py

import re
import json
import random
import requests
from core.data import conf
from core.data import logger
from core.data import queries
from core.common import filter_page_content
from core.common import remove_dynamic_content
from core.common import get_payload_url
from core.common import check_page_similarity
from requests.adapters import HTTPAdapter


class Connect(object):

    def __init__(self):
        # 初始化 Session连接，读取/连接 超时自动重试，最大次数3次
        self.Request = requests.Session()
        self.Request.mount('http://', HTTPAdapter(max_retries=3))
        self.Request.mount('https://', HTTPAdapter(max_retries=3))

    @staticmethod
    def result_handle(flags, result, original):
        """
        将请求结果放入全局变量 queries 中
        :param flags:
        :param result:
        :param original:
        :return:
        """
        if original:
            flags = 'original'

        queries[flags] = {}
        queries[flags]['code'] = result.status_code
        queries[flags]['url'] = result.url
        queries[flags]['time'] = result.elapsed.total_seconds()
        queries[flags]['text'] = result.text
        queries[flags]['data'] = result.request.body
        queries[flags]['ori_text'] = filter_page_content(result.text)
        queries[flags]['static_text'] = remove_dynamic_content(queries[flags]['ori_text']) if not original else ''

    @staticmethod
    def url_re(url, host):
        pattern = "(?<=//)(.*?)(?=/)"
        return re.sub(pattern, host, url)

    def get_page(self, **kwargs):
        """
        连接到目标URL并返回内容
        :param kwargs:
        :return:
        """
        url = kwargs.get("url", None) or conf.TARGET['url']
        method = kwargs.get("method", None) or conf.METHOD
        cookie = kwargs.get("cookie", None) or conf.COOKIE
        ua = kwargs.get("ua", None) or random.choice(conf.UA)
        host = kwargs.get("host", None) or conf.HOST
        headers = kwargs.get("headers", None) or conf.HEADER
        chunked = kwargs.get("chunked", False) or conf.CHUNK
        data = kwargs.get("data", False) or conf.DATA
        gzip = kwargs.get("gzip", False) or conf.GZIP_ENCODING
        original = kwargs.get("original", False)

        # 指定随机UA
        headers["User-Agent"] = ua

        # 指定真实IP
        if host:
            url = self.url_re(url, host)
            headers["Host"] = conf.TARGET['domain']

        # 请求页面并返回内容
        if not chunked:
            if not method or method.upper() == 'GET':
                try:
                    result = self.Request.get(url,
                                              headers=headers,
                                              cookies=cookie,
                                              allow_redirects=False,
                                              timeout=(3, 15))
                    self.result_handle(conf.COUNT, result, original)
                    conf.COUNT += 1
                except requests.exceptions.RequestException as e:
                    logger.error("请求超时，正在重试请求：%s" % conf.TARGET['url'])
                    logger.error(e)

            elif method.upper() == 'POST':
                if gzip:
                    headers["Content-Encoding"] = 'gzip'
                    headers["Content-Type"] = 'x-application/x-gzip'

                    def to_gzip_format(post_data):
                        """
                        定义gzip 发包 data 格式
                        :param post_data:
                        :return:
                        """
                        _data = bytes(json.dumps(post_data), 'utf-8')
                        ct = gzip.compress(_data, )
                        return ct

                    try:
                        result = self.Request.post(url=url,
                                                   data=to_gzip_format(data),
                                                   headers=headers,
                                                   cookies=cookie,
                                                   timeout=(3, 15))
                        self.result_handle(conf.COUNT, result, original)
                        conf.COUNT += 1
                    except requests.exceptions.RequestException as e:
                        logger.error("请求超时，正在重试请求：%s" % conf.TARGET['url'])
                        logger.error(e)
                else:
                    try:
                        result = self.Request.post(url=url,
                                                   data=data,
                                                   headers=headers,
                                                   cookies=cookie,
                                                   timeout=(3, 15))
                        self.result_handle(conf.COUNT, result, original)
                        conf.COUNT += 1
                    except requests.exceptions.RequestException as e:
                        logger.error("请求超时，正在重试请求：%s" % conf.TARGET['url'])
                        logger.error(e)

        else:
            pass

        return conf.COUNT - 1

    def query_page(self, params, payload, _return=None, url=None):
        """

        :param params: 参数
        :param payload:
        :param _return: 判断返回数据种类
        :param url:
        :return: 原页面或相似度
        """
        if not url:
            url = get_payload_url(params, payload)

        count = self.get_page(url=url)

        similarity = check_page_similarity(page=count)
        page = queries[count]['static_text']

        if _return == 'page':
            return page
        elif _return == 'similarity':
            return similarity
        elif _return == 'count':
            return count, similarity
        else:
            return page, similarity


Request = Connect()
