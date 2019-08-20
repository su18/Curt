#!/usr/bin/env python 
# -*- coding: utf-8 -*- 
# @Author : su18
# @Copyright : phoebebuffayfan9527@gmail.com
# @Time  : 2019-07-11 17:23
# @FileName: logger.py

"""
设置日志相关配置，输出实时的日志信息
"""

import os
import sys
import logging
import colorlog
import logging.handlers


class Logger(logging.Logger):
    def __init__(self):

        use_color = True  # 是否在终端中使用带色日志
        logger_name = "Curt"  # 模块名称
        level = logging.INFO  # 日志记录等级
        logger_file = "../Curt.log"  # 日志文件名

        # 创建日志文件
        logging.Logger.__init__(self, logger_file)
        try:
            os.makedirs(os.path.dirname(logger_file))
        except FileExistsError:
            pass
        except FileNotFoundError:
            pass

        log_format = logging.Formatter(
            "[%(asctime)s] [" + logger_name + "] [%(levelname)s] %(filename)s [line:%(lineno)d] %(message)s")

        if not sys.stdout.isatty():
            # 判断执行输出流是否是终端，是终端直接显示日志
            try:
                if use_color:
                    log_colors = {
                        'DEBUG': 'white',
                        'INFO': 'blue',
                        'WARNING': 'yellow',
                        'ERROR': 'red',
                        'CRITICAL': 'bold_red',
                    }

                    log_style = "%(log_color)s[%(asctime)s] [" + logger_name + \
                                "] [%(levelname)s] %(filename)s [line:%(lineno)d] %(message)s%(reset)s"
                    log_format = colorlog.ColoredFormatter(fmt=log_style, log_colors=log_colors, reset=True)
                    console_handle = logging.StreamHandler(sys.stdout)
                    console_handle.setLevel(level)
                    console_handle.setFormatter(log_format)
                    self.addHandler(console_handle)
                else:
                    console_handle = logging.StreamHandler(sys.stdout)
                    console_handle.setLevel(level)
                    console_handle.setFormatter(log_format)
                    self.addHandler(console_handle)
            except Exception as reason:
                self.error("%s" % reason)

        try:
            handler = logging.handlers.RotatingFileHandler(
                filename=logger_file,
                maxBytes=30 * 1024 * 1024,
                backupCount=1,
                mode='a',
                encoding=None,
                delay=0
            )
            handler.setLevel(level)
            handler.setFormatter(log_format)
            self.addHandler(handler)
        except Exception as reason:
            self.error("%s" % reason)
