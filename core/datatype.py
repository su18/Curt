#!/usr/bin/env python 
# -*- coding: utf-8 -*- 
# @Author : su18
# @Copyright : phoebebuffayfan9527@gmail.com
# @Time  : 2019-07-11 18:04
# @FileName: datatype.py

import copy
import types


class AttribDict(dict):

    def __init__(self, indict=None, attribute=None):
        if indict is None:
            indict = {}
        self.attribute = attribute
        dict.__init__(self, indict)
        self.__initialised = True

    def __getattr__(self, item):
        try:
            return self.__getitem__(item)
        except KeyError:
            raise AttributeError("unable to access item '%s'" % item)

    def __setattr__(self, item, value):
        if "_AttribDict__initialised" not in self.__dict__:
            return dict.__setattr__(self, item, value)
        elif item in self.__dict__:
            dict.__setattr__(self, item, value)
        else:
            self.__setitem__(item, value)

    def __getstate__(self):
        return self.__dict__

    def __setstate__(self, dict):
        self.__dict__ = dict

    def __deepcopy__(self, memo):
        ret_val = self.__class__()
        memo[id(self)] = ret_val
        for attr in dir(self):
            if not attr.startswith('_'):
                value = getattr(self, attr)
                if not isinstance(value, (types.BuiltinFunctionType, types.FunctionType, types.MethodType)):
                    setattr(ret_val, attr, copy.deepcopy(value, memo))

        for key, value in self.items():
            ret_val.__setitem__(key, copy.deepcopy(value, memo))

        return ret_val
