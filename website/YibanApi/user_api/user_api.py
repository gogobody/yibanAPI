#!/usr/bin/env python
# coding=utf-8

import requests,json

def user_real_info(url,token):
    return json.loads(requests.get(url+"/user/real_me?access_token={}".format(token)).content)


