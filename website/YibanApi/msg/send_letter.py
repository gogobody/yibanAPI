#!/usr/bin/env python
# coding=utf-8

import requests

def send_letter(url,data):
    return requests.post(url+"/msg/letter",data=data).content


