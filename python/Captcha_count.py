#!/usr/bin/env python
# encoding: utf-8

"""
@author: Whip1ash
@contact: security@Whip1ash.cn
@file: Captcha_count.py
@time: 6/11/21 2:53 PM
@desc:
"""
import requests,re, json
from random import randint
from urllib import pathname2url


headers = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4475.0 Safari/537.36",
    "sec-ch-ua": '"Chromium";v="92", " Not A;Brand";v="99", "Google Chrome";v="92"',
    "DNT": '1',
    "sec-ch-ua-mobile": '?0',
    "Accept": "*/*",
    "Sec-Fetch-Site": "cross-site",
    "Sec-Fetch-Mode": "no-cors",
    "Sec-Fetch-Dest": "script",
    "Referer": "https:/www.wenjuan.in/"

}

proxy_srv = {
    "http":"http://127.0.0.1:8080",
    "https":"http://127.0.0.1:8080"
    # "https:":"https://127.0.0.1:8080"
}

pem_locaiton = '/Users/mingxugeng/Downloads/charles-ssl-proxying-certificate.pem'

def first_req(url):

    s = requests.Session()
    s.verify = pem_locaiton
    # s.proxies.update(proxy_srv)
    req = requests.Request(
        'GET',
        url,
        headers=headers
    )

    p = req.prepare()
    _ret = s.send(p,proxies=proxy_srv)

    if _ret.status_code == 200:
        html = _ret.text
    else:
        print("Status Code:{}".format(_ret.status_code))
        exit()

    regx = r'(var requestInfo =.*headers: {},\n    };\n\n\n\n)'
    re_cfg = re.compile(regx, re.DOTALL)
    raw_res = re_cfg.findall(html)[0]
    token_regx = r'token: \'(.*?)\',\n'
    refer_regx = r'refer: \'(.*)\',\n'

    token_re_cfg = re.compile(token_regx, re.DOTALL)
    refer_re_cfg = re.compile(refer_regx, re.DOTALL)

    token = token_re_cfg.findall(raw_res)[0]
    refer = refer_re_cfg.findall(raw_res)[0]

    return {
        'token': token,
        'refer': refer
    }

def cap_req(token, path = '/initialize.jsonp', cap_data=''):
    cf_base_url = 'https://cf.aliyun.com/nocaptcha'
    app_name = 'CF_APP_WAF'
    token = token

    if path == '/initialize.jsonp':
        return init_req(app_name, token, cf_base_url)
    elif path == '/analyze.jsonp':
        return analyze_req(app_name, token, cf_base_url, cap_data)

def init_req(app_name, token, base, path = '/initialize.jsonp'):

    get_data = {
        'a': app_name,
        't': token,
        'scene': None,
        'lang': 'cn',
        'v': 'v1.2.20',
        'href': pathname2url(base_url),
        'comm':'{}',
        'callback':'initializeJsonp_{}'.format(randint(10000000000000000,99999999999999999))
    }

    s = requests.Session()
    s.proxies.update(proxy_srv)
    req = requests.Request(
        'GET',
        base+path,
        headers=headers,
        params=get_data
    )
    p = req.prepare()
    _ret = s.send(p, proxies=proxy_srv)
    json_regx = r'({.*})'
    json_re_cfg = re.compile(json_regx)
    json_res = json_re_cfg.findall(_ret.text)[0]
    js_data = json.loads(json_res)
    if js_data.get('result').get('msg') == 'success':
        return True
    print('Error in init req')
    exit()

def analyze_req(app_name, token, base, cap_data, path='/analyze.jsonp'):
    get_data = {
        'a': app_name,
        't': token,
        'n': cap_data,
        'scene': None,
        'asyn': 0,
        'lang': 'cn',
        'v': 1030,
        'callback': 'jsonp_{}'.format(randint(10000000000000000,99999999999999999))
    }

    s = requests.Session()
    s.proxies.update(proxy_srv)
    req = requests.Request(
        'GET',
        base+path,
        headers=headers,
        params=get_data
    )
    p = req.prepare()
    _ret = s.send(p, proxies=proxy_srv)
    json_regx = r'({.*})'
    json_re_cfg = re.compile(json_regx)
    json_res = json_re_cfg.findall(_ret.text)[0]
    js_data = json.loads(json_res)
    if js_data.get('success') == False or js_data.get('result').get('value') == 'block' :
        print('数据使用失败')
        exit()

    global cnt
    cnt += 1
    print('获取csessionid, value成功，已获取{}次'.format(cnt))
    print("csessionid = {}\n value = {}".format(js_data.get('result').get('csessionid'), js_data.get('result').get('value')))

if __name__ == '__main__':
    base_url = 'https://www.wenjuan.in/s/6N3iy2u'
    cnt=0
    # 手势数据
    cap_data = '140%238TbDYpCPzzFuAQo24Zdu4pN8s7aNhnvzFM7JfA8jceWnhI3Lg%2FkzZQbEIv36Lp9NkDkZqm09KziElp1zz%2FMg%2BkdfAFzxzz0LOth%2Fzzrb22U3lp1xzFWIIXVBUzrzKID%2BV3hqVzLq%2B5HaPtrPHpcolCucXDSiWG6ZB4JgYrOwSw93ldzzbmk7ldiYL9laSazefw7Fnh0VtyUiHwaxeLaTMTnMe7eNM2dhLdG0DAwsXR%2FKJjQgURtawCiXlqi4OFOISfUUye8ExnE1MCBsKdkoo3M0hrepymd5O9ajXZa%2FlPgmDhL4ilzTJsNoaUWU1WSt%2FeuHXTy8hqE1Ds1d%2BGSoFvxH%2FROoPYSj3Aq1QMGpJRbH5MueFcqqJaoJJDrsw06vdMFeA6RMck2w3tKWmwbQdeQzR7VQudaTCJa6ggoREVTItwqYcWjvRX3XRvIznPSIwBZ7vWZW%2FBFdGUde9qQahRE374Lg%2FLgY58PCi3IgFE4iv17s7fMYB1s%2FmWPahvdk5Ch2VV5DhGXJlp1YFufWuM8VVZI%2Fq0EjFKlMEc0xksXR2B5Uh2FeHDZoM2Oa9epTFigmdF5%2FnRvY07sB%2BWt92PXEJt0TQ80mwMnMuILSBs%2BibJJD%2FNjPZYPqZOPsSazTKP1o7RsVRCi%2FSZNZbUpvBu88TS03l8cJlQLi4WfsLh6T2jOAKlDAMcVMjvmlbcHX0Dxzu9zhesS6A53IFwWOXo9Xs0v5ySZo6vphK%2BnXz0D4QoCzVFx%2F7a6gk4s8Tag4yn9TjQcG9ah2dSD2nnfs1EGipVtxYnAC6CafFCTYWiWerK1WMcMW3WAmDJi4IgdFvMSdlsz3YsX%2BsEKVCmbj%2B2VuRgTGDDNtwVhAwUWzL9l52YJkoRI3fxmJdETL43Rzkt6Ja6NuBUIkEqtNVwYjPNij1Egz%2FmWMl1n4eCikU%2FAORA%2BLNRgM4UURn00pYn3z1Kn%2FOKv6vhXcmpCiNu8wzmM4wMPJysUyjNgHjFbKWwQhe1%2FrYt6OsWGFHAzfwavUv8XuCMRDC6YHHvLiJYv03d0TkZ1j3ZCDMqxzOWChcLcsXcAt8pJ4G96ayOSTco8h9Vf2LlVX1sL%2FMHgWl0BxtYugRZUcwB5B99%2BjjbPQG%2B08lVrBy2TJO7e2%2BUhAGMPcEh7TOfFGxdtMDPB4QOz310sFDasJhGusHQSBlSBE%2BFIJExhsW5GhbHYr1srBT4aJBX%2FzViU3palx4TpQ4io%2BXjqVQyRuKNc4jT%2BkPhgYRbViHfBg%2BwJw7IPQkEW01ml2nVrdO%2F8NsvfdFWS%3D&p=%7B%22key1%22%3A%22code100%22%2C%22user%22%3A%22default%22%2C%22ncSessionID%22%3A%225e701f00c251%22%2C%22umidToken%22%3A%22T2gAI__tNmGLxiQRZyIOaeNX8ElGSDMU0YnsNjs6H_WSTV5fUel13mOT7bPEaVUNYds%3D%22%7D'
    token = 'a784297e-dce8-4a9b-9757-3fe387421463'


    # if cap_data == '':
    #     print("cap_data is blank")
    #     exit()

    # ret = first_req(base_url)
    # token = ret.get('token')
    # ret = cap_req(token,cap_data=cap_data)
    # if ret:
    while 1:
        cap_req(token,path='/analyze.jsonp',cap_data=cap_data)
