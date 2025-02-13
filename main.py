import re
import os
import json
import html
import execjs
import requests
import hashlib
import random

from time import sleep
from bs4 import BeautifulSoup

requests.packages.urllib3.disable_warnings()

from datetime import datetime


def get_current_time():
    # 获取当前时间并格式化时间
    return datetime.now().strftime("%Y/%m/%d %H:%M:%S")


def get_jsl_clearance_s(jsl_data):
    chars = len(jsl_data['chars'])
    for i in range(chars):
        for j in range(chars):
            jsl_clearance_s = jsl_data['bts'][0] + jsl_data['chars'][i:(i + 1)] + jsl_data['chars'][j:(j + 1)] + \
                              jsl_data['bts'][1]
            if getattr(hashlib, jsl_data['ha'])(jsl_clearance_s.encode('utf-8')).hexdigest() == jsl_data['ct']:
                # print('get_jsl_clearance_s结果为：',jsl_clearance_s)
                return jsl_clearance_s


def request_cnvd(url, params, proxies, cookies):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.178 Safari/537.36', }
        return requests.get(url, params=params, cookies=cookies, headers=headers, proxies=proxies, verify=False, )
    except requests.exceptions.SSLError as e:
        print(f'[{get_current_time()}][!] 请求失败，错误信息为：', e)
        with open('error.txt', 'w', encoding='utf-8') as f:
            f.write(str(e) + '\n\n')
        print(f'[{get_current_time()}][!] 等待60秒后重试')
        sleep(60)
        return request_cnvd(url, params, proxies, cookies)


def cnvd_jsl(url, params, proxies, cookies):
    r = request_cnvd(url, params, proxies, cookies)
    if r.status_code == 521:
        if re.findall('document.cookie=(.*?);location.', r.text):
            # print('jsl_1')
            cookies = r.cookies.get_dict()
            __jsl_clearance_s = \
                execjs.eval(re.findall('document.cookie=(.*?);location.', r.text)[0]).split(';')[0].split('=')[1]
            cookies['__jsl_clearance_s'] = __jsl_clearance_s
            r = request_cnvd(url, params, proxies, cookies)
            # print(r.text[::100])
            jsl_data = None
            if r.text.find(';location.href=location.pathname+location.search') != -1:
                '''<script>document.cookie=('_')+('_')+('j')+('s')+('l')+('_')+('c')+('l')+('e')+('a')+('r')+('a')+('n')+('c')+('e')+('_')+('s')+('=')+(-~{}+'')+(7+'')+(3+'')+(1+[0]-(1)+'')+((1<<1)+'')+(1+4+'')+(1+[0]-(1)+'')+(-~(8)+'')+(-~(4)+'')+(2+4+'')+('.')+(-~[7]+'')+((2)*[2]+'')+((2)*[4]+'')+('|')+('-')+(-~[]+'')+('|')+('e')+('X')+('s')+('w')+('h')+('Y')+('L')+('c')+('w')+('K')+('%')+(1+1+'')+('F')+('r')+('A')+('%')+(+!+[]*2+'')+('B')+('E')+('k')+('D')+('T')+('h')+('m')+('K')+('d')+('R')+('t')+('M')+('V')+(3+5+'')+('%')+((2^1)+'')+('D')+(';')+(' ')+('M')+('a')+('x')+('-')+('a')+('g')+('e')+('=')+(-~[2]+'')+(6+'')+(~~false+'')+((+[])+'')+(';')+(' ')+('P')+('a')+('t')+('h')+('=')+('/')+(';')+(' ')+('S')+('a')+('m')+('e')+('S')+('i')+('t')+('e')+('=')+('N')+('o')+('n')+('e')+(';')+(' ')+('S')+('e')+('c')+('u')+('r')+('e');location.href=location.pathname+location.search</script>
                直接执行设置cookie
                '''
                # print('jsl_1_1')
                js_code = r.text.replace('<script>document.cookie=', '').replace(
                    ';location.href=location.pathname+location.search</script>', '')
                js_code = execjs.eval(js_code).split(';')[0].split('=')[1]
                # print(js_code)
                cookies['__jsl_clearance_s'] = js_code

            else:
                # print('jsl_1_2')
                # print(r.text)
                try:
                    jsl_data = json.loads(re.findall('go\((\{.*?\})\)', r.text)[0])
                except Exception as e:
                    # 创宇盾页面
                    print(f'[{get_current_time()}][!] 获取jsl_data失败，错误信息为：', e)
                    print(f'[{get_current_time()}][!] 当前页面内容为：', r.text)
                    with open('error.html', 'w', encoding='utf-8') as f:
                        f.write(r.text + '\n\n\n\n\n\n\n\n\n\n\n\n\n')
                    print(f'[{get_current_time()}][!] 等待60秒后重试')
                    sleep(60)
                    return cnvd_jsl("https://www.cnvd.org.cn/flaw/list", params=params, proxies=proxies,
                                    cookies=cookies)
                # print(jsl_data)
                cookies[jsl_data['tn']] = get_jsl_clearance_s(jsl_data)
            # print('当前cookie是',cookies)
            r = request_cnvd(url, params, proxies, cookies)
        if re.findall('go\((\{.*?\})\)', r.text):
            # print('jsl_2')
            jsl_data = json.loads(re.findall('go\((\{.*?\})\)', r.text)[0])
            cookies[jsl_data['tn']] = get_jsl_clearance_s(jsl_data)
            r = request_cnvd(url, params, proxies, cookies)
    elif r.status_code == 403:
        next_time = random.randint(60, 120)
        print(f'[{get_current_time()}][!] 检测到疑似攻击行为，等待{next_time}秒后重试')
        sleep(next_time)
        return cnvd_jsl("https://www.cnvd.org.cn/flaw/list", params=params, proxies=proxies, cookies=cookies)
    elif r.status_code == 404:
        next_time = random.randint(60, 120)
        print(f'[{get_current_time()}][!] 当前IP已被封禁，等到{next_time}秒后重试')
        sleep(next_time)
        return cnvd_jsl("https://www.cnvd.org.cn/flaw/list", params=params, proxies=proxies, cookies=cookies)
    else:
        print(f'[{get_current_time()}][+] 其他状态码：', r.status_code)
    return r, cookies


def get_current_vul_count(page):
    '''获取当前漏洞总数'''
    soup = BeautifulSoup(page, 'html.parser')
    # 拿到表足的所有span
    pages_div = soup.find('div', class_='pages clearfix')
    if pages_div:
        spans = pages_div.find_all('span')
        pattern = r'共\s*(\d+)\s*条'
        # 提取数字
        for span in spans:
            count = re.search(pattern, span.text)
            if count:
                return int(count.group(1))
    else:
        return None


def get_cnvd(page) -> list[str]:
    '''获取table下的所有cnvd'''
    result_list = []
    soup = BeautifulSoup(page, 'html.parser')
    table = soup.find('table', class_='tlist')
    if table:
        trs = table.find('tbody').find_all('tr')
        for tr in trs:
            # 获取a标签的href
            a = tr.find('a')
            if a:
                result_list.append(a['href'].replace('/flaw/show/', ''))
            else:
                raise Exception('未找到a标签或a标签href值为空')
    return result_list


def write_to_file(data: list):
    with open('cnvd.txt', 'a', encoding='utf-8') as f:
        for d in data:
            f.write(f'{d}\n')
        f.flush()


def main():
    proxy = {
        "http": "http://192.168.110.27:7890",
        "https": "http://192.168.110.27:7890",
    }
    size = 100
    page_count = 100
    with open('page.json', 'r', encoding='utf-8') as f:
        page = json.load(f)
        page = page['page']
    cookies = {}
    params = {'flag': True, 'numPerPage': size, 'offset': page * size, 'max': size}
    r1, cookies = cnvd_jsl("https://www.cnvd.org.cn/flaw/list", params=params, proxies=proxy, cookies=cookies)
    while r1.text.find(';location.href=location.pathname+location.search') != -1:
        # 页面不对，重新请求
        next_time = random.randint(3, 8)
        print(f'[{get_current_time()}][+]初始化中，等待{next_time}秒后重定向页面')
        sleep(next_time)
        r1, _ = cnvd_jsl("https://www.cnvd.org.cn/flaw/list", params=params, proxies=proxy, cookies=cookies)
    # print('循环外查询到页面内容，html为：' , r1.text[:50])
    # print('循环外当前cookie是：',cookies,'\n')
    # 获取漏洞总数
    vul_count = get_current_vul_count(r1.content)
    if not vul_count:
        next_time = random.randint(3, 8)
        print(f'[{get_current_time()}][!]获取漏洞总数失败，等待{next_time}秒后重试')
        return main()
    print(f'[{get_current_time()}][+] 获取到漏洞总数：{vul_count}')
    # 每页100 先用总数除以100 然后+1得到循环次数 每次请求页面设置offset为100的倍数
    print(f'[{get_current_time()}][+] cookie设置完成，开始获取漏洞信息')
    for i in range(page - 1, page + page_count - 1):
        next_time = random.randint(5, 10)
        print(f'[{get_current_time()}][+] 等待{next_time}秒后进行下一次cnvd获取')
        sleep(next_time)
        print(f'[{get_current_time()}][+] 开始获取第{i + 1}页，每页{size}个漏洞')
        params = {'flag': True, 'numPerPage': size, 'offset': i * size, 'max': size}
        r1, _ = cnvd_jsl("https://www.cnvd.org.cn/flaw/list", params=params, proxies=proxy, cookies=cookies)
        # print('循环内查询到页面内容，html为：' , r1.text[:50])
        while r1.text.find(';location.href=location.pathname+location.search') != -1:
            # 页面不对，重新请求
            retry_time = random.randint(3, 8)
            print(f'[{get_current_time()}][!] 等待{retry_time}秒后重定向页面')
            sleep(retry_time)
            r1, _ = cnvd_jsl("https://www.cnvd.org.cn/flaw/list", params=params, proxies=proxy, cookies=cookies)
            # print('循环内<再次>查询到页面内容，html为：' , r1.text[:50])
        if '<table class="tlist">' in r1.text:
            # 不能这样写 因为会把右边“热点漏洞”一起获取
            # cnvd_ids = re.findall(r'"/flaw/show/(.*?)"', r1.text)
            # 两种解决方法
            # 1、去掉每次cnvd_ids最后10个
            # 2、增加判断条件 √
            cnvd_ids = get_cnvd(r1.content)
            print(f'[{get_current_time()}][+] 获取到漏洞{len(cnvd_ids)}个，原始数据为：\n{cnvd_ids}')
            write_to_file(cnvd_ids)
    else:
        print(f'[{get_current_time()}][+] 获取完毕')
        with open('page.json', 'w', encoding='utf-8') as f:
            page = {'page': page + page_count}
            json.dump(page, f)


if __name__ == '__main__':
    main()
