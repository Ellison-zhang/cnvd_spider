import re
import os
import json
import html
import execjs
import requests
import hashlib
import traceback 

requests.packages.urllib3.disable_warnings()

def get_jsl_clearance_s(jsl_data):
    chars = len(jsl_data['chars'])
    for i in range(chars):
        for j in range(chars):
            jsl_clearance_s = jsl_data['bts'][0] + jsl_data['chars'][i:(i + 1)] + jsl_data['chars'][j:(j + 1)] + jsl_data['bts'][1]
            if getattr(hashlib,jsl_data['ha'])(jsl_clearance_s.encode('utf-8')).hexdigest() == jsl_data['ct']:
                return jsl_clearance_s
            
def cnvd_jsl(url,params={},proxies={},cookies={}):

    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.178 Safari/537.36',}
    r = requests.get(url,params=params, headers=headers,cookies=cookies,proxies=proxies, verify=False)
    if r.status_code == 521:
        if re.findall('document.cookie=(.*?);location.',r.text):
            cookies = r.cookies.get_dict()
            __jsl_clearance_s = execjs.eval(re.findall('document.cookie=(.*?);location.',r.text)[0]).split(';')[0].split('=')[1]
            cookies['__jsl_clearance_s'] = __jsl_clearance_s
            r = requests.get(url,params=params,cookies=cookies,headers=headers,proxies=proxies,verify=False,)
            jsl_data = json.loads(re.findall('go\((\{.*?\})\)',r.text)[0])       
            cookies[jsl_data['tn']] = get_jsl_clearance_s(jsl_data)
            r = requests.get(url,params=params,cookies=cookies,headers=headers,proxies=proxies,verify=False,)
        if re.findall('go\((\{.*?\})\)',r.text):
            jsl_data = json.loads(re.findall('go\((\{.*?\})\)',r.text)[0])       
            cookies[jsl_data['tn']] = get_jsl_clearance_s(jsl_data)
            r = requests.get(url,params=params,cookies=cookies,headers=headers,proxies=proxies,verify=False,)
    return r,cookies
import time
def replace_list(data_list: list) -> list:
    result_list = []
    for data in data_list:
        data = data.strip()
        if data == "" or data is None:
            pass
        else:
            result_list.append(data)
    return result_list
def get_data(data_html, url):
    day = time.strftime("%Y-%m-%d %H:%M:%S")
    spider_time = int(time.time() * 1000)
    item = {
        "parse_time": day,
        "path": url,
        "spider_time": spider_time
    }
    name = None
    cnvd = None
    publish = None
    severity = None
    cvss_vector = None
    product = None
    description = None
    flaw_type = None
    reference = None
    solution = None
    patch = None
    verify = None
    submit_time = None
    open_time = None
    update_time = None
    cve = None
    name_list = data_html.xpath('//div[@class="blkContainerSblk"]//h1/text()')

    # 有cve和没有cve的html标签是不一样的
    if name_list:
        name = name_list[0]
    item["name"] = name


    #
    cnvd_list = data_html.xpath('//tbody//td[contains(text(),"CNVD-ID")]/following-sibling::td//text()')
    cnvd_list = replace_list(cnvd_list)
    if cnvd_list:
        cnvd = cnvd_list[0]
    item["cnvd"] = cnvd

    publish_list = data_html.xpath('//tbody//td[contains(text(),"公开日期")]/following-sibling::td//text()')
    publish_list = replace_list(publish_list)
    if publish_list:
        publish = publish_list[0]
    item["publish"] = publish
    # 危害级别
    severity_and_cvss_list = data_html.xpath('//tbody//td[contains(text(),"危害级别")]/following-sibling::td//text()')
    severity_and_cvss_list = replace_list(severity_and_cvss_list)
    if severity_and_cvss_list:
        severity = severity_and_cvss_list[0][0]
        try:
            cvss_vector = severity_and_cvss_list[1]
        except:
            pass

    item["severity"] = severity
    item["cvss_vector"] = cvss_vector

    product_list = data_html.xpath('//tbody//td[contains(text(),"影响产品")]/following-sibling::td//text()')
    product_list = replace_list(product_list)
    if product_list:
        product = product_list
    item["product"] = json.dumps(product)

    # 另一套脚本
    cve_list = data_html.xpath('//td[contains(text(),"CVE ID")]/following-sibling::td//text()')

    cve_list = replace_list(cve_list)
    if cve_list:
        cve = cve_list[0]
        cve = cve.strip()
    item["cve"] = cve

    description_list = data_html.xpath('//td[contains(text(),"漏洞描述")]/following-sibling::td//text()')
    description_list = replace_list(description_list)
    if description_list:
        description = "".join(description_list)
        description = description.strip()
    item["description"] = description

    # 漏洞类型
    flaw_type_list = data_html.xpath('//tbody//td[contains(text(),"漏洞类型")]/following-sibling::td//text()')
    flaw_type_list = replace_list(flaw_type_list)
    if flaw_type_list:
        flaw_type = flaw_type_list[0]
        flaw_type = flaw_type.strip()
    item["flaw_type"] = flaw_type

    #  注意一下可能有多个的,以json格式存储
    reference_list = data_html.xpath('//tbody//td[contains(text(),"参考链接")]/following-sibling::td//text()')
    reference_list = replace_list(reference_list)

    if reference_list:
        reference = "\n".join(reference_list)
        reference = reference.strip()
    item["reference"] = reference

    # 修复建议链接
    solution_list = data_html.xpath('//tbody//td[contains(text(),"漏洞解决方案")]/following-sibling::td//text()')
    solution_list = replace_list(solution_list)
    if solution_list:
        solution = "\n".join(solution_list)
        if solution.strip().startswith("http"):
            solution = solution_list[0]
            solution = solution.strip()
            solution = "厂商已发布了漏洞修复程序，请及时关注更新：" + solution
    item["solution"] = solution

    # 补丁名称
    patch_list = data_html.xpath('//tbody//td[contains(text(),"厂商补丁")]/following-sibling::td//text()')
    patch_list = replace_list(patch_list)
    if patch_list:
        patch = patch_list[0]
        patch = patch.strip()
    item["patch"] = patch

    # 验证信息
    verify_list = data_html.xpath('//tbody//td[contains(text(),"验证信息")]/following-sibling::td//text()')
    verify_list = replace_list(verify_list)
    if verify_list:
        verify = verify_list[0]
        verify = verify.strip()

    item["verify"] = verify

    # 报送时间
    submit_time_list = data_html.xpath('//tbody//td[contains(text(),"报送时间")]/following-sibling::td//text()')
    submit_time_list = replace_list(submit_time_list)
    if submit_time_list:
        submit_time = submit_time_list[0]
    item["submit_time"] = submit_time

    # 公开时间
    open_time_list = data_html.xpath('//td[contains(text(),"收录时间")]/following-sibling::td//text()')
    open_time_list = replace_list(open_time_list)
    if open_time_list:
        open_time = open_time_list[0]
    item["open_time"] = open_time

    update_time_list = data_html.xpath('//tbody/tr[13]/td[2]//text()')
    update_time_list = replace_list(update_time_list)
    if update_time_list:
        update_time = update_time_list[0]
    item["update_time"] = update_time
        # data_summary这个得生成
    summary_item = {}
    for k, v in item.items():
        if v is None:
            summary_item[f"{k}"] = ""
        else:
            summary_item[f"{k}"] = v
    data_str = summary_item["path"] + summary_item["cnvd"] + summary_item["cve"] + summary_item["name"] + \
               summary_item["severity"] + summary_item[
                   "product"] + summary_item["flaw_type"] + summary_item["submit_time"] + summary_item["publish"] + \
               summary_item["reference"] + summary_item[
                   "solution"] + summary_item["patch"] + summary_item["description"]
    data_summary = hashlib.md5(data_str.encode("utf-8")).hexdigest()
    item["data_summary"] = data_summary
    
    return item
def parse_data(data):
    for k in data:
        text = data[k]
        # 实体编码解码
        text = html.unescape(text)
        if k == '危害级别':
            text = re.search('(高|中|低)',text).group(1) if re.search('(高|中|低)',text) else ''
        if k == '参考链接':
            text = '\n'.join(re.findall('href="(.*?)"',text))
        if k == '厂商补丁':
            text = "https://www.cnvd.org.cn"+ re.search('"(/patchInfo/show/\d+)"',text).group(1) if re.search('"(/patchInfo/show/\d+)"',text) else ''
        if k == 'CVE ID':
            text = re.search('>(CVE-\d+-\d+)\s*<',text).group(1) if re.search('>(CVE-\d+-\d+)\s*<',text) else ''

        # <br/>
        text = text.replace('<br/>','\n')
        # \r\n
        text = re.sub('\r\n','\n',text)
        text = re.sub('\n+','\n',text)
        text = text.strip()
        
        data[k] = text 
    return data

def main():
    # proxy = {
    #     "http": "http://192.168.110.27:7890",
    #     "https": "http://192.168.110.27:7890",
    # }
    cookies = {}
    page = 0
    size = 50
    params = {'flag':True,'numPerPage':size,'offset':page * size,'max':size}
    r1, cookies = cnvd_jsl("https://www.cnvd.org.cn/flaw/list",params=params,proxies=proxy,cookies=cookies)
    if '<table class="tlist">' in r1.text:
        cvnd_ids = re.findall(r'"/flaw/show/(.*?)"', r1.text)
        print(f'{len(cvnd_ids)=}')
        for cvnd_id in cvnd_ids:
            try:
                r, cookies = cnvd_jsl(f'https://www.cnvd.org.cn/flaw/show/{cvnd_id}',params={},proxies={},cookies=cookies)
                if r.status_code == 200:
                    os.makedirs('CNVD',exist_ok=True)
                    item = get_data(r.text, f'https://www.cnvd.org.cn/flaw/show/{cvnd_id}')
                    with open(f"CNVD/{cvnd_id}.json", "w",encoding='utf8') as f:
                        json.dump(item, f, ensure_ascii=False, indent=4)
                    print(f'{cvnd_id}')
                else:
                    print(f'{cvnd_id=} error')
                    break
            except:
                traceback.print_exc()
                pass

                # print(f'{cvnd_id=} continue')
    else:
        print(f'list error')

if __name__ == '__main__':
    main()