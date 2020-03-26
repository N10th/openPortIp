import re
import time
import requests
import multiprocessing
from bs4 import BeautifulSoup

#40x状态码配置
focus_status_code = [400,401,403,404]
#非HTTP服务端口配置
special_port = [21,22,23,445,110,69,3389,63389,13389,1521,3306,1433,27017,6379,11211,5432,5551,5432]
database_port_conf = {1521: 'Oracle', 3306: 'MySQL', 1433: 'SQLServer', 27017: 'MongoDB', 6379: 'Redis', 
11211: 'memcached', 5432: ['psotgreSQL','greenplum'], 5551: 'vertica'}
#读取的mass扫描后的路径文件名配置
masscan_result = './masscan_result.txt'
#UA头
headers = {'User-Agent':'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.89 Safari/537.36'}


pattern = re.compile('Discovered open port (\d+)/tcp on (\d+.\d+.\d+.\d+)')
with open(masscan_result,'r+') as file:
    file = file.readlines()
    number_lines = len(file)


def scrapy(i):
    # q.put(file)
    IP_Port = pattern.findall(file[i])
    ip = IP_Port[0][1]
    port = IP_Port[0][0]
    if int(port) not in special_port:
        if port == '443':
            url = 'https://' + ip
        else:
            url = 'http://' + ip + ':' + port
        try:
            res = requests.get(url,timeout=3,headers=headers)
            if res.status_code == 200:
                res.encoding = 'utf-8'
                soup = BeautifulSoup(res.text, 'lxml')
                title = soup.title.text
                # print(title)
                print(url + '---------------------->' + title)
                page_200 = url+title+'\n'
                with open('page_200.txt','a+') as url_200:
                    url_200.write(page_200)
            if res.status_code == 301 or 302:
                print(url + '       【状态码：】',res.status_code)
                with open('page_30x.txt','a+') as url_30x:
                    url_30x.write(url + '\n')
            if res.status_code in focus_status_code:
                print(url + '       【状态码：】',res.status_code)
                with open('page_40x.txt','a+') as url_40x:
                    url_40x.write(url + '【状态码：】' + str(res.status_code) + '\n')
        except requests.exceptions.ConnectionError:
            print(url+' 无法连接')
            with open('page_CannotOpen.txt','a+') as url_CannotOpen:
                url_CannotOpen.write(url + '\n')
        except requests.exceptions.ReadTimeout:
            print(url+' 连接超时')
            with open('page_TimeOut.txt','a+') as url_timeout:
                url_timeout.write(url + '\n')
        except AttributeError:
            print(url+' 我们的ip可能在服务器黑名单')
            with open('page_BlackList.txt','a+') as url_black:
                url_black.write(url + '\n')
        except UnicodeEncodeError:
            page_200 = url+'\n'
            with open('page_200.txt','a+') as url_200:
                    url_200.write(page_200)
    else:
        print('---------->非HTTP服务端口：',port)
        if int(port) in list(database_port_conf.keys()):
            service = '数据库类型：' + str(database_port_conf[int(port)])
        else:
            service = ''
        special_IP = ip + '开放端口：' + port + service
        with open('special_port.txt','a+') as nonHTTP:
            nonHTTP.write(special_IP + '\n')



if __name__ == '__main__':
    pool = multiprocessing.Pool(processes=16)
    result = pool.map(scrapy,range(len(file)))
    print('检测完成！')  
