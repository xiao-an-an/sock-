import logging
import select as sl
import socket
import struct
import time
from socketserver import StreamRequestHandler, ThreadingTCPServer
# from scapy_ssl_tls.ssl_tls import TLS
from scapy.layers.ssl_tls import TLSRecord
import time, threading

SOCKS_VERSION = 5
# 网站涉及到域名
# SNI为http2协议
H2_SNI = ['github.githubassets.com','assets.gitee.com','wkstatic.bdimg.com','bizapi.csdn.net']
# SNI为http1协议
H1_SNI=['github.com','gitee.com','wenku.baidu.com']

# gitee、wenku、github以及csdn新建页面网站模板，-1表示最大值，[特征最小值，特征最大值，特征SNI，特征上传方式]
all_temp = [[6150,6550, 'csdnimg.cn','csdn_upload_1'],[7000, 7300,'csdnimg.cn','csdn_upload_2'],[28500, -1,'github.com','github_new'], [75776, 79000,'github.githubassets.com','github_new'],[6534,6742,'wenku.baidu.com','wenku_upload'], [1700,1800,'wkstatic.bdimg.com','wenku_upload'],[16594,16930,'wenku.baidu.com','wenku_new'], [148800,152000,'wkstatic.bdimg.com','wenku_new'],[2485,2556,'bizapi.csdn.net'],[14800,15000,'gitee.com','gitee_new'],[15400,15600,'gitee.com','gitee_new'],[7986,8066,'gitee.com','gitee_new'] ,[27000,27400,'gitee.com','gitee_new'],[15770,15970,'gitee.com','gitee_upload'],[16310,16600,'gitee.com','gitee_upload'],[75776, 79000,'assets.gitee.com','gitee_upload']]  # 1

lock = threading.Lock()
# 当识别上传后，阻止用户访问一段时间，用来限制恶意用户访问 
limit_time=10
# 需要进行拦截的资源SNI的域名
all_flag={'github.githubassets.com':False,'bizapi.csdn.net':False,'assets.gitee.com':False,'wkstatic.bdimg.com':False,'gitee.com':False}
my_time={}
# doc资源加载与js等资源加载的最大时间差
TIME_INT = 15

class PageChecker():
    """
    资源模板检测
    """

    # 判断doc模板资源是否加载
    doc_flag={}
    # 初始化doc_flag 为True

    def __init__(self):
        """
        模板标志初始化
        """
        for line in all_temp:
            if len(line)>=4 and line[4] not in self.doc_flag:
                self.doc_flag[line[4]] = True
    #记录doc加载的时间
    time_dict={}
    #判断该tls大小是否符合模板
    def compare(self, obj, temp):
        '''大小比较'''
        if temp[1]<0:
            return temp[0] <= obj
        return temp[0] <= obj <= temp[1]
    # 判断是否匹配doc模板
    def set_True(self):
        """
        模板标志位初始化
        :return:
        """
        for key,value in self.doc_flag.items():
            if 'csdn' in key:
                self.doc_flag[key]=True
        return True
    # 判断doc是否满足模板范围
    def isdoc(self, obj,sni):
        """
        识别doc资源,并且将doc资源的标志位设置为false表示doc模板匹配成功，接下来一段时间内js或css等独有资源匹配成功，就表示用户在进行上传行为
        :param obj: tls大小
        :param sni: 域名
        :return: 是否符合模板值
        """
    	# wenku和github都是使用 h1 + h2 模板，其中h1不需要拦截，只需要识别，在一定时间内识别和拦截h2即可
        if sni in H1_SNI:
            for i in range(0, len(all_temp)):
                if all_temp[i][2]==sni:
                    if all_temp[i][3] == "wenku_upload":
                        if self.compare(obj, all_temp[i]):
                            self.doc_flag[all_temp[i][3]] = False
                            self.time_dict[all_temp[i][3]] = time.time()
                            return True
                    if all_temp[i][3] == "github_new":
                        if self.compare(obj, all_temp[i]):
                            self.doc_flag[all_temp[i][3]] = False
                            self.time_dict[all_temp[i][3]] = time.time()
                            return True

                    if all_temp[i][3] == "gitee_upload":
                        if self.compare(obj, all_temp[i]):
                            self.doc_flag[all_temp[i][3]] = False
                            self.time_dict[all_temp[i][3]] = time.time()
                            return True
                    if all_temp[i][3] == "gitee_new":
                        if self.compare(obj, all_temp[i]):
                            self.doc_flag[all_temp[i][3]] = False
                            self.time_dict[all_temp[i][3]] = time.time()
                            return True
                        else:

                            # gitee存在两个h1特征是相同的ip需要分开考虑
                            if self.doc_flag["gitee_new"] == False:
                                # TIME_INT 两个特征加载最大时间间隔
                                if time.time() - self.time_dict['gitee_new'] <= TIME_INT:
                                    if self.compare(obj, all_temp[i]):
                                        self.doc_flag['github_new'] = True
                                        return True
                                else:
                                    self.doc_flag['github_new'] = True

    # 判断是否匹配js模板
    def isobj(self, obj, sni):
        """
        识别js或css等独有资源，如果匹配成功，并且将doc资源的标志位设置为true，返回true，如果时间超时将doc资源的标志位设置为true，返回false
        :param obj: tls大小
        :param sni: 域名
        :return: 是否符合模板值
        """
        if sni == 'csdnimg.cn':
            for i in range(len(all_temp)):
                if all_temp[i][2] == sni:
                    if self.doc_flag[all_temp[i][3]]:
                        if self.compare(obj, all_temp[i]):
                            self.doc_flag[all_temp[i][3]] = False
                            return True

        elif sni == 'github.githubassets.com' or 'assets.gitee.com' or'wkstatic.bdimg.com':
            for i in range(0,len(all_temp)):
                if sni == all_temp[i][2]:
                    if self.doc_flag[all_temp[i][3]] == False:
                        if time.time()-self.time_dict[all_temp[i][3]]<=TIME_INT:
                            if self.compare(obj, all_temp[i]):
                                self.doc_flag[all_temp[i][3]] = True
                                return True
                        else:
                            self.doc_flag[all_temp[i][3]]=True
        # csdn 新建文件页面目前只使用一个js资源
        elif sni =='bizapi.csdn.net':
            for i in range(0, len(all_temp)):
                if sni == all_temp[i][2]:
                    if self.compare(obj, all_temp[i]):
                        return True


class SocksProxy(StreamRequestHandler):
    def handle(self):
        """
        处理socks代理传输过程中流量数据
        :return:
        """
        # print('Accepting connection from {}'.format(self.client_address))
        # 协商
        # 从客户端读取并解包两个字节的数据
        header = self.connection.recv(2)
        version, nmethods = struct.unpack("!BB", header)
        # 设置socks5协议，METHODS字段的数目大于0
        assert version == SOCKS_VERSION
        assert nmethods > 0
        # 接受支持的方法
        methods = self.get_available_methods(nmethods)
        # 无需认证
        if 0 not in set(methods):
            self.server.close_request(self.request)
            return
        # 发送协商响应数据包
        self.connection.sendall(struct.pack("!BB", SOCKS_VERSION, 0))
        # 请求
        version, cmd, _, address_type = struct.unpack("!BBBB", self.connection.recv(4))
        assert version == SOCKS_VERSION
        if address_type == 1:  # IPv4
            address = socket.inet_ntoa(self.connection.recv(4))
        elif address_type == 3:  # Domain name
            domain_length = self.connection.recv(1)[0]
            address = self.connection.recv(domain_length)
            # address = socket.gethostbyname(address.decode("UTF-8"))  # 将域名转化为IP，这一行可以去掉
        elif address_type == 4:  # IPv6
            addr_ip = self.connection.recv(16)
            address = socket.inet_ntop(socket.AF_INET6, addr_ip)
        else:
            self.server.close_request(self.request)
            return
        port = struct.unpack('!H', self.connection.recv(2))[0]
        # 响应，只支持CONNECT请求
        try:
            if cmd == 1:  # CONNECT
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.connect((address, port))
                bind_address = remote.getsockname()
                # print('Connected to {} {}'.format(address, port))
            else:
                self.server.close_request(self.request)
            addr = struct.unpack("!I", socket.inet_aton(bind_address[0]))[0]
            port = bind_address[1]
            # reply = struct.pack("!BBBBIH", SOCKS_VERSION, 0, 0, address_type, addr, port)
            # 注意：按照标准协议，返回的应该是对应的address_type，但是实际测试发现，当address_type=3，
            # 也就是说是域名类型时，会出现卡死情况，但是将address_type该为1，则不管是IP类型和域名类型都能正常运行
            reply = struct.pack("!BBBBIH", SOCKS_VERSION, 0, 0, 1, addr, port)
        except Exception as err:
            logging.error(err)
            # 响应拒绝连接的错误
            reply = self.generate_failed_reply(address_type, 5)
        self.connection.sendall(reply)

        try:
            # 建立连接成功，开始交换数据
            if reply[1] == 0 and cmd == 1:
                # 获取第一个客户端发送的包
                data0 = self.connection.recv(4096)
                if remote.send(data0) > 0:
                    sni = ''
                    # 如果客户端发送的Client_Hello包
                    global all_flag
                    global my_time
                    if len(data0) > 5 and data0[0] == 22 and data0[5] == 1:
                        try:
                            sni = bytes.decode(TLSRecord(data0)['TLSServerName'].data)
                        except Exception as err:
                            logging.error(err)
                    # 限制用户访问的时间
                    if all_flag[sni]:
                        if time.time()-my_time[sni]>limit_time:
                            all_flag[sni]=False
                    if sni in H1_SNI:
                        print('github传输')
                        # h1资源加载
                        self.h1_loop(self.connection, remote, sni)
                    elif sni in H2_SNI:
                    	# h2 资源加载
                        self.h2_loop2(self.connection, remote, sni)
                    elif sni == "csdnimg.cn" :
                        ## 两个h2资源模板，将第一个h2资源全部缓存，直到识别到第二个资源
                        self.h2_cache_loop(self.connection, remote, sni)
                    else:
                        # print('其他传输')
                        self.exchange_loop(self.connection, remote)
        except Exception as e:
            print(e)
        finally:
            print("error")
            self.server.close_request(self.request)

    def get_available_methods(self, n):
        methods = []
        for i in range(n):
            methods.append(ord(self.connection.recv(1)))
        return methods

    def generate_failed_reply(self, address_type, error_number):
        return struct.pack("!BBBBIH", SOCKS_VERSION, error_number, 0, address_type, 0, 0)

    def h1_loop(self, client, remote, sni):
        """
            计算h1协议tls大小,并且将其与doc模板进行匹配
            :param client: 用来处理sock与客户端通信
            :param remote: 用来处理sock与服务器通信
            :param sni: 域名
            :return:
        """

        objlen = 0
        while True:
            if all_flag[sni]:
                break
            r, w, e = sl.select([client, remote], [], [], 0.2)
            # 如果有浏览器发来的包
            if client in r:
                data = client.recv(5)
                tls_len = int.from_bytes(data[3:5], byteorder='big')
                if tls_len > 0:
                    data += client.recv(tls_len)
                    if data[0] == 23 and objlen > 0:
                        # print(objlen)
                        objlen = 0
                if remote.send(data) <= 0:
                    break
            # 如果有服务器发来的包
            if remote in r:
                # 获取前5个字节来读取tls类型和tls长度
                data = remote.recv(5)
                tls_len = int.from_bytes(data[3:5], byteorder='big')
                if tls_len > 0:
                    if data[0] == 23:
                        objlen += tls_len - 24
                        if (tls_len - 24) % 4096 != 0:
                            if checker.isdoc(objlen,sni):
                                #gitee使用两个h1的资源，并且都是相同的域名
                                if sni == "gitee.com" and checker.doc_flag["gitee_new"] == True:
                                    all_flag[sni]=True
                                    my_time[sni]=time.time()
                                    #将最后一个tls包丢弃
                                    break
                        remain_n = tls_len
                        while remain_n > 0:
                            tmp = remote.recv(remain_n)
                            remain_n -= len(tmp)
                            data += tmp
                        # 累加tls记录大小至指定资源
                    else:
                        data += remote.recv(tls_len)
                if client.send(data) <= 0:
                    break
        # pass

    #通过延时禁用多路复用
    def h2_loop2(self, client, remote, sni):
        """

            通过延时阻止多路复用，计算h2协议tls大小,并且将其与js、css等独有资源模板进行匹配
            只需要拦截一个h2资源
            :param client: 用来处理sock与客户端通信
            :param remote: 用来处理sock与服务器通信
            :param sni: 域名
            :return:
        """
        # 阻塞多路复用
        while True:
            if all_flag[sni]:
                break
            r, w, e = sl.select([client], [], [], 0.2)
            # 如果有浏览器发来的包
            if client in r:
                # 获取前5个字节来读取tls类型和tls长度
                data = client.recv(5)
                tls_len = int.from_bytes(data[3:5], byteorder='big')
                if tls_len > 0:
                    data += client.recv(tls_len)
                    # if data[0] == 23 and objlen > 0 and tls_len > 30:
                    #     objlen = 0
                if len(data) > 0 and remote.send(data) <= 0:
                    break
            r, w, e = sl.select([remote], [], [], 0.4)
            objlen = 0
            cache = ''
            while remote in r:
                # 获取前5个字节来读取tls类型和tls长度

                if len(cache) > 0:
                    if client.send(cache) <= 0:
                        return
                    cache = ''
                data = remote.recv(5)
                tls_len = int.from_bytes(data[3:5], byteorder='big')
                if tls_len > 0:
                    if tls_len > 30 and data[0] == 23:
                        # 加密算法填充值为24 ，不同加密算法填充差别不大，默认都取24
                        objlen += tls_len - 24
                    remain_n = tls_len
                    while remain_n > 0:
                        tmp = remote.recv(remain_n)
                        remain_n -= len(tmp)
                        data += tmp
                        # 累加tls记录大小至指定资源
                cache = data
                # 0.3秒内未收到服务器的包表示传输完成
                r, w, e = sl.select([remote], [], [], 0.3)
            if objlen > 0 and checker.isobj(objlen, sni):

                # 进行拦截
                all_flag[sni] = True
                my_time[sni] = time.time()

                break
            if len(cache) > 0:
                if client.send(cache) <= 0:
                    return
                cache = ''
    #缓存前一个h2资源的数据包
    def h2_cache_loop(self, client, remote, sni):
        """
            基本功能和h2_loop一样，该函数主要针对要拦截两个h2特征的情况
            使用两个连续h2特征，需要将前一个h2特征进行缓存，直到下一个h2特征匹配，将两个特征进行拦截，否则进行放行
            :param client: 用来处理sock与客户端通信
            :param remote: 用来处理sock与服务器通信
            :param sni: 域名
            :return:
        """
        # 阻塞多路复用
        global all_flag
        global my_time

        # 两个h2模板，flag为True表示，满足第一个h2模板值
        flag=False
        # next_cache 和 cache_last  表示完整资源大小，cache_last表示最后一个包大小
        next_cache=[]
        cache_last=''
        while True:
            if all_flag[sni]:
                break
            r, w, e = sl.select([client], [], [], 0.2)
            # 如果有浏览器发来的包
            if client in r:
                # 获取前5个字节来读取tls类型和tls长度
                data = client.recv(5)
                tls_len = int.from_bytes(data[3:5], byteorder='big')
                if tls_len > 0:
                    data += client.recv(tls_len)
                if len(data) > 0 and remote.send(data) <= 0:
                    break
            r, w, e = sl.select([remote], [], [], 0.3)
            objlen = 0
            cache = ''
            while remote in r:
                if flag is not True:
                    if len(cache) > 0:
                        if client.send(cache) <= 0:
                            return
                        cache = ''
                else:
                     # 缓存第一个资源传输值
                    if len(cache)>0:
                        next_cache.append(cache)
                    cache=''
                # 获取前5个字节来读取tls类型和tls长度
                data = remote.recv(5)
                tls_len = int.from_bytes(data[3:5], byteorder='big')
                if tls_len > 0:
                    if tls_len > 30 and data[0] == 23:
                        # -24 由于加密算法的填充大小，不同的加密算法填充大小不一样，由于我们使用的模板范围偏大，统一取24能有好效果
                        objlen += tls_len - 24
                    remain_n = tls_len
                    while remain_n > 0:
                        tmp = remote.recv(remain_n)
                        remain_n -= len(tmp)
                        data += tmp
                        # 累加tls记录大小至指定资源
                cache = data
                r, w, e = sl.select([remote], [], [], 0.3)
            if objlen > 0 and checker.isobj(objlen, sni):

                if flag:
                    # 进行拦截，识别到第二个JS资源
                    checker.set_True()
                    flag = False
                    # 清空缓存数据包和最后一个数据包
                    next_cache = []
                    cache_last = ''
                    cache=''
                    all_flag[sni]=True
                    my_time=time.time()
                    break
                else:
                    #将识别到的第一个资源进行缓存
                    flag=True
                    #将最后一个数据包大小缓存
                    cache_last=cache
                    cache=''
                    continue
            if flag:
                # 释放不满足模板的缓存的第一个资源
                if len(next_cache) > 0:
                    # 释放不满足模板的资源
                    for ccc in next_cache:
                        
                        if client.send(ccc) <= 0:
                            return
                if client.send(cache_last) <= 0:
                    return
                lock.acquire()
                # 标志位重置
                checker.set_True()
                lock.release()
                flag=False
                next_cache=[]
                cache_last=''
            # 两个特征都不满足直接释放
            if len(cache) > 0:
                if client.send(cache) <= 0:
                    return
                cache = ''
    def exchange_loop(self, client, remote):
        """
        处理非模板sni流量
        :param client:
        :param remote:
        :return:
        """
        while True:
            # 等待数据
            r, w, e = sl.select([client, remote], [], [], 0.1)
            try:
                if client in r:
                    data = client.recv(4096)
                    if remote.send(data) <= 0:
                        break
                if remote in r:
                    data = remote.recv(4096)
                    if client.send(data) <= 0:
                        break
            except Exception:
                break
if __name__ == '__main__':
    # 使用socketserver库的多线程服务器ThreadingTCPServer启动代理
    with ThreadingTCPServer(('127.0.0.1', 5443), SocksProxy) as server:
        checker = PageChecker()
        server.serve_forever()