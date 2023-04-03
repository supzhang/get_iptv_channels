#coding:utf-8
'''
name:成都电信IPTV电视频道组播及回放列表获取
author:业余选手-老张
仅供测试研究使用！

使用前提：
1、必须获取到IPTV接口的IP地址
2、必须获取到秘钥
3、必须抓包获取到UserID mac STBID ip STBType STBVersion UserAgent信息
使用方法
1、在上述前提条件下直接运行get_channel()
2、如果没有加密Authenticator的key，可以抓包获取Authenticator，然后使用find_key()方法获取到key
获取流程
获取token--获取session--请求频道列表--处理后保存

此方法只在成都电信测试通过，其他其他地区电信应该大同小异，
可能只需要更改  “182.138.3.142:8082”为当地的地址（抓包获取到的第一条HTTP请求地址）即可。---未测试
其他运营商未测试，请自行测试。
'''

import requests,re,time,random,os
from Crypto.Cipher import DES3
from urllib.parse import urlparse
#################################下列信息需要自行补充#####################################################
key = ''  #8位数字，加密Authenticator的秘钥，每个机顶盒可能都不同，获取频道列表必须使用
#下面的信息全部都可以由抓包获取到USERID,mac，stbid(mac,stbid机顶盒背面查询），ip(当前IPTV网络的IP地址），
UserID = ''
mac =  ''
STBID = ''
ip = '10.10.10.10'  #随便一个IPTV地址即可，不检测
STBType = ''
STBVersion = ''
UserAgent = ''
#如要获取Authenticator加密的秘钥，请填写Authenticator，并使用find_key(Authenticator)测试key值
Authenticator = ''
######################################################################################################
save_dir_txt = os.getcwd()+'/sctv.txt'  #频道信息保存目录
save_dir_m3u = os.getcwd()+'/sctv.m3u'  #生成m3u文件

date_now = time.strftime('%Y-%m-%d %X',time.localtime())
BS = DES3.block_size
def pad(s):
    p =  s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
    return p
def unpad(s):
    p =  s[0:-ord(s[-1])]
    return p
class prpcrypt():
    def __init__(self,key):
        self.key = key + '0'*16
        self.mode = DES3.MODE_ECB
    def encrypt(self, text): #加密文本字符串,返回 HEX文本
        text = pad(text)
        cryptor = DES3.new(self.key, self.mode)
        x = len(text) % 8
        if x != 0:
            text = text + '\0' * (8 - x)
        self.ciphertext = cryptor.encrypt(text)
        return self.ciphertext.hex()
    def decrypt(self, text):#需要解密的字符串，字符串为十六进制的字符串  如"a34f3e3583"....
        try:
            cryptor = DES3.new(self.key, self.mode)
        except Exception as e:
            if 'degenerates' in str(e):
                raisetxt = 'if key_out[:8] == key_out[8:16] or key_out[-16:-8] == key_out[-8:]:\nraise ValueError("Triple DES key degenerates to single DES")'
                print('请将调用的DES3.py文件里adjust_key_parity方法中的：%s  注释掉'%raisetxt)
            else:
                print(e)
        de_text = bytes.fromhex(text)
        plain_text = cryptor.decrypt(de_text)
        return plain_text.replace(b'\x08',b'').decode('utf-8')  #返回 string,不需要再做处理
#获取token,通过此token来获取session
def get_token():
    url = 'http://182.138.3.142:8082/EDS/jsp/AuthenticationURL?UserID=%s&Action=Login'%(UserID)
    headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'User-Agent': UserAgent,
            'X-Requested-With': 'com.android.smart.terminal.iptv',
    }
    res = requests.get(url,headers = headers,timeout = 10)
    host = urlparse(res.url).netloc

    url = 'http://%s/EPG/jsp/authLoginHWCTC.jsp'%host
    headers = {
                'User-Agent': UserAgent,
                'Content-Type': 'application/x-www-form-urlencoded',
                'Referer': 'http://%s/EPG/jsp/AuthenticationURL?UserID=%s&Action=Login'%(host,UserID),
                'X-Requested-With': 'com.android.smart.terminal.iptv',
                }
    data = {
            'UserID':UserID,
            'VIP':''
    }
    res = requests.post(url,headers = headers,data = data,timeout = 10)
    res.encoding = 'utf-8'
    txt = res.text
    r_enc = re.search('EncryptToken \= \"(.+?)\";.+?userToken\.value \= \"(.+?)\"',txt,re.DOTALL)
    EncryptToken = r_enc.group(1)
    userToken = r_enc.group(2)
    ret = {
        'host':host,
        'token':EncryptToken,
    }
    ret = [host,EncryptToken]
    return ret
#测试秘钥，如果已经抓包获取到了Authoritor，可以使用此方法获取秘钥，可能会获取到很多个，任何一个均可正常使用
def find_key(Authenticator):
    keys = []
    while len(Authenticator) < 10:
        Authenticator = input('未配置Authenticator，请输入正确的Authenticator的值：')
    print('开始测试00000000-99999999所有八位数字')
    for x in range(100000000):
        key = str('%08d'%x)
        if x % 500000 == 0:
            print('已经搜索至：-- %s -- '%key)
        pc = prpcrypt('%s'%key)
        try:
            ee = pc.decrypt(Authenticator)
            infos = ee.split('$')
            infotxt = '  随机数:%s\n  TOKEN:%s\n  USERID:%s\n  STBID:%s\n  ip:%s\n  mac:%s\n  运营商:%s'%(infos[0],infos[1],infos[2],infos[3],infos[4],infos[5],infos[7]) if len(infos)>7 else ''
            printtxt = '找到key:%s,解密后为:%s\n%s'%(x,ee,infotxt)
            print(printtxt)
            keys.append(key)
        except Exception as e:
            pass

    with open(os.getcwd() +'/key.txt','w') as f:
        line = '%s\n共找到KEY：%s个,分别为：%s\n解密信息为:%s\n详情：%s'%(date_now,len(keys),','.join(keys),str(ee),infotxt)
        f.write(line)
        f.flush()
    print('解密完成！共查找到 %s 个密钥，分别为：%s'%(len(keys),keys))#
#获取IPTV的session,后面的请求全部需要提交此session
def getSession(key):
    n = 0
    while n < 5: #重试
        try:
            host,token = get_token()
            url = 'http://%s/EPG/jsp/ValidAuthenticationHWCTC.jsp'%host
            rand = ''.join(random.sample('123456789',8))
            session_ref = '%s$%s$%s$%s$%s$%s$$CTC'%(rand,token,UserID,STBID,ip,mac) #    随机8位数 +$+TOKEN +$+USERID +$+STBID +$ip +$+mac +$$CTC
            Authenticator = prpcrypt(key).encrypt(session_ref)
            headers = {
                'User-Agent': UserAgent,
                'Content-Type': 'application/x-www-form-urlencoded',
                'Referer': 'http://%s/EPG/jsp/authLoginHWCTC.jsp'%host,
            }
            data = {
                'UserID': UserID,
                'Lang': '',
                'SupportHD': '1',
                'NetUserID': '',
                'Authenticator': Authenticator,
                'STBType': STBType,
                'STBVersion': STBVersion,
                'conntype': '',
                'STBID': STBID,
                'templateName': '',
                'areaId': '',
                'userToken': token,
                'userGroupId': '',
                'productPackageId': '',
                'mac': mac,
                'UserField': '',
                'SoftwareVersion': '',
                'IsSmartStb': 'undefined',
                'desktopId': 'undefined',
                'stbmaker': '',
                'VIP': '',
            }
            res = requests.post(url,headers = headers,data = data,timeout = 10)
            res.encoding = 'utf-8'
            re_token = re.search('UserToken\" value\=\"(.+?)\".+?stbid\" value\=\"(.+?)\"',res.text,re.DOTALL)
            user_token = re_token.group(1)
            stbid_ = re_token.group(2)
            ret = [host,res.cookies,user_token,stbid_]
            return ret
        except Exception as e:
            n += 1
            time.sleep(3)
            print(e)
def get_channel_list(host,usertoken,cookies,stbid):
    url = 'http://%s/EPG/jsp/getchannellistHWCTC.jsp' % host
    data = {
            'conntype':'',
            'UserToken':usertoken,
            'tempKey':'',
            'stbid':stbid,
            'SupportHD':'1',
            'UserID':UserID,
            'Lang':'1'
            }
    n = 1 #重试次数
    while n < 5:
        try:
            res = requests.post(url,data = data,cookies = cookies)
            break
        except Exception as e:
            print('获取成都电信频道列表 失败:%s'%e)
            n += 1
            time.sleep(3)
    res.encoding = 'utf-8'
    all_channels = re.findall('ChannelID\=\"(\d+)\",ChannelName\=\"(.+?)\",UserChannelID\=\"\d+\",ChannelURL=\"igmp://(.+?)\".+?TimeShift\=\"(\d+)\",TimeShiftLength\=\"(\d+)\".+?,TimeShiftURL\=\"(.+?)\"',res.text)#
    channels = []
    for channel in all_channels:
        channel = list(channel)
        url_re = re.match('(.+?\.smil)?', channel[5])
        channel[5] = url_re.group(1)
        channels.append(channel)
    print('共获取频道数量为：%s,文件存储于目录的:%s及%s.'%(len(channels),save_dir_txt,save_dir_m3u))
    return channels
def get_channels(key):
    print('%s 开始运行'%date_now)
    print('仅供测试使用，用于成都电信IPTV，其他地区请自行更改get_token中的url')
    while len(key) != 8:
        key = input('请输入8位数的key:')
        try:
            host, cookies, usertoken, stbid = getSession(key)
            if len(cookies['JSESSIONID']) < 5:
                print('未获取到SESSION，请检查：key、MAC、stbid、UserID等已正确配置！')
                return
        except Exception as e:
            print('获取SESSION失败,请检查网络！:%s'%e)
            return
        print('已经获取到session:\nusertoken:%s,\nJSESSIONID:%s'%(usertoken,cookies['JSESSIONID']))
        channels = get_channel_list(host,usertoken,cookies,stbid)
        ftxt = open(save_dir_txt,'w')
        fm3u = open(save_dir_m3u,'w')
        m3uline1 = '#EXTM3U\n'
        fm3u.write(m3uline1)
        ftxt.write(date_now)
        ftxt.write('\n组播地址列表--by:老张\n本次共共获取频道数量：%s\n可直接将以下信息复制到EXCEL\n'%(len(channels)))
        ftxt.write('%s\t%s\t%s\t%s\n'%('频道ID','频道名称','组拔地址','回放地址'))
        for channel in channels:
            m3uline = '#EXTINF:-1 ,%s\nrtp://%s\n'%(channel[1],channel[2])
            txtline = '%s\t%s\t%s\t%s\n'%(channel[0],channel[1],channel[2],channel[5])
            ftxt.write(txtline)
            fm3u.write(m3uline)
        ftxt.close()
        fm3u.close()
#get_channels(key)
find_key(Authenticator)