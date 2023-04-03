电信IPTV组拔及回放地址获取
===
#项目功能 
- 基于python3的数据抓取 
- 通过IPTV线路获取电信IPTV组拔地址以及回放的地址  
- 生成txt及m3u文件
#使用范围 
- 成都电信IPTV
- 其他地区及其他运营商估计大同小异（未测试）
#使用前提 
- 必须获取到IPTV接口的IP地址
- 必须获取到秘钥key
- 必须获取到UserID mac STBID ip STBType STBVersion UserAgent信息
```python
key = ''
UserID = ''
mac =  ''
STBID = ''
ip = ''
STBType = ''
STBVersion = ''
UserAgent = ''
```
# 使用方法 
```
python3 get_iptv_channels
```
# 其他问题
## 参数获取
UserID mac STBID ip STBType STBVersion UserAgent信息可由抓包以及查看机顶盒背面获得
## 秘钥获取 
抓包获取到Authenticator后，配置Authenticator的值
```python
Authenticator = 'XXX'
```
通过本程序中的find_key()方法测试获得。

#### 另：业余选手，请多关照