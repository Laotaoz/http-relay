## HTTP-Relay
Implement relay for HTTP access. 为HTTP访问实现中继.

------
### 特性 Features
- [x] 加密请求主机名
- [x] 使用Google Authenticator实现时间控制, 防止重发
- [x] 支持HTTPS
- [x] 支持HTTP代理

### 主要参数说明
|参数名称|建议值|备注|
|-|-|-|
|global.google2fa.secret|生成|防止重放攻击的密钥|
|global.google2fa.time|10|生成的code有效时间|
|global.privateKey|生成|SM2算法私钥 sm2.generateKeyPairHex()|
|global.privateKey|生成|SM2算法公钥 sm2.generateKeyPairHex()|
|client.proxyPort|生成|HTTP代理端口|
|server.address|无|运行relay-server的IPv4地址|
|server.cert.crt|无|Base64的HTTPS证书 通常为自签名生成|
|server.cert.key|无|Base64的HTTPS私钥 通常为自签名生成|
|server.httpPort|生成|运行relay-server的http协议端口号|
|server.httpsPort|生成|运行relay-server的https协议端口号|

生成配置文件参考test.js

### 工作过程
```flow
1=>start: HTTP代理访问接入
2=>start: 本地生成x-relay.protocol字段
3=>start: 连接至RelayServer
cond=>condition: 判断signed和g2fa
4=>start: 解密真实hostname(target)
5=>start: 反向代理目标站点
300=>end: 结束

1->2->3->cond->300
cond(yes)->4->5->300
cond(no)->300
```
