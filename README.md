


作为一个node初学者，发现上来就要跟一堆的node开源库打交道，很多库也不知道是干什么的。这里整理一份常用的node库，以及他们的简单介绍和使用。


## 锤子

async      异步控制
bcrypt     跨平台的文件加密工具
loader      资源加载工具
passport    登录认证，较少模块耦合
passport-github  https://github.com/jaredhanson/passport-github github授权
lodash    js工具库  https://github.com/lodash/lodash/
compression  压缩的中间件
body-parser   https://github.com/expressjs/body-parser multipart body 解析

errorhandler  错误处理中间件 https://github.com/expressjs/errorhandler


connect-busboy
content-flatten


debug  https://github.com/visionmedia/debug
node-inspector  https://github.com/node-inspector/node-inspector

[depd](https://github.com/dougwilson/nodejs-depd)  deprecate all the things
[escape-html](https://github.com/component/escape-html)  string html转换 

var escape = require('escape-html');
var html = escape('foo & bar');
// -> foo &amp; bar


finalhandler  https://github.com/pillarjs/finalhandler  final http responder



[on-finished](https://github.com/jshttp/on-finished)  Execute a callback when a request closes, finishes, or errors

[path-to-regexp](https://github.com/pillarjs/path-to-regexp)
Turn an Express-style path string such as /user/:name into a regular expression.



[qs](https://github.com/hapijs/qs)
A querystring parser with nesting support



[serve-static](https://github.com/expressjs/serve-static)
Create a new middleware function to serve files from within a given root directory




[after](https://github.com/Raynos/after)
All the flow control you'll ever need



[istanbul](https://github.com/gotwarlost/istanbul)
 a JS code coverage tool written in JS

[marked](https://github.com/chjj/marked)  
markdown 解析器

method-override
jade
ejs
express-session
morgan
multiparty

vhost   虚拟域名主机。 ip下可以部署多个不同域名站点
[proxy-addr](https://github.com/jshttp/proxy-addr) 
Determine address of proxied request


## HTTP

accepts  https://github.com/jshttp/accepts   http(s) header Accept 设置和解析
content-disposition  https://github.com/jshttp/content-disposition  http(s) header Content-Disposition 设置和解析
content-type  、https://github.com/jshttp/content-type http(s) header Content-Type 设置和解析

[range-parser](https://github.com/jshttp/range-parser) 
Range header field parser

[type-is](https://github.com/jshttp/type-is)
Infer the content-type of a request

methods   https://github.com/jshttp/methods   http method 小写

[parseurl] https://github.com/pillarjs/parseurl  
Parse the URL of the given request object

[send](https://github.com/pillarjs/send)
Send is a library for streaming files from the file system as a http response supporting partial responses (Ranges), conditional-GET negotiation


## 数据处理

connect-mongodb
connect-redis  redis存储session数据
redis
online


## 日志

### [morgan](https://github.com/expressjs/morgan)
HTTP request log 中间件



## 测试

mocha
should
supertest
[fresh](https://github.com/jshttp/fresh) HTTP request freshness testing

## cookie 

cookie
cookie-signature
cookie-parser 
cookie-session


## 网络安全

csurf    CSRF(cross-site request forgery)  token 创造和验证
cors   （cross-origin resource sharing） 跨域请求
helmet  安全性组件：xss跨站脚本，脚本注入，非安全请求



