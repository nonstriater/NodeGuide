


作为一个node初学者，发现上来就要跟一堆的node开源库打交道。这里整理一份常用的node库，以及他们的简单介绍和使用。


## 锤子

[async](https://github.com/caolan/async)      异步控制

[bcrypt](https://github.com/ncb000gt/node.bcrypt.js)     跨平台的文件加密工具

[lodash](https://github.com/lodash/lodash/)     js工具库 

[compression](https://github.com/expressjs/compression)  压缩的中间件

[after](https://github.com/Raynos/after)
All the flow control you'll ever need

[errorhandle](https://github.com/expressjs/errorhandler)
错误处理中间件

[debug](https://github.com/visionmedia/debug)

[node-inspector](https://github.com/node-inspector/node-inspector)

[depd](https://github.com/dougwilson/nodejs-depd)  deprecate all the things

[on-finished](https://github.com/jshttp/on-finished)  Execute a callback when a request closes, finishes, or errors

[istanbul](https://github.com/gotwarlost/istanbul)
 a JS code coverage tool written in JS


### 字符串处理

[qs](https://github.com/hapijs/qs)
A querystring parser with nesting support

[marked](https://github.com/chjj/marked)  
markdown 解析器


###[escape-html](https://github.com/component/escape-html)  string html转换 

```
var escape = require('escape-html');
var html = escape('foo & bar');
// -> foo &amp; bar
```

[path-to-regexp](https://github.com/pillarjs/path-to-regexp)
Turn an Express-style path string such as /user/:name into a regular expression.



## HTTP

### req && resp

[accepts](https://github.com/jshttp/accepts)   http(s) header Accept 设置和解析
[content-disposition](https://github.com/jshttp/content-disposition)  http(s) header Content-Disposition 设置和解析
[content-type](https://github.com/jshttp/content-type) http(s) header Content-Type 设置和解析

[range-parser](https://github.com/jshttp/range-parser) 
Range header field parser

[type-is](https://github.com/jshttp/type-is)
Infer the content-type of a request

[methods](https://github.com/jshttp/methods)   http method 小写

[method-override](https://github.com/expressjs/method-override)
Override HTTP verbs

[finalhandler](https://github.com/pillarjs/finalhandler)  final http responder

[body-parser](https://github.com/expressjs/body-parser) multipart body 解析

[parseurl] https://github.com/pillarjs/parseurl  
Parse the URL of the given request object

[send](https://github.com/pillarjs/send)
Send is a library for streaming files from the file system as a http response supporting partial responses (Ranges), conditional-GET negotiation

[serve-static](https://github.com/expressjs/serve-static)
Create a new middleware function to serve files from within a given root directory


[multiparty](https://github.com/andrewrk/node-multiparty/)
A node.js module for parsing multipart-form data requests which supports streams2


[express-session](https://github.com/expressjs/session)
Create a session middleware with the given options


[passport](https://github.com/jaredhanson/passport)    登录认证，较少模块耦合

[passport-github](https://github.com/jaredhanson/passport-github) github授权


[vhost](https://github.com/expressjs/vhost)   虚拟域名主机。 ip下可以部署多个不同域名站点

[proxy-addr](https://github.com/jshttp/proxy-addr) 
Determine address of proxied request


### cookie 

[cookie](https://github.com/jshttp/cookie） cookie serialization and parsing for node.js

[cookie-signature](https://github.com/tj/node-cookie-signature) cookie signing

[cookie-parser](https://github.com/expressjs/cookie-parser)  cookie parsing middleware

[cookie-session](https://github.com/expressjs/cookie-session)
Simple cookie-based session middleware


### 网络安全

csurf    CSRF(cross-site request forgery)  token 创造和验证
cors   （cross-origin resource sharing） 跨域请求
helmet  安全性组件：xss跨站脚本，脚本注入，非安全请求



## 数据库处理

connect-mongodb](https://github.com/treygriffith/connect-mongodb)
SessionStorage for connect's session middleware

[connect-redis](https://github.com/tj/connect-redis)  redis存储session数据

[redis](https://github.com/NodeRedis/node_redis) redis client for nodejs


## 日志 && 监控

### [morgan](https://github.com/expressjs/morgan)
HTTP request log 中间件



## 测试

mocha](https://github.com/mochajs/mocha)
mocha - simple, flexible, fun javascript test framework for node.js & the browser. (BDD, TDD, QUnit styles via interfaces)

[should](https://github.com/shouldjs/should.js)
BDD style assertions for node.js -- test framework agnostic

[supertest](https://github.com/visionmedia/supertest)
Super-agent driven library for testing node.js HTTP servers using a fluent API

[fresh](https://github.com/jshttp/fresh) HTTP request freshness testing



### views

[jade](https://github.com/jadejs/jade) 
Jade - robust, elegant, feature rich template engine for Node.js 

[ejs](https://github.com/tj/ejs)
Embedded JavaScript templates for node

[loader](https://github.com/JacksonTian/loader)      静态资源加载工具







