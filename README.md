


作为一个node初学者，发现上来就要跟一堆的node开源库打交道。这里整理一份常用的node库，以及他们的简单介绍和使用。


## 锤子

[utility](https://github.com/node-modules/utility) A collection of useful utilities
```
utils.md5('@Python发烧友');
utils.sha1('苏千', 'base64');
utils.hmac('sha1', 'I am a key', 'hello world');
utils.base64decode('5L2g5aW977-l', true); 
```

[bcrypt](https://github.com/ncb000gt/node.bcrypt.js)     跨平台的文件加密工具
```
var bcrypt = require('bcrypt');
bcrypt.genSalt(10, function(err, salt) {
    bcrypt.hash('B4c0/\/', salt, function(err, hash) {
        // Store hash in your password DB.
    });
});
```

[crypto-js](https://github.com/brix/crypto-js) JavaScript library of crypto standards
```
// Encrypt
var ciphertext = CryptoJS.AES.encrypt('my message', 'secret key 123');

// Decrypt
var bytes  = CryptoJS.AES.decrypt(ciphertext.toString(), 'secret key 123');
```


、
[moment](https://github.com/moment/moment) 时间格式处理
[官方文档](http://momentjs.com/)
```
moment().format('MMMM Do YYYY, h:mm:ss a'); // October 5th 2015, 7:48:22 pm
moment("20111031", "YYYYMMDD").fromNow(); // 4 years ago
moment().subtract(10, 'days').calendar(); // 09/25/2015
moment().format('lll');  // Oct 5, 2015 7:49 PM
```


[nodemailer](https://github.com/andris9/Nodemailer) 邮件发送服务
```
// create reusable transporter object using SMTP transport
var transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
        user: 'gmail.user@gmail.com',
        pass: 'userpass'
    }
});

// NB! No need to recreate the transporter object. You can use
// the same transporter object for all e-mails

// setup e-mail data with unicode symbols
var mailOptions = {
    from: 'Fred Foo ✔ <foo@blurdybloop.com>', // sender address
    to: 'bar@blurdybloop.com, baz@blurdybloop.com', // list of receivers
    subject: 'Hello ✔', // Subject line
    text: 'Hello world ✔', // plaintext body
    html: '<b>Hello world ✔</b>' // html body
};

// send mail with defined transport object
transporter.sendMail(mailOptions, function(error, info){
    if(error){
        return console.log(error);
    }
    console.log('Message sent: ' + info.response);

});

```


[qrcode](https://github.com/soldair/node-qrcode)  二维码生成器

[pm2](https://github.com/Unitech/pm2) Production process manager for Node.js applications with a built-in load balance

[cron](https://github.com/ncb000gt/node-cron)   cron 定时任务

[compression](https://github.com/expressjs/compression)  压缩的中间件

[errorhandle](https://github.com/expressjs/errorhandler)
错误处理中间件

[depd](https://github.com/dougwilson/nodejs-depd)  deprecate all the things


[lodash](https://github.com/lodash/lodash/)     js工具库 
[lodash api](https://lodash.com/docs)

[async](https://github.com/caolan/async)      异步控制

[eventproxy](https://github.com/JacksonTian/eventproxy)  An implementation of task/event based asynchronous pattern

[after](https://github.com/Raynos/after)
All the flow control you'll ever need

[on-finished](https://github.com/jshttp/on-finished)  Execute a callback when a request closes, finishes, or errors

## 字符串处理

[validator](https://github.com/chriso/validator.js)  字符串校验

[qs](https://github.com/hapijs/qs)
A querystring parser with nesting support

[marked](https://github.com/chjj/marked)  
markdown 解析器

[node-uuid](https://github.com/broofa/node-uuid)  Generate RFC-compliant UUIDs in JavaScript

###[escape-html](https://github.com/component/escape-html)  string html转换 

```
var escape = require('escape-html');
var html = escape('foo & bar');
// -> foo &amp; bar
```

[path-to-regexp](https://github.com/pillarjs/path-to-regexp)
Turn an Express-style path string such as /user/:name into a regular expression.


[multiline](https://github.com/sindresorhus/multiline) Multiline strings in JavaScript

before:
```
var str = '' +
'<!doctype html>' +
'<html>' +
'   <body>' +
'       <h1>❤ unicorns</h1>' +
'   </body>' +
'</html>' +
'';
```

after:
```
var str = multiline(function(){/*
<!doctype html>
<html>
    <body>
        <h1>❤ unicorns</h1>
    </body>
</html>
*/});

```


## HTTP

### req && resp

[request](https://github.com/request/request)  Simplified HTTP request client

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

[parseurl](https://github.com/pillarjs/parseurl) Parse the URL of the given request object

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

[cookie](https://github.com/jshttp/cookie) cookie serialization and parsing for node.js

[cookie-signature](https://github.com/tj/node-cookie-signature) cookie signing

[cookie-parser](https://github.com/expressjs/cookie-parser)  cookie parsing middleware
```
app.use(cookieParser('my secret here'));
res.cookie('remember', 1, { maxAge: minute });
res.clearCookie('remember');
```


[cookie-session](https://github.com/expressjs/cookie-session)
Simple cookie-based session middleware

```
app.use(cookieSession({ secret: 'manny is cool' }));
req.session.count
```

### 网络安全

[xss](https://github.com/leizongmin/js-xss) 根据白名单过滤HTML(防止XSS攻击)

[csurf](https://github.com/expressjs/csurf)    CSRF(cross-site request forgery)  token 创造和验证

[cors](https://github.com/expressjs/cors)   （cross-origin resource sharing） 跨域请求
A node.js package that provides an Express/Connect middleware to enable Cross Origin Resource Sharing (CORS) with various options

[helmet](https://github.com/helmetjs/helmet)  安全性组件：xss跨站脚本，脚本注入，非安全请求
Help secure Express apps with various HTTP headers

[captchagen](https://github.com/contra/captchagen) 验证码生成器，依赖canvas库


## 数据(库)处理

[mysql](https://github.com/felixge/node-mysql)  mysql协议的node实现

[connect-mongodb](https://github.com/treygriffith/connect-mongodb)
SessionStorage for connect's session middleware

[mongoose](https://github.com/Automattic/mongoose)  MongoDB object modeling designed to work in an asynchronous environment 

[connect-redis](https://github.com/tj/connect-redis)  redis存储session数据

[redis](https://github.com/NodeRedis/node_redis) redis client for nodejs

[ioredis](https://github.com/luin/ioredis) A robust, performance-focused and full-featured Redis client for Node and io.js

[memory-cache](https://github.com/ptarjan/node-cache)A simple in-memory cache for nodejs


## views

[jade](https://github.com/jadejs/jade) 
Jade - robust, elegant, feature rich template engine for Node.js 

[ejs](https://github.com/tj/ejs)
Embedded JavaScript templates for node

```
<% include error_header %>
<% if (user) { %>
    <h2><%= user.name %></h2>
<% } %>
<% include footer %>
```


[loader](https://github.com/JacksonTian/loader)      静态资源加载工具

[canvas](https://github.com/Automattic/node-canvas)  图像图片处理库
Node canvas is a Cairo backed Canvas implementation for NodeJS



## 测试

[mocha](https://github.com/mochajs/mocha)
mocha - simple, flexible, fun javascript test framework for node.js & the browser. (BDD, TDD, QUnit styles via interfaces)

[should](https://github.com/shouldjs/should.js)
BDD style assertions for node.js -- test framework agnostic

[supertest](https://github.com/visionmedia/supertest)
Super-agent driven library for testing node.js HTTP servers using a fluent API

[fresh](https://github.com/jshttp/fresh) HTTP request freshness testing


[coveralls](https://github.com/nickmerwin/node-coveralls)  代码测试覆盖率

[istanbul](https://github.com/gotwarlost/istanbul) 代码测试覆盖率


[gruntjs](http://gruntjs.com/)  

基于node的自动化任务运行器。对于一些重复的任务比如压缩，编译，单元测试，代码检查，打包发布，可以使用grunt处理



## 日志 && 监控

[morgan](https://github.com/expressjs/morgan)
HTTP request log 中间件

```
var logger = require('morgan');
app.use(logger('dev'));
```

预定义的格式有：combined,common,dev,short,tiny，比如dev:
```
:method :url :status :response-time ms - :res[content-length]
```
![morgan_dev](./assets/morgan_dev.png)


[debug](https://github.com/visionmedia/debug)  对console.log 封装，支持多种颜色输出

[colors](https://github.com/Marak/colors.js)  get colors in your node.js console

[node-inspector](https://github.com/node-inspector/node-inspector)


# 联系

[移动开发小冉](http://weibo.com/ranwj)





