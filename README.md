

#Node 开源项目分类汇总

作为一个node初学者，发现上来就要跟一堆的node开源库打交道。这里整理一份常用的node库，以及他们的简单介绍和使用。持续更行中...

欢迎大家推荐好的Node开源项目，欢迎star,fork :)

+ [**工具**](#工具)
    - 基本工具
    - 流程控制
    - 系统工具
+ [**HTTP**](#HTTP)
    - req 
    - resp
    - cookie && session 
    - 授权
    - socket
    - 网络安全
+ [**数据(库)处理**](#数据(库)处理)
    - mysql
    - redis
    - mongodb
    - cache
+ [**Views**](#Views)
    - 模板(jade,ejs)
+ [**测试**](测试)
+ [**错误处理、日志、监控**](错误处理、日志、监控)
+ [**学习资料**](学习资料)
+ [**People**](People)

## 工具

### 普通工具
[utility](https://github.com/node-modules/utility) A collection of useful utilities
```
utils.md5('@移动开发小冉');
utils.sha1('nonstriater', 'base64');
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
//sync
var hash = bcrypt.hashSync('B4c0/\/', salt);
```

[crypto-js](https://github.com/brix/crypto-js) JavaScript library of crypto standards
```
// Encrypt
var ciphertext = CryptoJS.AES.encrypt('my message', 'secret key 123');

// Decrypt
var bytes  = CryptoJS.AES.decrypt(ciphertext.toString(), 'secret key 123');
```

[moment](https://github.com/moment/moment) 时间格式处理

```
moment().format('MMMM Do YYYY, h:mm:ss a'); // October 5th 2015, 7:48:22 pm
moment("20111031", "YYYYMMDD").fromNow(); // 4 years ago
moment().subtract(10, 'days').calendar(); // 09/25/2015
moment().format('lll');  // Oct 5, 2015 7:49 PM
```
更多使用参考 [官方文档](http://momentjs.com/)

[utils-merge](https://github.com/jaredhanson/utils-merge) 合并2个对象的属性
```
var a = { foo: 'bar' }
  , b = { bar: 'baz' };

merge(a, b);
// => { foo: 'bar', bar: 'baz' }
```

[cron](https://github.com/ncb000gt/node-cron)   cron 定时任务
```
var CronJob = require('cron').CronJob;
new CronJob('* * * * * *', function() {
  console.log('You will see this message every second');
}, null, true, 'America/Los_Angeles');
```
其中，cron格式 ‘秒，分，时，日，月，周 ’，*表示1。

[compression](https://github.com/expressjs/compression)  压缩的中间件

[depd](https://github.com/dougwilson/nodejs-depd)  deprecate all the things

[serve-favicon](https://github.com/expressjs/serve-favicon/blob/master/index.js)

[lodash](https://github.com/lodash/lodash/)     js工具库 
[lodash api](https://lodash.com/docs)


### 系统工具
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

### 流程控制
[async](https://github.com/caolan/async)  异步控制,控制并发

[eventproxy](https://github.com/JacksonTian/eventproxy)  An implementation of task/event based asynchronous pattern
事件代理，避免事件的深度嵌套回调

[cheerio](https://github.com/cheeriojs/cheerio)    为服务器定制的，JQuery核心实现,  分析网页用。 


[after](https://github.com/Raynos/after)
All the flow control you'll ever need

[on-finished](https://github.com/jshttp/on-finished)  Execute a callback when a request closes, finishes, or errors


## 字符串处理

[validator](https://github.com/chriso/validator.js)  字符串校验
```
validator.isEmail('foo@bar.com'); //=> true
validator.isWhitespace('    \t\r\n');// => true
```


[qs](https://github.com/hapijs/qs)
A querystring parser with nesting support
```
var obj = Qs.parse('a=c');    // { a: 'c' }
var str = Qs.stringify(obj);  // 'a=c'
```

[marked](https://github.com/chjj/marked) markdown 解析器

同步调用方式
```
fs.readFile(path, 'utf8', function(err, str){
    if (err) return fn(err);
    try {
      var html = md(str);
      html = html.replace(/\{([^}]+)\}/g, function(_, name){
        return options[name] || '';
      });
      fn(null, html);
    } catch(err) {
      fn(err);
    }
  });
```

异步调用方式
```
// Using async version of marked
marked(markdownString, function (err, content) {
  if (err) throw err;
  console.log(content);
});

```


[node-uuid](https://github.com/broofa/node-uuid)  Generate RFC-compliant UUIDs in JavaScript
```
// Generate a v1 (time-based) id
uuid.v1(); // -> '6c84fb90-12c4-11e1-840d-7b25c5ee775a'

// Generate a v4 (random) id
uuid.v4(); // -> '110ec58a-a0f2-4ac4-8393-c866d813b8d1'
```


[escape-html](https://github.com/component/escape-html)  string html转换 
```
var escape = require('escape-html');
var html = escape('foo & bar');
// -> foo &amp; bar
```

[path-to-regexp](https://github.com/pillarjs/path-to-regexp)
Turn an Express-style path string such as /user/:name into a regular expression.
```
var keys = []
var re = pathToRegexp('/foo/:bar', keys)
// re = /^\/foo\/([^\/]+?)\/?$/i
// keys = [{ name: 'bar', prefix: '/', delimiter: '/', optional: false, repeat: false, pattern: '[^\\/]+?' }]
```


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
```
var request = require('request');
request('http://www.google.com', function (error, response, body) {
  if (!error && response.statusCode == 200) {
    console.log(body) // Show the HTML for the Google homepage.
  }
})
```


[accepts](https://github.com/jshttp/accepts)   http(s) header Accept 设置和解析

[content-disposition](https://github.com/jshttp/content-disposition)  http(s) header Content-Disposition 设置和解析

[content-type](https://github.com/jshttp/content-type) http(s) header Content-Type 设置和解析

[range-parser](https://github.com/jshttp/range-parser) 
Range header field parser

[parseurl](https://github.com/pillarjs/parseurl) Parse the URL of the given request object

[methods](https://github.com/jshttp/methods)   保证http method 都是小写字符串

[body-parser](https://github.com/expressjs/body-parser) multipart body 解析.只负责处理 JSON，Raw，text,URL-encoded body的解析
```
//解析url 编码的body
bodyParser(urlencoded())
```
其依赖的库有(from package.json)：
```
  "dependencies": {
    "bytes": "2.1.0",
    "content-type": "~1.0.1",
    "debug": "~2.2.0",
    "depd": "~1.1.0",
    "http-errors": "~1.3.1",
    "iconv-lite": "0.4.12",
    "on-finished": "~2.3.0",
    "qs": "5.1.0",
    "raw-body": "~2.1.4",
    "type-is": "~1.6.9"
  },
  "devDependencies": {
    "istanbul": "0.3.21",
    "methods": "~1.1.1",
    "mocha": "2.2.5",
    "supertest": "1.1.0"
  }
```

[raw-body](https://github.com/stream-utils/raw-body)  从可读的stream中获取有效的 row body.

[multiparty](https://github.com/andrewrk/node-multiparty/)
A node.js module for parsing multipart-form data requests which supports streams2
解析content-type为multipart/form-data的request
```
http.createServer(function(req, res) {
  if (req.url === '/upload' && req.method === 'POST') {
    // parse a file upload
    var form = new multiparty.Form();

    form.parse(req, function(err, fields, files) {
      res.writeHead(200, {'content-type': 'text/plain'});
      res.write('received upload:\n\n');
      res.end(util.inspect({fields: fields, files: files}));
    });

    return;
  }
  // show a file upload form
  res.writeHead(200, {'content-type': 'text/html'});
  res.end(
    '<form action="/upload" enctype="multipart/form-data" method="post">'+
    '<input type="text" name="title"><br>'+
    '<input type="file" name="upload" multiple="multiple"><br>'+
    '<input type="submit" value="Upload">'+
    '</form>'
  );
}).listen(8080);
```


[multer](https://github.com/expressjs/multer) 文件上传中间件
```
var multer = require('multer');
var uploadingOption = multer({
  dest: __dirname + '../public/uploads/',
  // 设定限制，每次最多上传1个文件，文件大小不超过1MB
  limits: {fileSize: 1000000, files:1},
});

router.post('/upload', uploadingOption, function(req, res) {
});
```

[send](https://github.com/pillarjs/send)
Send is a library for streaming files from the file system as a http response supporting partial responses (Ranges), conditional-GET negotiation

[superagent](https://github.com/visionmedia/superagent)  客户端网络请求HTTP模块， 抓取网页 [使用参考](https://cnodejs.org/topic/5378720ed6e2d16149fa16bd)


[serve-static](https://github.com/expressjs/serve-static)
Create a new middleware function to serve files from within a given root directory

[type-is](https://github.com/jshttp/type-is)
Infer the content-type of a request

[method-override](https://github.com/expressjs/method-override)
Override HTTP verbs

[finalhandler](https://github.com/pillarjs/finalhandler)  final http responder


### cookie && session

**cookie机制是在客户端保持状态的方案，session是服务器保持状态的方案**


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
req.session.regenerate()
req.session.destroy()
```


[express-session](https://github.com/expressjs/session) Express session中间件
Create a session middleware with the given options
```
app.use(session({
  resave: false, // don't save session if unmodified
  saveUninitialized: false, // don't create session until something stored
  secret: 'shhhh, very secret'
}));
```

###  授权

[passport](https://github.com/jaredhanson/passport)    登录认证，较少模块耦合

[passport-github](https://github.com/jaredhanson/passport-github) github授权

[vhost](https://github.com/expressjs/vhost)   虚拟域名主机。 ip下可以部署多个不同域名站点


[proxy-addr](https://github.com/jshttp/proxy-addr) 
Determine address of proxied request

### socket

[Socket.io](https://github.com/socketio/socket.io)


### 网络安全

[xss](https://github.com/leizongmin/js-xss) 根据白名单过滤HTML(防止XSS攻击)

[csurf](https://github.com/expressjs/csurf)    CSRF(cross-site request forgery)  token 创造和验证

[cors](https://github.com/expressjs/cors)   （cross-origin resource sharing） 跨域请求
A node.js package that provides an Express/Connect middleware to enable Cross Origin Resource Sharing (CORS) with various options

[helmet](https://github.com/helmetjs/helmet)  安全性组件：xss跨站脚本，脚本注入，非安全请求
Help secure Express apps with various HTTP headers

[captchagen](https://github.com/contra/captchagen) 验证码生成器，依赖canvas库


## 数据(库)处理

### mysql
[mysql](https://github.com/felixge/node-mysql)  mysql协议的node实现
```
var db = mysql.createConnection(config);
db.connect(handleError);
db.on('error', handleError);
```
这里监听error时间重连数据库

为避免建立mysql连接对内存资源的占用，避免高访问量时数据库内存溢出风险，常使用mysql连接池机制。mysql 连接池的使用如下：
```
var mysql = require('mysql');
var pool  = mysql.createPool(config);

pool.getConnection(function(err, connection) {
  // Use the connection
  connection.query( 'SELECT something FROM sometable', function(err, rows) {
  });
});
```

### redis
[connect-redis](https://github.com/tj/connect-redis)  redis存储session数据
```
var RedisStore = require('connect-redis')(session);
app.use(session({
  resave: false, // don't save session if unmodified
  saveUninitialized: false, // don't create session until something stored
  secret: 'keyboard cat',
  store: new RedisStore
}));
```


[redis](https://github.com/NodeRedis/node_redis) redis client for nodejs

[ioredis](https://github.com/luin/ioredis) A robust, performance-focused and full-featured Redis client for Node and io.js

### mongodb
[connect-mongodb](https://github.com/treygriffith/connect-mongodb)
SessionStorage for connect's session middleware

[mongoose](https://github.com/Automattic/mongoose)  MongoDB object modeling designed to work in an asynchronous environment 

[mongoskin](https://github.com/kissjs/node-mongoskin) The promise wrapper for node-mongodb-native

### cache
[memory-cache](https://github.com/ptarjan/node-cache)A simple in-memory cache for nodejs


## views

[ejs](https://github.com/tj/ejs)
Embedded JavaScript templates for node

```
<% include error_header %>
<% if (user) { %>
    <h2><%= user.name %></h2>
<% } %>
<% include footer %>
```

[jade](https://github.com/jadejs/jade) 
Jade - robust, elegant, feature rich template engine for Node.js 


[loader](https://github.com/JacksonTian/loader)  静态资源加载工具,用于发布模式下进行资源压缩和合并

[canvas](https://github.com/Automattic/node-canvas)  图像图片处理库
Node canvas is a Cairo backed Canvas implementation for NodeJS



## 测试

[mocha](https://github.com/mochajs/mocha) BDD模式测试框架

[should](https://github.com/shouldjs/should.js) BDD 模式断言库

[supertest](https://github.com/visionmedia/supertest) 模拟http request测试

[fresh](https://github.com/jshttp/fresh) HTTP request freshness testing

[beachmark](https://github.com/bestiejs/benchmark.js) 测试执行时间效率

[coveralls](https://github.com/nickmerwin/node-coveralls)  代码测试覆盖率

[istanbul](https://github.com/gotwarlost/istanbul) 代码测试覆盖率

[gruntjs](http://gruntjs.com/)  基于node的自动化任务运行器。对于一些重复的任务比如压缩，编译，单元测试，代码检查，打包发布，可以使用grunt处理，简化我们的工作


## 错误处理、日志、 监控

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


[colors](https://github.com/Marak/colors.js)  get colors in your node.js console
```
var colors = require('colors');

console.log('hello'.green); // outputs green text
console.log('i like cake and pies'.underline.red) // outputs red underlined text
console.log('inverse the color'.inverse); // inverses the color
console.log('OMG Rainbows!'.rainbow); // rainbow
console.log('Run the trap'.trap); // Drops the bass
```
![colors](./assets/colors.png)



[errorhandle](https://github.com/expressjs/errorhandler) 错误处理中间件
如下，结合node-notifier处理错误信息：
```
var errorhandler = require('errorhandler')
var notifier = require('node-notifier')
if (process.env.NODE_ENV === 'development') {
  // only use in development
  app.use(errorhandler({log: errorNotification}))
}

function errorNotification(err, str, req) {
  var title = 'Error in ' + req.method + ' ' + req.url
  notifier.notify({
    title: title,
    message: str
  })
}
```


[Log.io](https://github.com/NarrativeScience/Log.io) 实时日志监控系统
```
1. sudo npm install -g log.io --user "<pc user>"
2. log.io-server
3. subl ~/.log.io/harvester.conf . like:
exports.config = {
    nodeName: "application_server",
    logStreams: {
      apache: [
        "/var/log/apache2/access.log",
        "/var/log/apache2/error.log"
      ]
    },
    server: {
      host: '0.0.0.0',
      port: 28777
    }
  } 

4. log.io-harvester
5. Browse to http://localhost:28778
```

[node-inspector](https://github.com/node-inspector/node-inspector)
```
//install
$ npm install -g node-inspector
//start debug
$ node-debug -p <port> app.js
//start node app
$ node app.js
//browser and trigger the br to starting debug
```

[debug](https://github.com/visionmedia/debug)  对console.log 封装，支持多种颜色输出

[node-notifier](https://github.com/madhums/node-notifier)  处理app级别的通知。可实现邮件通知，apn

[pm2](https://github.com/Unitech/pm2)  node 进程管理方案，负载均衡


## 学习资料

[node 资源列表]（https://github.com/sindresorhus/awesome-nodejs）
[nodeclub 源码](https://github.com/cnodejs/nodeclub.git)  这是我学习到的第一个完整的node项目  
[阮一峰 node教程](http://javascript.ruanyifeng.com/nodejs/express.html)   
[《Node.js 包教包不会》](https://github.com/alsotang/node-lessons)

## People

[朴灵](http://github.com/JacksonTian/)
[阮一峰](http://www.ruanyifeng.com/)
[alsotang](https://github.com/alsotang/)

# 联系

[移动开发小冉](http://weibo.com/ranwj)





