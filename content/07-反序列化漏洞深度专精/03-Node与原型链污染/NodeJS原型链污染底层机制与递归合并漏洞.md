---
date: 2026-10-15
title: "NodeJS原型链污染底层机制与递归合并漏洞"
---
# 🧬 Node.js 原型链污染底层机制与递归 Merge 穿透原理

> **核心哲学**：在 JavaScript 中，“一切皆对象”。
> 每个普通对象都隐含地继承自根原型 `Object.prototype`。
> **原型链污染（Prototype Pollution）** 允许攻击者通过特殊的键名注入，篡改运行时最高层级的 `Object.prototype`。一旦根原型被注入了恶意属性，**当前 Node.js 进程中所有正在运行及后续新建的对象，都将全局无条件继承该恶意属性！**

---

## 0. 基础前置认知与小白扫盲：什么是 JavaScript 原型链污染？

> [!NOTE] 模块前置语言与工具清单
> - **前置通关必备**：零基础读者强烈建议先通读全局导航 **[[01-零基础入门前置指南与黑话工具字典]]**，掌握安全法律红线、终端命令行、HTTP 报文骨架与黑话字典！
> - **环境依赖**：具备基础 Web 浏览器（Chrome/Firefox）抓包认知或轻量 Python 脚本执行能力。


### 1. 生活比喻：投毒全人类共同的基因图谱
* **JavaScript 的对象继承哲学**：
  * 在 JS 中，对象没有传统面向对象语言（如 Java/C++）那么严格的类层次体系。
  * 每个对象内部都有一个隐藏的隐式指针——`__proto__`，指向它的父级“原型对象（Prototype）”。
  * 所有普通对象的始祖原型，最终都指向同一个顶层母体——**`Object.prototype`**！
* **属性寻址规则（从子到父）**：
  * 当你访问 `person.isAdmin` 时，系统先看 `person` 自己身上有没有 `isAdmin`；
  * 如果没有，系统不会直接放弃，而是顺着 `__proto__` 爬到 `Object.prototype` 身上去查：“始祖，你有这个属性吗？”
  * **原型链污染的灭顶之灾**：
    * 如果黑客利用程序中不严谨的递归对象合并（如 `merge()`、`clone()`），通过恶意的 JSON 输入（`{"__proto__": {"isAdmin": true}}`），强行修改了全局母体 `Object.prototype`；
    * 那么从这一毫秒开始，**整个 Node.js 进程中所有正在运行的、以及未来新生出来的任意对象，身上都会无中生有地多出一个 `isAdmin = true` 的属性！** 全站鉴权瞬间彻底崩塌！

---

## 一、JavaScript 原型链寻址模型与污染灾难

### 1. 原型链查找（Prototype Chain Lookup）
当代码试图访问对象 `user.isAdmin` 时，V8 引擎按如下链条向上逐级搜寻：

```text
[user 实例自身属性] ──(未找到)──> [user.__proto__ (即 Object.prototype)] ──(未找到)──> null
```
如果我们在 `Object.prototype` 上强行植入属性：
```javascript
Object.prototype.isAdmin = true;
```
那么在此刻之后，即使执行一个空对象 `{}`：
```javascript
let guest = {};
console.log(guest.isAdmin); // 输出: true！凭空获得了管理员权限！
```

---

## 二、漏洞核心触发源：递归合并函数（Deep Merge）

原型链污染最常见于处理用户 JSON 数据的**深层合并（Merge）、深拷贝（Clone）或路径设值（Path Set）**场景。

### 1. 经典存在漏洞的递归 `merge` 实现源码：
```javascript
function merge(target, source) {
    for (let key in source) {
        // 如果 key 在 target 和 source 中均为对象，则递归向下合并
        if (key in source && key in target) {
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}
```

---

## 三、`JSON.parse` 为什么是原型链污染的关键催化剂？

很多安全初学者会产生一个疑惑：在 JS 代码里直接写 `{__proto__: {a: 1}}`，并不能直接污染全局原型。为什么从 Web 请求传进来的 JSON 就能？

### 1. 底层解析差异剖析：
* **在原生 JS 代码字面量中**：
  `let a = {__proto__: {admin: true}};`
  JS 引擎把 `__proto__` 识别为设置对象原型的特殊语法糖，此时仅仅是把对象 `a` 的原型设为了一个包含 `admin: true` 的新对象，**根本不会影响全局 `Object.prototype`**！
* **在 `JSON.parse()` 解析中（核心转折点）**：
  ```javascript
  let malicious_json = JSON.parse('{"__proto__": {"admin": true}}');
  ```
  根据 ECMA-262 JSON 规范，**`JSON.parse()` 会将 `__proto__` 严格当作一个名为 `"__proto__"` 的普通自有字符串键（Own Property）解析出来！**

### 2. 递归 Merge 引爆全流程推导：
当这个 JSON 解析出来的对象传入 `merge(target, source)` 时：
1. 遍历到键名为 `key = "__proto__"`；
2. 执行 `target[key]` 即 `target["__proto__"]`；
3. **💥 关键转折**：在 JS 中，读取一个普通对象的 `__proto__` 属性，直接返回它的真正原型——**`Object.prototype`**！
4. 递归调用：`merge(Object.prototype, {"admin": true})`；
5. 第二层循环执行：`Object.prototype["admin"] = true`；
6. **污染彻底完成！全局所有对象瞬间被篡改！**

---

## 四、WAF 绕过黑魔法：`constructor.prototype` 替换绕过

许多开发者意识到风险后，写出了初级防御黑名单：
```javascript
if (key === '__proto__') {
    continue; // 过滤 __proto__
}
```

### 1. 绕过原理：原型链的双向闭环互通
在 JavaScript 面向对象体系中：
* 任何普通对象的构造函数是 `Object`（通过 `obj.constructor` 获取）；
* 而函数 `Object` 的原型属性正是 `Object.prototype`（通过 `Object.prototype` 获取）！

因此，存在恒等式：
$$\mathbf{target.constructor.prototype \equiv Object.prototype \equiv target.\_\_proto\_\_}$$

### 2. 绕过 Payload 结构：
```json
{
    "constructor": {
        "prototype": {
            "isAdmin": true
        }
    }
}
```

#### 🔍 逐级穿透执行流剖析：
1. 第一层 key 为 `"constructor"`（完全不包含 `__proto__`，避开黑名单）；
   `target["constructor"]` 提取到 `Object` 构造函数；
2. 第二层 key 为 `"prototype"`；
   `Object["prototype"]` 提取到原汁原味的 **`Object.prototype`**；
3. 第三层 key 为 `"isAdmin"`；
   直接将 `true` 写入 `Object.prototype["isAdmin"]`，**防御黑名单形同虚设！**

---

## 五、完整本地复现实测代码

```javascript
// vuln_merge_demo.js

function vulnerableMerge(target, source) {
    for (let key in source) {
        if (typeof target[key] === 'object' && typeof source[key] === 'object') {
            vulnerableMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// 模拟前端传入包含 constructor.prototype 绕过的恶意 JSON
let evilJsonPayload = '{"constructor": {"prototype": {"polluted_flag": "POLLUTED_FLAG"}}}';
let evilObj = JSON.parse(evilJsonPayload);

let targetObj = {};
console.log("[*] 合并前，检测新空对象属性: ", ({}).polluted_flag); // 输出: undefined

// 执行存在漏洞的深合并
vulnerableMerge(targetObj, evilObj);

console.log("[+] 合并后，检测全新空对象属性: ", ({}).polluted_flag); // 输出: POLLUTED_FLAG！
```

---

## 🔗 相关双向链接
- 上级模块：[[07-反序列化漏洞深度专精]]
- 基础依赖：[[Shiro反序列化：CBC与GCM加密与Key利用全流程]]
- 武器化利用：[[原型链污染高阶：污染模板引擎与环境变量实现RCE]]
- 知识地图：[[00-Web安全与CTF知识地图总览]]
