# 安全恢复哈希提取器 (网页离线版)

> **技术服务与算力支持**：淘宝@大希软件服务  
> **核心特性**：纯浏览器本地离线计算 · 零文件上传 · 100% 隐私安全 · PWA 离线自动缓存

---

## 📖 项目简介

本工具是一个专为文件密码恢复设计的纯前端静态单页应用（SPA）。  
用户只需在浏览器中打开页面，即可直接将受保护的文件（PDF、Office、ZIP、RAR5 等）拖入页面中。程序利用浏览器内存与客户端 JavaScript 毫秒级提取文档的加密元数据（Salt、Iteration Count、加密模式及特征散列），并生成标准的 `.recovery-hash` 文件。

### 🔒 极致隐私与安全
- **零网络上传**：所有计算均在用户本地浏览器的内存中完成，没有任何后端服务，绝不向任何服务器发送用户的文档或数据内容。
- **断网可用 (PWA)**：首次访问后，Service Worker 会自动将整站资源缓存至本地 Cache Storage。即使拔掉网线或开启飞行模式，刷新网页依然可以秒开并完整提取哈希。
- **轻量微哈希**：导出的 `.recovery-hash` 仅包含几十到几百字节的脱敏加密特征参数，用户只需将该小文件发给服务商，即可在 GPU 算力集群上进行找回，彻底告别传输数 GB 敏感大文件的隐患。

---

## 🎯 支持格式与 Hashcat 模式对照

| 格式 | 加密类型 / 提取目标 | Hashcat Mode | 浏览器本地支持 |
| :--- | :--- | :--- | :--- |
| **PDF** | 打开密码 (R=2 ~ R=6) | `10400` / `10500` / `10600` / `10700` | ✅ 原生支持 |
| **PDF** | 权限/打印限制密码 (R=3, 4) | `25400` | ✅ 原生支持 |
| **Office** | Word/Excel/PPT 2007 (Standard) | `9400` | ✅ 原生支持 |
| **Office** | Word/Excel/PPT 2010 (Agile SHA-1) | `9500` | ✅ 原生支持 |
| **Office** | Word/Excel/PPT 2013/2016/365 (Agile SHA-512) | `9600` | ✅ 原生支持 |
| **Office** | Excel 工作表/Word 限制编辑 (现代 SHA-512) | `25300` | ✅ 原生支持 |
| **Office** | Excel 传统工作表保护 (16-bit XOR) | `0` (瞬时破解) | ✅ 原生支持 |
| **ZIP** | WinZip AES (128/192/256-bit) | `13600` | ✅ 原生支持 |
| **ZIP** | 传统 PKZIP (ZipCrypto, ≤320KB) | `17200` | ✅ 原生支持 |
| **RAR** | RAR5 (PBKDF2-HMAC-SHA256) | `13000` | ✅ 原生支持 |
| **7z** | 7z 文件名加密陷阱 | 拦截保护 | ✅ 自动安全拦截 |

---

## 🚀 部署到 Cloudflare Pages 指南

### 1. 推送到 GitHub
```bash
git init
git add .
git commit -m "feat: 初始发布网页版恢复哈希提取器"
git branch -M main
git remote add origin https://github.com/你的用户名/你的仓库名.git
git push -u origin main
```

### 2. 在 Cloudflare Pages 创建项目
1. 登录 [Cloudflare 控制台](https://dash.cloudflare.com/)。
2. 左侧导航进入 **Workers 和 Pages** -> 点击 **创建应用程序** -> 切换到 **Pages**。
3. 点击 **连接到 Git**，选择刚刚推送到 GitHub 的仓库。
4. 构建参数配置：
   - **框架预设 (Framework preset)**: `Vite`
   - **构建命令 (Build command)**: `npm run build`
   - **构建输出目录 (Build output directory)**: `dist`
5. 点击 **保存并部署**。几秒内全球边缘 CDN 构建完成，并分配一个 `xxx.pages.dev` 二级域名。

### 3. 绑定自定义域名
1. 在部署成功的项目页，点击 **Custom domains (自定义域)**。
2. 输入你的域名或二级域名（例如 `hash.yourdomain.com`）。
3. 按照提示完成 CNAME DNS 解析记录配置，Cloudflare 会自动签发永久有效的免费 SSL 证书。

---

## 🛠️ 本地开发与测试

```bash
# 安装依赖
npm install

# 启动本地热重载调试服务器
npm run dev

# 生产环境打包
npm run build
```

---

## 🏷️ 版权与技术支持

本项目专为配合 GPU 密码恢复集群设计。  
技术支持与算力恢复服务：**淘宝@大希软件服务**
