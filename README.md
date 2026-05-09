# 🚀 SP-Proxy-Pages

**SP-Proxy-Pages** 是一个专为 **Cloudflare Pages 高级模式 (Advanced Mode)** 打造的无端代理（Web Proxy）解决方案。

---

## ✨ 项目亮点

- **全栈集成**：利用 Cloudflare Pages `_worker.js` 处理边缘逻辑，同时托管静态 `sw.js`。
- **动态屏蔽系统**：支持 `BLOCK_RULES` 环境变量，兼容纯文本与 Regex 正则匹配。
- **可私有访问**：独创的零信任入口密语和支持目录型密语 `const SECRET_PREFIX = "";`。
- **零门槛部署**：无需复杂服务器配置，全球边缘节点秒级生效。

---

## 📂 项目结构

```text
sp-proxy-pages/
├── dist/
│   ├── _worker.js      # 边缘网关、渲染与代理核心逻辑
│   ├── sw.js           # Service Worker 流媒体缓存与拦截核心
│   └── _routes.json    # Pages 路由优化配置文件
└── wrangler.toml       # 部署配置
```

---

## 🚀 部署指南

### 方法 A：使用 Wrangler CLI

1. **安装 Wrangler:**
   ```bash
   npm install -g wrangler
   ```

2. **登录账号:**
   ```bash
   wrangler login
   ```

3. **一键发布:**
   在根目录下运行以下命令（将项目名设为 `sp-proxy`）：
   ```bash
   wrangler pages deploy dist --project-name sp-proxy
   ```

### 方法 B：通过 GitHub 自动构建 (推荐)

1. 将本项目代码推送至您的 GitHub 仓库。
2. 在 Cloudflare 控制台选择 **Workers & Pages** -> **Create application** -> **Pages** -> **Connect to Git**。
3. 在构建设置中进行如下配置：
   * **Framework preset**: `None`
   * **Build command**: *(留空)*
   * **Build output directory**: `dist`
4. 点击 **Save and Deploy** 即可。以后每次 `git push` 都会自动触发更新部署。

---


## ⚙️ 变量配置 

您可以随时在 Cloudflare 控制面板中动态调整访问控制策略。
**配置路径**：设置 (Settings) -> 环境变量 (Environment variables) -> 添加变量

## 🔑 使用方法 (Zero Trust 模式)

| 变量名 | 必填 | 示例值 | 说明 |
| :--- | :---: | :--- | :--- |
| `AUTH_SECRET` | 否 | `MySecretPass123` | **(推荐)** 零信任入口密语。配置后，未携带密语的访问将被拦截。|
| `CRYPTO_SALT`   | 否     | `default`                    | **加密盐值**。网关在生成 RSA 公私钥（用于保护 POST 数据和防重放）时使用的缓存键后缀。建议每次修改 `AUTH_SECRET` 时同步更改此值以强制轮换全局密钥。                          |

如果您在环境变量中配置了 `AUTH_SECRET`，您的代理现已处于**私有化锁定状态**。

1. **首次授权访问**：
   在浏览器中访问您的代理域名，并在 URL 结尾附带 `?auth=您的密语`。
   > 示例：`https://你的域名.com/?auth=MySecretPass123`
2. **自动下发凭证**：
   系统验证通过后，会自动下发一个有效期为 30 天的加密 Cookie（`__UP_AUTH__`），并重定向至代理系统主页。
3. **日常使用**：
   在接下来的 30 天内，只要您的浏览器未清除 Cookie，您可以随时打开 `https://你的域名.com/` 直接使用网关功能，无需再次输入密语。


| 变量名 | 匹配示例 | 说明 |
| :--- | :--- | :--- |
| `BLOCK_RULES` | `youtube.com` | 自动匹配主域及其所有子域（如 www.youtube.com） |
| `BLOCK_RULES` | `/google\.[a-z]{2,3}/i` | 使用原生正则匹配，可精准锁定多国后缀域名 |

> **💡 提示**：多个规则之间请使用 **逗号** 或 **换行** 分隔。 `youtube.com, /google\.[a-z]{2,3}(?:\.[a-z]{2})?$/i, twitter.com` 若不配置，系统将默认采用内置的基础屏蔽规则。

| 变量名 | 说明 | 默认值 | 示例 |
| :--- | :--- | :--- | :--- |
| `BLOCK_RULES` | 拒绝代理的域名黑名单（支持正则/关键字） BLOCK 优先于 ALLOW | `duck.ai, chatgpt.com, openai.com, claude.ai, gemini.google.com, grok.com, copilot.microsoft.com, perplexity.ai, poe.com, ` | `91porn.com, \.xxx$` |
| `ALLOW_RULES` | 仅允许代理的域名白名单。配置此项后，不在名单内的域名将一律拦截。 | *(空，允许所有)* | `github.com, duckduckgo.com` |


**所有变量设置后需重新部署方可生效！**

**关于缓存更新**：由于前端注册了 Service Worker，如果在后续升级了后端代码遇到渲染异常，请在浏览器中按 `Ctrl + F5` 强制刷新，或在 DevTools -> Application -> Service Workers 中点击 `Unregister` 清理旧缓存。


**关于YouTube**：已对 m.youtube.com 进行框架替换，电脑端可用https://blog.kooker.jp/youtube.php 转换为框架再代理 如 https://你的域名.com/https://blog.kooker.jp/GnfBkCIHi9E 但取决于Cloudflare IP 的纯净度，大概率是不可播放的。

### 风险评级

| 场景 | 风险等级 | 说明 |
|------|----------|------|
| **个人私有自用**（仅自己/可信小圈子使用） | **低-中** | 可接受 |
| **公开部署 / 多人使用** | **高** | 不推荐 |
| **作为高安全站点（如网银、OA、企业邮箱）的跳板** | **致命** | 绝对禁止 |


### 最终建议

**✅ 上线的情况**：
- 仅限**你自己**或**极小可信圈子**使用
- 只访问低敏感站点（技术文档、论坛、GitHub 等）
- **绝不**输入任何金融/企业账号密码

**❌ 绝对不要做的事**：
- 公开分享域名（即使加了密码）
- 访问任何包含核心资产的系统（网银、企业邮箱、OA、GitHub 企业版等）


## ⚖️ 免责声明

1. 本项目仅供边缘计算与网络技术研究学习使用。请在遵守当地法律法规的前提下使用，开发者不对任何不当使用导致的后果承担责任。
2. 请勿将本项目用于任何违反当地法律法规的用途。
3. 由于网页结构的复杂性和跨域安全策略（CORS）的限制，代理并不能保证 100% 完美呈现所有站点（尤其是重度依赖 WebRTC 或非标准视频流的网站）。
4. **安全警告**：若非部署在你本人完全控制的域名或受信任的服务器上，**请勿通过代理站点登录任何包含个人核心隐私的账号（如网银、重要邮箱等）**。
