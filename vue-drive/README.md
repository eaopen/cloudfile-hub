# CloudFile Vue 网盘

实例 1 的资料库入口为 `/inst/1/`，资料库地址为 `/inst/1/{repoId}`。目录深链接使用 `path` 查询参数，共享目录入口额外保留 `root`。服务端负责检查每次请求的权限。默认沿用一个 Hub 的 authentik 登录和原生接口。增加实例后，库和共享根的身份由实例编号、库 UUID 和共享根共同确定。

## 本地验证

使用 Node.js 22.12 或更新版本，在本目录运行：

```sh
npm ci
npm test
npm run build
CLOUDFILE_DEV_UPSTREAM=http://127.0.0.1:8000 npm run dev
```

在开发服务器的 `/inst/1/` 打开页面。将代理目标改为包含 Hub 和文件服务的实际网关。联调时，Hub 的公开地址、authentik 回调与文件服务生成的链接应匹配浏览器地址，并在 Hub 的 CSRF 可信来源中配置该精确来源（含端口）。独立文件服务可在构建时用 `VITE_FILE_ORIGIN` 指定可信来源，并在文件服务配置上传 CORS。

## 单实例发布

将 `dist/` 的内容放到现有 Hub 网关所在站点的 `/srv/cloudfile-vue/inst/1/`，保留站点现有登录、API 和文件服务代理。以下 Nginx 配置支持直接访问和刷新资料库链接：

```nginx
location = /inst/1 { return 308 /inst/1/; }
location ^~ /inst/1/assets/ {
    root /srv/cloudfile-vue;
    try_files $uri =404;
}
location ^~ /inst/1/ {
    root /srv/cloudfile-vue;
    try_files $uri /inst/1/index.html;
}
```

## 多实例部署

在同一个门户下提供所有实例的 Vue 页面。首页 `/` 并行读取各实例当前账号可访问的库和共享根，按实例分组。尚未登录的实例显示连接按钮，单个实例离线时其他实例仍可浏览。访问 `/inst/2/` 只列出实例 2；库、目录书签和上传下载均沿用选库时的实例。保留原部署的编号 1，已有的 `/inst/1/{repoId}?root=…&path=…` 继续指向原库。

1. 在构建时设置 `VITE_CLOUDFILE_INSTANCES`。编号为 1–10 的整数，必须包含 1，编号不得重复。每个 `fileBase` 对应这个 Hub 实际签发的文件服务 URL 前缀，各实例的前缀须互不重叠。省略时为门户同源的 `/inst/{id}/seafhttp/`。
2. 将一份构建产物部署到门户的 `/srv/cloudfile-vue/inst/1/`。双实例 Nginx 示例见 [federation.nginx.conf](deploy/federation.nginx.conf)。在已有站点上追加页面和实例代理规则时，保留原生 Hub 路由。新增或移除实例时，同步更新前端登记和网关白名单。实例退役后保留编号，其旧链接应报不可用。
3. 每个 Hub 在同一套 authentik 注册独立应用和客户端。将该客户端及 Hub 的有效 `OAUTH_REDIRECT_URL` 都设为 `https://drive.example.com/inst/{id}/oauth/callback/`，并使用该应用自己的退出地址。门户使用 HTTPS，各 Hub 将其精确来源加入 `CSRF_TRUSTED_ORIGINS`。示例代理会剥离实例前缀，后端的原生 API、OAuth 和账号路由位于根路径。
4. 在各 Hub 的有效 Django 配置中分别设置 `SESSION_COOKIE_NAME = 'cfi1_session'`、`CSRF_COOKIE_NAME = 'cfi1_csrf'`（实例 2 改为 `cfi2_session`、`cfi2_csrf`）。Hub 使用仅当前主机有效、路径为 `/` 的 Cookie，网关将响应 Cookie 的路径改写到对应实例，并仅向上游传递该实例的会话及 CSRF 凭据。启用联邦时已有单实例用户首次访问需重新建立本地会话。
5. 为每个实例配置可达的文件服务，确保上传和下载签票均返回该实例的 `fileBase`。外部文件域名需允许门户来源的上传 POST 和 OPTIONS，并仅返回一份有效的 CORS 响应头。同源文件代理示例使用分实例路径，无需 CORS。检查生产部署中 Hub **实际签发**的地址；部分容器会从公开主机名派生文件地址。

双实例构建示例：

```sh
VITE_CLOUDFILE_INSTANCES='[{"id":1,"label":"主网盘","fileBase":"https://files-one.example.com/seafhttp/"},{"id":2,"label":"归档网盘","fileBase":"https://files-two.example.com/seafhttp/"}]' npm run build
```

未配置 `VITE_CLOUDFILE_INSTANCES` 时，仍使用原生无前缀 API、`sfcsrftoken`、`CLOUDFILE_DEV_UPSTREAM` 及可选的 `VITE_FILE_ORIGIN`。原单实例发布方式可继续使用。

## 联调复验

- 在浏览器连接第一个实例，再连接第二个实例。确认两个客户端各自回调，已登录 authentik 的用户按其策略复用登录。检查两个会话 Cookie 各自的名称和路径。
- 在两个隔离存储中准备相同 UUID 的测试库，分别在相同目录上传同名但字节不同的文件。用两个标签页重新打开深链接，核对上传会话、下载签票、文件服务地址和两个下载文件的摘要。
- 停用测试实例 2 后，从首页进入实例 1；恢复实例 2，清除其测试会话并直接打开其实例库书签。检查实例 1 的会话仍可使用，实例 2 回跳原库。
- 从门户退出后分别确认两个实例拒绝原会话。某个实例未确认退出时，门户保留待退出状态；恢复该实例后可继续退出。
