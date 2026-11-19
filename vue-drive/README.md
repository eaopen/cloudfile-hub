# CloudFile Vue 网盘

实例 1 的资料库入口为 `/inst/1/`，资料库地址为 `/inst/1/{repoId}`。目录深链接使用 `path` 查询参数，共享目录入口额外保留 `root`。服务端负责检查每次请求的权限。首版接入一个 Hub，使用其 authentik 登录、会话、资料库和共享目录发现、分页目录、上传会话和下载链接接口。

## 本地验证

使用 Node.js 22.12 或更新版本，在本目录运行：

```sh
npm ci
npm test
npm run build
CLOUDFILE_DEV_UPSTREAM=http://127.0.0.1:8000 npm run dev
```

在开发服务器的 `/inst/1/` 打开页面。将代理目标改为包含 Hub 和文件服务的实际网关。联调时，Hub 的公开地址、authentik 回调与文件服务生成的链接应匹配浏览器地址，并在 Hub 的 CSRF 可信来源中配置该精确来源（含端口）。独立文件服务可在构建时用 `VITE_FILE_ORIGIN` 指定可信来源，并在文件服务配置上传 CORS。

## 发布

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
