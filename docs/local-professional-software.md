<!-- generated-by: gsd-doc-writer -->
# 本地专业软件使用方案

> 用途：定义 Hub、Go fileserver 与 CloudFile Local Agent 2（Rust）之间的本地查看与编辑契约。
> 适用版本：Seafile CE 14.x，CloudFile V2。
> 状态：验证中（v2 scoped JWT + `/cf-edit/v1/*` 数据面已实现；仍缺签名发布包与跨平台升级）。

OnlyOffice 保持 Seafile CE 原生集成：由 Seafile 的文档配置、回调和部署参数负责，
CloudFile 不增加代理路由、会话接口或独立验收条件。

## 客户端范围

唯一在维护的桌面客户端是 **CloudFile Local Agent 2**（`cloudfile-local-agent2`，Rust）。
原 Go 版 `cloudfile-local-agent` 已停止开发，其 `cloudfile-local/v2` 会话文件协议与
`agent-sessions/claim/` 领取流程随之退役；不要按该协议开发新功能。

## 打开 URI 契约

```text
cloudfile-open://v2/open?instance=https%3A%2F%2Fcloudfile.example&session=<uuid>&ticket=<scoped-jwt>
```

| 参数 | 含义 | 校验 |
|---|---|---|
| `instance` | 签发票据的站点 origin | 必须与 Agent 受信任 origin 列表逐字匹配，拒绝重定向 |
| `session` | 本次打开请求的本地标识（随机 UUID） | 不是服务端会话记录，仅用于本地任务与 Journal 关联 |
| `ticket` | Hub 签发的 HS256 scoped JWT | 校验 `iss`/`aud`/`exp`，并绑定 `repo_id`/`path`/`file_id`/`mode` |

票据由 Hub `POST /api/v2.1/cloudfile/edit/v1/open/` 在已认证的浏览器会话内签发，
有效期上限 **24 小时（86400 秒）**，与 Go fileserver `cfEditClaimsFor` 的上限一致，
两处必须同批发布。选这个长度是因为 Guard 租约只有 10 分钟且靠 `renew` 滚动续期，
而票据是硬过期——给 1 小时会让长编辑在 Guard 仍有效时被 401 打断。浏览器、Chrome
扩展和文件系统都不接触内容 URL、写回凭据或 Seafile 登录凭据；Agent 用 `ticket`
直连 Go fileserver 的 `/seafhttp/cf-edit/v1/*`。

## 三种编辑模式

| mode | 允许的数据面操作 | 前置条件 |
|---|---|---|
| `local-view` | 仅 `read` | 用户对目标路径可读；只读是硬限制，账号可写也不放宽 |
| `optimistic-edit` | `read` / `status` / `publish`（`X-CF-Action: optimistic`） | 用户可写；不创建 Guard，Checkout 关闭时仍可用 |
| `exclusive-edit` | `checkout` / `renew` / `release` / `publish` | `CF_ENABLE_CHECKOUT` 开启且 `cf_edit_guard` 可用，否则 409 |

- 独占编辑只写 `cf_edit_guard` 单行（`repo_id` + `path_hash`），不建 Session/Intent/Device 表。
- 未确认的本地任务留在 Agent 的 Journal 中，服务端不保存编辑会话状态。
- `publish` 时服务端重新判定权限并校验原生 `file_id`；签发后被他人更新过的文件按冲突处理，
  Agent 不得静默覆盖。
- 票据过期、编辑提交完成或 Guard 释放后，Agent 必须删除本地临时文件与 Journal 记录。
- `cloudfile-open://v1/open` 已退役：Hub 前端只发 v2，收到旧前缀应拒绝而不是降级。

## 本地软件最小配置

首次安装只需要把 CloudFile 站点加入 Agent 的受信任 origin。Agent 对每一个打开成功的
本地任务按以下固定顺序选择本地软件：

1. 当前用户配置的 `open_rules`；
2. 本机自动检测的软件；
3. 操作系统当前的文件关联。

自动检测覆盖 Microsoft Word/Excel/PowerPoint/Visio、LibreOffice 和主流 CAD/三维工具：
AutoCAD、BricsCAD、DraftSight、Revit、SOLIDWORKS、Creo、NX、CATIA、SketchUp、Rhino
及 FreeCAD。Windows 优先使用用户或机器注册的 `App Paths`，再检查常见安装目录；只把
已存在的本地可执行文件作为候选，绝不从 Hub、Chrome 扩展或票据内容接收程序路径或命令。

`open_rules` 仅用于覆盖自动选择，例如指定某个 DWG 查看器。规则按顺序匹配，程序必须是
本机绝对路径，命令只允许一个 `{file}` 占位符，并使用参数数组启动、不经 shell。

## Chrome 扩展职责

扩展只做 URI 转发：把页面发起的 `cloudfile-open://v2/open?...` 交给 Native Messaging
Host。它不解析 JWT、不读 Cookie、不保存 Seafile token，也不显示可复制的票据。用户可在
扩展弹窗关闭自动打开；扩展只显示 Agent 已检测到的软件名称。

历史 `.cloudfile` 会话文件下载链随 Go 版 Agent 一起退役；扩展不再需要下载中间文件。

## 签出与释放

签出不再是 Hub 的独立 REST 资源。`exclusive-edit` 票据配合 `checkout` / `renew` /
`release` 完成同一件事，围栏值是 `cf_edit_guard` 的 Guard 标识，由服务端维护：

- 取编辑权：`exclusive-edit` 票据 → `POST /seafhttp/cf-edit/v1/checkout`
- 续租：`POST /seafhttp/cf-edit/v1/renew`
- 释放或签入结束：`POST /seafhttp/cf-edit/v1/release`
- 只读查看当前占用：`GET /api/v2.1/cloudfile/edit/v1/lock-info/`

读权限用户拿不到 `exclusive-edit` 票据，避免以锁阻塞真正的编辑者。锁定能力依赖
`CF_ENABLE_CHECKOUT`；C 端 Guard 存储不可用时返回冲突，不退化为 Hub 内的提示性记录。
