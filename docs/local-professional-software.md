<!-- generated-by: gsd-doc-writer -->
# 本地专业软件使用方案

> 用途：定义 Hub 与 CloudFile Local Agent 之间的本地查看、编辑和签出契约。
> 适用版本：Seafile CE 14.x。
> 状态：部分完成（后端会话与围栏逻辑已实现；浏览器下载链仍有阻断项，2026-08-11）。

OnlyOffice 保持 Seafile CE 原生集成：由 Seafile 的文档配置、回调和部署参数负责，
CloudFile 不增加代理路由、会话接口或独立验收条件。

CloudFile 的本地查看和本地编辑统一使用 `cloudfile-local/v2` 会话文件。浏览器只在
用户请求后下载短时 `*.cloudfile` 文件；绿色版 CloudFile Local 和已安装版 CloudFile
Local 使用相同的文件关联或命令行打开该文件，再按本机策略调用 PDF、CAD、图像等专业
应用。浏览器不直接连接本机端口，也不显示可复制的访问令牌。

当前 Hub API 已实现 v2 ticket、claim、心跳和带 generation 的回写；但 React 下载函数
读取 `session.file.name`，创建会话的响应当前没有 `file` 字段。修正并完成浏览器 + Agent
端到端验收前，本能力不能标为“已完成”。

## 会话文件契约

```json
{
  "protocol": "cloudfile-local/v2",
  "server": "https://cloudfile.example",
  "ticket": "single-claim-opaque-ticket",
  "expires_at": 1760000000
}
```

- 下载文件只携带一次性 ticket；Agent 以 `POST /api/v2.1/cloudfile/agent-sessions/claim/`
  领取后才收到短时下载 URL，编辑会话另收到 write-back capability 与心跳 URL。
- ticket 在 30–60 秒领取窗口内只能领取一次（当前默认 60 秒）；浏览器、扩展和会话文件都不接触内容 URL、写回 capability
  或 Seafile 登录凭据。
- `local-view` 下载为只读副本；`local-edit` 必须以 `multipart/form-data` 的 `file` 字段
  PUT 回写，并由服务端再次校验租约 owner、generation 和源文件版本。
- Agent 不得把会话文件、票据、URL 或文件内容上传到第三方服务；过期、回写成功或租约
  失效后必须删除本地临时文件与会话文件。

## 本地软件最小配置

首次安装只需要把 CloudFile 站点加入 Agent 的受信任 origin。Agent 对每一个领取成功的
会话按以下固定顺序选择本地软件：

1. 当前用户配置的 `open_rules`；
2. 本机自动检测的软件；
3. 操作系统当前的文件关联。

自动检测覆盖 Microsoft Word/Excel/PowerPoint/Visio、LibreOffice 和主流 CAD/三维工具：
AutoCAD、BricsCAD、DraftSight、Revit、SOLIDWORKS、Creo、NX、CATIA、SketchUp、Rhino
及 FreeCAD。Windows 优先使用用户或机器注册的 `App Paths`，再检查常见安装目录；只把
已存在的本地可执行文件作为候选，绝不从会话文件、Hub 或 Chrome 扩展接收程序路径或命令。

`open_rules` 仅用于覆盖自动选择，例如指定某个 DWG 查看器。规则按顺序匹配，程序必须是
本机绝对路径，命令只允许一个 `{file}` 占位符，并使用参数数组启动、不经 shell。远端会话
始终只携带站点、一次性 ticket 和过期时间。

Chrome 扩展默认把下载完成的 `.cloudfile`（含浏览器生成的 `blob:` 下载）交给 Native
Messaging Agent；用户可在扩展弹窗关闭自动打开。扩展仅显示 Agent 已检测到的软件名称，
不读取或保存程序路径、浏览器 Cookie 或 Seafile token。

## 手工与第三方签出

`POST /api/v2.1/cloudfile/repos/<repo_id>/checkout/` 是唯一签出入口，须使用有编辑权限
的 Seafile 登录会话或 API token：

```json
{"path":"/设计/assembly.step","source":"manual"}
```

第三方程序把 `source` 改为 `third-party`。成功响应中的 `generation` 是签入时必须携带
的围栏值；使用相同身份调用 `DELETE` 并提交 `path`、`generation` 才能释放。读权限
用户不能创建本地编辑会话或签出，避免以锁阻塞真正的编辑者。

签出与本地编辑都依赖 `CF_ENABLE_FILE_LOCK=true` 和 CE 的 `lock_backend=cloudfile`。
如果 C 端锁提供者未注册，接口返回冲突，不退化为 Hub 内的提示性记录。
