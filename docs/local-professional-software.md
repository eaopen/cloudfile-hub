# 本地专业软件使用方案

OnlyOffice 保持 Seafile CE 原生集成：由 Seafile 的文档配置、回调和部署参数负责，
CloudFile 不增加代理路由、会话接口或独立验收条件。

CloudFile 的本地查看和本地编辑统一使用 `cloudfile-local/v1` 会话文件。浏览器只在
用户请求后下载短时 `*.cloudfile` 文件；绿色版 CloudFile Local 和已安装版 CloudFile
Local 使用相同的文件关联或命令行打开该文件，再按本机策略调用 PDF、CAD、图像等专业
应用。浏览器不直接连接本机端口，也不显示可复制的访问令牌。

## 会话文件契约

```json
{
  "protocol": "cloudfile-local/v1",
  "mode": "local-edit",
  "expires_in": 300,
  "file": {
    "name": "drawing.dwg",
    "content_url": "/thirdparty-editor/file-content/?access_token=..."
  },
  "writeback": {
    "content_url": "/api/v2.1/cloudfile/agent-sessions/.../content/",
    "generation": "..."
  }
}
```

- `local-view` 只有 `file`，Agent 下载为只读副本。
- `local-edit` 同时包含 `writeback`。Agent 必须在有效期内以 `multipart/form-data`
  的 `file` 字段 PUT 回写；服务端再次校验租约 owner、generation 和源文件版本。
- Agent 不得把会话文件、URL 或文件内容上传到第三方服务；过期、回写成功或租约失效后
  必须删除本地临时文件与会话文件。

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
