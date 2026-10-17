# V2 原生标签批量读取（只读）

## 调用

- `GET /api/v2.1/cloudfile/tags/batch/`：当前用户认证后查询固定能力预算。
  `version=2, model=cloudfile-tag-read, max_items=200, max_bytes=65536, max_path_bytes=4096`。
- `POST`：`{"version":2,"repo_id":"<UUID>","items":[{"path":"/A/a.txt","is_dir":false}]}`。
  同库批量，可跨多个目录，不接受用户名、主体或跳过 ACL 参数。
- 响应：`{"version":2,"model":"cloudfile-tag-read","repo_id":"<UUID>","items":[{"path":"/A/a.txt","is_dir":false,"status":"OK","tags":[{"source":"repo","file_tag_id":1,"repo_tag_id":2,"tag_name":"SYS_XXX","tag_color":"#abc"},{"source":"legacy","legacy_tag_id":3,"tag_name":"自由标签","read_only":true}]}]}`。
  失败项 `DENIED/NOT_FOUND` 的 `tags` 为 null；只有 `OK` 的空数组表示“确实无标签”。

当前登录身份由 Seafile Token/Session 认证提供。先用 V2 `Authority` 计算精确目标
的有效 ACL，再核对当前原生对象存在且类型匹配；仅将授权且存在的对象交给现有
`tag_reads.read()` 做两类索引批量 SQL 查询。根目录对象不支持在此读标签。
权限/身份/原生/SQL 故障不回退为无授权、空标签或逐项 HTTP 扇出；返回 503。

## 与分页及 EAP 集成

- `items-page` 显式 `with_display_metadata=true` 时，仅对已授权的当前页附带
  同结构 `tag_batch`，不重复检查文件存在性；标签失败只把每项置为 `FAILED`。
- EAP 转换 V2 `source/tag_name` 为既有浏览器 `tags: string[]`，去重保序。
  系统词表/展示名仍由 EAP 管理；不再要求旧 FileTag 的 `creator` 字段。
- EAP 对外 `file-tags/batch`、单个标签增删改和前端 DTO 不变。
- 不新增表、缓存、功能开关、第三套标签读引擎，也不恢复 v0.9 标签服务。

CI 专项包含多来源标签、跨目录、拒绝访问、缺失对象、重复项、失败不伪空
与目录页内联。现场 Dev 需要进一步验证具体账号权限和耗时。
