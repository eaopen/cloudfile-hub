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

- 目录分页显式 `with_display_metadata=true` 时，将 `tags` 与 `tag_status` 直接合入
  当前已授权页的 `dirent_list[]`，不再返回独立 `tag_batch`。标签对象保持独立批量接口
  的原生结构；不重复检查文件存在性，也不按条目发 HTTP/RPC 请求。成功空标签为
  `tag_status=OK, tags=[]`；读取失败为 `FAILED, tags=null`，不阻断目录浏览。
- EAP 直接转换每项 V2 `source/tag_name` 为浏览器 `items[].tags: string[]`，去重保序，
  以 `items[].tagStatus` 保留状态，不再输出顶层 `tagBatch`。系统词表/展示名仍由 EAP 管理。
- CloudFile 已统一计算父目录 `user_perm` 和逐项 `permission`；EAP 新链路只保留本地
  业务库状态/作用域门禁，不再预查远程库/目录权限或补读标签。管理操作独立授权。
- 独立 `file-tags/batch` 及单个标签增删改协议不变；分页协议变更需要 CloudFile、EAP
  和前端配套更新。旧 EAP 不会消费新的条目标签；旧 CloudFile 不提供新的条目字段。
- 不新增表、缓存、功能开关、第三套标签读引擎，也不恢复 v0.9 标签服务。

CI 专项包含多来源标签、跨目录、拒绝访问、缺失对象、重复项、失败不伪空
与目录页内联。现场 Dev 需要进一步验证具体账号权限和耗时。
