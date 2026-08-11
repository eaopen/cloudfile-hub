<!-- generated-by: gsd-doc-writer -->
# CloudFile Hub 配置

> 用途：记录 Hub 代码实际读取的 `CF_*` 设置、默认值和生效边界。
> 适用版本：Seafile CE 14.x。
> 状态：已完成（与 `cloudfile_ext/settings_defaults.py` 及调用点核对，2026-08-11）。

## 配置来源

本仓不包含可直接编辑的生产 `conf/seahub_settings.py`。部署侧生成该文件，并先导入：

```python
from cloudfile_ext.settings_defaults import *
```

随后覆盖部署值。`EXTRA_INSTALLED_APPS = ['cloudfile_ext']` 由 Seahub 的 `EXTRA_<SETTING>` 机制追加到 `INSTALLED_APPS`。环境变量到 Python setting 的转换规则属于 `cloudfile-docker`，本页只描述 Hub 看到的最终 Django setting。

## 功能开关

全部默认 `False`，且只有严格的布尔值 `True` 才算开启。

| Setting | 默认值 | 当前 Hub 状态 |
|---|---:|---|
| `CF_ENABLE_SSO` | `False` | 组织映射验证中；登录复用 CE |
| `CF_ENABLE_DIR_ACL` | `False` | 验证中 |
| `CF_ENABLE_AUDIT` | `False` | 部分完成 |
| `CF_ENABLE_METADATA` | `False` | 规划 |
| `CF_ENABLE_TAGS` | `False` | 规划 |
| `CF_ENABLE_SEARCH` | `False` | 验证中 |
| `CF_ENABLE_FILE_PREVIEW` | `False` | 部分完成 |
| `CF_ENABLE_ONLYOFFICE` | `False` | CE 复用；CloudFile 回调未注册 |
| `CF_ENABLE_FILE_LOCK` | `False` | 验证中 |
| `CF_ENABLE_WATCH` | `False` | 验证中；复用 CE monitored-repos API 并放开非 Pro gate |
| `CF_ENABLE_CONVERT_EXPORT` | `False` | 规划 |
| `CF_ENABLE_CHECKOUT` | `False` | 验证中 |
| `CF_ENABLE_LOCAL_APP` | `False` | 部分完成 |
| `CF_ENABLE_S3_STORAGE` | `False` | Hub 仅有维护脚本边界 |
| `CF_ENABLE_EXTERNAL_SOURCES` | `False` | 验证中 |

不要仅凭开关存在判断能力可用，详细证据见 [能力矩阵](CAPABILITIES.md)。

## Provider 选择

| Setting | 默认值 | 可用值/说明 |
|---|---|---|
| `CF_PROVIDER_SEARCH` | `''` | 空值走 CE SeaSearch/Elasticsearch；当前 CloudFile 可注册 `meilisearch` |
| `CF_PROVIDER_ACL_RULE_SOURCE` | `''` | 未选时 ACL 使用本地数据库；可显式选 `local-db`；`external-service` 未实现 |
| `CF_PROVIDER_SSO_DIRECTORY` | `''` | 空值不做组映射；可选 `static`、`external-service` |

非空但未注册的名称在第一次使用时抛出 `UnknownProvider`，不会自动降级。

## 数据库

| Setting | 默认值 | 必需性 | 说明 |
|---|---|---|---|
| `CF_DATABASE_ALIAS` | `'cloudfile'` | 可选 | Django 连接别名 |
| `CF_DATABASE_NAME` | `''` | 使用 `cf_*` 能力时必需 | 为空时不创建额外连接 |
| `CF_DATABASE_USER` | `''` | 随部署 | 用户名 |
| `CF_DATABASE_PASSWORD` | `''` | 随部署 | 密码；不得写入文档或仓库 |
| `CF_DATABASE_HOST` | `''` | 随部署 | 主机 |
| `CF_DATABASE_PORT` | `'3306'` | 可选 | MySQL 端口 |

`CloudFileConfig.ready()` 使用这些标量建立 MySQL 连接并追加 `CloudFileRouter`。所有 `cloudfile_ext` 模型都 `managed=False`，DDL 由 `cloudfile-server/scripts/sql/*/cloudfile.sql` 管理，禁止用 `manage.py migrate` 创建 `cf_*` 表。

## ACL 与 SSO

| Setting | 默认值 | 说明 |
|---|---:|---|
| `CF_ACL_CACHE_TTL` | `30` | Hub 进程内 repo ACL 缓存秒数 |
| `CF_SSO_GROUP_OWNER` | `''` | 同步创建组的所有者；为空时同步拒绝执行 |
| `CF_SSO_SYNC_INTERVAL` | `600` | 全量同步秒数；运行时最小 60 |
| `CF_SSO_MAX_REMOVAL_RATIO` | `0.5` | 单次允许删除的受管成员比例；空字符串取消限制 |
| `CF_SSO_DIRECTORY_STATIC` | `[]` | static provider 的 `{external_id, name, members}` 列表 |

外部目录服务使用动态设置 `CF_SERVICE_SSO_DIRECTORY_{URL,SECRET,TIMEOUT,RETRIES,ON_FAILURE}`。URL 未设置时 external-service provider 拒绝工作；secret 同时用于出站 token 和 webhook 验证。生产值由部署密钥管理提供，不在仓库中定义。

## 搜索与外部源

| Setting | 默认值 | 说明 |
|---|---:|---|
| `CF_MEILISEARCH_URL` | `http://meilisearch:7700` | 仅选择 Meilisearch 时使用 |
| `CF_MEILISEARCH_API_KEY` | `''` | Meilisearch API key |
| `CF_MEILISEARCH_TIMEOUT` | `5` | 单次 HTTP 调用超时秒数 |
| `CF_SEARCH_INDEX_INTERVAL` | `60` | 增量索引周期；运行时最小 15 |
| `CF_SEARCH_INDEX_TEXT_MAX_BYTES` | `1048576` | 纯文本内容索引上限；其他文件只索引元数据 |
| `CF_EXTERNAL_SOURCES_ROOTS` | `['/shared/external']` | 外部源允许根目录；不得配置为 `/` |
| `CF_EXTERNAL_SCAN_INTERVAL` | 代码回退 `60` | 外部源扫描周期；运行时最小 15 |
| `CF_EXTERNAL_SCAN_MAX_DIRS` | 代码回退 `20` | 每个 tick 最多扫描目录数 |
| `CF_EXTERNAL_SCAN_MAX_FILES` | 代码回退 `2000` | 每个 tick 最多提交文件数 |

最后三个扫描设置没有写入 `settings_defaults.py`，由调用点提供回退值；部署若覆盖应传可转换为正整数的值。

## 文件动作

| Setting | 默认值 | 说明 |
|---|---:|---|
| `CF_FILE_ACTION_PREVIEW_EXTENSIONS` | 代码中的文档/文本/图像/音视频扩展名元组 | 哪些文件显示 CE 原生预览动作 |
| `CF_FILE_ACTION_OFFICE_EXTENSIONS` | Office/ODF/CSV/PDF 元组 | 预留的 office 分类；当前文件动作策略未使用该设置 |
| `CF_LOCAL_APP_SESSION_TTL` | `300` | 配置值会被 claim ticket 逻辑收敛到 30–60 秒；当前默认实际为 60 秒 |

领取后的 `local-view` capability 为 5 分钟，`local-edit` capability 与租约为 30 分钟并可心跳续租；这些时长当前写在服务代码中，不是独立 setting。

## 外部服务通用设置

`ExternalService.from_settings(name)` 动态读取：

```text
CF_SERVICE_<NAME>_URL
CF_SERVICE_<NAME>_SECRET
CF_SERVICE_<NAME>_TIMEOUT     # 默认 10 秒
CF_SERVICE_<NAME>_RETRIES     # 默认 2 次
CF_SERVICE_<NAME>_ON_FAILURE  # closed 或 open
```

外部服务只允许用于同步、webhook 或其他非同步权限路径；目录 ACL 的请求期权限检查不得发出网络调用。

## 环境覆盖

开发、测试、生产的差异由各自生成的 `seahub_settings.py` 管理。本仓没有 `.env.example` 或环境专用 settings 文件；生产 secret、服务 URL、域名和数据库地址均需在部署仓配置并通过部署生成器验证。
