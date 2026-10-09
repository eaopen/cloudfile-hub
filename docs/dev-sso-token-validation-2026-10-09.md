# Dev 身份兼容方案验证（2026-10-09）

## 范围与结论

经用户授权，已提交 Hub 修复并更新 dev 常驻 CloudFile 主服务及 worker。未操作生产，未修改或重启 EAP、Authentik。真实 dev HTTP 接口及外部入口验证通过；浏览器完整 EAP 登录、菜单流程仍未验收。生产库管理员修复以用户提供记录为准，本轮不作生产核验。

本地已找到提交 4cf2df4ef 的已核验别名模块：原用途为库管理员授权，未覆盖管理员取令牌及 account-info。dev 复查原工号取令牌仍为 404。补丁复用同一份 CF_LIBRARY_ADMIN_IDENTITY_ALIASES，避免另建账号或另一份映射。

## 修改

- EmployeeTokenView：继承原管理员鉴权、限流，优先核验显式别名的 Profile、OAuth 双向绑定、账号启用状态和别名占用；映射过期即拒绝，不回退到其他账号。未配置别名且原接口返回 404 时，使用已认证 v2 目录确认工号、稳定业务 UID 与唯一原账号。
- EmployeeAccountInfo：独立开关开启后，仅为显式已核验别名返回工号 email，并附 native_email；request.user、资料库权限及存储身份仍使用原账号。未配置别名的账号保持原响应。绑定变更返回 503，错误中不含令牌或内部异常。
- 两个开关 CF_EAP_ADMIN_TOKEN_IDENTITY_BRIDGE、CF_EAP_ACCOUNT_INFO_IDENTITY_BRIDGE 均默认 False，只接受 Python 布尔 True。通过扩展 URL 注册，不修改上游文件。

原因：EAP 的 verifyCookieIdentity 将 account-info.email 与当前工号技术身份精确比较；只修复令牌接口无法处理存量不透明账号的 Cookie。独立呈现开关用于明确接受这一接口兼容契约，禁止未经审核为所有用户推导显示身份。

## 验证结果

- dev 原生 Cookie 的 account-info 确实返回旧原生身份；同一会话通过候选视图及原 SessionAuthentication，返回工号身份 200，权限主体仍为原账号。
- 已核验别名取令牌 200，令牌属于原账号；未使用新增账号。
- 使用临时真实 Cookie 调用常驻 dev HTTP 接口：etech01 根目录 200（46 项），子目录 200（3 项）。临时会话已在 finally 删除。
- OAuth subject、业务 UID、工号任一映射不一致时，两个候选接口均 503；匿名访问 403；False 和字符串 false 均不启用兼容。
- 原账号 Profile、OAuth 绑定、私人资料库和 99 个群组关系检查前后相同。
- 在 dev 独立进程从 Django 初始化开始加载补丁，完整 django.setup 通过；两个 URL 都解析到候选扩展视图。
- 78 项相关回归测试通过，git diff --check 通过。本地 pytest 缺少 pytest-django，保留一条 DJANGO_SETTINGS_MODULE 配置警告；真实 Django 与会话验证在 dev 容器完成。
- 上轮首次建号及重复 provision 复用验证通过，临时账号已清理；不等同完整浏览器 OAuth 跳转验证。

## 配置与回滚边界

只在已审核的部署 seahub_settings.py 中使用 Python 布尔配置，不假定新变量会自动从 compose 环境导入：

```python
CF_EAP_ADMIN_TOKEN_IDENTITY_BRIDGE = True
CF_EAP_ACCOUNT_INFO_IDENTITY_BRIDGE = True
# CF_LIBRARY_ADMIN_IDENTITY_ALIASES 复用经核验的环境专属配置。
# 不可复制其他环境的 native_user、provider 或 oauth_subject。
```

开启 account-info 开关会改变被映射用户在该接口的 email 呈现；其他客户端兼容性仍须验收。关闭两个开关即可恢复原生接口行为，映射与原账号均保留。回滚可能恢复原有 EAP 身份不一致问题，不是数据回滚。

## 尚未完成

1. 真实浏览器 EAP 登录、菜单访问端到端验收。常驻 dev 部署和真实 HTTP 已完成，但未使用浏览器会话验证 EAP 转发流程。
2. dev 同步任务此前被删除保护拒绝：计划删除 104/5735 个受管成员关系，允许比例 0%。本轮未改同步策略，也未删除成员关系，须单独核查差异。
3. 生产部署和验证须用户另行明确授权。任何方案均遵守不重启生产 EAP。

## 常驻 Dev 部署与验收（12:30 +08:00）

- 代码提交：022869fb3（身份桥）、049c08746（启动配置覆盖修复）。当前运行镜像为 cloudfile/cloudfile:eap-alias-049c08746-app-dev、cloudfile/cloudfile:eap-alias-049c08746-worker-dev。
- 两个镜像以原 dev 镜像为基础，仅复制本次扩展文件及已提交的 library_admin_identity 依赖；未整体发布本地其他项目。
- 重建范围严格限定 cloudfile-dev 项目的 cloudfile、cloudfile-worker，使用 --no-deps --pull never。主服务 healthy，worker running，检查时两者重启计数 0。
- 启动脚本将默认配置 import 移到操作员设置之后，原显式默认值会覆盖 True；已移除导出的两个开关常量，由视图提供缺省 False，增加回归测试，确保重建后显式配置仍生效。
- 在容器内服务地址及外部 dev 入口 http://10.9.8.162:6111/seafile 分别验证：工号管理员取令牌 200；Cookie/Token 的 account-info 200 且匹配已核验工号；两种认证访问 etech01 根目录均 200/46 项、子目录均 200/3 项；匿名 403、未知工号 503。
- 比较前后 Profile、OAuth、群组及个人资料库均一致，临时会话已清理。没有建立重复账号。
- 只为 dev 经目录重新核验的邓鹏绑定启用显式别名；未将生产 native_user 或 OAuth subject 复制到 dev。

备份和回滚脚本位于 dev 专属目录：

```text
/data/etech-infra/cloudfile-dev/backups/eap-alias-022869fb3/
/data/etech-infra/cloudfile-dev/backups/eap-alias-022869fb3/rollback.sh
```

备份包括原 Compose、镜像标识、.env 和 seahub_settings.py，目录权限 700，不写入 Git。回滚脚本仅恢复这些 dev 配置并重建两个 dev 服务，不恢复数据库、不操作其他环境。
