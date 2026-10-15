# OIDC 与旧 OAuth2 并行兼容

## 协议与入口

CloudFile Server 负责登录协议适配。Authentik 是推荐 IdP，不是强制依赖。
OIDC 基于 OAuth2；旧登录继续使用 `/oauth/login/` 和 `/oauth/callback/`，
新版入口为 `/api/v2.1/cloudfile/extensions/identity/v1/begin/` 和同前缀的 `callback/`。
两套 state、回调和会话验证各自独立，不转用对方的 Token。

开启 `CLOUDFILE_OIDC_ENABLED` 不再关闭 `ENABLE_OAUTH`，也不禁止 Authentik 旧 OAuth 预设。
当旧 OAuth 已启用时保留现有 `LOGIN_URL`；仅 OIDC 模式使用新版 begin 入口。
部署生成器及 Hub 启动配置均保留旧认证后端、`OAUTH_PROVIDER` 和既有账号绑定。
新增功能未通过实机验收前维持原来的默认关闭状态。

仅需旧登录时设置 `CF_SSO_OAUTH_ENABLED=true`，仍可保持 `CF_ENABLE_SSO=false`，
避免启动旧目录同步发布器。既有 `CF_SSO_OAUTH_*` 和 EAP 登录适配配置保持有效。

## 账号与会话边界

- 新 OIDC 使用 issuer + sub 绑定；不根据邮箱自动合并账号。
- 不修改旧 `SocialAuthUser` 数据；迁移前保持旧 Provider 和 subject 稳定。
- 共用文件列表接受已配置的旧 OAuth 后端会话和原有 OIDC 会话。
  两者都要求现存、启用的原生账号和双向唯一的 `Profile.login_id` 映射，继续走相同 ACL。
- 旧会话在列表返回前后检查数据库中签名会话、过期时间、用户名与后端。
  Django 与授权 SQL 必须通过原有数据库同机证明，会话表必须为 InnoDB。
- 新版 OIDC 下载票据仍要求 OIDC 会话，不把旧会话伪装成 OIDC 会话。
  本次并行配置与列表适配不等于全部文件读写或旧 Agent 已完成验收。
- Agent 2.2 继续采用设备配对、签名挑战和受限授权，不增加 OAuth/OIDC Token 登录分支。

## 当前验证与待完成项

2026-10-15 的本地回归覆盖并行配置、保留旧 Provider、会话撤销/过期/切换、
账号重载、OIDC 票据隔离、身份绑定及设备证明。测试使用隔离环境，不能代替真实 IdP 与数据库验收。

仍需完成：

1. 在原 dev 验证登出和禁用账号；真实新版回调和同账号映射已核验。
2. 新版运行时使用明确端点；部署前可通过 Docker 仓库 `tools/oidc-discover.py`
   从固定 issuer 的 Discovery 生成配置，严格校验 issuer、RS256、PKCE 及客户端认证方式。
   工具不跟随重定向，不向 Discovery 发送客户端密钥，输出文件权限为 0600。
3. 通用 IdP 当前可配置 `user_id_claim`，但账号准备仍依赖目录服务。
   不可把不同 issuer 下的相同 sub 当作共用业务 UID；通用无目录部署需要额外设计和验收。
4. 旧会话与旧 Agent 的下载、上传及编辑链逐项验证；新版票据仍有原生数据面 OIDC 约束。
5. Agent 2.2 与目标部署进行设备配对、撤销和实际文件操作联调。

Authentik Provider 的 issuer 模式与 subject 模式应固定，不能在迁移时随意改变。
参见 [Authentik 官方 OAuth2/OIDC 文档](https://docs.goauthentik.io/add-secure-apps/providers/oauth2/)。

## 原 dev 部署验证（2026-10-15）

- 主机 `minio157`，目录 `/data/etech-infra/cloudfile-dev`。
- 镜像 `cloudfile:dual-login-dev-20261015-r2`；仅替换 app、worker、JIT 的 dev 服务。
- 回退配置位于 `backups/dual-login-20261015/compose-before.json`，原设置也已备份。
- 两个 begin 入口均 302 到 dev Authentik，回调地址各自独立，应用健康检查通过。
- Discovery 元数据与已配置 issuer、授权/token/userinfo/JWKS 端点一致。
- 新版真实登录成功，资料库列表可见；同一用户存在旧 OAuth 与新 OIDC 绑定和会话。
- 登录前后 2909 个原生账号、2909 个 Profile、38 个旧绑定及 1 个新绑定的数量和摘要均未变化。
- 旧 EAP 回调改为复用同 issuer 的新版目录资源，保留 UID、工号及账号冲突校验，不启动旧目录发布器。
- 修复后新旧真实回调与资料库列表均通过；切换到旧入口产生 OAuth 后端会话，再切回新版产生原生 OIDC 会话。
- 同一共享资料库详情在新旧会话下均拒绝访问；目录权限需独立排查，不能将列表成功视为文件操作通过。
- 修复后新旧真实回调与资料库列表均通过；切换到旧入口产生 OAuth 后端会话，再切回新版产生原生 OIDC 会话。
- 同一共享资料库详情在新旧会话下均拒绝访问；目录权限需独立排查，不能将列表成功视为文件操作通过。
- 文件读写、旧 Agent、登出和禁用账号仍需完整验收。
