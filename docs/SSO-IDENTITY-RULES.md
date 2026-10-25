# CloudFile SSO 统一用户身份规则

> 当前 V2 开发主线为 `dev`。本方案由 PR #35 唯一交付，选择性吸收 PR #34 的旧 OAuth UID 校验与协议验证；不恢复已退役的 EAP OAuth 桥接。尚未进行真实 DEV 身份及权限验收。

## 1. 唯一业务身份、认证身份、原生账号

在 企业 Directory 部署中，**业务 UID 是唯一业务身份**。CloudFile 使用现有 `Profile.login_id = 业务 UID`，以及唯一的 `Profile.user` 对应原生 Seafile `EmailUser.email`。原生账号可以是旧工号账号、预创建账号或不透明账号；不重命名、不搬迁文件。

OAuth2/OIDC 的 `provider + sub` 是 **外部认证凭证的标识**，不是业务 UID；同一人经多个 IdP 验证可对应多个 provider/sub，但这些绑定必须全部落在同一 `Profile.login_id` 指向的原生账号。

| 字段 | 语义 | 是否用于自动合并 |
| --- | --- | --- |
| 企业 Directory `userId` / CloudFile `login_id` | 唯一业务 UID | 是；仅限受信来源验证、严格等值且原生账号活跃 |
| OIDC `iss + sub` | IdP 主体（`sub` 只在 issuer 内唯一） | 只能验证后建立对应业务 UID 的认证绑定 |
| OAuth `provider + uid` | 旧 OAuth 受信主体 | 只可绑定已验证的唯一业务 UID |
| Seafile `Profile.user` / `EmailUser.email` | 原生文件拥有者与会话主体 | 一旦建立即保持不变 |
| 邮箱、昵称、工号、preferred_username | 辅助属性、展示、可能变更或复用 | **禁止**作为身份归并依据 |

通用 CloudFile 部署可把 `login_id` 绑定到其受信组织目录的不可回收 UID，但不能把任意 OIDC `sub`、用户自行可编辑的邮箱或员工编号直接声明为 业务 UID。

## 2. 支持的登录入口

身份来源字段 `identity_source` 的规范值为 `directory`（企业 Directory 来源）；旧值 `enterprise-directory` 继续兼容。省略该字段表示沿用原有 OAuth Provider 来源，不会按目录身份处理。


1. **enterprise Directory 认证 / 内部调用**：enterprise Directory 的受信目录和服务凭证负责传递 业务 UID；CloudFile 查找已存在且启用的原生账号，或按既有 enterprise Directory 预创建流程建号。enterprise Directory 门户的自身会话不能直接替代 CloudFile 登录证明。
2. **旧 OAuth2（含旧 ssoauth/Authentik 配置）**：保留 `/oauth/login/`、`/oauth/callback/` 和现有 Provider。只有管理员将可信 UserInfo `userId` 显式映射为 `login_id` 且该 claim 存在时，才强制从精确 UID 选已有原生账号，并验证 `sub` 与原生绑定；冲突、账号不存在或无效时拒绝登录。未映射可信 `userId` 的通用旧 OAuth 保留原生兼容流程，不将员工号或邮箱误当成 业务 UID。
3. **enterprise Directory 集成**：最新 V2 `dev` 已隔离历史 `cloudfile_ext/sso/eap_oauth.py` 模块，若启用 `CF_SSO_EAP_PROFILE_IDENTITY=true` 则明确拒绝，不恢复旧分支。enterprise Directory 采用可信 `userId` 映射的 OAuth、原生 V2 OIDC 与目录接口，不以工号归并账号。
4. **独立 OIDC（Authentik、ssoauth 或其他合规 IdP）**：`/api/v2.1/cloudfile/extensions/identity/v1/begin/` 和 `callback/` 验证固定 issuer、client audience、签名、nonce、state、PKCE、UserInfo `sub`、可信业务 UID 声明后，基于 UID 选同一原生账号。多个 issuer 的同名 `sub` 互不混用。

`/oidc/login/` 是 Seahub OAuth 入口的 OIDC 适配；也须检查 ID Token，而不能仅以拿到 access token 当作身份验证。

## 3. 统一 UID 关联流程

```text
可信 业务 UID / 旧 OAuth UserInfo / 已验证的 OIDC ID Token
    → 提取并验证 canonical business UID
    → 通过 Profile.login_id 精确查唯一原生账号
    → 检查原生 EmailUser 启用、非系统管理员、UID 无冲突
    → 检查现有 provider/sub（不可指向另一账号）
    → 必要时记录新 provider/sub → 原原生账号（事务 + 审计）
    → 对 enterprise Directory/配置的目录读取当前 UID 状态及组织权限
    → 最终重检 UID、活动状态、subject 准备及权限
    → 建立会话，沿用原生 CE ACL / File Server 授权
```

**新 OIDC 首次关联的优化**：若已有 UID 账号但尚无当前 issuer/sub 绑定，即使未允许创建新账号的 JIT，也可在 OIDC 已验证、受信 Directory 确认为活动用户后，原位追加绑定并审计；不改变 `Profile.login_id`，不创建第二个用户。UID 没有现存账号时才走既有受限 JIT/预创建通路，并遵守是否允许新建的原规则。

严禁把以下冲突当作成功登录：相同 provider/sub 指向别的账号、不同 UID 争夺同一账号、大小写/排序规则近似匹配、已禁用主体、目录不可用、过期 OIDC 状态/签名或不一致的 `userId`。返回认证错误或需要管理员处理；**不要自动迁移历史账户或文件归属**。

## 4. 部署接入约束

- enterprise Directory / Authentik 映射需由管理员固定并保证业务 UID 不可由最终用户自助更改。
- 旧 OAuth 的 `OAUTH_ATTRIBUTE_MAP`：可信 `userId` → `login_id`，稳定的 `sub` → `uid`。不能把邮箱或 `preferred_username` 假定为 业务 UID；没有映射的旧 OAuth 继续原生兼容。
- 新 OIDC 使用受信 `user_id_claim`（enterprise Directory 通常为 `userId`）与固定 issuer；不得把不同 issuer 的 `sub` 直接互认。
- 目录未接通时只允许既有明确可信的 UID 映射登录；不通过邮箱、工号或用户输入绕过目录验证。
- 不增加用户影子表、Feature Flag、一次性多账号迁移任务或 enterprise Directory 专用表；复用 `Profile`、`SocialAuthUser` 和已有审计。
- 旧登录 Session、OIDC Session 仍按原有各自的协议和撤销规则验证；身份相同不等于 Token 可以跨协议使用。

## 5. 检查与收口

**专项代码检查**：两套登录都回到同一个 `login_id`；变更邮件/工号不改变文件访问账号；新 issuer/sub 原位关联幂等；issuer+sub 冲突拒绝；大小写别名拒绝；禁用/目录离线拒绝；JIT 禁用时仅允许现存 UID 的新绑定；原生账户缺失时按旧 JIT 规则处理。

**DEV 验收（尚未执行）**：同一 业务 UID 分别通过旧 OAuth、ssoauth/Authentik OIDC 和 enterprise Directory 入口完成登录；核对 `Profile.login_id`、`Profile.user`、社会绑定和原有资料库/目录授权一致。另核对跨账号冲突、登出、撤销、旧 Agent 文件访问，不能用“登录成功/资料库列表出现”代表读写权限已通过。

交付策略：PR #35 吸收 #34 必需的可信 UID 严格关联、OAuth state 和 `/oidc/login/` nonce/ID Token 检查，作为单一 PR 合并 `dev`；#34 关闭，不单独合入。当前 Docker 默认旧 OAuth 可能仍配置 `preferred_username` 为 `login_id`，不代表已升级为 业务 UID。Server / Docker 没有随本 PR 修改，发布时需另行确认三仓版本；本次不构建镜像、不部署。
