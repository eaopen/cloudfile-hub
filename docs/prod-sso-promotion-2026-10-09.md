# CloudFile 生产身份修复发布及 Authentik 对比

检查时间：2026-10-09 12:53（Asia/Shanghai）。用户本轮明确授权检查并从 dev 更新生产 CloudFile，同时比较 Authentik 配置。

## 发布范围

已将 dev 验证过的工号取令牌和 account-info 身份兼容修复发布到生产主服务及 worker。来源提交 022869fb3、049c08746；生产镜像 cloudfile/cloudfile:eap-alias-049c08746-prod。

生产镜像基于原 library-admin-identity-20261009，仅增加四个 Hub 扩展文件：sso/__init__.py、sso/account_api.py、sso/token_api.py、sso/token_identity.py。原 library_admin_identity.py 与本地已提交版本一致。没有整体替换 dev 镜像；生产默认 ACL、锁、签出设置与 dev 不同，本次未覆盖这些设置，也未更换底层服务版本。

复用生产已核验的 10220942 映射，保留生产原账号、OAuth provider/sub、工号 Profile 和库授权。仅开启两个兼容开关；不启用生产业务 UID 身份模式，不复制 dev 账号或 OAuth 参数，不重启 EAP，不修改或重启 Authentik。

## 验收结果

- 生产主服务 healthy，worker running，最终容器重启计数均为 0；dev 主服务和 worker 仍正常。
- 经生产正式域名验证，工号管理员取令牌、Cookie/Token account-info 均 200，返回已核验工号身份，令牌仍属于原账号。
- stp-tech-mgmt-prepstd（9461aa10-c28d-4717-90f5-626e1cd87cc7）两种认证访问根目录均 200/46 项、子目录均 200/3 项；一个样本文件 Range 下载 206，读取 256 字节，不输出文件内容。
- 匿名请求 403，未知工号请求 503，无令牌泄露；Profile、OAuth、群组及个人资料库前后相同，临时验证会话已删除。
- 目标库记录仍为 862177 文件、714623492573 字节，原账号 rw 权限保持不变；这不是对全库重新做内容校验。
- 生产自动库根目录与目录/文件搜索镜像能力标签均保留。多存储类型、主服务和 worker 的 /shared 与 library-storage 挂载、存储类配置均与保存的存储方案一致。
- 未使用真实员工浏览器完成 EAP 登录及菜单端到端验收；当前结论覆盖 CloudFile 正式入口真实 HTTP 和抽样下载。

## 发布中发生的配置遗漏

首次重建仅指定主 Compose，遗漏原搜索及多存储覆盖文件，导致短时按默认单存储启动：身份接口成功，但目标库目录读取失败。操作中未移动或删除资料文件。

发现后恢复三份 Compose 的完整组合并重新重建，目录和抽样下载验收通过。已同步修正回滚脚本，避免同样遗漏。后续重建必须保留下面的完整配置链，不能仅使用 docker-compose.yml：

```bash
cd /data/etech-infra/cloudfile
docker compose -p cloudfile \
  -f docker-compose.yml \
  -f docker-compose.import-search.yml \
  -f docker-compose.library-storage.yml \
  up -d --no-deps --pull never cloudfile cloudfile-worker
```

## Authentik 对比结果

两套配置不完全一致；本轮只读检查，没有将 dev 配置写入生产。

| 项目 | Dev | Prod | 判断 |
|---|---|---|---|
| Authentik 版本/状态 | 2026.2.2，server/worker healthy | 相同 | 一致 |
| 默认识别字段 | username | username | 一致 |
| 工号登录和 bootstrap 阶段顺序 | prompt/user-write/login；bootstrap write/login/redirect | 相同 | 结构一致 |
| CloudFile OAuth 类型 | confidential | confidential | 一致 |
| sub、签名和 ID Token claims | hashed_user_id，签名键存在，包含 claims | 相同 | 一致 |
| Scope、有效期 | openid/email/profile；access 5 分钟、refresh 30 天 | 相同 | 一致 |
| Client ID、secret、callback | dev 独立配置 | prod 独立配置 | 分别与各自 CloudFile 精确匹配；不应跨环境复制 |
| 业务身份声明 | etech-business-uid-dev，含 userId | etech-login-id，不含 userId | 实质差异 |
| EAP 用户资料接口（etech-auth-and-sync） | /admin-api/obpm/system/auth/identity/profile | /admin-api/obpm/system/auth/get-permission-info | 实质差异 |
| CloudFile UID 身份模式 | 已启用，v2 目录通道 | 未启用，保留旧工号模式 | 尚未联动迁移 |

生产还存在旧 seafile 应用，其回调列表含 dev 地址；当前生产 CloudFile 使用 cloudfile-pro 客户端，配置匹配。旧应用是否仍被使用未核验，本次未删除或修改。

不能直接复制 dev 的 userId 映射到生产：它依赖已认证的业务 UID 目录通道，必须先验证生产 EAP 目录接口，再联动迁移 CloudFile 身份模式。本次修复使用原先显式核验的单用户映射，因此不依赖该迁移；不代表所有存量用户已批量同步。

## 备份与回滚

服务器备份目录 /data/etech-infra/cloudfile/backups/eap-alias-049c08746/，目录权限 700。包含原主 Compose、搜索/存储覆盖文件、.env、seahub_settings.py 和旧镜像标识；敏感配置不进入 Git。

回滚脚本：/data/etech-infra/cloudfile/backups/eap-alias-049c08746/rollback.sh。恢复旧配置与镜像，使用完整三份 Compose，仅重建 cloudfile、cloudfile-worker，不回滚数据库、不重启 EAP。旧版本会恢复原有身份兼容缺口。
