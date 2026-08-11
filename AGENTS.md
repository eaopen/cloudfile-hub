<!-- generated-by: gsd-doc-writer -->
<!-- generated-by: gsd-doc-writer -->
# AGENTS.md — cloudfile-hub

> 用途：约束 Hub/Web/API 扩展、测试和上游同步工作。
> 适用版本：CloudFile `dev`，面向 Seafile CE 14 参考基线。
> 当前状态：有效；能力状态以 [`docs/CAPABILITIES.md`](docs/CAPABILITIES.md) 为准。

> 用途：约束在 CloudFile Hub 仓库内工作的开发者和自动化 agent。
> 适用版本：Seafile CE 14.x。
> 状态：已完成（与当前 `dev` 能力和测试核对，2026-08-11）。

给在本仓库工作的 AI coding agent。人类同样适用。

## 这是什么

`haiwen/seahub` 的 fork，CloudFile（Seafile CE 企业扩展版）的 Web/API 层。

`dev` = **扩展基线 + 已验收能力**，全部 `CF_ENABLE_*` 默认关闭。
开发中的能力在 `feature/<耦合簇>`（例如 `feature/dir-acl`），
**验收后合回 `dev` 并删除分支**——不长期分叉，理由见
`cloudfile-docker/docs/BRANCHES.md` 第一节。

CloudFile 由三个仓库组成，通常并排 checkout：

```
workspace/
├── cloudfile-server/   fork of haiwen/seafile-server —— 底层强制校验
├── cloudfile-hub/      fork of haiwen/seahub        —— 本仓库
└── cloudfile-docker/   fork of haiwen/seafile-docker —— 构建、镜像、部署、规格文档
```

跨仓规格与部署说明在 `cloudfile-docker/`：
[BRANCHING.md](../cloudfile-docker/BRANCHING.md)、
[docs/BRANCHES.md](../cloudfile-docker/docs/BRANCHES.md)、
[deploy/compose/README.md](../cloudfile-docker/deploy/compose/README.md)。

## 最重要的一条：不要改上游文件

本仓库是长期跟随上游的 fork。**每多改一个上游文件，以后每次同步上游都要多付一次代价。**

新代码一律放进 `cloudfile_ext/`（后端）和 `frontend/src/cloudfile/`（前端）。

七个核心扩展点之外，原生文件列表/详情交互另有已登记兼容补丁；完整路径以
`cloudfile-docker/docs/upstream-patches/cloudfile-hub.txt` 为准。改动前请先确认你真的没有别的办法：

| 文件 | 改了什么 | 为什么必须改这里 |
|---|---|---|
| `seahub/utils/rooturl.py` | 挂载 CloudFile 路由 | `seahub/urls.py` 有一千多行且上游频繁改动；这个文件多年未变 |
| `seahub/views/__init__.py` | `check_folder_permission` 转发到注册中心 | 它是 Hub 侧权限判定的咽喉，被 53 个模块调用 255 次，钩这一处就覆盖全部入口 |
| `seahub/search/utils.py` | `search_files` 委派给已选中的检索 provider | 它是"查询变成结果"的唯一收敛点，之后全是展示逻辑。切在这里，provider 自动继承 Seahub 的库范围收敛——让后端自己实现那部分，写错就是跨库泄露文件 |
| `seahub/utils/__init__.py` | `HAS_FILE_SEARCH` 或上"provider 是否已配置" | 与上一条**成对，缺一不可**：这个标志是搜索入口本身的开关，六处调用点读它。不改这里，CE 部署根本不会路由到 `search_files` |
| `frontend/config/webpack.entry.js` | 注册前端入口 | 纯数据追加，往 `entryFiles` 字典加一个 key |
| `scripts/seaf-fsck.sh` | 修复模式前置校验服务已停止 + 传播退出码 | 脚本原生无论成败都以 `echo "Done."` 收尾、退出码固定为 0；离线迁移编排必须能拿到真实失败信号，只能在这唯一入口上改，新文件要么整份复制维护、要么留下能绕过校验的原脚本 |
| `scripts/seaf-gc.sh` | 传播退出码 | 同上，`run_seaf_gc` 失败时脚本自身也一直返回 0 |

**后端新能力不需要再改上游。** 已有的注入点足够；原生 React 菜单、历史版本和
页面上下文没有注册点时，只能修改已登记的前端兼容补丁，并保持开关关闭时行为不变：

- Django app / middleware / 认证后端 → 写进 `conf/seahub_settings.py` 的 `EXTRA_INSTALLED_APPS` 等。
  Seahub 的 `load_local_settings()`（`seahub/settings.py`）会把 `EXTRA_<NAME>` 追加到同名设置，
  **不需要动 `settings.py`**。
- 新路由 → `registry.register_urls()`
- 新权限约束 → `registry.register_permission_check()`
- 文件操作前后钩子 → `registry.register_file_op_hook()`
- 后台周期任务 → `registry.register_periodic_task()`
- 检索后端 → `registry.register_search_provider()`
- **同一件事的可互换实现** → `registry.register_provider(kind, name, ...)`，
  由 `CF_PROVIDER_<KIND>` 选中。meilisearch 之于检索、外部权限服务之于
  ACL 规则来源，都是这个形状
- 调用客户自己的服务 → `cloudfile_ext.external_service.ExternalService`
  （**注意：绝不放在同步权限判定路径上**，理由见
  `cloudfile-docker/docs/EXTENSION-POINTS.md` 第五节）

扩展点的完整清单、每个扩展点被哪些特性依赖、以及已知缺口，见
`cloudfile-docker/docs/EXTENSION-POINTS.md`。

如果你觉得必须再改一个上游文件，先停下来说明理由，并同步更新
`cloudfile-docker/BRANCHING.md` 里的清单——那份清单是同步上游时的检查依据，
它一旦失真，同步就会漏掉冲突点。

## 目录

```
cloudfile_ext/
├── features.py          CF_ENABLE_* 开关，全部默认 False
├── registry.py          扩展注册中心；启动后 seal()，不接受运行时注册
├── apps.py              AppConfig.ready() 里依次调用各能力的 register()
├── hooks.py             上游 patch 调进来的入口
├── urls.py              从 registry 组装，不手写
├── settings_defaults.py CF_* 默认值
├── db_router.py         cf_* 模型路由到 seafile-db
├── identity.py          登录串 → Seafile 身份。14 之后两者不是一回事，
│                        **每个存或比用户名的能力都撞上这条**，所以在基线
├── acl/ sso/ audit/ search/
│                        已接入运行时的能力模块
├── external_sources/    外部源、授权、shadow API 和扫描
├── file_actions/        预览动作、锁、签出和本地 Agent 会话
├── metadata/            元数据/标签占位，当前不登记有效行为
├── checkout/            早期占位；实际签出入口已在 file_actions/
└── office/              回调保护代码存在，但当前未加入 apps.py 注册列表
```

能力分支在这里加自己的包（例如 `feature/dir-acl` 的 `acl/`），并在 `apps.py`
的能力列表里加一行——**不需要再动任何上游文件**。

## 铁律

**1. 全部开关关闭 = 原生 CE 行为。**

这是 P0 的验收标准，也是升级成本可控的前提。任何代码在
`CF_ENABLE_*` 为 False 时都不能改变行为。写完新能力先自问：把开关关掉，
这段代码还会执行吗？

**2. 扩展只能收紧权限，不能放宽。**

`registry.apply_permission_checks` 串起来的每个钩子，返回值必须 ⊆ 入参。
实现权限类能力时，必须带一个穷举整个权限格的不变量测试。

**3. 隐藏按钮不是安全边界。**

前端的 `CF_ENABLE_*` 判断只决定显示什么。真正的校验在
`check_folder_permission`，以及它下面的 seafile-server。写前端时不要假设
后端会因为按钮没显示就不被调用。

**4. 能力包的纯算法部分不许引入 Django、数据库或 Seafile 依赖。**

它要能脱离整个 Seahub 直接跑，才能和 cloudfile-server 的 C 实现共用同一份
用例集。因此能力包的 `__init__.py` 里，`from cloudfile_ext.features import
is_enabled` 要**放在 `register()` 内部**而不是模块顶层——否则 `import` 该包
就会拉进 Django。

## 测试

```bash
python3 -m pytest cloudfile_ext/ -q
```

`dev` 已包含框架以及 ACL、SSO 组织映射、审计、搜索、外部源和文件动作测试。
当前状态与未完成项见 `docs/CAPABILITIES.md`，不要把“存在开关或包”当成已交付。

跨层语义（同一套规则同时在 Hub 和 seafile-server 实现）必须用共享用例集驱动
两端，规格放在 `cloudfile-docker/docs/`。改语义的正确顺序：先改规格 → 再改
用例集 → 最后同时改两处实现。只改一处 = 引入漂移。

上游自带的回归：

```bash
python3 -m pytest tests/ -q
```

## 约定

- 代码、注释、commit message 用英文；文档（`*.md`）用中文。
- 注释解释**为什么**，不解释**做了什么**。上游代码里的既有风格优先于个人偏好。
- 新 API 走 `api/v2.1/cloudfile/...`，管理端走 `api/v2.1/admin/cloudfile/...`。
- REST 视图沿用 Seahub 的写法：`TokenAuthentication + SessionAuthentication`、
  `UserRateThrottle`、`api_error()`。照抄 `seahub/api2/endpoints/` 里的邻居。
- 不要提交 `.codegraph/`、`__pycache__/`、`node_modules/`。

## 容易踩的坑

- **`check_folder_permission` 会应用所有已注册的权限钩子。** 能力自己的管理接口
  如果用它做鉴权，管理员写一条限制到自己头上就会被锁在门外。管理类接口一律用
  `seafile_api.check_permission()`（原生库级权限）。
- **`cf_*` 表在 seafile-db，不在 seahub-db。** 因为 seaf-server 和 Go fileserver
  都要读它们，而它们只连 ccnet-db 和 seafile-db。模型用 `managed=False`，
  建表由 cloudfile-server 的 `scripts/sql/*/cloudfile.sql` 负责，
  `manage.py migrate` 永远不该管这些表。
- **注册中心启动后会 `seal()`**，运行时注册会抛异常。所有注册都要在
  `CloudFileConfig.ready()` 里完成。
