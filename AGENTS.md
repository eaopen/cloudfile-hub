# AGENTS.md — cloudfile-hub

给在本仓库工作的 AI coding agent。人类同样适用。

## 这是什么

`haiwen/seahub` 的 fork，CloudFile（Seafile CE 企业扩展版）的 Web/API 层。

`dev` 上是**扩展基线**：只有扩展框架和扩展点，没有任何具体能力。目录 ACL 等
能力活在各自的长期特性分支上（`feature/dir-acl`）。

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

目前只改了三个上游文件，改动前请先确认你真的没有别的办法：

| 文件 | 改了什么 | 为什么必须改这里 |
|---|---|---|
| `seahub/utils/rooturl.py` | 挂载 CloudFile 路由 | `seahub/urls.py` 有一千多行且上游频繁改动；这个文件多年未变 |
| `seahub/views/__init__.py` | `check_folder_permission` 转发到注册中心 | 它是 Hub 侧权限判定的咽喉，被 53 个模块调用 255 次，钩这一处就覆盖全部入口 |
| `frontend/config/webpack.entry.js` | 注册前端入口 | 纯数据追加，往 `entryFiles` 字典加一个 key |

**加新能力不需要再改上游。** 已有的注入点足够：

- Django app / middleware / 认证后端 → 写进 `conf/seahub_settings.py` 的 `EXTRA_INSTALLED_APPS` 等。
  Seahub 的 `load_local_settings()`（`seahub/settings.py`）会把 `EXTRA_<NAME>` 追加到同名设置，
  **不需要动 `settings.py`**。
- 新路由 → `registry.register_urls()`
- 新权限约束 → `registry.register_permission_check()`
- 文件操作前后钩子 → `registry.register_file_op_hook()`
- 后台周期任务 → `registry.register_periodic_task()`

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
└── sso/ audit/ metadata/ search/ office/ checkout/ external_sources/
                         占位，各自的 register() 是 no-op
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

基线本身没有能力实现，这里只有框架级测试。能力的测试随能力分支走。

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
