<!-- generated-by: gsd-doc-writer -->
# CloudFile Hub 测试与证据

> 用途：说明本仓可执行的测试、CI 门禁、覆盖边界和最新验证结果。
> 适用版本：Seafile CE 14.x。
> 状态：验证中（Hub 单元测试通过，三仓与浏览器端到端不在本次结果内）。

## 测试框架

- Python：pytest；根目录 `pytest.ini` 发现 `test_*.py` 和 `tests.py`。
- Django setting：`pytest.ini` 声明 `DJANGO_SETTINGS_MODULE=seahub.test_settings`，但当前 `.venv` 未加载 pytest-django，运行时产生 unknown-option 警告。
- 前端：`frontend/package.json` 使用 Jest 脚本和 ESLint；未发现 `frontend/src/cloudfile/` 专属测试文件。
- 跨仓：`cloudfile-docker/tools/run-checks.sh` 统一执行 Hub、server、Go fileserver、Compose 和配置生成检查。

## 运行 Hub 扩展测试

使用已安装依赖的虚拟环境：

```bash
.venv/bin/python -m pytest cloudfile_ext/ -q
```

若从空环境开始，至少需要 pytest；涉及完整 Django/Seahub 测试时还需安装 `requirements.txt` 中依赖和 pytest-django。

单文件或子模块：

```bash
.venv/bin/python -m pytest cloudfile_ext/acl/tests/test_resolver.py -q
.venv/bin/python -m pytest cloudfile_ext/external_sources/tests/ -q
.venv/bin/python -m pytest cloudfile_ext/file_actions/tests/ -q
```

上游 Seahub 回归入口：

```bash
python3 -m pytest tests/ -q
```

上游套件依赖完整的 Seahub 测试环境，不等同于轻量 `cloudfile_ext/` 测试。

## 前端检查

```bash
cd frontend
npm run lint
npm test -- --runInBand
npm run build
```

当前 CloudFile 前端没有专属 Jest 用例，因此 lint/build 通过也不能覆盖菜单注入、API 调用或 `.cloudfile` 下载的浏览器行为。

## 三仓门禁

三个仓库并排检出后：

```bash
../cloudfile-docker/tools/run-checks.sh
```

该脚本检查：上游补丁登记、Hub 扩展测试、server C 能力用例、Go fileserver build/vet/契约、Compose profile、脚本语法、构建脚本偏离、配置生成和发布清单。缺少可选工具时脚本会明确记录跳过项。

## 测试组织

| 目录 | 主要覆盖 |
|---|---|
| `cloudfile_ext/acl/tests/` | 共享语义用例、路径规范化、权限不放宽、rule source |
| `cloudfile_ext/sso/tests/` | directory provider、异常策略、组织对账和删除上限 |
| `cloudfile_ext/search/tests/`、`cloudfile_ext/tests/test_search_query.py` | Meilisearch 翻译、库范围、结构化过滤 |
| `cloudfile_ext/external_sources/tests/` | 授权决策、开关关闭无贡献、路径/符号链接边界、provider、扫描游标 |
| `cloudfile_ext/file_actions/tests/` | 动作读写分类、锁 provider 门禁、generation 续租/强制释放 |
| `cloudfile_ext/audit/tests/` | 操作/对象过滤契约 |
| `cloudfile_ext/tests/` | CE 14 身份转换、provider 注册/封存 |
| `cloudfile_ext/office/tests/` | OnlyOffice 幂等 key；不证明模块已接入运行时 |

## 最新验证结果

2026-08-15 执行（Python 3.12.7、pytest 7.4.4）：

```text
collected 218 items
218 passed, 1 warning in 0.13s
```

警告为 `DJANGO_SETTINGS_MODULE` 未被当前 pytest 插件识别：`pytest.ini` 声明了该选项，但
`cloudfile_ext/` 是纯逻辑测试、不依赖 Django settings，不加载 pytest-django 不影响结果。
计数从 217 升到 218，是本地编辑 descriptor v2 修复（0503bf7a6）在 `test_lock_service.py`
新增的回归用例。

同日执行 `NODE_ENV=development ./node_modules/.bin/eslint ./src/cloudfile/` 通过。未设置 `NODE_ENV` 时 Babel preset 会拒绝解析，因此手工运行必须保留该环境变量；`npm run lint` 已内置。

## 覆盖与未验证项

仓库没有配置 coverage threshold，也没有证据表明 CI 强制 Python 覆盖率。以下内容必须单独验收：

- `cf_*` DDL、MySQL 路由与真实读写。
- ACL/锁在 server、Go fileserver、WebDAV、同步客户端中的不可绕过性。
- seafevents `Activity`、SeaSearch、Meilisearch 的真实数据链。
- IdP/外部目录、SMB/NFS 挂载、CloudFile Local Agent。
- CloudFile React 菜单、页面、原生路由 shadow 和本地会话浏览器流程。

因此“217 passed”只能作为 Hub 纯逻辑和适配器级证据，不能升级为整套产品“已验收”。

## CI

`.github/workflows/cloudfile-checks.yml` 在 `dev` push、所有 pull request 和手工触发时运行 `cloudfile-docker/tools/run-checks.sh`。工作流检出三仓 `dev`，使用 Python 3.12 和 server `go.mod` 指定的 Go 版本；CI 自身只显式安装 pytest 与 C 侧 glib 开发依赖。
