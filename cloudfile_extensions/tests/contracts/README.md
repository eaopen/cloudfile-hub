# 公共协议验收向量

`common.json` 由 EAP 规范导出，只包含路径正反例与虚构主体样例，随 Hub 提交固定版本。公共 Hub/Docker CI 无需检出私有产品文档库或配置跨仓凭据。

修改规范后，在同级 `eap-cloudfile` 执行 `python3 tools/export_test_contracts.py`，提交更新的公共向量；执行 `python3 tools/export_test_contracts.py --check` 校验规范与实现测试使用相同向量。测试不静默回退到其他文件或跳过缺失向量。
