# 市政饮用水污染响应

模块化纯 Python 3.9.6+ 标准库项目，默认端口 `8334`。

- `app.py`：服务生命周期和依赖组装。
- `src/domain.py`：水源、污染物、区域和来源校验。
- `src/rules.py`：污染评分、通知去重、停水、切换水源、冲洗、消毒、复检和恢复状态机。
- `src/repository.py`：SQLite、事务、重复保护、乐观版本、审计链、跨区事件组和补录台账。
- `src/service.py`：身份、角色、区域管辖、跨区配对、断网补录对账和用例编排。
- `src/http_api.py`：JSON 接口与静态首页。
- `src/audit.py`：审计哈希。

```bash
python3 app.py --init --db ./data.db
python3 app.py --db ./data.db --port 8334
python3 -m unittest discover -s tests -v
```

接口包括 `GET /health`、`GET /api/state`、`GET /api/items`、`POST /api/items`、`POST /api/items/<id>/sources`、`POST /api/items/<id>/actions`、`POST /api/incidents/link`、`POST /api/reconciliation/batches`、`GET /api/reconciliation/pending` 和审计查询。请求头 `X-User-Id`、`X-Role` 标识身份，`X-Region` 标识当前所在区域；立案可带 `region` 字段。测试覆盖完整响应流程、重复事件、重复通知、复检阈值、权限、版本冲突以及跨区联动与对账。

## 跨区联动与对账

- **配对**：相邻两个区各自立案（稳定键含区域，互不冲突）后，由监管角色通过 `POST /api/incidents/link` 接成同一件污染事件，配对在两边审计里都留痕，重复配对幂等。
- **通知只发一次**：同一通知编号在整个联动事件（所有成员区）里只能出现一次，另一个区再发返回 `duplicate_notification`。
- **联动恢复闸门**：恢复任一成员时检查所有联动区，任一区缺复检样本或存在超标样本就返回 `linked_regions_not_cleared`，`details.blocked` 列出缺哪个区及原因（`missing_samples`/`quality_not_met`）。
- **断网补录**：`POST /api/reconciliation/batches` 提交一个区域的补录批次，条目按 `seq` 原始顺序回放。区域编号 + 外部编号相同的只入账一次，重复条目回传第一次结果；同一批次号重复提交直接返回首次结果（`duplicate_batch: true`）。
- **版本对不上**：补录操作的乐观版本与当前记录不一致时，既有记录原样保留，补录条目进待处理，可在 `GET /api/reconciliation/pending` 查到（普通角色只看本区域，监管角色看全部）；修正版本后用同一外部编号重放即转为已入账。
- **审计**：补录产生的审计事件带 `_origin.kind = backfill` 及区域、批次号、外部编号、序号，可直接区分在线记录与补录记录。
- **管辖**：监管角色（`regulator`）可跨区读取、处置、配对；普通角色访问本区域以外的记录返回 403 `region_access_denied`，列表和总览也只返回本区域记录。

内置规则不替代真实水质模型、法定通报渠道或供水控制系统的联锁。
