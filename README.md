# 法律证据保管与流转后台

仅使用 Python 3.11+ 标准库实现的证据保管项目。支持真实 SHA-256 入册、封存/开箱/移交、分析衍生关系、案件成员权限、法律保留、保留期限、保留期满后的销毁复核、不可变保管事件链和 JSON 报告导出。

## 运行

```bash
python3 app.py --init --seed
python3 app.py
```

访问 <http://127.0.0.1:8105>，默认数据库 `custody.db`。测试：

```bash
python3 -m unittest -v
```

演示身份：`custodian1`、`custodian2`、`analyst1`、`auditor1`、`auditor2`、`outsider`。请求使用 `X-User-Id`。

## 主要接口

- `POST /api/cases`：创建案件，创建人自动成为保管员。
- `POST /api/cases/{id}/members`：授予 custodian、analyst 或 auditor 角色。
- `POST /api/cases/{id}/evidence`：以 Base64 入册证据，服务端计算 SHA-256 和大小。
- `GET /api/evidence/{id}`：查看元数据、完整保管事件链、完整性结果和衍生关系。
- `POST /api/evidence/{id}/open`：保管员开箱。
- `POST /api/evidence/{id}/transfer`：移交保管人并记录位置。
- `POST /api/evidence/{id}/derive`：分析员从已开箱证据创建衍生证据。
- `POST /api/evidence/{id}/hold`：审计员或案件创建人设置/解除法律保留。
- `POST /api/evidence/{id}/release`：存在法律保留或销毁待复核时拒绝释放。
- `POST /api/evidence/{id}/destruction-request`：保留期满后由保管员发起销毁申请。
- `POST /api/destruction-requests/{id}`：案件内另一名审计员同意/驳回销毁申请。
- `GET /api/cases/{id}/report`：校验所有证据哈希和每条事件链，导出完整报告（含销毁申请与处理结论）。
- 所有 `DELETE` 请求返回 405；证据和保管记录不提供删除接口。

## 保留期满销毁复核

- 只有保留期已过、无法律保留、且未释放/未销毁的证据才能由保管员发起销毁申请；每个证据同时只允许一条 `pending` 申请。
- 复核人必须是案件内的审计员，且不能是发起人本人（发起人不能自审）。
- 待复核期间证据仍可查看、开箱、移交，只暂停释放（`release` 返回 409 `destruction_pending`）。
- 待复核期间新设法律保留会自动撤下申请（状态 `withdrawn` 并记录事件），解除保留后不自动恢复，需要重新发起。
- 同意后原件状态标记为 `destroyed`，内容被清除，但 SHA-256、大小、元数据和完整事件链保留；此后不能再开箱、移交、派生或释放。
- 驳回后可重新申请；报告中的 `destruction_requests` 逐条列出申请理由、结论、发起人与复核人。
- 旧数据库启动时自动迁移：扩展状态/事件约束并新建销毁申请表，旧证据一律按"尚未发起处理"对待，页面可直接发起申请和审批。

保管事件通过前一条事件哈希串联；报告会重新计算文件哈希和事件链。项目适合流程与完整性原型，不涵盖现实中的签名证书、WORM 存储、证据文件加密或司法辖区合规认证。
