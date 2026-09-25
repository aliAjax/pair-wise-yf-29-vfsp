import base64
import sqlite3
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path

from app import BusinessError, CustodyStore


class CustodyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = CustodyStore(Path(self.tmp.name) / "test.db")
        self.store.seed()
        self.case = self.store.create_case("custodian1", "CASE-2026-001", "跨境资金调查")
        self.store.add_member("custodian1", self.case["id"], "custodian2", "custodian")
        self.store.add_member("custodian1", self.case["id"], "analyst1", "analyst")
        self.store.add_member("custodian1", self.case["id"], "auditor1", "auditor")
        self.store.add_member("custodian1", self.case["id"], "auditor2", "auditor")
        self.retention = (date.today() + timedelta(days=3650)).isoformat()
        self.expired = (date.today() - timedelta(days=1)).isoformat()

    def tearDown(self):
        self.tmp.cleanup()

    def test_full_custody_analysis_release_and_integrity_report(self):
        raw = b"bank statement original bytes"
        item = self.store.ingest_evidence(
            "custodian1", self.case["id"], "E-001", "statement.csv",
            base64.b64encode(raw).decode(), self.retention, "custodian1",
        )
        opened = self.store.open_evidence("custodian1", item["id"], "A 区证物室", "两名人员在场开箱")
        self.assertEqual(opened["status"], "opened")
        child = self.store.derive(
            "analyst1", item["id"], "CSV 提取交易记录", "E-001-D1", "transactions.json",
            base64.b64encode(b'[{"amount": 100}]').decode(),
        )
        self.store.transfer("custodian2", item["id"], "custodian2", "法院证物库", "封存后移交")
        self.store.release("custodian2", item["id"], "检察机关", "按调取令释放原件")
        report = self.store.report("auditor1", self.case["id"])
        self.assertTrue(report["overall_integrity_valid"])
        self.assertEqual(report["evidence_count"], 2)
        original = next(x for x in report["evidence"] if x["id"] == item["id"])
        self.assertEqual(original["status"], "released")
        self.assertTrue(original["chain_valid"])
        self.assertEqual(child["parent_id"], item["id"])

    def test_permissions_and_legal_hold_block_release(self):
        item = self.store.ingest_evidence(
            "custodian1", self.case["id"], "E-002", "raw.bin",
            base64.b64encode(b"evidence").decode(), self.retention,
        )
        with self.assertRaises(BusinessError) as ctx:
            self.store.get_evidence("outsider", item["id"])
        self.assertEqual(ctx.exception.status, 403)
        with self.assertRaises(BusinessError) as ctx:
            self.store.release("analyst1", item["id"], "外部机构")
        self.assertEqual(ctx.exception.status, 403)
        self.store.set_hold("auditor1", item["id"], True, "诉讼保全要求")
        with self.assertRaises(BusinessError) as ctx:
            self.store.release("custodian1", item["id"], "外部机构")
        self.assertEqual(ctx.exception.code, "legal_hold_active")


    def _expired_evidence(self, label="E-EX", custodian="custodian1"):
        item = self.store.ingest_evidence(
            "custodian1", self.case["id"], label, "raw.bin",
            base64.b64encode(b"expired evidence").decode(), self.retention, custodian,
        )
        # 模拟保留期流逝：直接把保留期限改到昨天
        with self.store.connect() as conn:
            conn.execute(
                "UPDATE evidence SET retention_until=? WHERE id=?", (self.expired, item["id"])
            )
        return item

    def test_request_requires_expiry_and_custodian_review_requires_auditor(self):
        # 未届满不能申请
        fresh = self.store.ingest_evidence(
            "custodian1", self.case["id"], "E-FRESH", "raw.bin",
            base64.b64encode(b"fresh").decode(), self.retention,
        )
        with self.assertRaises(BusinessError) as ctx:
            self.store.request_destruction("custodian1", fresh["id"], "保留期届满申请销毁")
        self.assertEqual(ctx.exception.code, "retention_active")

        item = self._expired_evidence()
        # 分析员不能发起
        with self.assertRaises(BusinessError) as ctx:
            self.store.request_destruction("analyst1", item["id"], "保留期届满申请销毁")
        self.assertEqual(ctx.exception.status, 403)
        # 保管员可以发起
        req = self.store.request_destruction("custodian1", item["id"], "保留期届满，申请销毁原件")
        self.assertEqual(req["status"], "pending")
        # 待复核期间不能重复申请
        with self.assertRaises(BusinessError) as ctx:
            self.store.request_destruction("custodian1", item["id"], "再次申请销毁")
        self.assertEqual(ctx.exception.code, "destruction_pending")
        # 保管员/分析员不能复核，必须是审计员
        with self.assertRaises(BusinessError) as ctx:
            self.store.review_destruction("custodian2", req["id"], True, "同意")
        self.assertEqual(ctx.exception.status, 403)
        with self.assertRaises(BusinessError) as ctx:
            self.store.review_destruction("analyst1", req["id"], True, "同意")
        self.assertEqual(ctx.exception.status, 403)
        # 案外人无权复核
        with self.assertRaises(BusinessError) as ctx:
            self.store.review_destruction("outsider", req["id"], True, "同意")
        self.assertEqual(ctx.exception.status, 403)

    def test_approval_flow_and_destroyed_restrictions(self):
        item = self._expired_evidence()
        # 先开箱，验证销毁对 opened 状态同样适用
        self.store.open_evidence("custodian1", item["id"], "证物室", "期满核验")
        req = self.store.request_destruction("custodian1", item["id"], "保留期届满申请销毁")

        # 待复核期间仍可查看、开箱（已开箱则跳过）、移交，但不能释放
        detail = self.store.get_evidence("auditor1", item["id"])
        self.assertTrue(detail["destruction_pending"])
        self.store.transfer("custodian1", item["id"], "custodian2", "复核暂存柜", "待销毁复核")
        with self.assertRaises(BusinessError) as ctx:
            self.store.release("custodian2", item["id"], "外部机构")
        self.assertEqual(ctx.exception.code, "destruction_pending")

        # 另一名审计员同意（发起人 custodian1 != auditor1）
        result = self.store.review_destruction("auditor1", req["id"], True, "符合销毁条件，同意")
        self.assertEqual(result["status"], "approved")
        self.assertEqual(result["reviewed_by"], "auditor1")

        detail = self.store.get_evidence("auditor1", item["id"])
        self.assertEqual(detail["status"], "destroyed")
        self.assertTrue(detail["content_destroyed"])
        self.assertIsNone(detail["integrity_valid"])
        with_content = self.store.get_evidence("auditor1", item["id"], include_content=True)
        self.assertEqual(with_content["content_b64"], "")

        # 已销毁不能再开箱、移交、派生、释放，也不能再次申请
        for call, code in [
            (lambda: self.store.open_evidence("custodian1", item["id"], "X"), "evidence_destroyed"),
            (lambda: self.store.transfer("custodian1", item["id"], "custodian2", "X"), "evidence_destroyed"),
            (lambda: self.store.derive("analyst1", item["id"], "哈希分析方法", "D", "f", base64.b64encode(b"x").decode()), "evidence_destroyed"),
            (lambda: self.store.release("custodian1", item["id"], "外部"), "evidence_destroyed"),
            (lambda: self.store.request_destruction("custodian1", item["id"], "销毁后再次申请原件"), "evidence_destroyed"),
        ]:
            with self.assertRaises(BusinessError) as ctx:
                call()
            self.assertEqual(ctx.exception.code, code)

        # 元数据和事件链保留且链完整（INGEST/OPEN/TRANSFER/REQUESTED/APPROVED）
        self.assertEqual(len(detail["events"]), 5)
        self.assertEqual(detail["events"][-1]["event_type"], "DESTRUCTION_APPROVED")
        report = self.store.report("auditor1", self.case["id"])
        entry = next(x for x in report["evidence"] if x["id"] == item["id"])
        self.assertTrue(entry["chain_valid"])
        self.assertTrue(entry["original_destroyed"])
        self.assertIsNone(entry["hash_valid"])
        self.assertTrue(report["overall_integrity_valid"])
        top = next(x for x in report["destruction_requests"] if x["id"] == req["id"])
        self.assertEqual(top["status"], "approved")

    def test_rejection_allows_reapply(self):
        item = self._expired_evidence()
        req = self.store.request_destruction("custodian1", item["id"], "保留期届满申请销毁")
        result = self.store.review_destruction("auditor1", req["id"], False, "仍有诉讼关联，驳回")
        self.assertEqual(result["status"], "rejected")
        # 驳回后可重新申请并通过
        again = self.store.request_destruction("custodian1", item["id"], "诉讼结束重新申请销毁")
        self.assertEqual(again["status"], "pending")
        self.store.review_destruction("auditor2", again["id"], True, "同意销毁")
        detail = self.store.get_evidence("custodian1", item["id"])
        self.assertEqual(detail["status"], "destroyed")

    def test_self_review_blocked_when_custodian_is_also_auditor(self):
        # 发起人不能自审：让发起人为另一名同时具备 auditor 角色的保管员 custodian2
        item = self._expired_evidence(custodian="custodian2")
        # custodian2 先作为保管员发起（案件中已是 custodian），随后追加 auditor 角色
        req = self.store.request_destruction("custodian2", item["id"], "保留期届满申请销毁")
        self.store.add_member("custodian1", self.case["id"], "custodian2", "auditor")
        with self.assertRaises(BusinessError) as ctx:
            self.store.review_destruction("custodian2", req["id"], True, "自己同意销毁")
        self.assertEqual(ctx.exception.code, "self_review_forbidden")
        # 重复复核拦截
        self.store.review_destruction("auditor2", req["id"], True, "他人复核同意")
        with self.assertRaises(BusinessError) as ctx:
            self.store.review_destruction("auditor1", req["id"], False, "再处理")
        self.assertEqual(ctx.exception.code, "request_closed")

    def test_legal_hold_withdraws_pending_and_no_auto_restore(self):
        item = self._expired_evidence()
        req = self.store.request_destruction("custodian1", item["id"], "保留期届满申请销毁")
        # 新设法律保留撤下申请
        out = self.store.set_hold("auditor1", item["id"], True, "新发现关联诉讼需保全")
        self.assertEqual(out["withdrawn_requests"], [req["id"]])
        detail = self.store.get_evidence("custodian1", item["id"])
        self.assertFalse(detail["destruction_pending"])
        self.assertEqual(detail["destruction_requests"][0]["status"], "withdrawn")
        # 保留期间不能再申请
        with self.assertRaises(BusinessError) as ctx:
            self.store.request_destruction("custodian1", item["id"], "保留期间重新申请销毁")
        self.assertEqual(ctx.exception.code, "legal_hold_active")
        # 解除保留后不自动恢复，需要重新发起
        self.store.set_hold("auditor1", item["id"], False, "诉讼结束解除保留")
        detail = self.store.get_evidence("custodian1", item["id"])
        self.assertFalse(detail["destruction_pending"])
        new_req = self.store.request_destruction("custodian1", item["id"], "解除保留后重新申请销毁")
        self.assertEqual(new_req["status"], "pending")

    def test_legacy_db_migration_treats_old_evidence_as_not_started(self):
        # 用旧版约束直接建库并写入证据，模拟旧库
        legacy = Path(self.tmp.name) / "legacy.db"
        import hashlib
        import json as _json
        created = "2020-01-02T00:00:00+00:00"
        genesis_payload = {
            "evidence_id": 1, "sequence": 1, "event_type": "INGEST",
            "actor_id": "custodian1", "from_person": None, "to_person": "custodian1",
            "location": "", "note": "入册", "previous_hash": "GENESIS", "created_at": created,
        }
        genesis_hash = hashlib.sha256(
            _json.dumps(genesis_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        raw = sqlite3.connect(str(legacy))
        raw.executescript(
            f"""
            CREATE TABLE users(id TEXT PRIMARY KEY, name TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1);
            CREATE TABLE cases(id INTEGER PRIMARY KEY AUTOINCREMENT, case_number TEXT NOT NULL UNIQUE,
                title TEXT NOT NULL, created_by TEXT NOT NULL, created_at TEXT NOT NULL);
            CREATE TABLE case_members(case_id INTEGER NOT NULL, user_id TEXT NOT NULL,
                role TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1,
                granted_by TEXT NOT NULL, granted_at TEXT NOT NULL, PRIMARY KEY(case_id,user_id));
            CREATE TABLE evidence(id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER NOT NULL,
                label TEXT NOT NULL, filename TEXT NOT NULL, sha256 TEXT NOT NULL, size INTEGER NOT NULL,
                content BLOB NOT NULL, status TEXT NOT NULL DEFAULT 'custody'
                    CHECK(status IN ('custody','opened','released','derivative')),
                current_custodian TEXT NOT NULL, legal_hold INTEGER NOT NULL DEFAULT 0,
                retention_until TEXT NOT NULL, created_by TEXT NOT NULL, created_at TEXT NOT NULL);
            CREATE TABLE custody_events(id INTEGER PRIMARY KEY AUTOINCREMENT, evidence_id INTEGER NOT NULL,
                sequence INTEGER NOT NULL, event_type TEXT NOT NULL
                    CHECK(event_type IN ('INGEST','TRANSFER','OPEN','ANALYZE','RELEASE','HOLD_SET','HOLD_CLEARED')),
                actor_id TEXT NOT NULL, from_person TEXT, to_person TEXT, location TEXT NOT NULL DEFAULT '',
                note TEXT NOT NULL DEFAULT '', previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL,
                created_at TEXT NOT NULL, UNIQUE(evidence_id,sequence));
            CREATE TABLE derivatives(id INTEGER PRIMARY KEY AUTOINCREMENT, parent_evidence_id INTEGER NOT NULL,
                child_evidence_id INTEGER NOT NULL UNIQUE, method TEXT NOT NULL, actor_id TEXT NOT NULL,
                created_at TEXT NOT NULL);
            CREATE TABLE audit_log(id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER NOT NULL,
                actor_id TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL, created_at TEXT NOT NULL);
            INSERT INTO users VALUES('custodian1','甲',1),('auditor1','审',1);
            INSERT INTO cases VALUES(1,'OLD-1','旧案','custodian1','2020-01-01T00:00:00+00:00');
            INSERT INTO case_members VALUES(1,'custodian1','custodian',1,'custodian1','2020-01-01T00:00:00+00:00');
            INSERT INTO case_members VALUES(1,'auditor1','auditor',1,'custodian1','2020-01-01T00:00:00+00:00');
            INSERT INTO evidence VALUES(1,1,'OLD-E','f.bin','abc',3,x'010203','custody','custodian1',0,
                '2020-01-01','custodian1','2020-01-02T00:00:00+00:00');
            INSERT INTO custody_events VALUES(1,1,1,'INGEST','custodian1',NULL,'custodian1','','入册','GENESIS',
                '{genesis_hash}','{created}');
            """
        )
        raw.commit()
        raw.close()

        store = CustodyStore(legacy)
        store.init_schema()  # 迁移不应报错
        # 旧证据按尚未发起处理：可发起销毁并由审计员审批
        req = store.request_destruction("custodian1", 1, "旧库证据保留期届满")
        self.assertEqual(req["status"], "pending")
        store.review_destruction("auditor1", req["id"], True, "同意销毁旧件")
        detail = store.get_evidence("auditor1", 1)
        self.assertEqual(detail["status"], "destroyed")
        self.assertEqual(len(detail["events"]), 3)  # 旧 INGEST + REQUESTED + APPROVED
        # 旧事件仍在
        self.assertEqual(detail["events"][0]["event_type"], "INGEST")
        report = store.report("auditor1", 1)
        self.assertTrue(report["overall_integrity_valid"])


if __name__ == "__main__":
    unittest.main()
