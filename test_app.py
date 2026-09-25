import base64
import sqlite3
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path

from app import BusinessError, CustodyStore


def _expire(store, evidence_id, days=1):
    """直接把保留期改到过去（入册接口不允许过去日期，仅测试用）。"""
    past = (date.today() - timedelta(days=days)).isoformat()
    conn = sqlite3.connect(store.db_path)
    try:
        conn.execute("UPDATE evidence SET retention_until=? WHERE id=?", (past, evidence_id))
        conn.commit()
    finally:
        conn.close()


def _build_legacy_db(path):
    """按旧版结构（无销毁相关列/约束）建库并写入一条已过保留期的证据。"""
    conn = sqlite3.connect(str(path))
    conn.executescript(
        """
        CREATE TABLE users(id TEXT PRIMARY KEY, name TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE cases(id INTEGER PRIMARY KEY AUTOINCREMENT, case_number TEXT NOT NULL UNIQUE,
            title TEXT NOT NULL, created_by TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE case_members(case_id INTEGER NOT NULL, user_id TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('custodian','analyst','auditor')),
            active INTEGER NOT NULL DEFAULT 1, granted_by TEXT NOT NULL, granted_at TEXT NOT NULL,
            PRIMARY KEY(case_id,user_id));
        CREATE TABLE evidence(
            id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER NOT NULL, label TEXT NOT NULL,
            filename TEXT NOT NULL, sha256 TEXT NOT NULL, size INTEGER NOT NULL, content BLOB NOT NULL,
            status TEXT NOT NULL DEFAULT 'custody' CHECK(status IN ('custody','opened','released','derivative')),
            current_custodian TEXT NOT NULL, legal_hold INTEGER NOT NULL DEFAULT 0,
            retention_until TEXT NOT NULL, created_by TEXT NOT NULL, created_at TEXT NOT NULL,
            UNIQUE(case_id,label));
        CREATE TABLE custody_events(
            id INTEGER PRIMARY KEY AUTOINCREMENT, evidence_id INTEGER NOT NULL, sequence INTEGER NOT NULL,
            event_type TEXT NOT NULL CHECK(event_type IN ('INGEST','TRANSFER','OPEN','ANALYZE','RELEASE','HOLD_SET','HOLD_CLEARED')),
            actor_id TEXT NOT NULL, from_person TEXT, to_person TEXT, location TEXT NOT NULL DEFAULT '',
            note TEXT NOT NULL DEFAULT '', previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL,
            created_at TEXT NOT NULL, UNIQUE(evidence_id,sequence));
        CREATE TABLE derivatives(id INTEGER PRIMARY KEY AUTOINCREMENT,
            parent_evidence_id INTEGER NOT NULL, child_evidence_id INTEGER NOT NULL UNIQUE,
            method TEXT NOT NULL, actor_id TEXT NOT NULL, created_at TEXT NOT NULL,
            UNIQUE(parent_evidence_id,child_evidence_id));
        CREATE TABLE audit_log(id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER NOT NULL,
            actor_id TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL, created_at TEXT NOT NULL);
        """
    )
    conn.execute("INSERT INTO users(id,name) VALUES('custodian1','保管员'),('auditor1','审计员')")
    conn.execute("INSERT INTO cases(case_number,title,created_by,created_at) VALUES('OLD-1','旧案','custodian1','t')")
    conn.execute("INSERT INTO case_members(case_id,user_id,role,granted_by,granted_at) VALUES(1,'custodian1','custodian','custodian1','t')")
    conn.execute("INSERT INTO case_members(case_id,user_id,role,granted_by,granted_at) VALUES(1,'auditor1','auditor','custodian1','t')")
    import hashlib
    empty_hash = hashlib.sha256(b"").hexdigest()
    conn.execute(
        """INSERT INTO evidence(case_id,label,filename,sha256,size,content,current_custodian,retention_until,created_by,created_at)
           VALUES(1,'OLD-E','old.bin',?,0,X'','custodian1','2000-01-01','custodian1','t')""",
        (empty_hash,),
    )
    # 给旧证据补一条格式合法的 INGEST 事件（按现网 _event_hash 规则计算）
    import json
    from app import CustodyStore as _CS
    payload = {"evidence_id":1,"sequence":1,"event_type":"INGEST","actor_id":"custodian1",
               "from_person":None,"to_person":"custodian1","location":"","note":"入册",
               "previous_hash":"GENESIS","created_at":"t"}
    digest = _CS._event_hash(payload)
    conn.execute(
        """INSERT INTO custody_events(evidence_id,sequence,event_type,actor_id,to_person,location,note,previous_hash,event_hash,created_at)
           VALUES(1,1,'INGEST','custodian1','custodian1','','入册','GENESIS',?,'t')""",
        (digest,),
    )
    # 再加一条衍生证据和派生关系，验证迁移会一并重建 derivatives 外键
    conn.execute(
        """INSERT INTO evidence(case_id,label,filename,sha256,size,content,status,current_custodian,retention_until,created_by,created_at)
           VALUES(1,'OLD-D','d.bin',?,0,X'','derivative','custodian1','2000-01-01','custodian1','t')""",
        (empty_hash,),
    )
    conn.execute(
        "INSERT INTO derivatives(parent_evidence_id,child_evidence_id,method,actor_id,created_at) VALUES(1,2,'测试方法','custodian1','t')"
    )
    conn.commit()
    conn.close()



class CustodyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = CustodyStore(Path(self.tmp.name) / "test.db")
        self.store.seed()
        self.case = self.store.create_case("custodian1", "CASE-2026-001", "跨境资金调查")
        self.store.add_member("custodian1", self.case["id"], "custodian2", "custodian")
        self.store.add_member("custodian1", self.case["id"], "analyst1", "analyst")
        self.store.add_member("custodian1", self.case["id"], "auditor1", "auditor")
        self.retention = (date.today() + timedelta(days=3650)).isoformat()

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

    def _expired_evidence(self, label="E-DEST", custodian="custodian1", raw=b"to be destroyed"):
        item = self.store.ingest_evidence(
            "custodian1", self.case["id"], label, "raw.bin",
            base64.b64encode(raw).decode(), self.retention, custodian,
        )
        _expire(self.store, item["id"])
        return item

    def test_destruction_review_happy_path(self):
        item = self._expired_evidence()
        req = self.store.request_destruction("custodian1", item["id"], "保留期已满，申请销毁原件")
        self.assertEqual(req["status"], "pending")
        # 待复核期间仍可查看、开箱、移交，只暂停释放
        detail = self.store.get_evidence("custodian2", item["id"])
        self.assertIsNotNone(detail["pending_destruction"])
        self.store.open_evidence("custodian1", item["id"], "A 区证物室", "复核期间开箱核对")
        self.store.transfer("custodian1", item["id"], "custodian2", "法院证物库", "复核期间移交")
        with self.assertRaises(BusinessError) as ctx:
            self.store.release("custodian2", item["id"], "外部机构")
        self.assertEqual(ctx.exception.code, "destruction_pending")
        # 审计员同意
        result = self.store.review_destruction("auditor1", req["id"], True, "核对无误，同意销毁")
        self.assertEqual(result["status"], "approved")
        detail = self.store.get_evidence("auditor1", item["id"])
        self.assertEqual(detail["status"], "destroyed")
        self.assertIsNotNone(detail["destroyed_at"])
        self.assertTrue(detail["integrity_valid"])  # 元数据与哈希仍可校验
        self.assertEqual(len(detail["events"]), 5)  # INGEST/OPEN/TRANSFER/REQUEST/APPROVED
        # 已销毁不能开箱/移交/派生/释放/下载原件
        for call, code in [
            (lambda: self.store.open_evidence("custodian2", item["id"], "X"), "evidence_destroyed"),
            (lambda: self.store.transfer("custodian2", item["id"], "custodian1", "X"), "evidence_destroyed"),
            (lambda: self.store.release("custodian2", item["id"], "外部"), "evidence_destroyed"),
            (lambda: self.store.get_evidence("custodian2", item["id"], include_content=True), "evidence_destroyed"),
        ]:
            with self.assertRaises(BusinessError) as ctx:
                call()
            self.assertEqual(ctx.exception.code, code)
        with self.assertRaises(BusinessError) as ctx:
            self.store.derive("analyst1", item["id"], "分析已销毁件", "D2", "a.bin", b"Yg==")
        self.assertEqual(ctx.exception.code, "evidence_destroyed")
        # 事件链与报告完整
        report = self.store.report("auditor1", self.case["id"])
        self.assertTrue(report["overall_integrity_valid"])
        self.assertEqual(len(report["destruction_requests"]), 1)
        rec = report["destruction_requests"][0]
        self.assertEqual(rec["status"], "approved")
        self.assertEqual(rec["reviewer_id"], "auditor1")
        self.assertEqual(rec["decision_note"], "核对无误，同意销毁")

    def test_destruction_permissions_and_self_review(self):
        item = self._expired_evidence()
        # 保留期未满不能发起
        fresh = self.store.ingest_evidence(
            "custodian1", self.case["id"], "E-FRESH", "f.bin", b"ZnJlc2g=", self.retention,
        )
        with self.assertRaises(BusinessError) as ctx:
            self.store.request_destruction("custodian1", fresh["id"], "想提前销毁不行")
        self.assertEqual(ctx.exception.code, "retention_active")
        # 非保管员不能发起，非成员不能发起
        with self.assertRaises(BusinessError):
            self.store.request_destruction("analyst1", item["id"], "分析员发起销毁")
        # 保管员同时被授审计角色时，发起后也不能自审；另一名审计员（analyst1 改授 auditor）可复核
        req = self.store.request_destruction("custodian1", item["id"], "保留期满申请销毁")
        self.store.add_member("custodian1", self.case["id"], "custodian1", "auditor")
        with self.assertRaises(BusinessError) as ctx:
            self.store.review_destruction("custodian1", req["id"], True)
        self.assertEqual(ctx.exception.code, "self_review_forbidden")
        # 非审计员不能复核
        with self.assertRaises(BusinessError):
            self.store.review_destruction("custodian2", req["id"], True)
        # 另一名审计员可以
        self.store.add_member("custodian1", self.case["id"], "analyst1", "auditor")
        out = self.store.review_destruction("analyst1", req["id"], True)
        self.assertEqual(out["status"], "approved")

    def test_reject_then_reapply(self):
        item = self._expired_evidence(label="E-REJ")
        req1 = self.store.request_destruction("custodian1", item["id"], "第一次申请销毁")
        with self.assertRaises(BusinessError) as ctx:
            self.store.request_destruction("custodian1", item["id"], "重复申请销毁")
        self.assertEqual(ctx.exception.code, "destruction_pending")
        self.store.review_destruction("auditor1", req1["id"], False, "材料不齐，先补充清单")
        # 已处理申请不能重复复核
        with self.assertRaises(BusinessError) as ctx:
            self.store.review_destruction("auditor1", req1["id"], True)
        self.assertEqual(ctx.exception.code, "request_closed")
        # 驳回后可以重新申请并通过
        req2 = self.store.request_destruction("custodian1", item["id"], "补齐材料，重新申请")
        self.store.review_destruction("auditor1", req2["id"], True)
        detail = self.store.get_evidence("custodian1", item["id"])
        self.assertEqual(detail["status"], "destroyed")
        self.assertEqual([r["status"] for r in detail["destruction_requests"]], ["rejected", "approved"])

    def test_legal_hold_withdraws_pending_and_no_auto_restore(self):
        item = self._expired_evidence(label="E-HOLD")
        req = self.store.request_destruction("custodian1", item["id"], "保留期满申请销毁")
        result = self.store.set_hold("auditor1", item["id"], True, "新发现关联诉讼需保全")
        self.assertEqual(result["withdrawn_destruction_requests"], [req["id"]])
        # 申请被撤下，释放恢复可用（先解除保留即可释放）
        self.store.set_hold("auditor1", item["id"], False, "诉讼终结解除保留")
        self.store.release("custodian1", item["id"], "检察机关", "解除保留后释放")
        detail = self.store.get_evidence("auditor1", item["id"])
        self.assertIsNone(detail["pending_destruction"])
        self.assertEqual(detail["destruction_requests"][0]["status"], "withdrawn")
        self.assertTrue(
            any(e["event_type"] == "DESTRUCTION_WITHDRAWN" for e in detail["events"])
        )
        # 已释放的证据不能再发起销毁
        with self.assertRaises(BusinessError) as ctx:
            self.store.request_destruction("custodian1", item["id"], "释放后再次申请销毁")
        self.assertEqual(ctx.exception.code, "evidence_released")

    def test_legacy_database_migration_treated_as_not_requested(self):
        db_path = Path(self.tmp.name) / "legacy.db"
        _build_legacy_db(db_path)
        store = CustodyStore(db_path)
        store.init_schema()  # 触发迁移
        # 外键完整性：迁移不应留下指向 evidence_old 的悬挂引用
        import sqlite3
        raw = sqlite3.connect(str(db_path))
        raw.execute("PRAGMA foreign_keys=ON")
        self.assertEqual(raw.execute("PRAGMA foreign_key_check").fetchall(), [])
        raw.close()
        detail = store.get_evidence("custodian1", 1)
        self.assertEqual(detail["status"], "custody")
        self.assertTrue(detail["retention_expired"])
        self.assertEqual(detail["destruction_requests"], [])  # 旧库按尚未发起处理
        self.assertEqual(len(detail["derived_children"]), 1)  # 派生关系迁移后完好
        # 页面/接口可发起与审批
        req = store.request_destruction("custodian1", 1, "旧库证据保留期满申请销毁")
        store.review_destruction("auditor1", req["id"], True, "同意销毁")
        report = store.report("auditor1", 1)
        self.assertTrue(report["overall_integrity_valid"])  # 迁移不破坏事件链
        self.assertEqual(report["evidence"][0]["status"], "destroyed")
        self.assertEqual(report["destruction_requests"][0]["status"], "approved")


if __name__ == "__main__":
    unittest.main()
