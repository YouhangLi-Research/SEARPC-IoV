"""Certificate validation regressions for the localhost integration prototype."""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "artifact/code/scoped_evidence/run_process_measurements.py"
SPEC = importlib.util.spec_from_file_location("searpc_certificate_test_target", PATH)
PROTO = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PROTO
SPEC.loader.exec_module(PROTO)


class ProcessCertificateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = [PROTO.Ed25519PrivateKey.generate() for _ in range(40)]
        cls.publics = [key.public_key() for key in cls.keys]
        cls.payload = b"certificate regression block"
        cls.digest = hashlib.sha256(cls.payload).digest()
        cls.fast_policy = PROTO.CertificatePolicy(cls.digest.hex(), frozenset(range(13)), 9)
        cls.base_policy = PROTO.CertificatePolicy(cls.digest.hex(), frozenset(range(40)), 27)

    def prepare_qc(self, members=range(9)):
        return [[i, self.keys[i].sign(b"prepare:" + self.digest).hex()] for i in members]

    def request(self, phase="finality", quorum=9, members=range(9)):
        prepare = self.prepare_qc(members)
        message = b"commit:" + self.digest + PROTO._qc_hash(prepare)
        commit = [[i, self.keys[i].sign(message).hex()] for i in members]
        return {"phase": phase, "digest": self.digest.hex(), "payload": self.payload.hex(),
                "prepare_qc": prepare, "commit_qc": commit, "quorum": quorum}

    def handle(self, request, policy=None):
        return PROTO._handle_request(request, self.keys[39], self.publics, {},
                                     policy=self.fast_policy if policy is None else policy)

    def test_negative_alias_cannot_count_twice(self):
        message = b"certificate range check"
        signature = self.keys[39].sign(message).hex()
        with self.assertRaises(ValueError):
            PROTO._verify_qc(self.publics, [[39, signature], [-1, signature]], message, 2)

    def test_signer_must_be_an_in_range_integer(self):
        message = b"certificate signer check"
        signature = self.keys[39].sign(message).hex()
        for signer in (-1, -40, 40, True, "39", 39.2):
            with self.subTest(signer=signer), self.assertRaises(ValueError):
                PROTO._verify_qc(self.publics, [[signer, signature]], message, 1)

    def test_duplicate_signer_is_rejected(self):
        qc = self.prepare_qc()
        with self.assertRaises(ValueError):
            PROTO._verify_qc(self.publics, qc + [qc[0]], b"prepare:" + self.digest, 9)

    def test_signer_outside_local_candidate_set_is_rejected(self):
        qc = self.prepare_qc([*range(8), 13])
        with self.assertRaises(ValueError):
            PROTO._verify_qc(self.publics, qc, b"prepare:" + self.digest, 9,
                             allowed_signers=self.fast_policy.signer_ids)

    def test_eight_fast_signatures_do_not_meet_nine(self):
        reply = self.handle(self.request(members=range(8)))
        self.assertEqual(reply.get("error"), "invalid_commit_qc")

    def test_nine_correct_fast_signatures_are_accepted(self):
        request = self.request()
        reply = self.handle(request)
        self.assertIn("signature", reply)
        self.publics[39].verify(bytes.fromhex(reply["signature"]),
                               b"finality:" + self.digest + PROTO._qc_hash(request["commit_qc"]))

    def test_normal_commit_checks_prepare_certificate(self):
        reply = self.handle(self.request(phase="commit"))
        self.assertIn("signature", reply)

    def test_request_cannot_lower_fast_quorum(self):
        for phase in ("commit", "finality"):
            with self.subTest(phase=phase):
                reply = self.handle(self.request(phase=phase, quorum=1, members=range(1)))
                self.assertEqual(reply.get("error"), "quorum_mismatch")

    def test_empty_certificate_with_zero_quorum_is_rejected(self):
        reply = self.handle(self.request(quorum=0, members=[]))
        self.assertEqual(reply.get("error"), "quorum_mismatch")

    def test_request_cannot_raise_quorum_to_switch_paths(self):
        reply = self.handle(self.request(quorum=27, members=range(27)))
        self.assertEqual(reply.get("error"), "quorum_mismatch")

    def test_missing_quorum_is_rejected(self):
        request = self.request()
        request.pop("quorum")
        self.assertEqual(self.handle(request).get("error"), "quorum_mismatch")

    def test_quorum_type_is_strict(self):
        for quorum in (True, "9", 9.0, -1):
            with self.subTest(quorum=quorum):
                self.assertEqual(self.handle(self.request(quorum=quorum)).get("error"), "quorum_mismatch")

    def test_signing_requires_local_policy(self):
        reply = PROTO._handle_request(self.request(), self.keys[39], self.publics, {})
        self.assertEqual(reply.get("error"), "missing_local_policy")

    def test_policy_is_bound_to_current_digest(self):
        policy = PROTO.CertificatePolicy("00" * 32, self.fast_policy.signer_ids, 9)
        self.assertEqual(self.handle(self.request(), policy).get("error"), "missing_local_policy")

    def test_network_candidate_fields_do_not_override_policy(self):
        request = self.request(members=[*range(8), 13])
        request["signer_ids"] = list(range(40))
        request["members"] = list(range(40))
        self.assertEqual(self.handle(request).get("error"), "invalid_commit_qc")

    def test_full_path_uses_twenty_seven_signatures(self):
        reply = self.handle(self.request(phase="commit", quorum=27, members=range(27)), self.base_policy)
        self.assertIn("signature", reply)

    def test_base_path_cannot_be_lowered_to_fast_quorum(self):
        reply = self.handle(self.request(phase="commit", quorum=9), self.base_policy)
        self.assertEqual(reply.get("error"), "quorum_mismatch")

    def test_twenty_six_base_signatures_are_insufficient(self):
        reply = self.handle(self.request(phase="commit", quorum=27, members=range(26)), self.base_policy)
        self.assertEqual(reply.get("error"), "invalid_prepare_qc")

    def test_invalid_signature_is_refused(self):
        request = self.request()
        request["commit_qc"][0][1] = (b"\x00" * 64).hex()
        self.assertEqual(self.handle(request).get("error"), "invalid_commit_qc")

    def test_malformed_certificate_is_refused(self):
        for qc in (None, {}, [[0]], [[0, "not hexadecimal"]], [[0, "00"]]):
            with self.subTest(qc=qc):
                request = self.request()
                request["commit_qc"] = qc
                self.assertEqual(self.handle(request).get("error"), "invalid_commit_qc")

    def test_fixed_size_selection_rotates_members(self):
        a = PROTO.committee_for("fixed_k13", 40, 0)[0]
        b = PROTO.committee_for("fixed_k13", 40, 1)[0]
        self.assertEqual(len(a), 13)
        self.assertEqual(len(b), 13)
        self.assertNotEqual(a, b)

    def test_legacy_entry_uses_maintained_checks(self):
        path = ROOT / "artifact/code/participation_control/run_process_measurements.py"
        spec = importlib.util.spec_from_file_location("searpc_legacy_certificate_test", path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        request = self.request(quorum=1, members=range(1))
        policy = module.CertificatePolicy(self.digest.hex(), self.fast_policy.signer_ids, 9)
        reply = module._handle_request(request, self.keys[39], self.publics, {}, policy=policy)
        self.assertEqual(reply.get("error"), "quorum_mismatch")


if __name__ == "__main__":
    unittest.main()
