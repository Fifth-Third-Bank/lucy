"""End-of-run certification summary rendering (display only — never re-judges)."""

import unittest

from lucy.runtime.seal import render_certification_summary


def _outcome(**overrides):
    outcome = {
        "certified": True,
        "seal_token": "ef99063614c4194a",
        "m_audit": True,
        "checks": [
            {"id": "C1", "name": "VISITATION", "ok": True, "detail": "every census file was opened (321/321)"},
            {"id": "C2", "name": "QUIET", "ok": True, "detail": "all units converged — two consecutive quiet passes (8/8)"},
            {"id": "C3", "name": "RECALL", "ok": True, "detail": "8/8 planted canaries found"},
            {"id": "C4", "name": "PRIORS", "ok": None, "detail": "no priors staged — passes as N/A"},
            {"id": "C5", "name": "INTEGRITY", "ok": True, "detail": "lane deaths 1 == redispatched 1, orphans 0"},
            {"id": "C6", "name": "GATES", "ok": True, "detail": "scan-report gate PASS · seal-card gate PASS"},
        ],
        "totals": {
            "emitted": 586,
            "verified": 200,
            "conditional_court": 41,
            "refuted": 87,
            "tiers": {"PRIORITIZED_CRITICAL": 2, "CRITICAL": 31, "HIGH": 118, "MEDIUM": 203, "LOW": 191},
            "recall": "8/8",
            "historical_refound": None,
            "priors": None,
            "duration": "3h12m",
        },
        "final_line": "REVIEW-COMPLETE r-test ef99063614c4194a CERTIFIED",
    }
    outcome.update(overrides)
    return outcome


class SummaryRenderTests(unittest.TestCase):
    def test_certified_table(self):
        text = render_certification_summary(_outcome(), color=False)
        self.assertIn("RESULT: CERTIFIED  (seal token ef99063614c4194a)", text)
        for check_id in ("C1", "C2", "C3", "C4", "C5", "C6"):
            self.assertIn(check_id, text)
        self.assertEqual(text.count("✓"), 5)
        self.assertIn("–", text)  # C4 N/A on a cold run
        self.assertNotIn("✗", text)
        self.assertIn("findings: 586 emitted — 2 prioritized-critical / 31 critical / 118 high / 203 medium / 191 low", text)
        self.assertIn("41 conditional", text)
        self.assertIn("87 refuted", text)
        self.assertIn("recall:   8/8 plants", text)
        self.assertIn("duration: 3h12m", text)

    def test_refused_check_shows_red_x_and_gate_commentary(self):
        outcome = _outcome(certified=False, seal_token=None)
        outcome["checks"][1] = {
            "id": "C2", "name": "QUIET", "ok": False,
            "detail": "C2 QUIET: 5/8 units show two consecutive quiet passes",
        }
        text = render_certification_summary(outcome, color=False)
        self.assertIn("✗", text)
        self.assertIn("5/8 units show two consecutive quiet passes", text)
        self.assertIn("RESULT: PROCESS-COMPLETE", text)
        self.assertIn("review complete, certification pending", text)

    def test_all_checks_pass_but_maudit_fails_names_reason(self):
        text = render_certification_summary(
            _outcome(certified=False, m_audit=False), color=False
        )
        self.assertIn("RESULT: PROCESS-COMPLETE", text)
        self.assertIn("m-audit failed", text)

    def test_color_codes_only_when_enabled(self):
        self.assertIn("\033[", render_certification_summary(_outcome(), color=True))
        self.assertNotIn("\033[", render_certification_summary(_outcome(), color=False))

    def test_no_checks_renders_nothing(self):
        self.assertEqual(render_certification_summary({"certified": False}), "")

    def test_priors_totals_line(self):
        outcome = _outcome()
        outcome["totals"]["priors"] = {"staged": 1171, "refound": 214, "not_evidenced": 957}
        outcome["totals"]["historical_refound"] = "3/4"
        text = render_certification_summary(outcome, color=False)
        self.assertIn("blind historical 3/4", text)
        self.assertIn("priors 214/1171 refound", text)


class BudgetRecoveryNoticeTests(unittest.TestCase):
    """A budget-killed lane aborts fail-closed; the launcher must then say
    what happened, hand back the exact rerun command, and state the
    trade-off — without softening the failure exit."""

    def test_recapture_budget_death_proposes_exact_rerun(self):
        from lucy.runtime.trial import budget_recovery_notice

        lines = budget_recovery_notice(
            "recapture",
            "claude lane exited 1: Error: Exceeded USD budget (4)",
            run_id="r-example",
            results="/tmp/results",
            lane_budget_usd=4.0,
        )
        text = "\n".join(lines)
        self.assertIn("fails", text)
        self.assertIn("closed", text)
        self.assertIn(
            "lucy recapture --run r-example --results /tmp/results "
            "--lane-budget-usd 16",
            text,
        )
        self.assertIn("nothing is lost", text)
        self.assertIn("never weakens the claim", text)

    def test_scan_budget_death_points_at_resume(self):
        from lucy.runtime.trial import budget_recovery_notice

        lines = budget_recovery_notice(
            "scan",
            "budget exhausted: ~$12.10 of $12",
            results="/tmp/results",
        )
        text = "\n".join(lines)
        self.assertIn("lucy scan --resume <run-id> --results /tmp/results", text)
        self.assertIn("--max-budget-usd", text)

    def test_non_budget_errors_stay_silent(self):
        from lucy.runtime.trial import budget_recovery_notice

        self.assertEqual(
            budget_recovery_notice(
                "recapture",
                "claude lane exited 137: killed",
                run_id="r-x",
                results="/tmp/results",
                lane_budget_usd=4.0,
            ),
            [],
        )


if __name__ == "__main__":
    unittest.main()
