#!/usr/bin/env python3
"""
Tests for scripts/_resource_bundle.py — the shared all-in-one bundle driver.

Focus: prompt_script_selection() now delegates to utils.prompt_multiselect
(single-voice), maps chosen indices back to (display, filename) tuples, and
propagates the navigation signals (BackSignal / ExitToMainSignal / QuitSignal)
instead of returning 'back'/'exit' sentinel strings.
"""

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
import _resource_bundle as bundle  # noqa: E402

import utils  # noqa: E402

SCRIPTS = [
    ("Billing Export", "billing_export.py"),
    ("Budgets Export", "budgets_export.py"),
    ("Savings Plans Export", "savings_plans_export.py"),
]


class TestPromptScriptSelection:
    def test_maps_indices_to_tuples(self, monkeypatch):
        monkeypatch.delenv("STRATUSSCAN_AUTO_RUN", raising=False)
        with patch('utils.prompt_multiselect', return_value=[1, 3]):
            result = bundle.prompt_script_selection("Cost Management", SCRIPTS)
        assert result == [SCRIPTS[0], SCRIPTS[2]]

    def test_auto_run_returns_all(self, monkeypatch):
        monkeypatch.setenv("STRATUSSCAN_AUTO_RUN", "1")
        result = bundle.prompt_script_selection("Cost Management", SCRIPTS)
        assert result == SCRIPTS

    def test_back_signal_propagates(self, monkeypatch):
        monkeypatch.delenv("STRATUSSCAN_AUTO_RUN", raising=False)
        with patch('utils.prompt_multiselect', side_effect=utils.BackSignal), \
             pytest.raises(utils.BackSignal):
            bundle.prompt_script_selection("Cost Management", SCRIPTS)

    def test_exit_to_main_signal_propagates(self, monkeypatch):
        monkeypatch.delenv("STRATUSSCAN_AUTO_RUN", raising=False)
        with patch('utils.prompt_multiselect', side_effect=utils.ExitToMainSignal), \
             pytest.raises(utils.ExitToMainSignal):
            bundle.prompt_script_selection("Cost Management", SCRIPTS)

    def test_all_label_passed_through(self, monkeypatch):
        monkeypatch.delenv("STRATUSSCAN_AUTO_RUN", raising=False)
        with patch('utils.prompt_multiselect', return_value=[1]) as mock_ms:
            bundle.prompt_script_selection("Cost Management", SCRIPTS)
        # An explicit All row replaces the old magic 0 = All convention.
        _, kwargs = mock_ms.call_args
        assert "all_label" in kwargs and kwargs["all_label"]
