from __future__ import annotations

import json

from reizan_ansigate.cli import main


def test_cli_clean_text_output(capsys):
    code = main(["scan", "fixtures/clean.txt"])

    assert code == 0
    assert "CLEAN fixtures/clean.txt" in capsys.readouterr().out


def test_cli_poisoned_json_output(capsys):
    code = main(["scan", "fixtures/poisoned_jqwik_ansi.txt", "--json"])

    assert code == 2
    report = json.loads(capsys.readouterr().out)
    assert report["verdict"] == "POISONED"
    assert report["results"][0]["findings"]


def test_cli_directory_scan_blocks_poisoned_fixture(capsys):
    code = main(["scan", "fixtures"])

    assert code == 2
    output = capsys.readouterr().out
    assert "POISONED fixtures/poisoned_jqwik_ansi.txt" in output
