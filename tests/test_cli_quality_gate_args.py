import pytest

import main


@pytest.mark.parametrize(
    "quality_gate_args",
    [
        ["--fail-on-incomplete"],
        ["--fail-on-severity", "HIGH"],
    ],
)
def test_system_info_rejects_quality_gate_options(
    monkeypatch, capsys, quality_gate_args
):
    monkeypatch.setattr(
        "sys.argv",
        ["lpe-audit", "--system-info", *quality_gate_args],
    )
    monkeypatch.setattr(
        main,
        "run_system_info",
        lambda: pytest.fail("system-info must not run with quality gates"),
    )

    with pytest.raises(SystemExit) as exc_info:
        main.main()

    output = capsys.readouterr().err
    assert exc_info.value.code == 2
    assert "Quality gates cannot be used with --system-info." in output


def test_system_info_without_quality_gate_still_runs(monkeypatch):
    monkeypatch.setattr("sys.argv", ["lpe-audit", "--system-info"])
    monkeypatch.setattr(main, "run_system_info", lambda: 0)

    assert main.main() == 0
