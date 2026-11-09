from types import SimpleNamespace

import pytest

from app.api.queries import case_dir, read_case_file


@pytest.fixture
def rt(tmp_path):
    cases = tmp_path / "cases"
    case = cases / "INC-2026-000001"
    (case / "screenshots").mkdir(parents=True)
    (case / "incident.json").write_text('{"ok": true}', encoding="utf-8")
    (case / "screenshots" / "shot.png").write_bytes(b"\x89PNG")
    (tmp_path / "secret.txt").write_text("outside", encoding="utf-8")
    return SimpleNamespace(dirs={"cases": cases})


def test_reads_top_level_and_nested_artifacts(rt):
    data, p = read_case_file(rt, "INC-2026-000001", "incident.json")
    assert data == b'{"ok": true}' and p.name == "incident.json"
    data, _ = read_case_file(rt, "INC-2026-000001", "screenshots/shot.png")
    assert data == b"\x89PNG"


@pytest.mark.parametrize("rel", ["../../secret.txt", "..\\..\\secret.txt", "", ".", "screenshots", "missing.json"])
def test_rejects_paths_outside_case_or_not_files(rt, rel):
    with pytest.raises(FileNotFoundError):
        read_case_file(rt, "INC-2026-000001", rel)


def test_rejects_absolute_path(rt, tmp_path):
    with pytest.raises(FileNotFoundError):
        read_case_file(rt, "INC-2026-000001", str(tmp_path / "secret.txt"))


@pytest.mark.parametrize("case_id", ["", "..", "a/b", "a\\b", "\\Windows", "C:foo", "C:\\Windows"])
def test_rejects_case_ids_that_escape_cases_folder(rt, case_id):
    with pytest.raises(ValueError):
        case_dir(rt, case_id)
