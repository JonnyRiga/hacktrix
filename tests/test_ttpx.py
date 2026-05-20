import sys
import os
import subprocess
import pytest
from pathlib import Path
sys.path.insert(0, str(Path.home() / "Tools"))

from ttpx import extract_snippet, extract_title, find_matches, ask_claude, source_label, strip_markdown, extract_section, mirror_file, log_payload_result, _content_root, _recently_changed_dirs, HACKTRICKS_PATH, PATT_PATH, MAX_PAYLOAD_MATCHES, parse_raw_request, generate_csrf_poc, ask_claude_csrf_bypass, detect_csrf_tokens, display_csrf_poc, ask_claude_script, display_script_result, log_script_result
from unittest.mock import patch, MagicMock


def test_extract_snippet_returns_heading_and_context():
    lines = [
        "# Introduction",
        "Some unrelated text",
        "## SSTI in Handlebars",
        "Handlebars RCE example",
        "{{7*7}}",
        "More details here",
        "Extra line 1",
        "Extra line 2",
    ]
    result = extract_snippet(lines, ["handlebars", "rce"])
    assert "## SSTI in Handlebars" in result
    assert "Handlebars RCE example" in result


def test_extract_snippet_falls_back_to_start_if_no_heading():
    lines = [
        "No heading here",
        "handlebars rce payload",
        "{{7*7}}",
    ]
    result = extract_snippet(lines, ["handlebars"])
    assert "handlebars rce payload" in result


def test_extract_snippet_is_case_insensitive():
    lines = [
        "## Template Injection",
        "HANDLEBARS RCE here",
    ]
    result = extract_snippet(lines, ["handlebars"])
    assert "HANDLEBARS RCE here" in result


def test_extract_snippet_returns_start_when_no_terms():
    lines = ["line one", "line two", "line three"]
    result = extract_snippet(lines, [])
    assert "line one" in result


def test_find_matches_returns_match_when_all_terms_present(tmp_path):
    md = tmp_path / "test.md"
    md.write_text("## SSTI\nHandlebars template RCE\n{{7*7}}")
    results = find_matches(["handlebars", "ssti", "rce"], search_paths=[tmp_path])
    assert len(results) == 1
    assert results[0][0] == md


def test_find_matches_excludes_file_missing_a_term(tmp_path):
    md = tmp_path / "test.md"
    md.write_text("## SSTI\nHandlebars template injection\n{{7*7}}")
    results = find_matches(["handlebars", "ssti", "rce"], search_paths=[tmp_path])
    assert results == []


def test_find_matches_is_case_insensitive(tmp_path):
    md = tmp_path / "test.md"
    md.write_text("## SSTI\nHANDLEBARS RCE template\n{{7*7}}")
    results = find_matches(["handlebars", "rce"], search_paths=[tmp_path])
    assert len(results) == 1


def test_find_matches_returns_empty_list_when_repo_missing(tmp_path):
    nonexistent = tmp_path / "nonexistent"
    results = find_matches(["ssti"], search_paths=[nonexistent])
    assert results == []


def test_find_matches_searches_subdirectories(tmp_path):
    subdir = tmp_path / "pentesting" / "web"
    subdir.mkdir(parents=True)
    md = subdir / "ssti.md"
    md.write_text("## Handlebars\nRCE via SSTI\n{{7*7}}")
    results = find_matches(["handlebars", "rce", "ssti"], search_paths=[tmp_path])
    assert len(results) == 1


def test_find_matches_combines_results_from_multiple_paths(tmp_path):
    src1 = tmp_path / "hacktricks"
    src2 = tmp_path / "patt"
    src1.mkdir()
    src2.mkdir()
    (src1 / "ssti.md").write_text("## SSTI\nhandlebars rce payload")
    (src2 / "ssti.md").write_text("## SSTI\nhandlebars rce example")
    results = find_matches(["handlebars", "rce"], search_paths=[src1, src2])
    assert len(results) == 2


def test_find_matches_skips_missing_path(tmp_path):
    existing = tmp_path / "exists"
    existing.mkdir()
    (existing / "ssti.md").write_text("## SSTI\nhandlebars rce")
    missing = tmp_path / "missing"
    results = find_matches(["handlebars", "rce"], search_paths=[existing, missing])
    assert len(results) == 1


def test_ask_claude_returns_parsed_json():
    import json
    matches = [
        (Path("/fake/ssti.md"), "## Handlebars SSTI\n{{7*7}} = 49 means vulnerable\nRCE via: ...")
    ]
    mock_response = MagicMock()
    mock_response.content = [MagicMock(text=json.dumps({
        "vulnerability": "SSTI via Handlebars (Node.js)",
        "technique": "RCE via prototype chain escape",
        "language": "javascript",
        "payload": "{{#with 'x'}}...{{/with}}",
        "changes": "",
        "recommendation": "Most impactful: gives direct RCE."
    }))]

    with patch("anthropic.Anthropic") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.messages.create.return_value = mock_response

        result = ask_claude(matches, ["handlebars", "ssti", "rce"])

    assert result["vulnerability"] == "SSTI via Handlebars (Node.js)"
    assert result["language"] == "javascript"
    assert "payload" in result
    assert "recommendation" in result
    assert result.get("changes", "") == ""  # no details — changes must be empty
    call_kwargs = mock_client.messages.create.call_args[1]
    assert call_kwargs["model"] == "claude-sonnet-4-6"


def test_ask_claude_includes_details_in_prompt():
    import json
    matches = [
        (Path("/fake/ssti.md"), "## Handlebars SSTI\n{{7*7}} = 49\nRCE via: ...")
    ]
    mock_response = MagicMock()
    mock_response.content = [MagicMock(text=json.dumps({
        "vulnerability": "SSTI via Handlebars (Node.js)",
        "technique": "RCE via prototype chain escape",
        "language": "javascript",
        "payload": "{{#with 'x'}}...{{/with}}",
        "recommendation": "Adapted after require error."
    }))]

    with patch("anthropic.Anthropic") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.messages.create.return_value = mock_response

        result = ask_claude(matches, ["handlebars", "rce"], details=["'require' is not defined"])

    call_kwargs = mock_client.messages.create.call_args[1]
    prompt = call_kwargs["messages"][0]["content"]
    assert "'require' is not defined" in prompt
    assert "adapt" in prompt.lower()
    assert result["language"] == "javascript"


def test_cli_find_no_results():
    result = subprocess.run(
        ["python", str(Path.home() / "Tools" / "ttpx.py"), "-f", "nonexistentterm123xyz"],
        capture_output=True, text=True
    )
    assert result.returncode == 0


def test_cli_payload_flag_without_api_key():
    env = os.environ.copy()
    env.pop("ANTHROPIC_API_KEY", None)
    result = subprocess.run(
        ["python", str(Path.home() / "Tools" / "ttpx.py"), "-p", "ssti"],
        capture_output=True, text=True, env=env
    )
    assert "ANTHROPIC_API_KEY" in result.stdout or "ANTHROPIC_API_KEY" in result.stderr


def test_cli_requires_flag():
    result = subprocess.run(
        ["python", str(Path.home() / "Tools" / "ttpx.py")],
        capture_output=True, text=True
    )
    assert result.returncode != 0


def test_source_label_identifies_hacktricks_path():
    path = HACKTRICKS_PATH / "web" / "ssti.md"
    assert source_label(path) == "[hacktricks] web/ssti.md"


def test_source_label_identifies_patt_path():
    path = PATT_PATH / "SSTI" / "README.md"
    assert source_label(path) == "[payloadsallthethings] SSTI/README.md"


def test_source_label_falls_back_to_str_for_unknown_path():
    path = Path("/tmp/unknown.md")
    assert source_label(path) == "/tmp/unknown.md"


def test_extract_title_returns_nearest_heading_stripped():
    lines = [
        "# Introduction",
        "Some text",
        "## Handlebars - RCE",
        "Handlebars rce payload here",
    ]
    assert extract_title(lines, ["handlebars", "rce"]) == "Handlebars - RCE"


def test_extract_title_truncates_long_headings():
    lines = [
        "## This Is A Very Long Heading That Exceeds Forty Five Characters Total",
        "handlebars rce content",
    ]
    result = extract_title(lines, ["handlebars"])
    assert len(result) <= 45
    assert result.endswith("...")


def test_extract_title_falls_back_to_filename_when_no_heading(tmp_path):
    md = tmp_path / "handlebars-rce.md"
    lines = ["no heading here", "handlebars rce payload"]
    result = extract_title(lines, ["handlebars"], fallback=md)
    assert result == "handlebars-rce.md"


def test_extract_title_returns_unknown_when_no_terms_and_no_fallback():
    lines = ["## Some Heading", "some content"]
    result = extract_title(lines, [])
    assert result == "Unknown"


def test_strip_markdown_preserves_dunder_names():
    payload = '{{config.__class__.__init__.__globals__["os"].popen("id").read()}}'
    assert strip_markdown(payload) == payload


def test_strip_markdown_preserves_glob_asterisks():
    assert "*.php" in strip_markdown("find / -name '*.php'")
    assert "rm *" in strip_markdown("rm *")


def test_strip_markdown_removes_images_cleanly():
    result = strip_markdown("before\n![alt](http://example.com/img.png)\nafter")
    assert "!" not in result
    assert "before" in result
    assert "after" in result


def test_strip_markdown_strips_headings():
    result = strip_markdown("## Handlebars - RCE\nsome content")
    assert "##" not in result
    assert "Handlebars - RCE" in result


def test_strip_markdown_preserves_code_fence_content():
    result = strip_markdown("```javascript\n{{7*7}}\n```")
    assert "{{7*7}}" in result


def test_extract_section_returns_matching_section():
    text = "## Lodash\nlodash content\n\n## Handlebars\nhandlebars content\n\n## Pug\npug content"
    result = extract_section(text, "handlebars")
    assert "handlebars content" in result
    assert "lodash content" not in result
    assert "pug content" not in result


def test_extract_section_stops_at_equal_level_heading():
    text = "## Handlebars\nsome content\n### Handlebars - RCE\npayload here\n## Lodash\nlodash"
    result = extract_section(text, "handlebars")
    assert "payload here" in result
    assert "lodash" not in result


def test_extract_section_returns_none_when_not_found():
    text = "## Lodash\nlodash content\n## Pug\npug content"
    assert extract_section(text, "handlebars") is None


def test_extract_section_is_case_insensitive():
    text = "## HANDLEBARS\ncontent here"
    result = extract_section(text, "handlebars")
    assert "content here" in result


def test_list_categories_shows_directories(tmp_path, monkeypatch):
    import ttpx
    ht = tmp_path / "hacktricks"
    patt = tmp_path / "patt"
    (ht / "Web Attacks").mkdir(parents=True)
    (ht / "Network").mkdir(parents=True)
    (ht / ".git").mkdir(parents=True)
    (patt / "SQL Injection").mkdir(parents=True)
    monkeypatch.setattr(ttpx, "HACKTRICKS_PATH", ht)
    monkeypatch.setattr(ttpx, "PATT_PATH", patt)
    # Should not raise; hidden dirs excluded
    ttpx.list_categories()


def test_list_categories_excludes_hidden_dirs(tmp_path, monkeypatch):
    import io
    import ttpx
    from rich.console import Console as RichConsole
    ht = tmp_path / "hacktricks"
    (ht / ".git").mkdir(parents=True)
    (ht / "Web Attacks").mkdir(parents=True)
    monkeypatch.setattr(ttpx, "HACKTRICKS_PATH", ht)
    monkeypatch.setattr(ttpx, "PATT_PATH", tmp_path / "missing")
    buf = io.StringIO()
    monkeypatch.setattr(ttpx, "console", RichConsole(file=buf, highlight=False))
    ttpx.list_categories()
    output = buf.getvalue()
    assert ".git" not in output
    assert "Web Attacks" in output


def test_update_sources_already_up_to_date(tmp_path, monkeypatch):
    import ttpx
    ht = tmp_path / "hacktricks"
    ht.mkdir()
    monkeypatch.setattr(ttpx, "HACKTRICKS_PATH", ht)
    monkeypatch.setattr(ttpx, "PATT_PATH", tmp_path / "missing")

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        if "pull" in cmd:
            result.returncode = 0
            result.stdout = "Already up to date."
            result.stderr = ""
        return result

    monkeypatch.setattr(ttpx.subprocess, "run", fake_run)
    ttpx.update_sources()


def test_update_sources_prints_stat_on_new_commits(tmp_path, monkeypatch):
    import ttpx
    ht = tmp_path / "hacktricks"
    ht.mkdir()
    monkeypatch.setattr(ttpx, "HACKTRICKS_PATH", ht)
    monkeypatch.setattr(ttpx, "PATT_PATH", tmp_path / "missing")

    call_count = {"n": 0}

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        if "pull" in cmd:
            result.returncode = 0
            result.stdout = "Updating abc..def\nFast-forward\n 3 files changed"
            result.stderr = ""
        elif "diff" in cmd:
            result.returncode = 0
            result.stdout = " 3 files changed, 10 insertions(+), 2 deletions(-)"
        call_count["n"] += 1
        return result

    monkeypatch.setattr(ttpx.subprocess, "run", fake_run)
    ttpx.update_sources()
    assert call_count["n"] >= 2


def test_update_sources_handles_git_failure(tmp_path, monkeypatch):
    import ttpx
    ht = tmp_path / "hacktricks"
    ht.mkdir()
    monkeypatch.setattr(ttpx, "HACKTRICKS_PATH", ht)
    monkeypatch.setattr(ttpx, "PATT_PATH", tmp_path / "missing")

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 1
        result.stdout = ""
        result.stderr = "not a git repository"
        return result

    monkeypatch.setattr(ttpx.subprocess, "run", fake_run)
    ttpx.update_sources()  # should not raise


@pytest.mark.skipif(
    not (HACKTRICKS_PATH.exists() or PATT_PATH.exists()),
    reason="requires at least one knowledge base to be cloned"
)
def test_cli_list_flag():
    result = subprocess.run(
        ["python", str(Path.home() / "Tools" / "ttpx.py"), "-l"],
        capture_output=True, text=True
    )
    assert result.returncode == 0


def test_cli_update_flag_missing_repos(monkeypatch, tmp_path):
    import ttpx
    monkeypatch.setattr(ttpx, "HACKTRICKS_PATH", tmp_path / "missing_ht")
    monkeypatch.setattr(ttpx, "PATT_PATH", tmp_path / "missing_patt")

    with pytest.raises(SystemExit) as exc:
        ttpx.update_sources()
    assert exc.value.code != 0


def test_recently_changed_dirs_parses_git_output(tmp_path, monkeypatch):
    import ttpx
    captured = {}

    def fake_run(cmd, **kw):
        captured["cmd"] = cmd
        return MagicMock(
            stdout="Server Side Template Injection/JavaScript.md\n\nSQL Injection/README.md\n",
            returncode=0
        )

    monkeypatch.setattr(ttpx.subprocess, "run", fake_run)
    dirs = ttpx._recently_changed_dirs(tmp_path, 7)
    assert "Server Side Template Injection" in dirs
    assert "SQL Injection" in dirs
    assert "--since=7 days ago" in captured["cmd"]


def test_recently_changed_dirs_ignores_blank_lines(tmp_path, monkeypatch):
    import ttpx
    monkeypatch.setattr(ttpx.subprocess, "run", lambda cmd, **kw: MagicMock(
        stdout="\n\nSQL Injection/README.md\n\n",
        returncode=0
    ))
    dirs = ttpx._recently_changed_dirs(tmp_path, 7)
    assert "SQL Injection" in dirs
    assert "" not in dirs


def test_recently_changed_dirs_handles_src_prefix(tmp_path, monkeypatch):
    import ttpx
    # Simulate HackTricks GitBook layout: content under src/
    (tmp_path / "src").mkdir()
    monkeypatch.setattr(ttpx.subprocess, "run", lambda cmd, **kw: MagicMock(
        stdout="src/pentesting-web/ssti.md\n\nsrc/network/README.md\n",
        returncode=0
    ))
    dirs = ttpx._recently_changed_dirs(tmp_path, 7)
    assert "pentesting-web" in dirs
    assert "network" in dirs
    assert "src" not in dirs


def test_content_root_returns_src_when_present(tmp_path):
    (tmp_path / "src").mkdir()
    assert _content_root(tmp_path) == tmp_path / "src"


def test_content_root_returns_base_when_no_src(tmp_path):
    assert _content_root(tmp_path) == tmp_path


def test_list_categories_descends_into_src(tmp_path, monkeypatch):
    import io
    import ttpx
    from rich.console import Console as RichConsole
    ht = tmp_path / "hacktricks"
    src = ht / "src"
    (src / "pentesting-web").mkdir(parents=True)
    (src / "network").mkdir(parents=True)
    (ht / "scripts").mkdir()  # top-level non-content dir; should not appear
    monkeypatch.setattr(ttpx, "HACKTRICKS_PATH", ht)
    monkeypatch.setattr(ttpx, "PATT_PATH", tmp_path / "missing")
    buf = io.StringIO()
    monkeypatch.setattr(ttpx, "console", RichConsole(file=buf, highlight=False))
    ttpx.list_categories()
    output = buf.getvalue()
    assert "pentesting-web" in output
    assert "network" in output
    assert "scripts" not in output


def test_list_categories_since_filters_to_recent(tmp_path, monkeypatch):
    import io
    import ttpx
    from rich.console import Console as RichConsole
    ht = tmp_path / "hacktricks"
    (ht / "SQL Injection").mkdir(parents=True)
    (ht / "Network").mkdir(parents=True)
    monkeypatch.setattr(ttpx, "HACKTRICKS_PATH", ht)
    monkeypatch.setattr(ttpx, "PATT_PATH", tmp_path / "missing")
    monkeypatch.setattr(ttpx.subprocess, "run", lambda cmd, **kw: MagicMock(
        stdout="SQL Injection/README.md\n", returncode=0
    ))
    buf = io.StringIO()
    monkeypatch.setattr(ttpx, "console", RichConsole(file=buf, highlight=False))
    ttpx.list_categories(since_days=7)
    output = buf.getvalue()
    assert "SQL Injection" in output
    assert "Network" not in output
    assert "of 2" in output  # "1 of 2 categories (last 7d)"


def test_list_categories_shows_count_footer(tmp_path, monkeypatch):
    import io
    import ttpx
    from rich.console import Console as RichConsole
    ht = tmp_path / "hacktricks"
    (ht / "Web Attacks").mkdir(parents=True)
    (ht / "Network").mkdir(parents=True)
    monkeypatch.setattr(ttpx, "HACKTRICKS_PATH", ht)
    monkeypatch.setattr(ttpx, "PATT_PATH", tmp_path / "missing")
    buf = io.StringIO()
    monkeypatch.setattr(ttpx, "console", RichConsole(file=buf, highlight=False))
    ttpx.list_categories()
    output = buf.getvalue()
    assert "2 categories" in output


def test_ask_claude_includes_changes_field_when_details_given():
    import json
    matches = [(Path("/fake/ssti.md"), "## Handlebars SSTI\n{{7*7}}\nRCE via: ...")]
    mock_response = MagicMock()
    mock_response.content = [MagicMock(text=json.dumps({
        "vulnerability": "SSTI via Handlebars (Node.js)",
        "technique": "RCE via prototype chain escape",
        "language": "javascript",
        "payload": "{{#with 'x'}}...{{/with}}",
        "changes": "- Replaced require() with process.mainModule.require()",
        "recommendation": "Adapted after require error."
    }))]
    with patch("anthropic.Anthropic") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.messages.create.return_value = mock_response
        result = ask_claude(matches, ["handlebars"], details=["require is not defined"])
    call_kwargs = mock_client.messages.create.call_args[1]
    prompt = call_kwargs["messages"][0]["content"]
    assert '"changes"' in prompt
    assert "one change per line" in prompt.lower()
    assert result["changes"] == "- Replaced require() with process.mainModule.require()"


def test_ask_claude_changes_field_empty_without_details():
    import json
    matches = [(Path("/fake/ssti.md"), "## Handlebars SSTI\n{{7*7}}\nRCE via: ...")]
    mock_response = MagicMock()
    mock_response.content = [MagicMock(text=json.dumps({
        "vulnerability": "SSTI via Handlebars",
        "technique": "RCE via prototype",
        "language": "javascript",
        "payload": "{{7*7}}",
        "changes": "",
        "recommendation": "Most impactful."
    }))]
    with patch("anthropic.Anthropic") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.messages.create.return_value = mock_response
        result = ask_claude(matches, ["handlebars"])
    call_kwargs = mock_client.messages.create.call_args[1]
    prompt = call_kwargs["messages"][0]["content"]
    assert '"changes": ""' in prompt


def test_display_payload_result_shows_changes_section(monkeypatch):
    import io
    import ttpx
    from rich.console import Console as RichConsole
    buf = io.StringIO()
    monkeypatch.setattr(ttpx, "console", RichConsole(file=buf, highlight=False))
    data = {
        "vulnerability": "SSTI via Handlebars",
        "technique": "RCE via prototype chain",
        "language": "javascript",
        "payload": "{{7*7}}",
        "changes": "- Used process.mainModule instead of require",
        "recommendation": "Most impactful.",
    }
    ttpx.display_payload_result(data, ["[hacktricks] ssti.md"])
    output = buf.getvalue()
    assert "What changed" in output
    assert "process.mainModule" in output


def test_display_payload_result_no_changes_section_when_empty(monkeypatch):
    import io
    import ttpx
    from rich.console import Console as RichConsole
    buf = io.StringIO()
    monkeypatch.setattr(ttpx, "console", RichConsole(file=buf, highlight=False))
    data = {
        "vulnerability": "SSTI via Handlebars",
        "technique": "RCE via prototype chain",
        "language": "javascript",
        "payload": "{{7*7}}",
        "changes": "",
        "recommendation": "Most impactful.",
    }
    ttpx.display_payload_result(data, ["[hacktricks] ssti.md"])
    output = buf.getvalue()
    assert "What changed" not in output


def test_display_payload_result_includes_raw_copy_paste_block(monkeypatch):
    import io
    import ttpx
    from rich.console import Console as RichConsole
    buf = io.StringIO()
    monkeypatch.setattr(ttpx, "console", RichConsole(file=buf, highlight=False))
    payload = "{{#with 'x' as |string|}}\n  {{string.constructor payload}}\n{{/with}}"
    data = {
        "vulnerability": "SSTI",
        "technique": "proto chain",
        "language": "javascript",
        "payload": payload,
        "changes": "",
        "recommendation": "Most impactful.",
    }
    ttpx.display_payload_result(data, [])
    output = buf.getvalue()
    assert "copy-paste" in output
    assert "{{#with" in output


def test_mirror_file_rejects_path_traversal(tmp_path, monkeypatch):
    import ttpx
    ht = tmp_path / "hacktricks"
    patt = tmp_path / "patt"
    ht.mkdir()
    patt.mkdir()
    sensitive = tmp_path / "secret.md"
    sensitive.write_text("secret content")
    monkeypatch.setattr(ttpx, "HACKTRICKS_PATH", ht)
    monkeypatch.setattr(ttpx, "PATT_PATH", patt)

    with pytest.raises(SystemExit) as exc:
        ttpx.mirror_file("../secret.md")

    assert exc.value.code != 0
    assert not sensitive.read_text() == ""  # file not read or modified


# Task #11: multi-pass -d

def test_ask_claude_multi_pass_details_joined():
    import json
    matches = [(Path("/fake/ssti.md"), "## SSTI\ncontent")]
    mock_response = MagicMock()
    mock_response.content = [MagicMock(text=json.dumps({
        "vulnerability": "SSTI",
        "technique": "chain",
        "language": "javascript",
        "payload": "payload",
        "changes": "- changed x",
        "recommendation": "use it",
    }))]
    with patch("anthropic.Anthropic") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.messages.create.return_value = mock_response
        ask_claude(matches, ["ssti"], details=["first error", "second error"])
    prompt = mock_client.messages.create.call_args[1]["messages"][0]["content"]
    assert "first error" in prompt
    assert "second error" in prompt
    assert "Previous attempts" in prompt


def test_ask_claude_single_detail_uses_singular_label():
    import json
    matches = [(Path("/fake/ssti.md"), "## SSTI\ncontent")]
    mock_response = MagicMock()
    mock_response.content = [MagicMock(text=json.dumps({
        "vulnerability": "SSTI",
        "technique": "t",
        "language": "text",
        "payload": "p",
        "changes": "- x",
        "recommendation": "r",
    }))]
    with patch("anthropic.Anthropic") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.messages.create.return_value = mock_response
        ask_claude(matches, ["ssti"], details=["one error"])
    prompt = mock_client.messages.create.call_args[1]["messages"][0]["content"]
    assert "A previous attempt produced" in prompt


# Task #7: result cap

def test_find_matches_capped_in_main(tmp_path, monkeypatch):
    import io
    import ttpx
    from rich.console import Console as RichConsole
    # Create more files than MAX_PAYLOAD_MATCHES
    for i in range(MAX_PAYLOAD_MATCHES + 3):
        md = tmp_path / f"file{i}.md"
        md.write_text("## SSTI\nhandlebars rce payload here")
    monkeypatch.setattr(ttpx, "HACKTRICKS_PATH", tmp_path)
    monkeypatch.setattr(ttpx, "PATT_PATH", tmp_path / "missing")
    buf = io.StringIO()
    monkeypatch.setattr(ttpx, "console", RichConsole(file=buf, highlight=False))

    results = ttpx.find_matches(["handlebars", "rce"], search_paths=[tmp_path])
    assert len(results) > MAX_PAYLOAD_MATCHES
    capped = results[:MAX_PAYLOAD_MATCHES]
    assert len(capped) == MAX_PAYLOAD_MATCHES


# Task #8: source header in mirrored file

def test_mirror_file_includes_source_header(tmp_path, monkeypatch):
    import ttpx
    ht = tmp_path / "hacktricks"
    ht.mkdir()
    md = ht / "ssti.md"
    md.write_text("## SSTI\nsome content here")
    monkeypatch.setattr(ttpx, "HACKTRICKS_PATH", ht)
    monkeypatch.setattr(ttpx, "PATT_PATH", tmp_path / "missing")
    monkeypatch.chdir(tmp_path)
    ttpx.mirror_file("ssti.md")
    out = tmp_path / "ssti.txt"
    content = out.read_text()
    assert "# Source:" in content
    assert "[hacktricks]" in content
    assert "ssti.md" in content
    assert "mirrored:" in content


# Task #9: file count in -l

def test_list_categories_shows_file_count(tmp_path, monkeypatch):
    import io
    import ttpx
    from rich.console import Console as RichConsole
    ht = tmp_path / "hacktricks"
    cat = ht / "SQL Injection"
    cat.mkdir(parents=True)
    (cat / "README.md").write_text("content")
    (cat / "mysql.md").write_text("content")
    monkeypatch.setattr(ttpx, "HACKTRICKS_PATH", ht)
    monkeypatch.setattr(ttpx, "PATT_PATH", tmp_path / "missing")
    buf = io.StringIO()
    monkeypatch.setattr(ttpx, "console", RichConsole(file=buf, highlight=False))
    ttpx.list_categories()
    output = buf.getvalue()
    assert "SQL Injection" in output
    assert "2" in output  # 2 .md files


# Task #10: auto-log

def test_log_payload_result_writes_to_log(tmp_path, monkeypatch):
    import ttpx
    log_path = tmp_path / "ttpx-session.log"
    monkeypatch.setattr(ttpx, "LOG_PATH", log_path)
    data = {
        "vulnerability": "SSTI via Handlebars",
        "payload": "{{7*7}}\nmore lines",
        "recommendation": "use it",
    }
    log_payload_result(["ssti", "handlebars"], data)
    content = log_path.read_text()
    assert "ssti handlebars" in content
    assert "SSTI via Handlebars" in content
    assert "{{7*7}}" in content


def test_log_payload_result_appends_not_overwrites(tmp_path, monkeypatch):
    import ttpx
    log_path = tmp_path / "ttpx-session.log"
    log_path.write_text("existing entry\n\n")
    monkeypatch.setattr(ttpx, "LOG_PATH", log_path)
    data = {"vulnerability": "XSS", "payload": "<script>", "recommendation": "r"}
    log_payload_result(["xss"], data)
    content = log_path.read_text()
    assert "existing entry" in content
    assert "XSS" in content


# CSRF PoC tests

def _write_req(tmp_path, content):
    f = tmp_path / "req.txt"
    f.write_text(content)
    return str(f)


def test_parse_raw_request_form_post(tmp_path):
    req = _write_req(tmp_path, (
        "POST /account/change-email HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "\r\n"
        "email=attacker%40evil.com&confirm=attacker%40evil.com"
    ))
    parsed = parse_raw_request(req)
    assert parsed["method"] == "POST"
    assert parsed["url"] == "http://example.com/account/change-email"
    assert parsed["content_type"] == "application/x-www-form-urlencoded"
    assert "email=attacker" in parsed["body"]


def test_parse_raw_request_json_post(tmp_path):
    req = _write_req(tmp_path, (
        "POST /api/update HTTP/1.1\n"
        "Host: api.example.com\n"
        "Content-Type: application/json\n"
        "\n"
        '{"username":"admin","role":"superuser"}'
    ))
    parsed = parse_raw_request(req)
    assert parsed["method"] == "POST"
    assert "application/json" in parsed["content_type"]
    assert '"username"' in parsed["body"]


def test_parse_raw_request_get(tmp_path):
    req = _write_req(tmp_path, (
        "GET /admin/delete?id=5 HTTP/1.1\n"
        "Host: example.com\n"
    ))
    parsed = parse_raw_request(req)
    assert parsed["method"] == "GET"
    assert parsed["url"] == "http://example.com/admin/delete?id=5"
    assert parsed["body"] == ""


def test_parse_raw_request_http_scheme_on_port_80(tmp_path):
    req = _write_req(tmp_path, (
        "POST /login HTTP/1.1\n"
        "Host: example.com:80\n"
        "\n"
        "user=x"
    ))
    parsed = parse_raw_request(req)
    assert parsed["url"].startswith("http://")


def test_parse_raw_request_https_scheme_on_port_443(tmp_path):
    req = _write_req(tmp_path, (
        "POST /login HTTP/1.1\n"
        "Host: example.com:443\n"
        "\n"
        "user=x"
    ))
    parsed = parse_raw_request(req)
    assert parsed["url"].startswith("https://")


def test_parse_raw_request_http_scheme_on_nonstandard_port(tmp_path):
    req = _write_req(tmp_path, (
        "POST /login HTTP/1.1\n"
        "Host: 10.10.10.10:8080\n"
        "\n"
        "user=x"
    ))
    parsed = parse_raw_request(req)
    assert parsed["url"].startswith("http://")


def test_parse_raw_request_http_default_no_port(tmp_path):
    req = _write_req(tmp_path, (
        "GET /profile HTTP/1.1\n"
        "Host: example.com\n"
    ))
    parsed = parse_raw_request(req)
    assert parsed["url"].startswith("http://")


def test_generate_csrf_poc_escapes_html_in_field_values(tmp_path):
    req = _write_req(tmp_path, (
        "POST /update HTTP/1.1\n"
        "Host: example.com\n"
        "Content-Type: application/x-www-form-urlencoded\n"
        "\n"
        'name="><script>alert(1)</script>&token=abc'
    ))
    parsed = parse_raw_request(req)
    html, _ = generate_csrf_poc(parsed)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html or "&#x27;" in html or "&gt;" in html


def test_generate_csrf_poc_escapes_url_in_form_action(tmp_path):
    req = _write_req(tmp_path, (
        "POST /update HTTP/1.1\n"
        'Host: example.com\n'
        "Content-Type: application/x-www-form-urlencoded\n"
        "\n"
        "x=1"
    ))
    parsed = parse_raw_request(req)
    # Manually inject a URL with quotes to verify escaping
    parsed["url"] = 'https://example.com/path?a="onmouseover=alert(1)'
    html, _ = generate_csrf_poc(parsed)
    assert '"onmouseover=alert(1)' not in html


def test_parse_raw_request_missing_file():
    with pytest.raises(SystemExit):
        parse_raw_request("/nonexistent/req.txt")


def test_parse_raw_request_empty_file(tmp_path):
    f = tmp_path / "req.txt"
    f.write_text("")
    with pytest.raises(SystemExit):
        parse_raw_request(str(f))


def test_generate_csrf_poc_form_post(tmp_path):
    req = _write_req(tmp_path, (
        "POST /change-email HTTP/1.1\n"
        "Host: example.com\n"
        "Content-Type: application/x-www-form-urlencoded\n"
        "\n"
        "email=evil%40attacker.com&csrf_token=abc"
    ))
    parsed = parse_raw_request(req)
    html, poc_type = generate_csrf_poc(parsed)
    assert poc_type == "form"
    assert 'action="http://example.com/change-email"' in html
    assert 'method="POST"' in html
    assert 'name="email"' in html
    assert 'csrf-form' in html
    assert 'submit()' in html


def test_generate_csrf_poc_json_post(tmp_path):
    req = _write_req(tmp_path, (
        "POST /api/settings HTTP/1.1\n"
        "Host: example.com\n"
        "Content-Type: application/json\n"
        "\n"
        '{"admin":true}'
    ))
    parsed = parse_raw_request(req)
    html, poc_type = generate_csrf_poc(parsed)
    assert poc_type == "json"
    assert "fetch(" in html
    assert "credentials: 'include'" in html
    assert "application/json" in html
    assert "CORS preflight" in html


def test_generate_csrf_poc_get(tmp_path):
    req = _write_req(tmp_path, (
        "GET /admin/reset?user=5 HTTP/1.1\n"
        "Host: example.com\n"
    ))
    parsed = parse_raw_request(req)
    html, poc_type = generate_csrf_poc(parsed)
    assert poc_type == "get"
    assert '<form' in html
    assert 'method="GET"' in html
    assert 'action="http://example.com/admin/reset"' in html
    assert 'name="user" value="5"' in html
    assert "csrf" in html  # auto-submit script


def test_generate_csrf_poc_html5_boilerplate(tmp_path):
    req = _write_req(tmp_path, "GET /x HTTP/1.1\nHost: example.com\n")
    parsed = parse_raw_request(req)
    html, _ = generate_csrf_poc(parsed)
    assert html.startswith("<!DOCTYPE html>")
    assert '<html lang="en">' in html
    assert '<meta charset="UTF-8">' in html
    assert 'name="viewport"' in html
    assert "<title>CSRF PoC</title>" in html
    assert html.rstrip().endswith("</html>")


def test_generate_csrf_poc_multipart(tmp_path):
    req = _write_req(tmp_path, (
        "POST /upload HTTP/1.1\n"
        "Host: example.com\n"
        "Content-Type: multipart/form-data; boundary=----abc\n"
        "\n"
        "------abc\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\ndata\r\n------abc--"
    ))
    parsed = parse_raw_request(req)
    html, poc_type = generate_csrf_poc(parsed)
    assert poc_type == "multipart"
    assert "FormData" in html
    assert "fetch(" in html


def test_generate_csrf_poc_json_fetch_syntax_valid(tmp_path):
    req = _write_req(tmp_path, (
        "POST /api/settings HTTP/1.1\n"
        "Host: example.com\n"
        "Content-Type: application/json\n"
        "\n"
        '{"admin":true}'
    ))
    parsed = parse_raw_request(req)
    html, _ = generate_csrf_poc(parsed)
    # fetch call must close with }); not }});
    assert "});" in html
    assert "}});" not in html


def test_generate_csrf_poc_multipart_fetch_syntax_valid(tmp_path):
    req = _write_req(tmp_path, (
        "POST /upload HTTP/1.1\n"
        "Host: example.com\n"
        "Content-Type: multipart/form-data; boundary=----abc\n"
        "\n"
        "data"
    ))
    parsed = parse_raw_request(req)
    html, _ = generate_csrf_poc(parsed)
    assert "});" in html
    assert "}});" not in html


def test_generate_csrf_poc_json_invalid_body_is_quoted(tmp_path):
    req = _write_req(tmp_path, (
        "POST /api HTTP/1.1\n"
        "Host: example.com\n"
        "Content-Type: application/json\n"
        "\n"
        "not valid json"
    ))
    parsed = parse_raw_request(req)
    html, _ = generate_csrf_poc(parsed)
    # fallback body must be quoted, not a bare JS expression
    assert "JSON.stringify('not valid json')" in html or "JSON.stringify('" in html
    # must not be unquoted
    assert "JSON.stringify(not valid json)" not in html


def test_js_escape_prevents_script_tag_breakout_via_url(tmp_path):
    req = _write_req(tmp_path, (
        "POST /api HTTP/1.1\n"
        "Host: example.com\n"
        "Content-Type: application/json\n"
        "\n"
        "{}"
    ))
    parsed = parse_raw_request(req)
    parsed["url"] = "https://example.com/</script><script>alert(1)//"
    html, _ = generate_csrf_poc(parsed)
    # raw </script> must appear exactly once — only the legitimate closing tag
    assert html.count("</script>") == 1


def test_js_escape_prevents_script_tag_breakout_via_json_body(tmp_path):
    req = _write_req(tmp_path, (
        "POST /api HTTP/1.1\n"
        "Host: example.com\n"
        "Content-Type: application/json\n"
        "\n"
        '{"url":"https://evil.com/</script><script>alert(1)//"}'
    ))
    parsed = parse_raw_request(req)
    html, _ = generate_csrf_poc(parsed)
    # json.dumps must not embed a raw </script> that would close the script block
    assert html.count("</script>") == 1


def test_generate_csrf_poc_no_body_form(tmp_path):
    req = _write_req(tmp_path, (
        "POST /action HTTP/1.1\n"
        "Host: example.com\n"
        "\n"
    ))
    parsed = parse_raw_request(req)
    html, poc_type = generate_csrf_poc(parsed)
    assert poc_type == "form"
    assert 'method="POST"' in html


def test_ask_claude_csrf_bypass_returns_parsed_json():
    import json
    mock_response = MagicMock()
    mock_response.content = [MagicMock(text=json.dumps({
        "content_type_attack": "Remove Content-Type header to skip CORS preflight.",
        "method_override_applicable": False,
        "bypass_variants": [
            {"technique": "Token removal", "poc_note": "Drop the csrf_token field entirely."},
        ],
        "recommendation": "Try removing the csrf_token parameter — server may not validate it."
    }))]
    mock_response.usage = MagicMock(input_tokens=100, output_tokens=50)

    parsed = {
        "method": "POST",
        "url": "https://example.com/action",
        "content_type": "application/x-www-form-urlencoded",
        "body": "action=delete&csrf_token=abc123",
        "headers": {"Host": "example.com", "Content-Type": "application/x-www-form-urlencoded"},
    }
    tokens = [("body field", "csrf_token")]

    with patch("anthropic.Anthropic") as mock_cls:
        mock_client = MagicMock()
        mock_cls.return_value = mock_client
        mock_client.messages.create.return_value = mock_response
        result = ask_claude_csrf_bypass(parsed, tokens)

    assert len(result["bypass_variants"]) == 1
    assert "_usage" in result


def test_ask_claude_csrf_bypass_prompt_contains_token_context():
    import json
    mock_response = MagicMock()
    mock_response.content = [MagicMock(text=json.dumps({
        "content_type_attack": "",
        "method_override_applicable": False,
        "bypass_variants": [],
        "recommendation": "Strip the token."
    }))]
    mock_response.usage = MagicMock(input_tokens=80, output_tokens=30)

    parsed = {
        "method": "POST",
        "url": "https://example.com/action",
        "content_type": "application/x-www-form-urlencoded",
        "body": "x=1&csrf_token=abc",
        "headers": {},
    }
    tokens = [("body field", "csrf_token")]

    with patch("anthropic.Anthropic") as mock_cls:
        mock_client = MagicMock()
        mock_cls.return_value = mock_client
        mock_client.messages.create.return_value = mock_response
        ask_claude_csrf_bypass(parsed, tokens)

    prompt = mock_client.messages.create.call_args[1]["messages"][0]["content"]
    # offline token facts must be in the prompt
    assert "csrf_token" in prompt
    assert "body field" in prompt
    # Claude must not be asked to re-detect the token
    assert "csrf_token_present" not in prompt
    assert "token_field" not in prompt
    # focus instruction must steer towards specific bypass families
    assert "stripping" in prompt or "leaking" in prompt or "manipulation" in prompt.lower()


# --script: ask_claude_script tests

def test_ask_claude_script_returns_parsed_json():
    import json
    mock_response = MagicMock()
    mock_response.content = [MagicMock(text=json.dumps({
        "vulnerabilities": [
            {"name": "Wildcard injection in tar", "severity": "critical", "line": 14,
             "detail": "tar czf /tmp/backup.tar.gz * is exploitable via checkpoint files."}
        ],
        "exploitation": "Drop a file named --checkpoint-action=exec=sh shell.sh in the backup dir.",
        "weaponization_strategy": "adds SUID to /bin/bash on execution",
        "language": "bash",
        "weaponized_script": "#!/bin/bash\nchmod u+s /bin/bash\n",
    }))]
    mock_response.usage = MagicMock(input_tokens=200, output_tokens=150)

    with patch("anthropic.Anthropic") as mock_cls:
        mock_client = MagicMock()
        mock_cls.return_value = mock_client
        mock_client.messages.create.return_value = mock_response
        result = ask_claude_script("#!/bin/bash\ntar czf /tmp/backup.tar.gz *", "backup.sh")

    assert len(result["vulnerabilities"]) == 1
    assert result["vulnerabilities"][0]["severity"] == "critical"
    assert result["weaponization_strategy"] == "adds SUID to /bin/bash on execution"
    assert result["weaponized_script"] == "#!/bin/bash\nchmod u+s /bin/bash\n"
    assert "_usage" in result
    call_kwargs = mock_client.messages.create.call_args[1]
    assert call_kwargs["model"] == "claude-sonnet-4-6"
    assert call_kwargs["max_tokens"] == 4096


def test_ask_claude_script_includes_details_in_prompt():
    import json
    mock_response = MagicMock()
    mock_response.content = [MagicMock(text=json.dumps({
        "vulnerabilities": [],
        "exploitation": "n/a",
        "weaponization_strategy": "installs cron reverse shell",
        "language": "bash",
        "weaponized_script": "#!/bin/bash\ncrontab -l | { cat; echo '* * * * * /tmp/rs.sh'; } | crontab -\n",
    }))]
    mock_response.usage = MagicMock(input_tokens=100, output_tokens=80)

    with patch("anthropic.Anthropic") as mock_cls:
        mock_client = MagicMock()
        mock_cls.return_value = mock_client
        mock_client.messages.create.return_value = mock_response
        ask_claude_script(
            "#!/bin/bash\necho hello",
            "monitor.sh",
            details=["runs as root via cronjob", "world-writable"]
        )

    prompt = mock_client.messages.create.call_args[1]["messages"][0]["content"]
    assert "runs as root via cronjob" in prompt
    assert "world-writable" in prompt


def test_ask_claude_script_handles_malformed_json():
    mock_response = MagicMock()
    mock_response.content = [MagicMock(text="not valid json at all")]
    mock_response.usage = MagicMock(input_tokens=10, output_tokens=5)

    with patch("anthropic.Anthropic") as mock_cls:
        mock_client = MagicMock()
        mock_cls.return_value = mock_client
        mock_client.messages.create.return_value = mock_response
        result = ask_claude_script("#!/bin/bash\necho hi", "test.sh")

    assert result["vulnerabilities"] == []
    assert result["language"] == "text"
    assert "not valid json" in result["weaponized_script"]


def test_ask_claude_csrf_bypass_no_token_prompt_focuses_on_defences():
    import json
    mock_response = MagicMock()
    mock_response.content = [MagicMock(text=json.dumps({
        "content_type_attack": "",
        "method_override_applicable": False,
        "bypass_variants": [],
        "recommendation": "No meaningful defence detected — offline PoC should work."
    }))]
    mock_response.usage = MagicMock(input_tokens=70, output_tokens=25)

    parsed = {
        "method": "POST",
        "url": "https://example.com/action",
        "content_type": "application/x-www-form-urlencoded",
        "body": "email=x",
        "headers": {},
    }

    with patch("anthropic.Anthropic") as mock_cls:
        mock_client = MagicMock()
        mock_cls.return_value = mock_client
        mock_client.messages.create.return_value = mock_response
        ask_claude_csrf_bypass(parsed, tokens=[])

    prompt = mock_client.messages.create.call_args[1]["messages"][0]["content"]
    assert "No CSRF token" in prompt
    assert "SameSite" in prompt or "Origin" in prompt or "Referer" in prompt


def test_cli_csrf_generates_poc_file(tmp_path):
    req = tmp_path / "req.txt"
    req.write_text(
        "POST /change-email HTTP/1.1\n"
        "Host: example.com\n"
        "Content-Type: application/x-www-form-urlencoded\n"
        "\n"
        "email=evil%40attacker.com"
    )
    result = subprocess.run(
        ["python", str(Path.home() / "Tools" / "ttpx.py"), "--csrf", str(req)],
        capture_output=True, text=True, cwd=str(tmp_path)
    )
    assert result.returncode == 0
    assert (tmp_path / "csrf_poc.html").exists()
    content = (tmp_path / "csrf_poc.html").read_text()
    assert "csrf-form" in content


def test_cli_csrf_bypass_without_api_key(tmp_path):
    req = tmp_path / "req.txt"
    req.write_text(
        "POST /action HTTP/1.1\n"
        "Host: example.com\n"
        "\n"
        "x=1"
    )
    env = os.environ.copy()
    env.pop("ANTHROPIC_API_KEY", None)
    result = subprocess.run(
        ["python", str(Path.home() / "Tools" / "ttpx.py"), "--csrf", str(req), "--bypass"],
        capture_output=True, text=True, env=env, cwd=str(tmp_path)
    )
    assert result.returncode != 0
    assert "ANTHROPIC_API_KEY" in result.stdout or "ANTHROPIC_API_KEY" in result.stderr


# CSRF token detection tests

def test_detect_csrf_tokens_finds_form_field(tmp_path):
    req = _write_req(tmp_path, (
        "POST /action HTTP/1.1\n"
        "Host: example.com\n"
        "Content-Type: application/x-www-form-urlencoded\n"
        "\n"
        "email=x&csrf_token=abc123"
    ))
    parsed = parse_raw_request(req)
    found = detect_csrf_tokens(parsed)
    assert any(name == "csrf_token" for _, name in found)


def test_detect_csrf_tokens_finds_authenticity_token(tmp_path):
    req = _write_req(tmp_path, (
        "POST /action HTTP/1.1\n"
        "Host: example.com\n"
        "Content-Type: application/x-www-form-urlencoded\n"
        "\n"
        "authenticity_token=xyz&data=1"
    ))
    parsed = parse_raw_request(req)
    found = detect_csrf_tokens(parsed)
    assert any(name == "authenticity_token" for _, name in found)


def test_detect_csrf_tokens_finds_json_field(tmp_path):
    req = _write_req(tmp_path, (
        "POST /api HTTP/1.1\n"
        "Host: example.com\n"
        "Content-Type: application/json\n"
        "\n"
        '{"_csrf":"tok123","admin":true}'
    ))
    parsed = parse_raw_request(req)
    found = detect_csrf_tokens(parsed)
    assert any(name == "_csrf" for _, name in found)


def test_detect_csrf_tokens_finds_header(tmp_path):
    req = _write_req(tmp_path, (
        "POST /api HTTP/1.1\n"
        "Host: example.com\n"
        "X-CSRF-Token: abc123\n"
        "Content-Type: application/json\n"
        "\n"
        "{}"
    ))
    parsed = parse_raw_request(req)
    found = detect_csrf_tokens(parsed)
    assert any(name == "X-CSRF-Token" for _, name in found)


def test_detect_csrf_tokens_returns_empty_when_none(tmp_path):
    req = _write_req(tmp_path, (
        "POST /action HTTP/1.1\n"
        "Host: example.com\n"
        "Content-Type: application/x-www-form-urlencoded\n"
        "\n"
        "email=x&confirm=x"
    ))
    parsed = parse_raw_request(req)
    assert detect_csrf_tokens(parsed) == []


def test_detect_csrf_tokens_single_field_no_content_type(tmp_path):
    # Single field body with no Content-Type header — heuristic must still detect
    req = _write_req(tmp_path, (
        "POST /action HTTP/1.1\n"
        "Host: example.com\n"
        "\n"
        "csrf_token=abc123"
    ))
    parsed = parse_raw_request(req)
    found = detect_csrf_tokens(parsed)
    assert any(name == "csrf_token" for _, name in found)


def test_detect_csrf_tokens_header_case_insensitive(tmp_path):
    req = _write_req(tmp_path, (
        "POST /api HTTP/1.1\n"
        "Host: example.com\n"
        "x-csrf-token: abc123\n"
        "Content-Type: application/json\n"
        "\n"
        "{}"
    ))
    parsed = parse_raw_request(req)
    found = detect_csrf_tokens(parsed)
    assert any(name == "x-csrf-token" for _, name in found)


def test_detect_csrf_tokens_get_with_header_only(tmp_path):
    req = _write_req(tmp_path, (
        "GET /action HTTP/1.1\n"
        "Host: example.com\n"
        "X-CSRF-Token: abc123\n"
    ))
    parsed = parse_raw_request(req)
    found = detect_csrf_tokens(parsed)
    assert any(name == "X-CSRF-Token" for _, name in found)


def test_detect_csrf_tokens_no_false_positive_on_token_field(tmp_path):
    # bare "token" field was removed from the list — must not trigger
    req = _write_req(tmp_path, (
        "POST /oauth HTTP/1.1\n"
        "Host: example.com\n"
        "Content-Type: application/x-www-form-urlencoded\n"
        "\n"
        "token=bearer_abc&grant_type=authorization_code"
    ))
    parsed = parse_raw_request(req)
    assert detect_csrf_tokens(parsed) == []


def test_detect_csrf_tokens_no_false_positive_on_x_requested_with(tmp_path):
    # x-requested-with is a same-origin hint, not a CSRF token — must not trigger
    req = _write_req(tmp_path, (
        "POST /api HTTP/1.1\n"
        "Host: example.com\n"
        "X-Requested-With: XMLHttpRequest\n"
        "Content-Type: application/json\n"
        "\n"
        "{}"
    ))
    parsed = parse_raw_request(req)
    assert detect_csrf_tokens(parsed) == []


def test_detect_csrf_tokens_case_insensitive_field(tmp_path):
    req = _write_req(tmp_path, (
        "POST /action HTTP/1.1\n"
        "Host: example.com\n"
        "Content-Type: application/x-www-form-urlencoded\n"
        "\n"
        "CSRF_TOKEN=abc&data=1"
    ))
    parsed = parse_raw_request(req)
    found = detect_csrf_tokens(parsed)
    assert any(name == "CSRF_TOKEN" for _, name in found)


def test_detect_csrf_tokens_requestverificationtoken(tmp_path):
    req = _write_req(tmp_path, (
        "POST /action HTTP/1.1\n"
        "Host: example.com\n"
        "Content-Type: application/x-www-form-urlencoded\n"
        "\n"
        "__RequestVerificationToken=abc&data=1"
    ))
    parsed = parse_raw_request(req)
    found = detect_csrf_tokens(parsed)
    assert any(name == "__RequestVerificationToken" for _, name in found)


def test_cli_csrf_warns_on_token_detection(tmp_path):
    req = tmp_path / "req.txt"
    req.write_text(
        "POST /action HTTP/1.1\n"
        "Host: example.com\n"
        "Content-Type: application/x-www-form-urlencoded\n"
        "\n"
        "data=x&csrf_token=abc123"
    )
    result = subprocess.run(
        ["python", str(Path.home() / "Tools" / "ttpx.py"), "--csrf", str(req)],
        capture_output=True, text=True, cwd=str(tmp_path)
    )
    assert result.returncode == 0
    assert "csrf_token" in result.stdout
    assert "token" in result.stdout.lower()


def test_display_csrf_poc_suppresses_bypass_hint_when_bypass_active(monkeypatch, tmp_path):
    import io
    import ttpx
    from rich.console import Console as RichConsole
    buf = io.StringIO()
    monkeypatch.setattr(ttpx, "console", RichConsole(file=buf, highlight=False))
    monkeypatch.chdir(tmp_path)
    parsed = {
        "method": "POST", "url": "https://example.com/x",
        "content_type": "application/x-www-form-urlencoded", "body": "",
        "headers": {},
    }
    bypass_data = {
        "content_type_attack": "", "method_override_applicable": False,
        "bypass_variants": [], "recommendation": "test rec",
    }
    display_csrf_poc("<html/>", parsed, "form",
                     tokens=[("body field", "csrf_token")], bypass_data=bypass_data)
    out = buf.getvalue()
    assert "csrf_token" in out       # token warning still shown
    assert "--bypass" not in out     # hint suppressed when bypass already active


def test_display_csrf_poc_shows_bypass_hint_without_bypass(monkeypatch, tmp_path):
    import io
    import ttpx
    from rich.console import Console as RichConsole
    buf = io.StringIO()
    monkeypatch.setattr(ttpx, "console", RichConsole(file=buf, highlight=False))
    monkeypatch.chdir(tmp_path)
    parsed = {
        "method": "POST", "url": "https://example.com/x",
        "content_type": "application/x-www-form-urlencoded", "body": "",
        "headers": {},
    }
    display_csrf_poc("<html/>", parsed, "form", tokens=[("body field", "csrf_token")])
    out = buf.getvalue()
    assert "csrf_token" in out
    assert "--bypass" in out         # hint shown when bypass not active


def test_log_payload_result_silent_on_error(tmp_path, monkeypatch):
    import ttpx
    # Point to a path where we can't write (file is a directory)
    log_path = tmp_path / "ttpx-session.log"
    log_path.mkdir()
    monkeypatch.setattr(ttpx, "LOG_PATH", log_path)
    data = {"vulnerability": "X", "payload": "p", "recommendation": "r"}
    log_payload_result(["x"], data)  # must not raise
