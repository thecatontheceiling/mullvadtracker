#!/usr/bin/env python3
"""Track changes to the Mullvad VPN server list.

Files written:
  data/servers.json     current JSON list of all servers
  data/changes.jsonl    changes journal
  changes/YYYY-MM.md    changelog for the month, newest entry first
  README.md             the block between the STATUS markers

Standard library only so no extra requirements needed.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

API_URL = "https://api.mullvad.net/www/relays/all/"

ROOT = Path(__file__).resolve().parent.parent
SNAPSHOT = ROOT / "data" / "servers.json"
HISTORY = ROOT / "data" / "changes.jsonl"
CHANGES_DIR = ROOT / "changes"
README = ROOT / "README.md"

STATUS_START = "<!-- STATUS:START -->"
STATUS_END = "<!-- STATUS:END -->"

# A response with fewer servers than this fraction of the prior server list is treated as broken.
MIN_FLEET_FRACTION = 0.5
# Tables with more rows than this are wrapped in <details>.
COLLAPSE_ABOVE = 25
RECENT_RUNS_IN_README = 10

FIELD_LABELS = {
    "active": "Online",
    "owned": "Mullvad-owned",
    "stboot": "RAM-only (stboot)",
    "daita": "DAITA",
    "network_port_speed": "Port speed (Gbps)",
    "provider": "Provider",
    "type": "Server type",
    "country_code": "Country code",
    "country_name": "Country",
    "city_code": "City code",
    "city_name": "City",
    "multihop_port": "Multihop port",
    "socks_name": "SOCKS5 hostname",
    "socks_port": "SOCKS5 port",
    "ipv4_v2ray": "IPv4 (v2ray)",
    "ipv4_addr_in": "IPv4 address",
    "ipv6_addr_in": "IPv6 address",
    "pubkey": "WireGuard public key",
    "fqdn": "FQDN",
    "ssh_fingerprint_sha256": "SSH fingerprint (SHA256)",
    "ssh_fingerprint_md5": "SSH fingerprint (MD5)",
}

# Changes to these fields go under "Network and key changes". Every other field
# goes under "Feature and attribute changes", including fields not listed here.
NETWORK_FIELDS = {
    "fqdn",
    "ipv4_addr_in",
    "ipv6_addr_in",
    "ipv4_v2ray",
    "pubkey",
    "multihop_port",
    "socks_name",
    "socks_port",
    "ssh_fingerprint_sha256",
    "ssh_fingerprint_md5",
}


def fetch_servers() -> list[dict]:
    request = urllib.request.Request(
        API_URL,
        headers={
            "User-Agent": "mullvad-server-tracker (+https://github.com)",
            "Accept": "application/json",
        },
    )
    for attempt in range(1, 6):
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                data = json.load(response)
            if isinstance(data, list) and all(isinstance(s, dict) for s in data):
                return data
            error = ValueError("unexpected response format (expected a list of objects)")
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            error = exc
        print(f"fetch attempt {attempt} failed: {error}", file=sys.stderr)
        time.sleep(5 * attempt)
    raise SystemExit(f"could not fetch {API_URL}: {error}")


def index_by_hostname(servers: list[dict]) -> dict[str, dict]:
    indexed: dict[str, dict] = {}
    for server in servers:
        hostname = server["hostname"]
        if hostname in indexed:
            raise SystemExit(f"duplicate hostname in data: {hostname}")
        indexed[hostname] = server
    return indexed


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def save_snapshot(servers: dict[str, dict]) -> None:
    lines = [json.dumps(servers[h], sort_keys=True, ensure_ascii=False) for h in sorted(servers)]
    write_text(SNAPSHOT, "[\n" + ",\n".join(lines) + "\n]\n")


def _messages_by_key(server: dict) -> dict[str, dict]:
    return {json.dumps(m, sort_keys=True, ensure_ascii=False): m for m in server.get("status_messages") or []}


def _locations(servers: dict[str, dict]) -> tuple[dict, dict, set]:
    countries = {s["country_code"]: s["country_name"] for s in servers.values()}
    cities = {
        (s["country_code"], s["city_code"]): f'{s["city_name"]}, {s["country_name"]}'
        for s in servers.values()
    }
    providers = {s["provider"] for s in servers.values()}
    return countries, cities, providers


def diff(old: dict[str, dict], new: dict[str, dict]) -> list[dict]:
    events: list[dict] = []
    for host in sorted(new.keys() - old.keys()):
        events.append({"event": "server_added", "hostname": host, "server": new[host]})
    for host in sorted(old.keys() - new.keys()):
        events.append({"event": "server_removed", "hostname": host, "server": old[host]})

    for host in sorted(old.keys() & new.keys()):
        old_server, new_server = old[host], new[host]
        for field in sorted((old_server.keys() | new_server.keys()) - {"status_messages"}):
            if old_server.get(field) != new_server.get(field):
                events.append(
                    {
                        "event": "changed",
                        "hostname": host,
                        "field": field,
                        "old": old_server.get(field),
                        "new": new_server.get(field),
                    }
                )
        before, after = _messages_by_key(old_server), _messages_by_key(new_server)
        for key in sorted(after.keys() - before.keys()):
            events.append({"event": "message_added", "hostname": host, "message": after[key]})
        for key in sorted(before.keys() - after.keys()):
            events.append({"event": "message_removed", "hostname": host, "message": before[key]})

    old_countries, old_cities, old_providers = _locations(old)
    new_countries, new_cities, new_providers = _locations(new)
    for code in sorted(new_countries.keys() - old_countries.keys()):
        events.append({"event": "country_added", "name": new_countries[code], "code": code})
    for code in sorted(old_countries.keys() - new_countries.keys()):
        events.append({"event": "country_removed", "name": old_countries[code], "code": code})
    for key in sorted(new_cities.keys() - old_cities.keys()):
        events.append({"event": "city_added", "name": new_cities[key], "code": "-".join(key)})
    for key in sorted(old_cities.keys() - new_cities.keys()):
        events.append({"event": "city_removed", "name": old_cities[key], "code": "-".join(key)})
    for name in sorted(new_providers - old_providers):
        events.append({"event": "provider_added", "name": name})
    for name in sorted(old_providers - new_providers):
        events.append({"event": "provider_removed", "name": name})
    return events


def _kind_of(event: dict) -> str:
    """Return the summary category for an event."""
    if event["event"] == "changed":
        if event["field"] == "active":
            return "online" if event["new"] else "offline"
        return "attribute"
    kinds = {
        "server_added": "added",
        "server_removed": "removed",
        "message_added": "message",
        "message_removed": "message",
    }
    # Anything not listed here is a country, city or provider event.
    return kinds.get(event["event"], "location")


def summarize(events: list[dict]) -> str:
    phrases = {
        "added": "added",
        "removed": "removed",
        "offline": "went offline",
        "online": "went online",
        "attribute": "attribute changes",
        "message": "message changes",
        "location": "location/provider changes",
    }
    counts = Counter(_kind_of(e) for e in events)
    return ", ".join(f"{counts[k]} {phrases[k]}" for k in phrases if counts[k])


def stats(servers: dict[str, dict]) -> dict:
    vals = list(servers.values())
    countries, cities, providers = _locations(servers)
    return {
        "servers": len(vals),
        "online": sum(1 for s in vals if s.get("active")),
        "offline": sum(1 for s in vals if not s.get("active")),
        "with_messages": sum(1 for s in vals if s.get("status_messages")),
        "countries": len(countries),
        "cities": len(cities),
        "providers": len(providers),
        "owned": sum(1 for s in vals if s.get("owned")),
        "rented": sum(1 for s in vals if not s.get("owned")),
        "daita": sum(1 for s in vals if s.get("daita")),
        "ram_only": sum(1 for s in vals if s.get("stboot")),
        "types": dict(sorted(Counter(s.get("type", "unknown") for s in vals).items())),
    }


def _tally(label: str, new: int, old: int) -> str:
    change = new - old
    return f"{new} {label}" + (f" ({change:+d})" if change else "")


def flag(country_code: str) -> str:
    code = (country_code or "").lower()
    if len(code) == 2 and code.isalpha() and code.isascii():
        return "".join(chr(0x1F1E6 + ord(c) - ord("a")) for c in code)
    return ""


def place(server: dict) -> str:
    return f'{flag(server["country_code"])} {server["city_name"]}, {server["country_name"]}'.strip()


def cell(text: object) -> str:
    """Make a value safe for a markdown table cell."""
    return str(text).replace("|", "\\|").replace("\n", " ")


def fmt_value(value: object) -> str:
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "yes" if value else "no"
    return f"`{cell(value)}`"


def section(title: str, count: int, body: list[str]) -> list[str]:
    lines = [f"### {title} ({count})", ""]
    if count > COLLAPSE_ABOVE:
        return lines + ["<details><summary>Show all</summary>", "", *body, "", "</details>", ""]
    return lines + [*body, ""]


def server_table(servers: list[dict]) -> list[str]:
    rows = [
        "| Server | Location | Provider | Speed | Ownership | Type | Features |",
        "|---|---|---|---|---|---|---|",
    ]
    for s in servers:
        features = [name for name, on in (("DAITA", s.get("daita")), ("RAM-only", s.get("stboot"))) if on]
        rows.append(
            f'| `{s["hostname"]}` | {cell(place(s))} | {cell(s["provider"])} | '
            f'{s["network_port_speed"]} Gbps | {"Owned" if s["owned"] else "Rented"} | '
            f'{s["type"]} | {", ".join(features) or "—"} |'
        )
    return rows


def host_lines(hosts: list[str], servers: dict[str, dict]) -> list[str]:
    return [f"- `{h}`: {place(servers[h])}" for h in hosts]


def change_table(events: list[dict]) -> list[str]:
    groups: dict[tuple, list[str]] = defaultdict(list)
    for e in events:
        groups[(e["field"], json.dumps(e["old"]), json.dumps(e["new"]))].append(e["hostname"])
    rows = ["| Attribute | Before | After | Servers |", "|---|---|---|---|"]
    for (field, old_json, new_json), hosts in sorted(groups.items()):
        names = ", ".join(f"`{h}`" for h in sorted(hosts))
        rows.append(
            f"| {FIELD_LABELS.get(field, field)} | {fmt_value(json.loads(old_json))} | "
            f"{fmt_value(json.loads(new_json))} | {len(hosts)}: {names} |"
        )
    return rows


def render_entry(heading: str, events: list[dict], old: dict[str, dict], new: dict[str, dict]) -> str:
    by_kind: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        by_kind[_kind_of(e)].append(e)
    old_stats, new_stats = stats(old), stats(new)
    totals = ", ".join(
        [
            _tally("servers", new_stats["servers"], old_stats["servers"]),
            _tally("online", new_stats["online"], old_stats["online"]),
            _tally("offline", new_stats["offline"], old_stats["offline"]),
        ]
    )
    out = [f"## {heading}", "", f"**{summarize(events)}**", "", f"Totals: {totals}.", ""]

    added = [e["server"] for e in by_kind["added"]]
    if added:
        out += section("New servers", len(added), server_table(added))

    removed = [e["server"] for e in by_kind["removed"]]
    if removed:
        out += section("Removed servers", len(removed), server_table(removed))

    went_offline = sorted(e["hostname"] for e in by_kind["offline"])
    if went_offline:
        out += section("Went offline", len(went_offline), host_lines(went_offline, new))

    went_online = sorted(e["hostname"] for e in by_kind["online"])
    if went_online:
        out += section("Back online", len(went_online), host_lines(went_online, new))

    attr = [e for e in by_kind["attribute"] if e["field"] not in NETWORK_FIELDS]
    if attr:
        out += section("Feature and attribute changes", len(attr), change_table(attr))

    net = [e for e in by_kind["attribute"] if e["field"] in NETWORK_FIELDS]
    if net:
        out += section("Network and key changes", len(net), change_table(net))

    msgs = by_kind["message"]
    if msgs:
        body = []
        for e in sorted(msgs, key=lambda e: (e["hostname"], e["event"])):
            verb = "added" if e["event"] == "message_added" else "removed"
            m = e["message"]
            stamp = f" ({m['timestamp']})" if m.get("timestamp") else ""
            body.append(f"- `{e['hostname']}` {verb}: {m.get('message', json.dumps(m))}{stamp}")
        out += section("Status messages", len(msgs), body)

    geo = by_kind["location"]
    if geo:
        body = [f'- {e["event"].replace("_", " ").capitalize()}: {e["name"]}' for e in geo]
        out += section("Countries, cities and providers", len(geo), body)

    return "\n".join(out).rstrip() + "\n"


def prepend_entry(month_file: Path, month: str, entry: str) -> None:
    if month_file.exists():
        text = month_file.read_text(encoding="utf-8")
    else:
        text = f"# Mullvad server changes: {month}\n\nNewest first. Times are UTC.\n"
    # Everything before the first "## " heading is the file header.
    head, sep, rest = text.partition("\n## ")
    write_text(month_file, head.rstrip("\n") + "\n\n" + entry + (f"\n## {rest}" if sep else ""))


def render_status(servers: dict[str, dict]) -> str:
    st = stats(servers)
    types = ", ".join(f"{n} {t}" for t, n in st["types"].items())
    lines = [
        STATUS_START,
        "",
        "## Current status",
        "",
        "| | |",
        "|---|---|",
        f"| Servers online | **{st['online']}** |",
        f"| Servers offline | **{st['offline']}** |",
        f"| Servers with status messages | **{st['with_messages']}** |",
        f"| Total servers | {st['servers']} ({types}) |",
        f"| Countries / cities / providers | {st['countries']} / {st['cities']} / {st['providers']} |",
        f"| Ownership | {st['owned']} owned, {st['rented']} rented |",
        f"| DAITA | {st['daita']} servers |",
        f"| RAM-only | {st['ram_only']} servers |",
        "",
    ]

    by_country: dict[str, list[dict]] = defaultdict(list)
    for s in servers.values():
        by_country[s["country_name"]].append(s)
    lines += [
        "<details><summary>Servers by country</summary>",
        "",
        "| Country | Servers | Online | Offline | Cities |",
        "|---|---:|---:|---:|---:|",
    ]
    for name in sorted(by_country):
        group = by_country[name]
        online = sum(1 for s in group if s.get("active"))
        cities = len({s["city_code"] for s in group})
        lines.append(
            f"| {flag(group[0]['country_code'])} {cell(name)} | {len(group)} | {online} | {len(group) - online} | {cities} |"
        )
    lines += ["", "</details>", ""]

    by_provider = Counter(s["provider"] for s in servers.values())
    lines += ["<details><summary>Servers by provider</summary>", "", "| Provider | Servers |", "|---|---:|"]
    for name, n in sorted(by_provider.items(), key=lambda kv: (-kv[1], kv[0].lower())):
        lines.append(f"| {cell(name)} | {n} |")
    lines += ["", "</details>", ""]

    lines += ["## Recent changes", ""]
    runs = []
    if HISTORY.exists():
        runs = [json.loads(line) for line in HISTORY.read_text(encoding="utf-8").splitlines() if line.strip()]
    if runs:
        lines += ["| Detected (UTC) | Changes |", "|---|---|"]
        for run in reversed(runs[-RECENT_RUNS_IN_README:]):
            heading = run["heading"]
            # The same anchor GitHub generates for the changelog heading.
            slug = re.sub(r"[^\w\- ]", "", heading.lower()).replace(" ", "-")
            lines.append(f"| [{heading}](changes/{run['time'][:7]}.md#{slug}) | {cell(run['summary'])} |")
    else:
        lines.append("No data yet.")
    months = ", ".join(f"[{p.stem}](changes/{p.name})" for p in sorted(CHANGES_DIR.glob("*.md"), reverse=True))
    lines += ["", f"Full history: {months or 'none yet'}", "", STATUS_END]
    return "\n".join(lines)


def update_readme(servers: dict[str, dict]) -> None:
    text = README.read_text(encoding="utf-8")
    start, end = text.find(STATUS_START), text.find(STATUS_END)
    if start == -1 or end == -1 or end < start:
        raise SystemExit(f"README.md is missing the {STATUS_START} / {STATUS_END} markers")
    write_text(README, text[:start] + render_status(servers) + text[end + len(STATUS_END) :])


def emit_ci_outputs(summary: str, markdown: str) -> None:
    if path := os.environ.get("GITHUB_OUTPUT"):
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(f"summary={summary}\n")
    if path := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(markdown + "\n")


def main() -> None:
    new = index_by_hostname(fetch_servers())
    old = index_by_hostname(json.loads(SNAPSHOT.read_text(encoding="utf-8"))) if SNAPSHOT.exists() else None
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    day = now.strftime("%Y-%m-%d")
    heading = now.strftime("%Y-%m-%d %H:%M UTC")
    month = now.strftime("%Y-%m")
    stamp = now.strftime("%Y-%m-%dT%H:%MZ")

    if old is None:
        counts = stats(new)
        summary = f"Initial server list: {counts['servers']} servers"
        entry = f"## {heading}\n\n**{summary}** ({counts['online']} online, {counts['offline']} offline).\n"
        record = {"time": stamp, "heading": heading, "summary": summary, "baseline": True, "events": []}
    else:
        if not new or len(new) < len(old) * MIN_FLEET_FRACTION:
            raise SystemExit(
                f"refusing to record: API returned {len(new)} servers vs {len(old)} so it's probably broken."
            )
        events = diff(old, new)
        if not events:
            print("No changes.")
            save_snapshot(new)
            update_readme(new)
            emit_ci_outputs("no changes", "No changes in Mullvad's server list.")
            return
        summary = summarize(events)
        entry = render_entry(heading, events, old, new)
        record = {"time": stamp, "heading": heading, "summary": summary, "events": events}

    prepend_entry(CHANGES_DIR / f"{month}.md", month, entry)
    HISTORY.parent.mkdir(parents=True, exist_ok=True)
    with open(HISTORY, "a", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n")
    save_snapshot(new)
    update_readme(new)

    print(summary)
    emit_ci_outputs(f"{day}: {summary}", entry)


if __name__ == "__main__":
    main()
