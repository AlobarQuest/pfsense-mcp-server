import subprocess, json, os, re, urllib.request

BASE = os.environ.get('BASE_REF', 'origin/main')
HEAD = os.environ['HEAD_REF']  # e.g. "v1.1.0" — required

# --- commits section (capped) ---
commits_raw = subprocess.check_output(
    ['git', 'log', f'{BASE}..{HEAD}', '--oneline'], text=True
).strip()
commit_lines = commits_raw.splitlines()
if len(commit_lines) > 100:
    commits = '\n'.join(commit_lines[:100]) + f'\n[... {len(commit_lines) - 100} more commits]'
else:
    commits = commits_raw

# --- diff section (trust-relevant paths, capped) ---
DIFF_PATHS = [
    'src/', 'pyproject.toml', 'requirements.txt', 'Dockerfile',
    'docker-compose.yml', 'start.sh', 'mcp.json', '.claude/',
]
diff = subprocess.check_output(
    ['git', 'diff', f'{BASE}..{HEAD}', '--'] + DIFF_PATHS,
    text=True
)
diff_lines = diff.splitlines()
truncated = len(diff_lines) > 1500
if truncated:
    diff = '\n'.join(diff_lines[:1500]) + '\n\n[TRUNCATED — see full diff in GitHub PR]'

# --- trust-critical modules: always include full contents at HEAD ---
# client.py is the only network caller (pfSense HTTP/auth, TLS-verify);
# guardrails.py decides which destructive tools are gated/rate-limited;
# middleware.py + server.py enforce read-only mode and request handling.
TRUST_CRITICAL = ['src/client.py', 'src/guardrails.py', 'src/middleware.py', 'src/server.py']
critical_parts = []
for path in TRUST_CRITICAL:
    try:
        content = subprocess.check_output(['git', 'show', f'{HEAD}:{path}'], text=True)
        critical_parts.append("### " + path + "\n```python\n" + content + "\n```")
    except subprocess.CalledProcessError:
        critical_parts.append("### " + path + "\n[Not present at " + HEAD + " — may have moved; flag this]")
critical_section = (
    "\n\n## Trust-Critical Module Full Contents\n"
    "These modules are reviewed in full every sync regardless of diff size. "
    "client.py is the only network-calling module (talks to the pfSense API, "
    "handles credentials and TLS verification); guardrails.py decides which "
    "destructive tools are gated/rate-limited; middleware.py and server.py "
    "enforce read-only mode and request handling.\n\n"
    + "\n\n".join(critical_parts)
)

# --- automated pattern scan over changed .py files + trust-critical modules ---
DANGER_PATTERNS = [
    (r'subprocess|os\.system|Popen|os\.popen', 'exec: process execution'),
    (r'\beval\(|\bexec\(|__import__|compile\(', 'exec: dynamic code'),
    (r'pickle\.|marshal\.|yaml\.load\b(?!er)', 'deser: unsafe deserialization'),
    (r'verify\s*=\s*False|ssl\._create_unverified|CERT_NONE', 'tls: certificate verification disabled'),
    (r'https?://', 'network: hardcoded URL'),
    (r'requests\.|httpx\.|aiohttp|urllib\.request|TcpStream|socket\.', 'network: client usage'),
    (r'os\.environ(?:\.get)?\([^)]*(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)', 'creds: secret env read'),
    (r'\.ssh|\.aws|\.netrc|\.gnupg', 'creds: credential path'),
    (r'\.claude', 'fs: ~/.claude access'),
    (r'base64|b64decode|b64encode', 'obfuscation: base64'),
    (r'getattr\(|setattr\(', 'reflection: dynamic attribute access'),
]

changed = subprocess.check_output(
    ['git', 'diff', '--name-only', f'{BASE}..{HEAD}', '--', 'src/'],
    text=True
).splitlines()
scan_files = sorted(set(
    [p for p in changed if p.endswith('.py')] + TRUST_CRITICAL
))

scan_findings = []
for path in scan_files:
    try:
        lines = subprocess.check_output(['git', 'show', f'{HEAD}:{path}'], text=True).splitlines()
    except subprocess.CalledProcessError:
        continue  # deleted or moved at HEAD
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith('#'):
            continue
        for regex, label in DANGER_PATTERNS:
            if re.search(regex, line):
                scan_findings.append("  [{}] {}:{} — {}".format(label, path, i, stripped[:160]))

scan_section = "\n\n## Automated Pattern Scan\n"
scan_section += "Scanned {} changed/trust-critical .py files at {}.\n".format(len(scan_files), HEAD)
if scan_findings:
    if len(scan_findings) > 200:
        scan_findings = scan_findings[:200] + ["  [... truncated at 200 hits]"]
    scan_section += "Matched {} pattern(s):\n".format(len(scan_findings))
    scan_section += "\n".join(scan_findings)
else:
    scan_section += "No danger patterns matched."

# --- build prompt ---
prompt = (
    "You are a security reviewer for a personal fork of gensecaihq/pfsense-mcp-server.\n\n"
    "This is a Python MCP (Model Context Protocol) server that exposes ~327 tools for "
    "managing a pfSense firewall (firewall rules, NAT, VPN, DHCP, DNS, certificates, "
    "users, system config). An LLM agent calls these tools; ~48 are destructive and are "
    "meant to be gated by a guardrail decorator system. A malicious upstream change could "
    "silently weaken those guardrails, exfiltrate the pfSense API credentials, disable TLS "
    "verification, or add a hidden network/exec path. I review every upstream release before "
    "running the server locally against my live firewall.\n\n"
    "Trust-critical paths: src/client.py (only legitimate network caller — pfSense API client, "
    "credential + TLS handling), src/guardrails.py (decides which destructive tools are "
    "gated/rate-limited), src/middleware.py and src/server.py (read-only-mode enforcement, "
    "request handling).\n\n"
    "Upstream release range under review: " + BASE + " -> " + HEAD + "\n\n"
    "New commits:\n" + commits + "\n\n"
    "Diff (trust-relevant files only" + (", truncated" if truncated else "") + "):\n"
    + diff
    + critical_section
    + scan_section
    + "\n\n"
    "Your job:\n"
    "1. Summarize what changed in 2-4 plain English sentences.\n"
    "2. Flag any of the following if present (with file:line reference):\n"
    "   - Disabled TLS verification (verify=False, CERT_NONE) or weakened cert handling in client.py\n"
    "   - Guardrail changes that ungate a destructive tool, remove @guarded/@rate_limited, "
    "or reclassify a tool's risk downward\n"
    "   - Read-only-mode bypasses or middleware changes that let destructive calls through\n"
    "   - New network calls or hardcoded URLs/hosts outside client.py, or credential exfiltration\n"
    "   - New process execution (subprocess/os.system/Popen) or dynamic code (eval/exec/__import__)\n"
    "   - Unsafe deserialization (pickle/marshal/yaml.load) of remote data\n"
    "   - New environment variable reads of secrets, or new access to ~/.ssh, ~/.aws, ~/.netrc, ~/.claude\n"
    "   - New or changed dependencies in pyproject.toml/requirements.txt, or install hooks\n"
    "   - base64/obfuscation or embedded blobs\n"
    "   - Changes under .claude/ (skills/commands that auto-load into Claude Code sessions) — "
    "treat as a prompt-injection surface\n"
    "   - Automated pattern scan hits (listed above) — assess each: benign or risky?\n"
    "3. Give a one-line recommendation.\n\n"
    "Respond in exactly this format:\n\n"
    "## Summary\n"
    "[2-4 sentences]\n\n"
    "## Security Flags\n"
    "[Bulleted list with file references, or \"None detected\"]\n\n"
    "## Pattern Scan Assessment\n"
    "[For each automated scan hit (group similar hits): BENIGN or RISK — one-line reason]\n\n"
    "## Recommendation\n"
    "MERGE SAFE / REVIEW NEEDED / DO NOT MERGE — [one sentence reason]"
)

payload = {
    "model": "claude-haiku-4-5-20251001",
    "max_tokens": 2048,
    "messages": [{"role": "user", "content": prompt}]
}

api_key = os.environ.get('ANTHROPIC_API_KEY')
if not api_key:
    review = "Warning: ANTHROPIC_API_KEY not set — AI review skipped. Review the diff manually before merging."
else:
    req = urllib.request.Request(
        'https://api.anthropic.com/v1/messages',
        data=json.dumps(payload).encode(),
        headers={
            'x-api-key': api_key,
            'anthropic-version': '2023-06-01',
            'content-type': 'application/json'
        }
    )
    try:
        with urllib.request.urlopen(req) as resp:
            result = json.loads(resp.read())
            review = result['content'][0]['text']
    except Exception as e:
        review = "Warning: Error generating AI review: {}\n\nReview the diff manually before merging.".format(e)

# prepend scan hits so they're visible even if the AI summary is brief
output = review
if scan_findings:
    output = (
        "## Raw Pattern Scan Hits\n"
        + "\n".join(scan_findings)
        + "\n\n---\n\n"
        + review
    )

with open('/tmp/ai_review.md', 'w') as f:
    f.write(output)
print(output)
