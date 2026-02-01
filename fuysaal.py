#!/usr/bin/env python3
"""
Fuysaal - Advanced Bug Bounty Reconnaissance Tool
A comprehensive automated reconnaissance framework for bug bounty hunters.
"""

import os
import subprocess
import sys
import re
import json
import logging
import atexit
import random
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.panel import Panel
from rich.rule import Rule

console = Console()
SCAN_DIR = ""
LOG_FILE = ""

BANNER = (
    "\033[1;35m\n"
    "  ______                             _\n"
    " |  ____|                           | |\n"
    " | |__ _   _ _   _ ___  __ _  __ _  | |\n"
    " |  __| | | | | | / __|/ _` |/ _` | | |\n"
    " | |  | |_| | |_| \\__ \\ (_| | (_| | |_|\n"
    " |_|   \\__,_|\\__, |___/\\__,_|\\__,_| (_)\n"
    "              __/ |\n"
    "             |___/           by Fuysaal\033[0m\n"
)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Edg/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Edg/121.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
]

ALLOWED_DOMAIN_REGEX = re.compile(
    r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$'
)

TECH_TEMPLATE_MAP = {
    "wordpress": ["http/cves/", "http/exposures/", "wordpress/"],
    "drupal": ["http/cves/", "drupal/"],
    "joomla": ["http/cves/", "joomla/"],
    "wp-includes": ["wordpress/"],
    "laravel": ["http/cves/", "laravel/"],
    "django": ["http/cves/", "django/"],
    "symfony": ["http/cves/", "symfony/"],
    "ruby on rails": ["http/cves/", "rails/"],
    "rails": ["http/cves/", "rails/"],
    "express": ["http/cves/", "nodejs/"],
    "node.js": ["http/cves/", "nodejs/"],
    "spring": ["http/cves/", "springboot/"],
    "spring boot": ["http/cves/", "springboot/"],
    "struts": ["http/cves/", "struts/"],
    "angular": ["http/cves/"],
    "react": ["http/cves/"],
    "vue.js": ["http/cves/"],
    "php": ["http/cves/", "php/"],
    "python": ["http/cves/"],
    "java": ["http/cves/", "java/"],
    "asp.net": ["http/cves/", "aspnet/"],
    "ruby": ["http/cves/"],
    "apache": ["http/cves/", "apache/"],
    "nginx": ["http/cves/", "nginx/"],
    "microsoft iis": ["http/cves/", "iis/"],
    "iis": ["http/cves/", "iis/"],
    "tomcat": ["http/cves/", "tomcat/"],
    "jetty": ["http/cves/"],
    "caddy": ["http/cves/"],
    "aws": ["http/cves/", "aws/"],
    "amazon": ["http/cves/", "aws/"],
    "azure": ["http/cves/", "azure/"],
    "gcloud": ["http/cves/", "gcp/"],
    "google cloud": ["http/cves/", "gcp/"],
    "cloudflare": ["http/cves/"],
    "heroku": ["http/cves/"],
    "jenkins": ["http/cves/", "jenkins/"],
    "gitlab": ["http/cves/", "gitlab/"],
    "github": ["http/cves/"],
    "confluence": ["http/cves/", "confluence/"],
    "jira": ["http/cves/", "jira/"],
    "grafana": ["http/cves/", "grafana/"],
    "kibana": ["http/cves/", "kibana/"],
    "elasticsearch": ["http/cves/", "elasticsearch/"],
    "docker": ["http/cves/", "docker/"],
    "kubernetes": ["http/cves/", "kubernetes/"],
    "graphql": ["http/cves/", "graphql/"],
    "swagger": ["http/cves/", "swagger/"],
    "openapi": ["http/cves/", "swagger/"],
    "jquery": [],
    "bootstrap": [],
    "wix": ["http/cves/", "wix/"],
    "shopify": ["http/cves/"],
    "wp-json": ["wordpress/"],
    "x-powered-by": ["http/cves/"],
}

UNIVERSAL_TEMPLATES = [
    "http/misconfigurations/",
    "http/exposures/",
    "http/security-audit/",
    "http/cves/",
]

def get_random_ua():
    return random.choice(USER_AGENTS)

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)s: %(message)s",
        handlers=[logging.FileHandler(LOG_FILE)]
    )

def sanitize_domain(domain):
    domain = domain.strip().lower().replace("*.", "")
    if not domain or len(domain) > 253:
        return None
    if not ALLOWED_DOMAIN_REGEX.match(domain):
        return None
    return domain

def run_cmd(cmd, timeout=300):
    logging.info(f"CMD: {cmd}")
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        if result.returncode != 0 and result.stderr:
            logging.warning(f"STDERR: {result.stderr[:200]}")
        return result
    except subprocess.TimeoutExpired:
        logging.error(f"TIMEOUT ({timeout}s): {cmd}")
        return subprocess.CompletedProcess(args=cmd, returncode=-1, stdout="", stderr="TIMEOUT")
    except Exception as e:
        logging.error(f"ERROR: {cmd} -> {e}")
        return subprocess.CompletedProcess(args=cmd, returncode=-1, stdout="", stderr=str(e))

def jitter(min_sec=0.5, max_sec=3.0):
    time.sleep(random.uniform(min_sec, max_sec))

def fpath(filename):
    return os.path.join(SCAN_DIR, filename)

def count_lines(filename):
    path = fpath(filename)
    if not os.path.exists(path):
        return 0
    with open(path, 'r') as f:
        return sum(1 for line in f if line.strip())

def read_lines(filename):
    path = fpath(filename)
    if not os.path.exists(path):
        return []
    with open(path, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def detect_wildcard_ips(targets):
    wildcard_ips = set()
    import string
    for target in targets:
        for _ in range(3):
            rand_sub = ''.join(random.choices(string.ascii_lowercase, k=12))
            result = run_cmd(f"dig +short {rand_sub}.{target}", timeout=10)
            for ip in result.stdout.strip().split('\n'):
                ip = ip.strip()
                if ip:
                    wildcard_ips.add(ip)
    logging.info(f"Wildcard IPs: {wildcard_ips}")
    return wildcard_ips

def filter_wildcards(subs_file, wildcard_ips):
    if not wildcard_ips:
        return
    subs = read_lines(subs_file)
    filtered = []
    for sub in subs:
        result = run_cmd(f"dig +short {sub}", timeout=5)
        resolved_ips = set(result.stdout.strip().split('\n'))
        if not resolved_ips.intersection(wildcard_ips):
            filtered.append(sub)
    with open(fpath(subs_file), 'w') as f:
        f.write('\n'.join(filtered) + '\n')
    logging.info(f"Wildcard filter: {len(subs)} -> {len(filtered)}")

def filter_in_scope(input_file, output_file, targets):
    lines = read_lines(input_file)
    in_scope = []
    for line in lines:
        domain = re.sub(r'^https?://', '', line).split('/')[0].split(':')[0]
        if any(domain == t or domain.endswith('.' + t) for t in targets):
            in_scope.append(line)
    with open(fpath(output_file), 'w') as f:
        f.write('\n'.join(in_scope) + '\n')
    return len(in_scope)

def run_parallel(commands, max_workers=4):
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(run_cmd, cmd, timeout): cmd for cmd, timeout in commands}
        for future in as_completed(futures):
            results.append(future.result())
    return results

def cleanup():
    temp_files = ["for_param_spider.txt", "sensitive_patterns.txt",
                  "fuzz_targets.txt", "deep_scan_targets.txt", "cloud_buckets_raw.txt"]
    for f in temp_files:
        path = fpath(f)
        if os.path.exists(path):
            os.remove(path)

def detect_waf(live_file):
    waf_map = {}
    hosts = read_lines(live_file)
    unique_hosts = list(set(h.split()[0] for h in hosts if h.strip()))

    for host in unique_hosts:
        jitter(0.3, 1.0)
        result = run_cmd(f"wafw00f {host} -f json 2>/dev/null", timeout=15)
        try:
            output = result.stdout.strip()
            if output:
                data = json.loads(output)
                detected = data.get("detected", [])
                if detected and detected[0].get("waf") != "None":
                    waf_map[host] = True
                    logging.info(f"WAF DETECTED on {host}: {detected[0].get('waf')}")
                else:
                    waf_map[host] = False
            else:
                if "detected" in result.stdout.lower() and "none" not in result.stdout.lower():
                    waf_map[host] = True
                else:
                    waf_map[host] = False
        except Exception:
            if "The site" in result.stdout and "is behind" in result.stdout:
                waf_map[host] = True
            else:
                waf_map[host] = False

    return waf_map

class ScanConfig:
    def __init__(self, waf_detected):
        if waf_detected:
            self.httpx_rate_limit = 2
            self.httpx_delay = 1
            self.naabu_rate = 5
            self.ferox_threads = 5
            self.ferox_delay = 2
            self.nuclei_rate = 10
            self.nuclei_bulk = 5
            self.jitter_min = 1.0
            self.jitter_max = 4.0
            self.katana_concurrency = 5
            self.katana_delay = 2
        else:
            self.httpx_rate_limit = 50
            self.httpx_delay = 0
            self.naabu_rate = 100
            self.ferox_threads = 30
            self.ferox_delay = 0
            self.nuclei_rate = 50
            self.nuclei_bulk = 20
            self.jitter_min = 0.2
            self.jitter_max = 1.0
            self.katana_concurrency = 20
            self.katana_delay = 0

def detect_technologies(live_file, cfg, proxy_flag):
    ua = get_random_ua()
    run_cmd(
        f"cat {fpath(live_file)} | awk '{{print $1}}' | httpx "
        f'-H "User-Agent: {ua}" '
        f"-tech -no-color -silent "
        f"-rate-limit {cfg.httpx_rate_limit} "
        f"{proxy_flag} "
        f"| anew {fpath('tech_map.txt')}",
        timeout=240
    )

    tech_map = {}
    for line in read_lines('tech_map.txt'):
        match = re.match(r'^(https?://\S+)\s+\[(.+)\]$', line)
        if match:
            host = match.group(1)
            techs = [t.strip() for t in match.group(2).split(',') if t.strip()]
            tech_map[host] = techs

    logging.info(f"Tech detection: {len(tech_map)} hosts mapped")
    return tech_map

def build_nuclei_groups(tech_map, waf_detected_hosts, ferox_file, url_file, templates_root="/root/nuclei-templates/"):
    surface_signals = set()
    for line in read_lines(ferox_file) + read_lines(url_file):
        low = line.lower()
        if "graphql" in low:
            surface_signals.add("graphql")
        if "swagger" in low or "openapi" in low or "api-docs" in low:
            surface_signals.add("swagger")
        if "actuator" in low:
            surface_signals.add("spring boot")
        if "wp-json" in low or "wp-includes" in low:
            surface_signals.add("wordpress")
        if "jenkins" in low:
            surface_signals.add("jenkins")
        if "gitlab" in low:
            surface_signals.add("gitlab")
        if "confluence" in low:
            surface_signals.add("confluence")
        if "grafana" in low:
            surface_signals.add("grafana")
        if "kibana" in low:
            surface_signals.add("kibana")

    group_map = {}
    all_hosts = list(tech_map.keys())
    if not all_hosts:
        all_hosts = [h.split()[0] for h in read_lines('live.txt') if h.strip()]

    for host in all_hosts:
        templates = set()
        for tech in tech_map.get(host, []):
            for p in TECH_TEMPLATE_MAP.get(tech.lower(), []):
                templates.add(os.path.join(templates_root, p))
        for signal in surface_signals:
            for p in TECH_TEMPLATE_MAP.get(signal.lower(), []):
                templates.add(os.path.join(templates_root, p))
        group_map.setdefault(frozenset(templates), []).append(host)

    groups = []
    for template_set, hosts in group_map.items():
        if not template_set:
            continue
        groups.append({
            "hosts": hosts,
            "templates": sorted(template_set),
            "is_waf": any(h in waf_detected_hosts for h in hosts),
        })

    universal_paths = [os.path.join(templates_root, t) for t in UNIVERSAL_TEMPLATES]
    groups.append({
        "hosts": all_hosts,
        "templates": universal_paths,
        "is_waf": len(waf_detected_hosts) > 0,
    })

    logging.info(f"Nuclei groups: {len(groups)} ({len(all_hosts)} hosts total)")
    return groups

def generate_json_report(stats, targets, scan_dir, waf_map):
    report = {
        "tool": "Fuysaal",
        "version": "2.1",
        "scan_time": datetime.now().isoformat(),
        "targets": targets,
        "waf_detection": waf_map,
        "summary": {k: str(v) for k, v in stats.items()},
        "files": {}
    }
    file_map = {
        "subdomains": "subs.txt",
        "takeovers": "subdomaintakeover.txt",
        "ports": "naabu.txt",
        "live_hosts": "live.txt",
        "urls": "all_urls.txt",
        "js_files": "js.txt",
        "secrets": "secretfinder.txt",
        "links": "linkfinder.txt",
        "parameters": "params_names.txt",
        "nuclei_results": "nuclei.txt",
        "ferox_results": "ferox.txt",
        "cors_results": "cors.txt",
        "sensitive_files": "sensitive.txt",
        "cloud_buckets": "cloud_buckets.txt",
        "waf_hosts": "waf_detected.txt",
    }
    for key, fname in file_map.items():
        report["files"][key] = read_lines(fname)

    report_path = os.path.join(scan_dir, "report.json")
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    return report_path

def generate_html_report(stats, targets, scan_dir, waf_map):
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def section(title, filename, color="#4ecca3"):
        lines = read_lines(filename)
        if not lines:
            return ""
        items = "\n".join(f'<li>{l}</li>' for l in lines[:500])
        return f"""
        <div class="section">
            <h2 style="color:{color};">&#9658; {title} <span class="badge">{len(lines)}</span></h2>
            <ul>{items}</ul>
        </div>"""

    stats_rows = "\n".join(f'<tr><td>{k}</td><td>{v}</td></tr>' for k, v in stats.items())
    waf_rows = "\n".join(
        f'<tr><td>{host}</td><td style="color:{"#e94560" if detected else "#4ecca3"};">'
        f'{"⚠ WAF Detected" if detected else "✓ No WAF"}</td></tr>'
        for host, detected in waf_map.items()
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Fuysaal — Scan Report</title>
<style>
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ background:#0a0e1a; color:#c8d6e5; font-family:'Segoe UI',sans-serif; padding:40px 20px; min-height:100vh; }}
  .container {{ max-width:1100px; margin:0 auto; }}
  h1 {{ text-align:center; color:#4ecca3; font-size:2.2rem; margin-bottom:6px; letter-spacing:2px; }}
  .meta {{ text-align:center; color:#636e72; font-size:0.85rem; margin-bottom:40px; }}
  .summary-table {{ width:100%; border-collapse:collapse; margin-bottom:40px; background:#111827; border-radius:10px; overflow:hidden; }}
  .summary-table th {{ background:#1a2332; color:#4ecca3; padding:12px 18px; text-align:left; font-weight:600; font-size:0.8rem; text-transform:uppercase; letter-spacing:1px; }}
  .summary-table td {{ padding:10px 18px; border-bottom:1px solid #1e293b; font-size:0.9rem; }}
  .summary-table tr:last-child td {{ border-bottom:none; }}
  .summary-table tr:hover {{ background:#1a2332; }}
  .section {{ background:#111827; border-radius:10px; padding:24px; margin-bottom:28px; }}
  .section h2 {{ font-size:1rem; margin-bottom:14px; font-weight:500; }}
  .badge {{ background:#4ecca3; color:#0a0e1a; border-radius:12px; padding:2px 10px; font-size:0.72rem; font-weight:700; margin-left:10px; }}
  ul {{ list-style:none; max-height:340px; overflow-y:auto; padding-right:8px; }}
  ul::-webkit-scrollbar {{ width:5px; }}
  ul::-webkit-scrollbar-track {{ background:#0a0e1a; }}
  ul::-webkit-scrollbar-thumb {{ background:#4ecca3; border-radius:3px; }}
  li {{ padding:5px 0; border-bottom:1px solid #1e293b; font-size:0.82rem; font-family:'Consolas','Courier New',monospace; color:#a8b2d1; word-break:break-all; }}
  li:last-child {{ border-bottom:none; }}
  .footer {{ text-align:center; color:#636e72; font-size:0.75rem; margin-top:60px; }}
</style>
</head>
<body>
<div class="container">
  <h1>&#128269; FUYSAAL SCAN REPORT</h1>
  <p class="meta">Targets: {", ".join(targets)} &nbsp;|&nbsp; Scanned: {scan_time}</p>
  <table class="summary-table">
    <tr><th>Category</th><th>Result</th></tr>
    {stats_rows}
  </table>
  <div class="section">
    <h2 style="color:#e17055;">&#9658; WAF Detection Results <span class="badge">{len(waf_map)}</span></h2>
    <table class="summary-table" style="margin-top:10px;">
      <tr><th>Host</th><th>WAF Status</th></tr>
      {waf_rows}
    </table>
  </div>
  {section("Subdomains", "subs.txt", "#4ecca3")}
  {section("Subdomain Takeover", "subdomaintakeover.txt", "#e94560")}
  {section("Live Hosts", "live.txt", "#00cec9")}
  {section("Nuclei Findings", "nuclei.txt", "#e94560")}
  {section("Port Scan Results", "naabu.txt", "#6c5ce7")}
  {section("Directory Fuzzing", "ferox.txt", "#fdcb6e")}
  {section("CORS Misconfigurations", "cors.txt", "#e17055")}
  {section("Sensitive Files Found", "sensitive.txt", "#e94560")}
  {section("Cloud Buckets", "cloud_buckets.txt", "#fd79a8")}
  {section("All URLs", "all_urls.txt", "#74b9ff")}
  {section("JS Files", "js.txt", "#ffeaa7")}
  {section("Secrets Found", "secretfinder.txt", "#e94560")}
  {section("LinkFinder Results", "linkfinder.txt", "#a29bfe")}
  {section("Parameters", "params_names.txt", "#55efc4")}
  <div class="footer">Generated by Fuysaal v2.1</div>
</div>
</body>
</html>"""

    report_path = os.path.join(scan_dir, "report.html")
    with open(report_path, 'w') as f:
        f.write(html)
    return report_path

def main():
    global SCAN_DIR, LOG_FILE

    os.system('clear')
    print(BANNER)

    target_input = console.input("[bold cyan]Target Domain or List Path: [/bold cyan]")

    if os.path.exists(target_input):
        raw_targets = [line.strip() for line in open(target_input, 'r') if line.strip()]
    else:
        raw_targets = [target_input]

    targets = []
    for t in raw_targets:
        sanitized = sanitize_domain(t)
        if sanitized:
            targets.append(sanitized)
        else:
            console.print(f"[red]Skipped invalid:[/red] [white]{t}[/white]")

    if not targets:
        console.print("[red bold]No valid targets. Exiting.[/red bold]")
        sys.exit(1)

    proxy_file = None
    use_proxy = console.input("[bold cyan]Proxy list path (Enter to skip): [/bold cyan]").strip()
    if use_proxy and os.path.exists(use_proxy):
        proxy_file = use_proxy
        console.print(f"[green]✓ Proxy file loaded:[/green] [white]{use_proxy}[/white]")
    else:
        console.print("[yellow]⚠ No proxy — using direct connection[/yellow]")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    SCAN_DIR = os.path.join(os.getcwd(), f"scan_{timestamp}")
    os.makedirs(SCAN_DIR, exist_ok=True)
    os.chdir(SCAN_DIR)

    LOG_FILE = fpath("scan.log")
    setup_logging()
    atexit.register(cleanup)

    target_grep_pattern = "|".join(re.escape(t) for t in targets)
    proxy_flag_httpx = f"-proxy {proxy_file}" if proxy_file else ""
    proxy_flag_nuclei = f"-proxy {proxy_file}" if proxy_file else ""
    proxy_flag_katana = f"-proxy {proxy_file}" if proxy_file else ""
    proxy_flag_ferox = f"--proxy file://{proxy_file}" if proxy_file else ""

    console.print(f"\n[bold magenta]Targets:[/bold magenta] [white]{', '.join(targets)}[/white]")
    console.print(f"[bold magenta]Scan Dir:[/bold magenta] [white]{SCAN_DIR}[/white]\n")

    stats = {}
    waf_map = {}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40),
        TaskProgressColumn(),
        console=console
    ) as progress:

        task1 = progress.add_task("[green] Subdomain Enumeration...", total=3)
        enum_cmds = []
        for target in targets:
            enum_cmds.extend([
                (f"subfinder -d {target} -all -recursive | anew {fpath('subs.txt')}", 120),
                (f"assetfinder --subs-only {target} | anew {fpath('subs.txt')}", 60),
            ])
        run_parallel(enum_cmds, max_workers=5)
        progress.advance(task1, 1)

        run_cmd(f"sort -u {fpath('subs.txt')} -o {fpath('subs.txt')}")
        progress.advance(task1, 1)

        wildcard_ips = detect_wildcard_ips(targets)
        if wildcard_ips:
            console.print(f"[yellow]⚠ Wildcard IPs detected — filtering...[/yellow]")
            filter_wildcards('subs.txt', wildcard_ips)
        progress.advance(task1, 1)
        stats['Total Subdomains'] = count_lines('subs.txt')

        task2 = progress.add_task("[magenta] Checking Takeover...", total=1)
        run_cmd(f"cat {fpath('subs.txt')} | dnstake | anew {fpath('subdomaintakeover.txt')}", timeout=180)
        progress.advance(task2, 1)
        takeover_count = count_lines('subdomaintakeover.txt')
        if takeover_count > 0:
            stats['⚠ Takeover Found'] = takeover_count

        task3 = progress.add_task("[cyan] Live Check...", total=1)
        ua = get_random_ua()
        run_cmd(
            f'cat {fpath("subs.txt")} | httpx '
            f'-H "User-Agent: {ua}" '
            f"-rate-limit 30 -sc -td -ip -no-color -silent "
            f"{proxy_flag_httpx} "
            f"| anew {fpath('live.txt')}",
            timeout=300
        )
        progress.advance(task3, 1)

        codes = ["200", "301", "302", "400", "401", "403", "404", "500"]
        for code in codes:
            count_raw = run_cmd(f"grep -cF '[{code}]' {fpath('live.txt')}").stdout.strip()
            count = int(count_raw) if count_raw.isdigit() else 0
            if count > 0:
                stats[f"Status {code}"] = count

        task4 = progress.add_task("[bold red] WAF Detection...", total=1)
        waf_map = detect_waf('live.txt')
        waf_detected_hosts = [h for h, detected in waf_map.items() if detected]
        with open(fpath('waf_detected.txt'), 'w') as f:
            f.write('\n'.join(waf_detected_hosts) + '\n')

        any_waf = len(waf_detected_hosts) > 0
        if any_waf:
            console.print(f"[red]⚠ WAF detected on {len(waf_detected_hosts)} host(s) — stealth mode activated[/red]")
            stats['⚠ WAF Hosts'] = len(waf_detected_hosts)
        else:
            console.print("[green]✓ No WAF detected — normal speed[/green]")

        cfg = ScanConfig(waf_detected=any_waf)
        progress.advance(task4, 1)

        task5 = progress.add_task("[blue] Port Scanning...", total=1)
        run_cmd(
            f"cat {fpath('subs.txt')} | naabu "
            f"-rate {cfg.naabu_rate} -timeout 5 -silent "
            f"| anew {fpath('naabu.txt')}",
            timeout=300
        )
        progress.advance(task5, 1)
        try:
            with open(fpath('naabu.txt'), 'r') as f:
                ports = ",".join(sorted(set(line.strip().split(':')[-1] for line in f if line.strip())))
            stats['Open Ports'] = ports if ports else "0"
        except Exception:
            stats['Open Ports'] = "0"

        task6 = progress.add_task("[yellow] URL Discovery...", total=2)
        passive_url_cmds = [
            (f"cat {fpath('live.txt')} | awk '{{print $1}}' | sed -E 's|https?://||' | sed 's|/||' | waybackurls | anew {fpath('all_urls.txt')}", 500),
            (f"cat {fpath('live.txt')} | awk '{{print $1}}' | sed -E 's|https?://||' | sed 's|/||' | gau --subs --threads 50 | grep -ivE '\\.(jpg|jpeg|png|gif|svg|css|woff|woff2|ttf|otf|ico|pdf|mp4|txt|xml|js)' | anew {fpath('all_urls.txt')}", 240),
        ]
        run_parallel(passive_url_cmds, max_workers=2)
        progress.advance(task6, 1)

        jitter(cfg.jitter_min, cfg.jitter_max)
        ua = get_random_ua()
        run_cmd(
            f"cat {fpath('live.txt')} | awk '{{print $1}}' | "
            f'hakrawler -d 2 -ua "{ua}" | '
            f"grep -E '{target_grep_pattern}' | anew {fpath('all_urls.txt')}",
            timeout=180
        )

        jitter(cfg.jitter_min, cfg.jitter_max)
        ua = get_random_ua()
        run_cmd(
            f"cat {fpath('live.txt')} | awk '{{print $1}}' | "
            f"katana -c {cfg.katana_concurrency} -d 2 -jc -kf all -fs rdn -aff -silent "
            f'-H "User-Agent: {ua}" -delay {cfg.katana_delay} '
            f"-ef png,jpg,jpeg,gif,css,woff,woff2,svg,pdf {proxy_flag_katana} "
            f"| anew {fpath('all_urls.txt')}",
            timeout=500
        )

        filter_in_scope('all_urls.txt', 'all_urls.txt', targets)
        run_cmd(f"sort -u {fpath('all_urls.txt')} -o {fpath('all_urls.txt')}")
        progress.advance(task6, 1)
        stats['Total URLs'] = count_lines('all_urls.txt')

        task7 = progress.add_task("[red] JS Discovery & Analysis...", total=2)
        run_cmd(f"cat {fpath('all_urls.txt')} | grep -iE '\\.js($|\\?)' | anew {fpath('js.txt')}")
        run_cmd(f"cat {fpath('live.txt')} | awk '{{print $1}}' | subjs | anew {fpath('js.txt')}")
        run_cmd(f"sort -u {fpath('js.txt')} -o {fpath('js.txt')}")
        progress.advance(task7, 1)

        js_analysis_cmds = [
            (f"cat {fpath('js.txt')} | xargs -I % python3 /root/pentest/SecretFinder/SecretFinder.py -i % -o cli >> {fpath('secretfinder.txt')}", 500),
            (f"cat {fpath('js.txt')} | xargs -I % python3 /root/pentest/LinkFinder/linkfinder.py -i % -o cli >> {fpath('linkfinder.txt')}", 300),
        ]
        run_parallel(js_analysis_cmds, max_workers=2)
        progress.advance(task7, 1)

        stats['JS Files'] = count_lines('js.txt')
        secrets_count = count_lines('secretfinder.txt')
        if secrets_count > 0:
            stats['⚠ Secrets Found'] = secrets_count

        task8 = progress.add_task("[bold cyan] Technology Detection...", total=1)
        tech_map = detect_technologies('live.txt', cfg, proxy_flag_httpx)
        if tech_map:
            console.print(f"[cyan]  ✓ {len(tech_map)} hosts fingerprinted[/cyan]")
            all_techs = set()
            for techs in tech_map.values():
                all_techs.update(techs)
            console.print(f"[dim]    Technologies: {', '.join(sorted(all_techs))}[/dim]")
            stats['Technologies'] = ', '.join(sorted(all_techs))
        progress.advance(task8, 1)

        task9 = progress.add_task("[red bold] Nuclei Targeted Scan...", total=1)
        jitter(cfg.jitter_min, cfg.jitter_max)
        nuclei_groups = build_nuclei_groups(tech_map, waf_detected_hosts, 'ferox.txt', 'all_urls.txt')

        for idx, group in enumerate(nuclei_groups):
            hosts = group["hosts"]
            templates = group["templates"]
            is_waf = group["is_waf"]
            if not hosts or not templates:
                continue

            group_hosts_file = fpath(f'nuclei_group_{idx}.txt')
            with open(group_hosts_file, 'w') as f:
                f.write('\n'.join(hosts) + '\n')

            t_flags = " ".join(f"-t {t}" for t in templates)
            if is_waf:
                rate, bulk, severity = 5, 2, "medium,high,critical"
            else:
                rate, bulk, severity = cfg.nuclei_rate, cfg.nuclei_bulk, "low,medium,high,critical"

            jitter(cfg.jitter_min, cfg.jitter_max)
            ua = get_random_ua()
            run_cmd(
                f"nuclei -l {group_hosts_file} {t_flags} -severity {severity} "
                f'-rate-limit {rate} -bulk-size {bulk} -H "User-Agent: {ua}" '
                f"{proxy_flag_nuclei} -o {fpath('nuclei.txt')} -silent",
                timeout=600
            )

        progress.advance(task9, 1)
        nuclei_count = count_lines('nuclei.txt')
        if nuclei_count > 0:
            stats['⚠ Nuclei Findings'] = nuclei_count

        task10 = progress.add_task("[bold yellow] Directory Fuzzing...", total=2)
        live_hosts = read_lines('live.txt')
        fuzz_targets = [h.split()[0] for h in live_hosts if any(f'[{c}]' in h for c in ['200', '301', '302'])]

        WORDLIST_COMMON = "/usr/share/seclists/Discovery/Web-Content/common.txt"
        WORDLIST_DEEP = "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt"

        if fuzz_targets:
            with open(fpath('fuzz_targets.txt'), 'w') as f:
                f.write('\n'.join(fuzz_targets) + '\n')

            jitter(cfg.jitter_min, cfg.jitter_max)
            ua = get_random_ua()
            run_cmd(
                f"feroxbuster --stdin --wordlist {WORDLIST_COMMON} "
                f"--threads {cfg.ferox_threads} --depth 2 --delay {cfg.ferox_delay} "
                f'--status-codes 200,301,302,403 --user-agent "{ua}" {proxy_flag_ferox} '
                f"--output {fpath('ferox.txt')} --quiet --insecure < {fpath('fuzz_targets.txt')}",
                timeout=300
            )
        progress.advance(task10, 1)

        if fuzz_targets and os.path.exists(fpath('ferox.txt')):
            ferox_results = read_lines('ferox.txt')
            deep_scan_hosts = set()
            for line in ferox_results:
                parts = line.split()
                if len(parts) >= 3 and parts[0] == '200':
                    url = parts[-1]
                    host_url = re.sub(r'/.*', '', url)
                    if host_url not in waf_detected_hosts:
                        deep_scan_hosts.add(host_url)

            if deep_scan_hosts and os.path.exists(WORDLIST_DEEP):
                jitter(cfg.jitter_min, cfg.jitter_max)
                with open(fpath('deep_scan_targets.txt'), 'w') as f:
                    f.write('\n'.join(deep_scan_hosts) + '\n')
                ua = get_random_ua()
                run_cmd(
                    f"feroxbuster --stdin --wordlist {WORDLIST_DEEP} "
                    f"--threads {max(cfg.ferox_threads - 10, 3)} --depth 3 --delay {max(cfg.ferox_delay, 1)} "
                    f'--status-codes 200,301,302,403 --user-agent "{ua}" {proxy_flag_ferox} '
                    f"--output {fpath('ferox_deep.txt')} --quiet --insecure < {fpath('deep_scan_targets.txt')}",
                    timeout=600
                )
                run_cmd(f"cat {fpath('ferox_deep.txt')} | anew {fpath('ferox.txt')}")

        progress.advance(task10, 1)
        stats['Ferox Endpoints'] = count_lines('ferox.txt')

        task11 = progress.add_task("[bold magenta] Sensitive Files & Cloud...", total=2)
        sensitive_patterns = [
            ".env", ".git/config", ".git/HEAD", "config.json", "wp-config.php",
            "docker-compose.yml", ".dockerenv", "application.yml",
            "credentials", "secret.key", ".htpasswd", "id_rsa",
            "backup.sql", "dump.sql", ".npmrc", ".pypirc",
            "swagger.json", "swagger.yaml", "openapi.json",
            "api-docs", "graphql", "actuator", "actuator/env",
        ]

        if fuzz_targets:
            jitter(cfg.jitter_min, cfg.jitter_max)
            patterns_file = fpath('sensitive_patterns.txt')
            with open(patterns_file, 'w') as f:
                f.write('\n'.join(sensitive_patterns) + '\n')
            ua = get_random_ua()
            run_cmd(
                f"cat {fpath('fuzz_targets.txt')} | httpx "
                f'-H "User-Agent: {ua}" -rate-limit {cfg.httpx_rate_limit} '
                f"-ep {patterns_file} -mc 200 -no-color -silent {proxy_flag_httpx} "
                f"| anew {fpath('sensitive.txt')}",
                timeout=180
            )
        progress.advance(task11, 1)

        for target in targets:
            variations = [target, target.replace('.', '-'), target.replace('.', '')]
            for variation in variations:
                jitter(0.5, 2.0)
                ua = get_random_ua()
                run_cmd(
                    f'curl -sk -H "User-Agent: {ua}" -o /dev/null -w "%{{http_code}} s3://{variation}\\n" '
                    f"https://{variation}.s3.amazonaws.com/ >> {fpath('cloud_buckets_raw.txt')}",
                    timeout=10
                )
                jitter(0.3, 1.5)
                ua = get_random_ua()
                run_cmd(
                    f'curl -sk -H "User-Agent: {ua}" -o /dev/null -w "%{{http_code}} gs://{variation}\\n" '
                    f"https://{variation}.storage.googleapis.com/ >> {fpath('cloud_buckets_raw.txt')}",
                    timeout=10
                )

        try:
            with open(fpath('cloud_buckets_raw.txt'), 'r') as f:
                for line in f:
                    code = line.strip().split()[0] if line.strip() else ""
                    if code in ['200', '403']:
                        with open(fpath('cloud_buckets.txt'), 'a') as out:
                            out.write(line)
        except Exception:
            pass

        cloud_count = count_lines('cloud_buckets.txt')
        sensitive_count = count_lines('sensitive.txt')
        if sensitive_count > 0:
            stats['⚠ Sensitive Files'] = sensitive_count
        if cloud_count > 0:
            stats['⚠ Cloud Buckets'] = cloud_count
        progress.advance(task11, 1)

        task12 = progress.add_task("[bold orange] CORS Check...", total=1)
        live_urls = [h.split()[0] for h in read_lines('live.txt') if h.strip()]
        cors_targets = [url for url in live_urls[:150] if url not in waf_detected_hosts]

        for url in cors_targets:
            jitter(cfg.jitter_min, cfg.jitter_max)
            ua = get_random_ua()
            result = run_cmd(
                f'curl -sk -H "User-Agent: {ua}" -H "Origin: https://evil.com" '
                f'-D - -o /dev/null "{url}" 2>/dev/null',
                timeout=10
            )
            if 'access-control-allow-origin: https://evil.com' in result.stdout.lower():
                with open(fpath('cors.txt'), 'a') as f:
                    f.write(f"CORS_VULN: {url}\n")
                logging.info(f"CORS found: {url}")

        progress.advance(task12, 1)
        cors_count = count_lines('cors.txt')
        if cors_count > 0:
            stats['⚠ CORS Vulns'] = cors_count

        task13 = progress.add_task("[green] Parameter Mining...", total=2)
        run_cmd(f"cat {fpath('live.txt')} | awk '{{print $1}}' | sed 's|https\\?://||' | sed 's|/||' | anew {fpath('for_param_spider.txt')}")
        run_cmd(f"cd {SCAN_DIR} && paramspider -l {fpath('for_param_spider.txt')}", timeout=180)
        progress.advance(task13, 1)

        run_cmd(f"cat {fpath('all_urls.txt')} | grep -oP '(?<=[?&])[^=]+' | sort -u | anew {fpath('params_names.txt')}")
        progress.advance(task13, 1)
        stats['Unique Params'] = count_lines('params_names.txt')

    json_path = generate_json_report(stats, targets, SCAN_DIR, waf_map)
    html_path = generate_html_report(stats, targets, SCAN_DIR, waf_map)

    console.print("\n")
    console.print(Rule(style="magenta"))

    table = Table(title="SCAN SUMMARY", title_style="bold underline magenta", header_style="bold cyan")
    table.add_column("Category", style="yellow", min_width=25)
    table.add_column("Result", style="white")

    for key, value in stats.items():
        style = "red bold" if "⚠" in str(key) else "white"
        table.add_row(key, str(value), style=style)

    console.print(table)

    console.print(Panel.fit(
        f"[bold green]COMPLETED[/bold green]\n"
        f"[dim]Scan Dir : {SCAN_DIR}[/dim]\n"
        f"[dim]JSON     : {json_path}[/dim]\n"
        f"[dim]HTML     : {html_path}[/dim]\n"
        f"[dim]Log      : {LOG_FILE}[/dim]",
        title="Status",
        border_style="green"
    ))

if __name__ == "__main__":
    main()
