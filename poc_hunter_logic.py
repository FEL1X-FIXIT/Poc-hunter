"""
PoC Hunter core search logic — shared between desktop and mobile
Handles all GitHub API calls, parsing, parallel fetching, and source adapters
"""

import urllib.request
import urllib.error
import urllib.parse
import json
import re
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

SOURCES = {
    "nomi-sec": {
        "label":   "nomi-sec/PoC-in-GitHub",
        "repo":    "nomi-sec/PoC-in-GitHub",
        "branch":  "master",
        "ext":     ".json",
        "tag":     "nomi",
    },
    "trickest": {
        "label":   "trickest/cve",
        "repo":    "trickest/cve",
        "branch":  "main",
        "ext":     ".md",
        "tag":     "trick",
    },
    "ycdxsb": {
        "label":   "ycdxsb/PocOrExp_in_Github",
        "repo":    "ycdxsb/PocOrExp_in_Github",
        "branch":  "main",
        "ext":     ".md",
        "tag":     "ycdx",
    },
    "ghosttroops": {
        "label":   "GhostTroops/TOP",
        "repo":    "GhostTroops/TOP",
        "branch":  "main",
        "ext":     ".md",
        "tag":     "top",
    },
    "marcio": {
        "label":   "0xMarcio/cve",
        "repo":    "0xMarcio/cve",
        "branch":  "main",
        "ext":     ".md",
        "tag":     "marc",
    },
    "sploitus": {
        "label":   "Sploitus (web API)",
        "repo":    "",
        "branch":  "",
        "ext":     "",
        "tag":     "splt",
    },
}

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CURRENT_YEAR = datetime.now().year
YEARS = [str(y) for y in range(2012, CURRENT_YEAR + 1)]


@dataclass
class SearchResult:
    cve_id: str
    source: str
    poc_name: str
    html_url: str
    description: str
    nvd_description: str
    stars: int
    pushed_at: str
    kev: bool = False

    @property
    def dedup_key(self):
        u = self.html_url.lower().rstrip("/").removesuffix(".git") if self.html_url else ""
        return (self.cve_id.upper(), u)

    @property
    def summary(self):
        parts = []
        if self.nvd_description:
            parts.append(self.nvd_description[:200].rstrip())
        if self.description and self.description not in self.nvd_description:
            parts.append(f"[PoC] {self.description[:120].rstrip()}")
        return "  ".join(parts) if parts else "(no description)"


# ── Network helpers ───────────────────────────────────────────────────────

def gh_get(url, token=None):
    """GitHub API GET with optional token"""
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "poc-browser-mobile/1.0")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 403:
            raise Exception("Rate limited — add GitHub token")
        if e.code == 404:
            raise Exception("Not found")
        raise


def raw_get(url):
    """Raw GitHub content GET"""
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "poc-browser-mobile/1.0")
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.read().decode()


# ── Parsers ──────────────────────────────────────────────────────────────

def parse_nomi_json(cve_id, raw_text, source_tag):
    try:
        data = json.loads(raw_text)
    except:
        return []
    if not isinstance(data, list):
        data = [data]
    results = []
    for poc in data:
        r = SearchResult(
            cve_id=cve_id,
            source=source_tag,
            poc_name=poc.get("full_name") or poc.get("name", ""),
            html_url=poc.get("html_url", ""),
            description=poc.get("description") or "",
            nvd_description=poc.get("nvd_description") or "",
            stars=int(poc.get("stargazers_count", 0) or 0),
            pushed_at=poc.get("pushed_at", ""),
        )
        results.append(r)
    return results


def parse_markdown_pocs(cve_id, raw_text, source_tag):
    results = []
    nvd_desc = ""
    for line in raw_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("|"):
            continue
        if re.match(r"https?://", line):
            continue
        nvd_desc = line[:300]
        break

    url_pat = re.compile(r"https://github\.com/[\w\-\.]+/[\w\-\.]+(?:/[\w\-\./#?=&]*)?")
    desc_pat = re.compile(r"https://github\.com/[\w\-\.]+/[\w\-\.]+\S*\s+(.*)")
    seen = set()

    for line in raw_text.splitlines():
        for url in url_pat.findall(line):
            repo_url = re.sub(r"(https://github\.com/[^/]+/[^/\s#?]+).*", r"\1", url)
            if repo_url in seen or "shields.io" in repo_url:
                continue
            seen.add(repo_url)
            m = desc_pat.search(line)
            inline_desc = m.group(1).strip() if m else ""
            parts = repo_url.rstrip("/").split("/")
            poc_name = "/".join(parts[-2:]) if len(parts) >= 2 else repo_url
            r = SearchResult(
                cve_id=cve_id,
                source=source_tag,
                poc_name=poc_name,
                html_url=repo_url,
                description=inline_desc,
                nvd_description=nvd_desc,
                stars=0,
                pushed_at="",
            )
            results.append(r)
    return results


def parse_readme_table(raw_text, source_tag, year, keyword, match_target):
    results = []
    cve_pat = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
    kw = keyword.lower()

    year_section_pat = re.compile(
        rf"^##\s+{re.escape(year)}\b.*?(?=^##\s+\d{{4}}\b|\Z)",
        re.MULTILINE | re.DOTALL
    )
    m = year_section_pat.search(raw_text)
    if not m:
        return []
    section = m.group(0)

    row5 = re.compile(
        r"^\|\s*(\d+)[^|]*\|"
        r"\s*([^|]+?)\s*\|"
        r"\s*([^|]+?)\s*\|"
        r"\s*([^|]+?)\s*\|"
        r"\s*([^|]*?)\s*\|?$",
        re.MULTILINE
    )

    url_extract = re.compile(r"https?://[^\s\)>\|]+")
    seen_urls = set()

    for row_m in row5.finditer(section):
        stars_s = row_m.group(1).strip()
        col3 = row_m.group(3).strip()
        col4 = row_m.group(4).strip()
        col5 = row_m.group(5).strip()

        if "---" in col3 or "star" in col3.lower():
            continue

        try:
            stars = int(stars_s)
        except:
            continue

        url = ""
        name = col3
        md_link = re.search(r"\[([^\]]+)\]\((https?://[^\)]+)\)", col3)
        if md_link:
            name = md_link.group(1)
            url = md_link.group(2)
            desc = col4
        else:
            urls_found = url_extract.findall(col4)
            url = urls_found[0].rstrip(">") if urls_found else ""
            desc = col5

        if not url or url in seen_urls:
            continue
        seen_urls.add(url)
        url = re.sub(r"(https://github\.com/[^/]+/[^/\s#?]+).*", r"\1", url)

        all_cves = cve_pat.findall(name + " " + desc + " " + url)
        cve_id = all_cves[0].upper() if all_cves else f"CVE-{year}-????"

        searchable = (name + " " + desc + " " + cve_id).lower()
        if kw:
            if match_target == "CVE ID" and kw not in cve_id.lower():
                continue
            elif match_target == "Description only" and kw not in desc.lower():
                continue
            elif match_target == "Filename only" and kw not in name.lower():
                continue
            elif match_target == "All fields" and kw not in searchable:
                continue

        poc_name = "/".join(url.rstrip("/").split("/")[-2:]) if url else name
        results.append(SearchResult(
            cve_id=cve_id,
            source=source_tag,
            poc_name=poc_name,
            html_url=url,
            description=desc[:200],
            nvd_description="",
            stars=stars,
            pushed_at="",
        ))

    return results


# ── Search coordinator ────────────────────────────────────────────────────

class PoCSearcher:
    def __init__(self, token=None, callback=None):
        self.token = token
        self.results = []
        self.dedup_keys = set()
        self.kev_ids = set()
        self.kev_loaded = False
        self.callback = callback  # for mobile UI updates
        self._load_kev()

    def _load_kev(self):
        try:
            data = json.loads(raw_get(KEV_URL))
            self.kev_ids = {v["cveID"].upper() for v in data.get("vulnerabilities", [])}
            self.kev_loaded = True
        except:
            self.kev_loaded = False

    def add_result(self, r: SearchResult):
        """Dedup and add result"""
        dk = r.dedup_key
        if dk in self.dedup_keys:
            return
        self.dedup_keys.add(dk)
        if self.kev_loaded:
            r.kev = r.cve_id.upper() in self.kev_ids
        self.results.append(r)
        if self.callback:
            self.callback("result_added", r)

    def search_source(self, src_key, year, keyword, match_target):
        """Search a single source. Returns list of SearchResult objects."""
        info = SOURCES[src_key]
        repo, branch, ext, tag = info["repo"], info["branch"], info["ext"], info["tag"]

        if src_key == "sploitus":
            return self._search_sploitus(year, keyword, match_target, tag)
        elif src_key == "ghosttroops":
            return self._search_ghosttroops(year, keyword, match_target, tag)
        elif src_key == "marcio":
            readme_results = self._search_readme(repo, year, keyword, match_target, tag)
            dir_results = self._search_github_tree(repo, branch, year, keyword, match_target, tag, ext)
            return readme_results + dir_results
        else:
            return self._search_github_tree(repo, branch, year, keyword, match_target, tag, ext)

    def _search_github_tree(self, repo, branch, year, keyword, match_target, tag, ext):
        """Generic GitHub tree walker"""
        results = []
        raw_base = f"https://raw.githubusercontent.com/{repo}/{branch}"
        kw_lower = keyword.lower()

        try:
            root_tree = gh_get(
                f"https://api.github.com/repos/{repo}/git/trees/{branch}",
                self.token)
            year_sha = next(
                (t["sha"] for t in root_tree.get("tree", [])
                 if t["path"] == year and t["type"] == "tree"),
                None)
            if not year_sha:
                return []

            year_tree = gh_get(
                f"https://api.github.com/repos/{repo}/git/trees/{year_sha}?recursive=1",
                self.token)
            all_blobs = [
                t for t in year_tree.get("tree", [])
                if t["type"] == "blob" and t["path"].endswith(ext)
            ]

            if match_target == "Filename only" and kw_lower:
                all_blobs = [b for b in all_blobs if kw_lower in b["path"].lower()]
                for b in all_blobs:
                    cve_id = b["path"].replace(ext, "")
                    r = SearchResult(
                        cve_id=cve_id, source=tag,
                        poc_name=cve_id, html_url="",
                        description="", nvd_description="",
                        stars=0, pushed_at="",
                    )
                    results.append(r)
                return results

            files_to_fetch = [
                (b["path"].replace(ext, ""),
                 f"{raw_base}/{year}/{b['path']}")
                for b in all_blobs
            ]

            def fetch_and_parse(item):
                cve_id, url = item
                try:
                    raw = raw_get(url)
                except:
                    return []
                pocs = (parse_nomi_json(cve_id, raw, tag) if ext == ".json"
                        else parse_markdown_pocs(cve_id, raw, tag))
                if kw_lower:
                    pocs = [p for p in pocs if self._matches(p, kw_lower, match_target)]
                return pocs

            with ThreadPoolExecutor(max_workers=16) as pool:
                futures = [pool.submit(fetch_and_parse, item) for item in files_to_fetch]
                for fut in as_completed(futures):
                    results.extend(fut.result())

        except Exception as e:
            if self.callback:
                self.callback("error", f"[{tag}] {str(e)}")

        return results

    def _search_readme(self, repo, year, keyword, match_target, tag):
        try:
            for branch in ("main", "master"):
                try:
                    raw = raw_get(f"https://raw.githubusercontent.com/{repo}/{branch}/README.md")
                    return parse_readme_table(raw, tag, year, keyword, match_target)
                except:
                    continue
        except:
            pass
        return []

    def _search_ghosttroops(self, year, keyword, match_target, tag):
        try:
            for branch in ("main", "master"):
                try:
                    raw = raw_get(f"https://raw.githubusercontent.com/GhostTroops/TOP/{branch}/README.md")
                    return parse_readme_table(raw, tag, year, keyword, match_target)
                except:
                    continue
        except:
            pass
        return []

    def _search_sploitus(self, year, keyword, match_target, tag):
        results = []
        query = keyword if keyword else f"CVE-{year}"
        cve_full_pat = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)

        try:
            offset = 0
            while offset < 50:
                body = json.dumps({
                    "type": "exploits",
                    "sort": "default",
                    "query": query,
                    "title": False,
                    "offset": offset,
                }).encode()
                req = urllib.request.Request("https://sploitus.com/search", data=body, method="POST")
                req.add_header("Content-Type", "application/json")
                req.add_header("User-Agent", "Mozilla/5.0 poc-browser-mobile/1.0")

                try:
                    with urllib.request.urlopen(req, timeout=15) as resp:
                        data = json.loads(resp.read().decode())
                except:
                    break

                exploits = data.get("exploits", [])
                if not exploits:
                    break

                for ex in exploits:
                    title = ex.get("title", "")
                    href = ex.get("href", "") or ex.get("source", "")
                    score = ex.get("score", "")

                    all_cves = cve_full_pat.findall(title + " " + href)
                    year_cves = [c for c in all_cves if c.split("-")[1] == year]
                    if not year_cves and all_cves:
                        continue
                    cve_id = year_cves[0].upper() if year_cves else f"CVE-{year}-????"

                    r = SearchResult(
                        cve_id=cve_id,
                        source=tag,
                        poc_name=title[:80],
                        html_url=href,
                        description=f"[score:{score}] {title}",
                        nvd_description="",
                        stars=0,
                        pushed_at="",
                    )
                    if self._matches(r, keyword.lower(), match_target):
                        results.append(r)

                offset += 10
                if len(exploits) < 10:
                    break
                time.sleep(0.3)
        except:
            pass

        return results

    def _matches(self, r: SearchResult, kw: str, target: str) -> bool:
        if not kw:
            return True
        if target == "Filename only":
            return kw in r.poc_name.lower()
        if target == "CVE ID":
            return kw in r.cve_id.lower()
        if target == "Description only":
            return kw in r.description.lower() or kw in r.nvd_description.lower()
        return (kw in r.cve_id.lower() or
                kw in r.poc_name.lower() or
                kw in r.description.lower() or
                kw in r.nvd_description.lower())
