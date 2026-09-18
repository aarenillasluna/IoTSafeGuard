import json
import os
import re
import subprocess
from typing import Dict, List, Optional
from loguru import logger


class SearchsploitClient:
    """
    Cliente local para Exploit-DB mediante searchsploit CLI.
    """
    def __init__(self, binary: str = "searchsploit", timeout: int = 20):
        self.binary = binary
        self.timeout = timeout

    def _run_searchsploit(self, query: str) -> List[Dict]:
        if not query or len(query.strip()) < 2:
            return []
        cmd = [self.binary, "--json", query]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout, check=False)
        except FileNotFoundError:
            logger.warning("[SEARCHSPLOIT] CLI no encontrado. Instala exploitdb/searchsploit.")
            return []
        except subprocess.TimeoutExpired:
            logger.warning(f"[SEARCHSPLOIT] Timeout para query: {query}")
            return []
        except Exception as exc:
            logger.warning(f"[SEARCHSPLOIT] Error ejecutando query '{query}': {exc}")
            return []

        if res.returncode not in (0, 1):
            logger.warning(f"[SEARCHSPLOIT] Código inesperado {res.returncode} en query '{query}'")
            return []

        payload = (res.stdout or "").strip()
        if not payload:
            return []

        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            logger.warning(f"[SEARCHSPLOIT] JSON inválido para query '{query}'")
            return []

        entries = data.get("RESULTS_EXPLOIT", [])
        normalized = []
        for row in entries:
            title = row.get("Title", "").strip()
            path = row.get("Path", "").strip()
            edb_id = str(row.get("EDB-ID", "")).strip()
            date = row.get("Date", "").strip()
            if not title and not path:
                continue
            normalized.append(
                {
                    "title": title,
                    "path": path,
                    "edb_id": edb_id,
                    "date": date,
                    "query": query,
                    "source": "searchsploit",
                    "content": self._read_exploit_content(path),
                }
            )
        return normalized

    @staticmethod
    def _read_exploit_content(path: str, max_bytes: int = 2000) -> str:
        """Read exploit file content, returning a truncated snippet."""
        if not path or not os.path.isfile(path):
            return ""
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read(max_bytes)
            return content.strip()
        except OSError:
            return ""

    @staticmethod
    def _tokenize_text(text: str) -> List[str]:
        cleaned = re.sub(r"[^a-zA-Z0-9._:-]+", " ", text.lower())
        return [x for x in cleaned.split() if len(x) > 2]

    def _score_match(self, item: Dict, tokens: List[str], cpe: Optional[str]) -> int:
        title = (item.get("title") or "").lower()
        path = (item.get("path") or "").lower()
        score = 0
        for token in tokens:
            if token in title:
                score += 4
            if token in path:
                score += 2
        if cpe:
            cpe_tail = cpe.split(":")[-2] if ":" in cpe else cpe
            cpe_tail = cpe_tail.lower()
            if cpe_tail and (cpe_tail in title or cpe_tail in path):
                score += 5
        return score

    def search(self, cpe: Optional[str], keywords: List[str], limit: int = 20) -> List[Dict]:
        """
        Busca exploits locales por CPE y palabras clave, luego puntúa y filtra.
        """
        queries = []
        if cpe:
            cpe_parts = [p for p in cpe.split(":") if p and p != "*"]
            if len(cpe_parts) >= 5:
                vendor = cpe_parts[3]
                product = cpe_parts[4]
                queries.extend([f"{vendor} {product}", product])
        for kw in keywords:
            if not kw:
                continue
            clean_kw = kw.strip()
            if len(clean_kw) > 2:
                queries.append(clean_kw)

        unique_queries = []
        for q in queries:
            key = q.lower()
            if key not in unique_queries:
                unique_queries.append(key)

        aggregated = []
        for q in unique_queries[:10]:
            aggregated.extend(self._run_searchsploit(q))

        if not aggregated:
            return []

        tokens = []
        for kw in keywords:
            tokens.extend(self._tokenize_text(kw))
        if cpe:
            tokens.extend(self._tokenize_text(cpe))
        tokens = list(dict.fromkeys(tokens))

        dedup = {}
        for item in aggregated:
            key = f"{item.get('edb_id')}|{item.get('path')}"
            score = self._score_match(item, tokens, cpe)
            item["match_score"] = score
            if key not in dedup or score > dedup[key].get("match_score", 0):
                dedup[key] = item

        ranked = sorted(dedup.values(), key=lambda x: x.get("match_score", 0), reverse=True)
        ranked = [r for r in ranked if r.get("match_score", 0) > 0]
        return ranked[:limit]
