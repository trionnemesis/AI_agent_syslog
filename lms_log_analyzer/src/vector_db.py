from __future__ import annotations
"""OpenSearch k-NN 向量儲存"""

import hashlib
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .. import config
from . import log_parser

try:
    from opensearchpy import OpenSearch
except Exception:  # pragma: no cover - optional
    OpenSearch = None  # type: ignore

try:
    from sentence_transformers import SentenceTransformer
    EMBEDDING_MODEL_NAME_DEFAULT = 'paraphrase-multilingual-MiniLM-L12-v2'
    EMBEDDING_MODEL_NAME = os.getenv("EMBEDDING_MODEL_NAME", EMBEDDING_MODEL_NAME_DEFAULT)
    SENTENCE_MODEL: Optional[SentenceTransformer] = SentenceTransformer(EMBEDDING_MODEL_NAME)
    if SENTENCE_MODEL:
        EMBED_DIM = SENTENCE_MODEL.get_sentence_embedding_dimension()
    else:
        EMBED_DIM = 384
except Exception:  # pragma: no cover - optional
    SENTENCE_MODEL = None
    EMBED_DIM = 384

logger = logging.getLogger(__name__)


def embed(text: str) -> List[float]:
    """取得文字的向量表示

    若系統已安裝 `sentence-transformers` 會直接產生真正的嵌入；
    否則使用 SHA-256 雜湊計算出假向量，方便在無依賴環境下測試。

    會優先解析 syslog 行，只取 process 與 message 部分進行嵌入，
    以更聚焦地捕捉事件語義。
    """

    parsed = log_parser.parse_syslog_line(text)
    if parsed:
        to_embed = (parsed.get("app", "") + " " + parsed.get("msg", "")).strip()
        if to_embed:
            text = to_embed

    if SENTENCE_MODEL:
        return SENTENCE_MODEL.encode(text, convert_to_numpy=True).tolist()
    digest = hashlib.sha256(text.encode("utf-8", "replace")).digest()
    vec_template = list(digest)
    vec = []
    while len(vec) < EMBED_DIM:
        vec.extend(vec_template)
    return [v / 255.0 for v in vec[:EMBED_DIM]]


class VectorIndex:
    """利用 OpenSearch 建立 k-NN 索引"""

    def __init__(self, path: Path, cases_path: Path, dimension: int) -> None:
        self.dimension = dimension
        self.client = self._connect()
        self.index_name = config.OPENSEARCH_KNN_INDEX
        self.cases: List[Dict[str, Any]] = []
        if self.client:
            self._ensure_index()
            self._load_cases()

    def _connect(self):
        if OpenSearch is None:
            logger.warning("opensearch-py not installed; vector search disabled")
            return None
        auth = None
        if config.OPENSEARCH_USER and config.OPENSEARCH_PASSWORD:
            auth = (config.OPENSEARCH_USER, config.OPENSEARCH_PASSWORD)
        try:
            return OpenSearch(
                hosts=[{"host": config.OPENSEARCH_HOST, "port": config.OPENSEARCH_PORT}],
                http_auth=auth,
                use_ssl=False,
            )
        except Exception as exc:  # pragma: no cover - optional network failure
            logger.error(f"Failed connecting OpenSearch: {exc}")
            return None

    def _ensure_index(self):
        try:
            if not self.client.indices.exists(index=self.index_name):
                body = {
                    "settings": {"index": {"knn": True}},
                    "mappings": {
                        "properties": {
                            "vector": {"type": "knn_vector", "dimension": self.dimension},
                            "case_id": {"type": "integer"},
                            "log": {"type": "text"},
                            "analysis": {"type": "object"},
                        }
                    },
                }
                self.client.indices.create(index=self.index_name, body=body)
        except Exception as exc:  # pragma: no cover - optional network failure
            logger.error(f"Failed creating OpenSearch index: {exc}")

    def _load_cases(self):
        if not self.client:
            return
        try:
            resp = self.client.search(
                index=self.index_name, body={"query": {"match_all": {}}, "size": 1000}
            )
            for hit in resp.get("hits", {}).get("hits", []):
                cid = hit["_source"].get("case_id")
                case = {"log": hit["_source"].get("log"), "analysis": hit["_source"].get("analysis")}
                if cid is not None:
                    while len(self.cases) <= cid:
                        self.cases.append({})
                    self.cases[cid] = case
        except Exception as exc:  # pragma: no cover - optional
            logger.error(f"Failed loading cases from OpenSearch: {exc}")

    def save(self):
        # OpenSearch 由後端負責持久化，此處無需額外處理
        pass

    def search(self, vec: List[float], k: int = 5) -> Tuple[List[int], List[float]]:
        if not self.client:
            return [], []
        body = {
            "size": k,
            "query": {"knn": {"vector": {"vector": vec, "k": k}}},
        }
        try:
            resp = self.client.search(index=self.index_name, body=body)
            hits = resp.get("hits", {}).get("hits", [])
            ids = [int(h["_source"].get("case_id", 0)) for h in hits]
            scores = [float(h.get("_score", 0.0)) for h in hits]
            return ids, scores
        except Exception as exc:  # pragma: no cover - optional
            logger.error(f"OpenSearch search failed: {exc}")
            return [], []

    def add(self, vecs: List[List[float]], cases: List[Dict[str, Any]]):
        """新增多個向量與對應案例至索引"""

        if not self.client:
            return
        for vec, case in zip(vecs, cases):
            cid = len(self.cases)
            doc = {
                "case_id": cid,
                "vector": vec,
                "log": case.get("log"),
                "analysis": case.get("analysis"),
            }
            try:
                self.client.index(index=self.index_name, id=str(cid), body=doc)
                self.cases.append(case)
            except Exception as exc:  # pragma: no cover - optional
                logger.error(f"Failed indexing case: {exc}")

    def get_cases(self, ids: List[int]) -> List[Dict[str, Any]]:
        """根據索引 ID 取得案例資訊"""

        return [self.cases[i] for i in ids if 0 <= i < len(self.cases)]


VECTOR_DB = VectorIndex(config.VECTOR_DB_PATH, config.CASE_DB_PATH, EMBED_DIM)
