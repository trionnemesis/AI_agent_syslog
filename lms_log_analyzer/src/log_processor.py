from __future__ import annotations
"""日誌讀取與分析核心邏輯"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .. import config
from . import log_parser
from .llm_handler import llm_analyse, COST_TRACKER
from .vector_db import VECTOR_DB, embed
from .utils import tail_since, save_state, STATE
from .wazuh_consumer import get_alerts_for_lines

# 模組層級記錄器，供其他函式使用
logger = logging.getLogger(__name__)


def analyse_lines(lines: List[str]) -> List[Dict[str, Any]]:
    """分析多行日誌並回傳結果"""

    if not lines:
        return []


    # 先不依賴 Wazuh，直接對原始日誌逐行評分

    scored: List[Tuple[float, str]] = []
    for line in lines:
        scored.append((log_parser.fast_score(line), line))

    scored.sort(key=lambda x: x[0], reverse=True)
    num_to_sample = max(1, int(len(scored) * config.SAMPLE_TOP_PERCENT / 100))
    top_scored = [sl for sl in scored if sl[0] > 0.0][:num_to_sample]
    if not top_scored:
        save_state(STATE)
        VECTOR_DB.save()
        return []

    top_lines = [line for _, line in top_scored]


    # 若設定了 Wazuh，僅對挑出的高分日誌再去比對其告警結果

    alerts_map: Dict[str, List[Dict[str, Any]]] = {}
    if config.WAZUH_ENABLED or config.WAZUH_ALERTS_FILE or config.WAZUH_ALERTS_URL:
        for item in get_alerts_for_lines(top_lines):
            alerts_map.setdefault(item["line"], []).append(item["alert"])


    # 產生向量以便後續搜尋歷史案例

    embeddings = [embed(line) for line in top_lines]

    # 從向量庫中取得相似歷史案例作為輔助上下文
    contexts = []
    if VECTOR_DB.index is not None:
        for emb in embeddings:
            ids, _ = VECTOR_DB.search(emb, k=3)
            contexts.append(VECTOR_DB.get_cases(ids))
    else:
        contexts = [[] for _ in embeddings]


    # 組合要送入 LLM 的輸入，每筆包含告警內容與歷史案例

    analysis_inputs = []
    for line, ctx in zip(top_lines, contexts):
        wazuh_alerts = alerts_map.get(line)
        alert = wazuh_alerts[0] if wazuh_alerts else {"original_log": line}
        analysis_inputs.append({"alert": alert, "examples": ctx})

    # 呼叫 LLM 取得分析結果
    analysis_results = llm_analyse(analysis_inputs)

    if VECTOR_DB.index is not None:
        # 將新產生的向量與分析結果存回向量庫
        cases_to_add = []
        for line, analysis in zip(top_lines, analysis_results):
            cases_to_add.append({"log": line, "analysis": analysis})
        VECTOR_DB.add(embeddings, cases_to_add)

    # 組成輸出結果，包含原始行、評分與分析資料
    exported: List[Dict[str, Any]] = []
    for (fast_s, line), analysis in zip(top_scored, analysis_results):
        exported.append({"log": line, "fast_score": fast_s, "analysis": analysis})

    # 於流程結束時更新狀態與向量庫
    save_state(STATE)
    VECTOR_DB.save()
    logger.info(f"LLM stats: {COST_TRACKER.get_total_stats()}")
    return exported


def process_logs(log_paths: List[Path]) -> List[Dict[str, Any]]:
    """讀取指定的日誌檔並回傳可疑行的分析結果"""

    # 依序讀取所有待處理的檔案，只保留新增的部分
    all_new_lines: List[str] = []
    for p in log_paths:
        if not p.exists() or not p.is_file():
            continue
        # ``tail_since`` 只會取出自上次處理後的新行
        all_new_lines.extend(tail_since(p))

    # 將所有新行交給前述函式進行分析
    return analyse_lines(all_new_lines)
