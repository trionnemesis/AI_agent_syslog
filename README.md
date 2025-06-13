# LMS AI 日誌分析與告警系統 (基於 Gemini 與 LangChain)

## I. 專案目標與概覽

本專案旨在自動化分析日誌檔案，利用啟發式規則、向量搜尋以及 Google Gemini 大型語言模型（透過 LangChain 框架）來識別潛在的攻擊或異常行為。系統會從大量、格式不一的日誌中，快速識別可疑活動，產生結構化的分析結果與告警，以輔助資安人員進行決策。

---

## II. 系統架構

### 核心組件

本系統採用模組化設計，主要包含以下幾個核心部分：

1.  **日誌來源 (Log Source)**:
    * **批次處理**: 定期掃描並處理指定目錄下的日誌檔案（支援 `.log`, `.gz`, `.bz2`）。預設會掃描 `/var/log` 目錄。
    * **即時處理**: 透過 HTTP 端點接收來自 Filebeat 等代理程式的即時日誌流。
2.  **前置處理與過濾 (Preprocessor & Filter)**:
    * **啟發式評分 (Heuristic Scoring)**: 透過內建的關鍵字與規則，對日誌進行快速評分，篩選出高風險日誌。
    * **智慧取樣 (Sampling)**: 僅挑選評分最高的日誌樣本送交 LLM，大幅降低 API 成本。
3.  **核心分析引擎 (Core Analyzer)**:
    * **向量化與相似度搜尋**: 使用 Sentence Transformers 模型將日誌轉換為向量，並在 FAISS 向量資料庫中尋找相似的歷史攻擊案例。
    * **LLM 分析**: 呼叫 Google Gemini 模型，結合當前日誌與歷史案例，進行攻擊判斷、類型分類與原因分析。
    * **成本控制**: 包含結果快取 (Cache)、批次處理 (Batching) 及每小時費用上限，確保成本可控。
4.  **結果輸出 (Output)**:
    * 將分析結果以結構化的 JSON 格式寫入檔案中。

### 概念流程

1.  **Filebeat 近即時輸入**：Filebeat 監控日誌並將新行透過 HTTP 傳送至 `filebeat_server.py`，立即觸發後續分析。
2.  **批次日誌處理**：亦可定期執行 `main.py`，程式會根據 `data/file_state.json` 記錄的偏移量只讀取新增內容。
3.  **啟發式評分與取樣**：直接對日誌行以 `fast_score()` 計算分數，挑選最高分的前 `SAMPLE_TOP_PERCENT`％ 作為候選。
4.  **向量嵌入與歷史比對**：將候選日誌嵌入向量並寫入 FAISS 索引，以便搜尋過往相似模式。
5.  **LLM 深度分析**：將解析後的 syslog 與原始行傳入 `llm_analyse()` 由 Gemini 分析是否為攻擊行為並回傳結構化結果。
6.  **結果輸出與成本控制**：將分析結果寫入 `analysis_results.json`，同時更新向量索引、狀態檔並追蹤 LLM Token 成本。

### 架構圖

```text
┌────────────┐
│ Log Source │  ← 來自 LMS 系統的 .log/.gz/.bz2 檔案
└────┬───────┘
     │
     ▼
┌──────────────┐
│  Filebeat    │ ← 監控日誌並透過 HTTP 送出
└────┬─────────┘
     │
     ▼
┌────────────┐
│  Parser    │ ← 逐行讀取新日誌、解壓縮、處理編碼
│ tail_since │
└────┬───────┘
     │
     ▼
┌──────────────┐
│ Fast Scorer  │ ← 啟發式快速評分
│ fast_score() │
└────┬─────────┘
     │ top X%
     ▼
┌────────────────────┐
│ Vector Embedder    │ ← 用 sentence-transformers 或 SHA256 偽向量
│ embed()            │
└────┬────────────────┘
     │               ┌────────────────────┐
     │               │ FAISS Vector Index │ ← 搜尋歷史相似模式
     ├───────────────▶│ search(), add()    │
     │               └────────────────────┘
     ▼
┌────────────────────┐
│ Gemini LLM (Langchain) │ ← 分析是否為攻擊行為
│ llm_analyse()        │
└────────┬───────────┘
         │
         ▼
┌────────────────────┐
│ Cache / Token Cost │ ← 避免重複分析 + 成本控制
│ LRUCache / Tracker │
└────────┬───────────┘
         ▼
┌────────────────────┐
│ Exporter           │ ← 將分析結果輸出為 JSON
│ JSON / Log Report  │
└────────────────────┘
```
專案目錄
```
MCP_lms_log_analyzer/
└─ EDGE-codex-refactor-lms_log_analyzer_v2-into-modular-project/
   ├─ lms_log_analyzer/
   │  ├─ main.py
   │  ├─ config.py
   │  ├─ requirements.txt
   │  ├─ src/
   │  │  ├─ filebeat_server.py
   │  │  ├─ llm_handler.py
   │  │  ├─ log_parser.py
   │  │  ├─ log_processor.py
   │  │  ├─ utils.py
   │  │  ├─ vector_db.py
   │  ├─ data/
   │  └─ logs/
   └─ tests/
      ├─ test_integration.py
      ├─ test_llm_handler.py
      ├─ test_log_parser.py
```
III. 技術與主要工具
本專案基於以下技術與工具建構而成：

程式語言:

Python 3.8+: 作為主要的開發語言。
核心函式庫:

LangChain: 用於快速建構 LLM 應用，管理與串聯提示 (Prompt)、模型 (LLM) 與輸出解析 (Output Parser)。
Sentence Transformers: 用於將日誌文本轉換為高品質的語義向量 (Embeddings)。
FAISS (Facebook AI Similarity Search): 由 Facebook AI 開發的高效相似度搜尋函式庫，用於本地向量儲存與檢索。
Pytest: 用於驅動專案的單元測試與整合測試。
整合服務:

Google Gemini: 作為核心分析引擎的大型語言模型。
Filebeat: 作為收集與轉發即時日誌的代理程式。
開發與維運:

GitHub Actions: 用於實現 CI/CD，自動化執行測試與程式碼檢查。

IV. 安裝與設定
1. 建議環境
作業系統 (Operating System):
建議使用 Linux 發行版 (如 Ubuntu, CentOS, Debian)。
macOS 應該也可以運作。
Windows 可能需要調整路徑寫法及排程方式。
Python 版本:
Python 3.8 或更高版本。
虛擬環境 (Virtual Environment - 強烈建議):
使用 venv 或 conda 建立獨立的 Python 環境，以避免套件版本衝突。
2. 安裝步驟
先決條件:

Python 與 Pip: 確保您的系統已安裝 Python 3.8+ 及 Pip。
日誌目錄存取權限: 執行腳本的使用者需要有權限讀取您設定的 LOG_DIRECTORY。
Google AI Studio API Key: 您需要前往 Google AI Studio 取得 Gemini API 金鑰。
建立並啟動虛擬環境 (建議):

Bash

# 建立虛擬環境 (名稱自訂)
```
python3 -m venv lms_ai_env
```
# 啟動虛擬環境
```
# Linux/macOS:
source lms_ai_env/bin/activate
# Windows:
# lms_ai_env\Scripts\activate
啟動後，您的終端機提示符前應會出現 (lms_ai_env)。
```
安裝 Python 套件:
在已啟動的虛擬環境中，執行以下指令安裝必要的 Python 函式庫：

```
pip install -r requirements.txt
設定 API 金鑰與組態:

API 金鑰: 建議將您的金鑰設定為環境變數，以策安全。
export GEMINI_API_KEY="YOUR_GOOGLE_API_KEY"
```
調整組態: 所有可調整的設定都集中在 config.py。您可以直接修改該檔案，或透過設定對應的環境變數來覆寫預設值（如 LMS_TARGET_LOG_DIR）。
V. 使用方式
1. 批次處理模式
直接執行 main.py，程式會自動掃描 config.py 中設定的日誌目錄。
```
python main.py
```
腳本將從上次中斷的地方繼續處理新的日誌行，並將結果輸出至指定的 JSON 檔案。

2. 即時處理模式 (Filebeat)
啟動接收伺服器:
```
python src/filebeat_server.py
伺服器預設會在 localhost:8080 監聽。
```

設定 Filebeat:
在您的 filebeat.yml 中，設定 output 指向本專案的 HTTP 端點。
```
YAML

filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/*.log

output.http:
  url: "http://localhost:8080"
  method: "POST"
  headers:
    Content-Type: "application/json"
```
VI. 測試
本專案包含單元測試與整合測試。執行以下指令來運行所有測試：

pytest
VII. 設定詳解
所有可自訂的參數都集中在 config.py 中，也可透過環境變數覆寫。常見的設定包含：
```
LMS_TARGET_LOG_DIR：要掃描的日誌目錄，預設為 `/var/log`。
LMS_ANALYSIS_OUTPUT_FILE：分析結果輸出的 JSON 路徑。
CACHE_SIZE、SAMPLE_TOP_PERCENT：控制快取大小與取樣比例。
BATCH_SIZE：LLM 一次處理的告警筆數，可透過 LMS_LLM_BATCH_SIZE 設定。
MAX_HOURLY_COST_USD：每小時允許的 LLM 費用上限。
GEMINI_API_KEY：Gemini API 金鑰，可透過環境變數提供。
```
VIII. 專案進度與未來展望
此章節追蹤專案的實作進度與未來的優化方向。

已完成項目
以下是根據初期規劃，目前已在專案中實現的功能：

進階向量搜尋: 已導入 faiss-cpu 與 sentence-transformers，實現了高效的本地向量相似度搜尋。
壓縮日誌處理: 系統能自動讀取並處理 .gz 與 .bz2 格式的壓縮日誌。
狀態管理與日誌輪替: 透過追蹤檔案 inode 與讀取位移，能穩定處理日誌輪替 (Log Rotation) 而不遺漏或重複。
錯誤處理與韌性: 關鍵的網路I/O（如 LLM 呼叫）已加上具備指數退讓的重試機制。
外部化設定: 專案設定皆可透過環境變數覆寫，無需修改程式碼。
近即時處理: 已提供 filebeat_server.py，支援透過 HTTP 進行近即時的日誌分析。
成本控制與批次處理: 成功實作了結果快取、智慧取樣、成本上限保護，並透過批次處理提升 LLM API 呼叫效率。
自動化測試: 已建立完整的 pytest 測試集，並透過 GitHub Actions 實現 CI/CD。
未來擴充與優化建議
1. 核心建議：導入 OpenSearch 打造一站式分析平台
這是最具價值的下一步。將目前的輸出（JSON 檔案）改為直接寫入 OpenSearch，可以一次性解決多個問題：
視覺化儀表板 (Dashboard): 利用 OpenSearch Dashboards 建立互動式儀表板，取代手動查閱 JSON，實現告警視覺化、趨勢分析與系統監控。
取代本地向量庫: 利用 OpenSearch 內建的 k-NN 向量搜尋功能，將日誌嵌入向量直接存入 OpenSearch。這能簡化系統架構，並具備更強的擴展性。
實現進階告警: 透過 OpenSearch 的告警外掛，設定規則（如：當 attack_type 為 SQL Injection 且信賴度 > 0.9 時），自動發送通知到 Slack 或 Teams。

2. 進一步降低 LLM Token 消耗
目前的成本控制已相當有效，但仍可從「提示工程 (Prompt Engineering)」層面繼續優化：
總結歷史上下文: 修改 _summarize_examples 函式，不要傳送完整的歷史日誌原文，改為傳送其摘要，如 歷史攻擊: {attack_type} | 理由: {reason}。這能大幅減少每次呼叫的 Token 量。
導入分層式 LLM 架構: 對於 LLM 回傳「不確定」或信賴度低的結果，可設計一個升級機制，呼叫更強大（也更昂貴）的模型進行二次分析，實現成本與準確性的最佳平衡。

3. 增強日誌解析與安全性
增強日誌解析能力: 對於複雜的 syslog 格式，可導入 python-grok 函式庫，取代現有的字串切割，讓日誌解析更精準、更具擴展性。
強化金鑰安全性: 將 GEMINI_API_KEY 等敏感資訊從環境變數改為由專門的密鑰管理系統（如 HashiCorp Vault、AWS/GCP Secret Manager）進行管理。

5. 持續優化程式碼
效能剖析 (Profiling): 定期對程式碼進行效能剖析，特別是 log_processor.py 中的熱點路徑，找出潛在瓶頸並進行優化。
依賴管理: 定期更新 requirements.txt 中的函式庫版本，以獲取效能改進與安全性更新。

IX. 常見問題排解 (Troubleshooting)

ModuleNotFoundError: No module named '...

1.原因: Python 環境中缺少必要的套件。
解決: 啟動正確的虛擬環境，然後使用 pip install -r requirements.txt 重新安裝。
權限錯誤 (Permission Denied / Errno 13)

2.原因: 腳本執行使用者沒有讀取日誌目錄/檔案或寫入輸出目錄/檔案的權限。
解決: 檢查並修正相關目錄和檔案的權限 (ls -l, chmod, chown)，或將輸出路徑設置到使用者有權限的位置。
API 金鑰問題 (認證失敗、401/403 錯誤)
3.原因: GEMINI_API_KEY 未設定、設定錯誤或金鑰本身無效/權限不足。
解決: 再次確認 GEMINI_API_KEY 環境變數已正確設定，且金鑰有效。
