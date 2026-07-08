# Member 2 — Detection Engine: Test Report

**Module:** `detection_engine.py`
**Paper reference:** Mirheidari et al., *"Web Cache Deception Escalates!"* (USENIX Security 2022) — Algorithm 1 (DE-style detection) + Algorithm 2 (false-positive filtering)
**Environment:** WSL, Docker Compose (Flask origin + Nginx reverse-proxy cache)

---

## 1. Setup & commands used

**Project layout**
```
~/NSpapertest/NSpapersim/
├── app/                      # Member 1 — Flask origin
├── proxy/                    # Member 1 — nginx.conf
├── docker-compose.yml
├── member3_wcd_completed.py  # Member 3 — payloads, cache heuristics, FP filter
└── detector/
    └── detection_engine.py   # Member 2 — this module
```

Member 3's module is imported directly by `detection_engine.py`, so a copy was placed inside `detector/`:
```bash
cd ~/NSpapertest/NSpapersim
cp member3_wcd_completed.py detector/
```

**Bring up the stack (Flask origin on :5000, Nginx cache on :8080):**
```bash
cd ~/NSpapertest/NSpapersim
docker compose up --build -d
docker ps
```

**Confirm Nginx is caching and exposing visible cache-status headers:**
```bash
curl -I http://localhost:8080/profile
# HTTP/1.1 200 OK
# Cache-Control: no-store, no-cache, must-revalidate, max-age=0
# Pragma: no-cache
# X-Cache: MISS
```

**Run the detection engine — baseline (no cache) vs. real target (Nginx cache):**
```bash
cd detector

# Baseline / negative control — Flask directly, no proxy cache
python3 detection_engine.py --url http://localhost:5000/profile > ../baseline_run_log_no_cache.txt

# Real target — through Nginx
python3 detection_engine.py --url http://localhost:8080/profile \
  --output-json ../findings.json | tee ../full_run_log.txt
```

---

## 2. Bug found and fixed during testing

**Symptom:** first run against port 8080 showed `first=HIT second=HIT` for every live payload — instead of the expected `MISS → HIT`.

**Root cause:** `step2_liveness_check()` was probing `payload.attack_url` directly to confirm the path was routable. That request itself became the cache-poisoning MISS, so by the time `step3_cache_analysis()` ran its own two requests against the *same* URL, the cache was already warm — both came back HIT.

**Fix:** `step2_liveness_check()` now asks Member 3's `generate_attack_url()` for a fresh sibling URL (same mode/extension, new random filename) and probes that instead, leaving `payload.attack_url`'s cache key untouched until Step 3 runs.

**Manual confirmation of root cause (before applying the code fix):**
```bash
url="http://localhost:8080/profile/$(uuidgen | tr -d '-').css"
curl -sI "$url" | grep -i x-cache   # -> MISS
curl -sI "$url" | grep -i x-cache   # -> HIT
```
This matched the intended MISS→HIT behavior, confirming the proxy config was correct and the bug was in Step 2's request ordering, not in Nginx.

---

## 3. Results

### 3.1 Baseline run — `http://localhost:5000/profile` (Flask only, no cache)

| Step | Result |
|---|---|
| Step 1 — dynamic check | `Dynamic content confirmed: True` (different body hash per client state) |
| Step 2 — liveness | 2 of 12 modes alive (`PATH_PARAMETER`, `ENCODED_SLASH`); 10 correctly skipped (routing rejects the rest) |
| Step 3 — cache analysis | Both live modes: `first=UNKNOWN second=UNKNOWN`, `bodies_identical=False` → `NOT_SUSPICIOUS` |
| Final | **0 findings** |

No reverse proxy is present at this port, so there is no `X-Cache` header and no caching at all — the engine correctly reports `UNKNOWN`/`NOT_SUSPICIOUS` rather than a false positive. This is the negative control.

### 3.2 Real target — `http://localhost:8080/profile` (through Nginx)

| Step | Result |
|---|---|
| Step 1 — dynamic check | `Dynamic content confirmed: True` |
| Step 2 — liveness | Same 2 of 12 modes alive |
| Step 3 — cache analysis | Both live modes: `first=MISS second=HIT`, `bodies_identical=True` → `SUSPICIOUS` |
| Algorithm 2 — FP filter | `/profile` (no payload) → **kept**, not a false positive (not cached on its own) |
| Final | **2 confirmed WCD findings** |

```
- [PATH_PARAMETER] http://localhost:8080/profile/7idugzjpyp7ranc_rq0e.css
- [ENCODED_SLASH]  http://localhost:8080/profile%2Fzzwruz8g5c6omwuc.css
```

Full structured output saved in `findings.json`; full console trace of every step and mode saved in `full_run_log.txt` and `baseline_run_log_no_cache.txt`.

---

## 4. Why this counts as evidence the code is correct

- **Step 1 verified:** both runs independently confirm `/profile` is dynamic (fresh CSRF token per request, different hash each time).
- **Step 2 verified:** identical liveness results (2/12 alive) across both runs shows the module consistently and correctly identifies which path-confusion techniques survive Flask/Werkzeug's routing, independent of caching.
- **Step 3 verified:** the *only* difference between the two runs is the presence of the Nginx cache — same URLs, same app, same routing behavior — yet the baseline reports `UNKNOWN`/`NOT_SUSPICIOUS` and the real target reports `MISS→HIT`/`SUSPICIOUS`. This isolates the cache as the variable causing the detection, ruling out a false positive baked into the detector itself.
- **Algorithm 2 verified:** the false-positive filter correctly kept both findings, since `/profile` alone (without the `.css` trick) is never cached — confirming the findings are attributable to the path-confusion technique, not to an overly aggressive cache policy.
- **Manual cross-check:** independent `curl` calls against a fresh, never-requested attack URL reproduced the same MISS→HIT transition the script reported, confirming the script's verdict against ground truth rather than trusting the script alone.
