"""
03_train_eval.py — AI 에이전트 공격 탐지 모델 학습 및 '정직한' 평가

기존 02_train_rf.py / ai_siem_rf_colab.ipynb 와의 차이
  1) 세션 단위 교차검증 (StratifiedGroupKFold)
     - 같은 세션(파일__IP)의 창이 학습과 검증에 동시에 들어가지 않음 -> 데이터 누수 방지
     - 기존: 한 세션의 앞 75% 학습 / 뒤 25% 검증 -> 같은 사람·같은 공격을 외워서 맞히는 구조
  2) '처음 보는 공격 도구' 일반화 평가 (Leave-One-Family-Out)
     - 예: PentAGI + ARTEX 로 학습 -> Kali+Claude 로 검증
  3) 오탐률(FPR) 목표에 맞춘 임계값 선택 (기본 0.5 고정 X)
  4) 베이스라인 비교: 단순 규칙 / IsolationForest(정상만 학습) / RandomForest
     - ML 이 단순 규칙보다 나은지 확인해야 '보안장비가 못 잡는 것을 ML 이 잡는다'를 입증할 수 있음
  5) 지름길(shortcut) 피처 경고: 피처 하나만으로 정상/공격이 완벽히 갈리면 경고
  6) 세션 단위 경보 + TTD: 공격 세션 '시작 시점'부터 첫 경보까지 시간 (연속 k개 창 탐지 시 경보)
  7) 최근 2분 맥락 피처: 느린(저속) 공격도 누적으로 잡도록 직전 창들의 합/최대값 추가
  8) Permutation Importance (검증 데이터 기준) - RF 기본 중요도보다 신뢰도 높음
     - [2026-10-29] '피처 그룹' 단위로 함께 섞는 방식 추가 (메인 지표)
       피처 하나씩 섞으면 비슷한 정보를 가진 다른 피처가 대신 맞혀서 대부분 0 으로 나옴
       -> 같은 종류의 정보(예: Shadow API 피처 + 그 2분 맥락 피처)를 한꺼번에 섞어
          '이 종류의 행동 정보가 없으면 성능이 얼마나 떨어지나'를 측정
  9) [2026-10-29] 경로 기본값은 '현재 폴더' 기준 (./features 읽기 -> ./models 저장)
     서로 다른 피처 파일에 같은 IP·시간 창이 있으면 (추출 시간대 겹침) 경고

실행 예시
  python 03_train_eval.py                                   # ./features/*_features.csv 사용 (ml/data 에서 실행)
  python 03_train_eval.py --target-fpr 0.025 --alert-k 2
  python 03_train_eval.py --exclude-features unique_ua_count bytes_mean
"""

import argparse
import json
import pathlib
import sys
import warnings

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.metrics import average_precision_score, roc_auc_score, roc_curve
from sklearn.model_selection import StratifiedGroupKFold

warnings.filterwarnings("ignore", category=UserWarning)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

LOAD_INFO = {}  # load_features 가 채움: 파일별 피처 컬럼 (버전 섞임 진단용)
META_COLS = ["session_id", "window_idx", "client_ip", "window_start", "label", "family", "_ts", "_file"]
CONTEXT_WINDOW = "120s"  # 맥락 피처: 직전 2분(현재 창 포함)

# 그룹 단위 중요도용 피처 그룹 (key, 한글 이름, 기본 피처 목록)
#   01_preprocess.py 피처 14종 기준 (예전 피처 이름도 같은 그룹에 넣어 구버전 피처 파일도 동작)
#   ctx2m_* 맥락 피처는 원래 피처의 그룹에 함께 들어감 (예: ctx2m_shadow_api_ratio_max -> shadow_api)
#   목록에 없는 새 피처는 'other' 그룹으로 자동 분류
FEATURE_GROUPS = [
    ("shadow_api",    "Shadow API·API 직접 호출", ["shadow_api_ratio", "orphan_api_ratio", "api_ratio"]),
    ("idor_exfil",    "ID 열거·유출량",           ["unique_id_count", "id_seq_ratio", "api_2xx_bytes_sum",
                                                   "bytes_mean", "bytes_max"]),
    ("errors",        "에러·인증 실패",           ["error_404_ratio", "auth_fail_ratio", "error_5xx_ratio",
                                                   "error_abnormal_ratio"]),
    ("volume_rhythm", "요청량·리듬",              ["req_count", "interval_mean", "interval_cv", "interval_std",
                                                   "active_windows"]),
    ("exploration",   "탐색 다양성·요청 방식",    ["unique_url_ratio", "ratio_post", "method_nunique",
                                                   "unique_url_count", "unique_ua_count"]),
]
GROUP_LABEL_KO = {k: ko for k, ko, _ in FEATURE_GROUPS}
GROUP_LABEL_KO["other"] = "기타"
PERM_REPEATS = 10


# =============================================================
# 1. 데이터 로드
# =============================================================
def load_features(paths, default_dir):
    files = []
    for p in (paths or [str(default_dir)]):
        p = pathlib.Path(p)
        files += sorted(p.glob("*_features.csv")) if p.is_dir() else [p]
    if not files:
        sys.exit(f"[ERROR] 피처 파일이 없습니다: {paths or default_dir} (먼저 01_preprocess.py 실행)")
    parts = [pd.read_csv(f).assign(_file=f.name) for f in files]
    LOAD_INFO["cols_by_file"] = {f.name: frozenset(p.columns) - set(META_COLS) for f, p in zip(files, parts)}
    df = pd.concat(parts, ignore_index=True)
    if len(files) > 1:
        # 파일이 다르면 다른 세션 (파일마다 실행 번호를 따로 매긴 경우 이름이 겹칠 수 있음)
        df["session_id"] = df["session_id"].astype(str) + "@" + df["_file"].str.replace("_features.csv", "", regex=False)
    df["label"] = df["label"].astype(int)
    df["_ts"] = pd.to_datetime(df["window_start"])
    df["family"] = df.apply(_family, axis=1)
    return df, files


def _family(row):
    """세션의 공격 계열: 정상은 benign, 공격은 파일명 첫 단어 (pentagi / artex / claude / attack / mixed ...)"""
    if row["label"] == 0:
        return "benign"
    stem = str(row["session_id"]).split("__")[0]
    return stem.split("_")[0].lower()


def add_context_features(df, base_cols):
    """세션별 직전 2분 누적 피처 (느린 공격 대응). 현재 창 포함, 미래 창은 사용하지 않음."""
    agg = {
        "req_count": "sum",
        "unique_id_count": "sum",
        "shadow_api_ratio": "max",
        "orphan_api_ratio": "mean",
        "error_404_ratio": "mean",
        "auth_fail_ratio": "max",
    }
    agg = {k: v for k, v in agg.items() if k in base_cols}
    out = []
    for _, g in df.sort_values("_ts").groupby("session_id", sort=False):
        r = g.set_index("_ts")[list(agg)].rolling(CONTEXT_WINDOW)
        ctx = pd.DataFrame({f"ctx2m_{c}_{fn}": getattr(r[c], fn)().values for c, fn in agg.items()}, index=g.index)
        ctx["ctx2m_active_windows"] = g.set_index("_ts")["req_count"].rolling(CONTEXT_WINDOW).count().values
        out.append(ctx)
    return df.join(pd.concat(out))


# =============================================================
# 2. 데이터 진단
# =============================================================
def diagnose(df, feature_cols):
    print("\n[1] 데이터 진단")
    print("-" * 70)
    sess = df.groupby(["family", "label"])["session_id"].nunique()
    wins = df.groupby(["family", "label"]).size()
    for (fam, lb), n in sess.items():
        print(f"  {fam:<12} label={lb}  세션 {n:>3}개 / 창 {wins[(fam, lb)]:>5}개")

    n_sess = df.groupby("label")["session_id"].nunique()
    problems = []

    # 같은 IP 의 같은 시간대가 서로 다른 피처 파일에 들어 있으면 같은 로그를 두 번 추출한 것 (시간대 겹침)
    #   파일마다 30초 창 경계가 달라 window_start 가 정확히 같지 않으므로 IP별 시간 구간이 겹치는지로 판단
    span = df.groupby(["_file", "client_ip"])["_ts"].agg(["min", "max"]).reset_index()
    overlaps = set()
    for ip, g in span.groupby("client_ip"):
        rows = g.to_dict("records")
        for i in range(len(rows)):
            for j in range(i + 1, len(rows)):
                a, b = rows[i], rows[j]
                if a["min"] <= b["max"] + pd.Timedelta(seconds=30) and b["min"] <= a["max"] + pd.Timedelta(seconds=30):
                    overlaps.add(tuple(sorted((a["_file"], b["_file"]))))
    if overlaps:
        pairs = ", ".join(f"{a} <-> {b}" for a, b in sorted(overlaps))
        problems.append(f"서로 다른 피처 파일에 같은 IP·같은 시간대가 들어 있습니다: {pairs}\n"
                        "      -> 추출 시간대가 겹친 파일입니다. 하나만 남기세요 (중복 데이터는 평가를 부풀림).")
    # 피처 구성이 다른 파일이 섞이면 (01_preprocess.py 버전이 다름) 없는 피처가 0 으로 채워져 학습이 틀어짐
    cols_by_file = LOAD_INFO.get("cols_by_file", {})
    if len(set(cols_by_file.values())) > 1:
        common = frozenset.intersection(*cols_by_file.values())
        diff = {f: sorted(c - common) for f, c in cols_by_file.items() if c - common}
        problems.append(f"피처 구성이 다른 파일이 섞여 있습니다 (01_preprocess.py 버전 차이): {diff}\n"
                        "      -> 원본 로그로 피처를 다시 만드세요 (run_pipeline.py --raw ...).")
    if n_sess.min() < 3:
        problems.append(f"라벨별 세션 수가 3개 미만입니다 ({n_sess.to_dict()}). "
                        "교차검증 결과를 신뢰하기 어렵습니다. 세션을 더 모으세요.")

    # 지름길 피처: 피처 하나로 AUC ≥ 0.99
    shortcuts = []
    for c in feature_cols:
        x = df[c].fillna(0)
        if x.nunique() < 2:
            continue
        auc = roc_auc_score(df["label"], x)
        auc = max(auc, 1 - auc)
        if auc >= 0.99:
            shortcuts.append((c, auc))
    if shortcuts:
        problems.append("피처 하나만으로 정상/공격이 거의 완벽히 갈립니다: "
                        + ", ".join(f"{c}(AUC {a:.3f})" for c, a in sorted(shortcuts, key=lambda t: -t[1]))
                        + "\n      -> 데이터가 너무 쉬운 상태일 수 있습니다. 공격이 '정상처럼 보이는' 세션"
                          "(저속, 브라우저 UA, 페이지 경유)을 추가해야 ML 의 가치가 드러납니다.")
    for p in problems:
        print(f"  [경고] {p}")
    if not problems:
        print("  [OK] 큰 문제 없음")
    return problems, shortcuts


# =============================================================
# 3. 모델 / 베이스라인
# =============================================================
def make_rf(seed=42):
    return RandomForestClassifier(
        n_estimators=300, max_depth=None, min_samples_leaf=2,
        class_weight="balanced_subsample", n_jobs=-1, random_state=seed)


def feature_groups(feature_cols):
    """피처 이름 -> 그룹 key 로 묶기. {group_key: [features]}"""
    base_to_group = {b: k for k, _, bases in FEATURE_GROUPS for b in bases}
    bases = sorted(base_to_group, key=len, reverse=True)  # 긴 이름 먼저 (접두사 겹침 방지)
    out = {}
    for c in feature_cols:
        name = c[len("ctx2m_"):] if c.startswith("ctx2m_") else c
        g = next((base_to_group[b] for b in bases if name == b or name.startswith(b + "_")), "other")
        out.setdefault(g, []).append(c)
    order = [k for k, _, _ in FEATURE_GROUPS] + ["other"]
    return {k: out[k] for k in order if k in out}


def grouped_permutation_drops(model, X, y, groups, n_repeats, rng):
    """그룹 안의 피처들을 '같은 순서로 함께' 섞었을 때 PR-AUC 하락폭 (반복별 리스트)"""
    base = average_precision_score(y, model.predict_proba(X)[:, 1])
    drops = {}
    for g, cols in groups.items():
        d = []
        for _ in range(n_repeats):
            Xp = X.copy()
            Xp[cols] = X[cols].values[rng.permutation(len(X))]
            d.append(base - average_precision_score(y, model.predict_proba(Xp)[:, 1]))
        drops[g] = d
    return drops


def rule_score(X):
    """단순 규칙 베이스라인 (WAF/IPS 수준의 임계값 규칙을 흉내)"""
    s = np.zeros(len(X))
    if "req_count" in X:
        s = np.maximum(s, (X["req_count"] >= 100).astype(float))
    if "error_404_ratio" in X:
        s = np.maximum(s, (X["error_404_ratio"] >= 0.5).astype(float))
    if "auth_fail_ratio" in X:
        s = np.maximum(s, (X["auth_fail_ratio"] >= 0.5).astype(float))
    return s


def pick_threshold(y, score, target_fpr):
    """FPR <= target 을 만족하는 임계값 중 재현율이 가장 높은 것"""
    fpr, tpr, thr = roc_curve(y, score)
    ok = np.where(fpr <= target_fpr)[0]
    i = ok[np.argmax(tpr[ok])]
    return float(min(thr[i], 1.0)) if np.isfinite(thr[i]) else 1.0


def window_metrics(y, score, thr):
    pred = (score >= thr).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum()); fn = int(((pred == 0) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum()); tn = int(((pred == 0) & (y == 0)).sum())
    m = {"recall": tp / (tp + fn) if tp + fn else np.nan,
         "fpr": fp / (fp + tn) if fp + tn else np.nan,
         "precision": tp / (tp + fp) if tp + fp else np.nan,
         "tp": tp, "fn": fn, "fp": fp, "tn": tn}
    if len(np.unique(y)) == 2 and len(np.unique(score)) > 1:
        m["roc_auc"] = roc_auc_score(y, score)
        m["pr_auc"] = average_precision_score(y, score)
    return m


def session_alerts(df, pred, k):
    """세션별 경보: 연속 k개 창이 탐지되면 경보. TTD = 세션 첫 창 ~ 경보 창 시각"""
    d = df[["session_id", "label", "family", "_ts"]].copy()
    d["pred"] = pred
    rows = []
    for sid, g in d.sort_values("_ts").groupby("session_id"):
        run, alert_ts = 0, None
        need = min(k, len(g))  # 창이 k개보다 적은 짧은 세션은 전부 탐지되면 경보
        for ts, p in zip(g["_ts"], g["pred"]):
            run = run + 1 if p else 0
            if run >= need:
                alert_ts = ts
                break
        dur_h = max((g["_ts"].max() - g["_ts"].min()).total_seconds(), 30) / 3600
        rows.append({"session_id": sid, "label": g["label"].iloc[0], "family": g["family"].iloc[0],
                     "alert": alert_ts is not None,
                     "ttd_sec": (alert_ts - g["_ts"].min()).total_seconds() + 30 if alert_ts is not None else np.nan,
                     "hours": dur_h})
    return pd.DataFrame(rows)


# =============================================================
# 4. 교차검증
# =============================================================
def cross_validate(df, feature_cols, n_splits, target_fpr, seed):
    y = df["label"].values
    groups = df["session_id"].values
    n_min = df.groupby("label")["session_id"].nunique().min()
    n_splits = max(2, min(n_splits, n_min))
    cv = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=seed)

    oof = {"rule": np.zeros(len(df)), "iforest": np.zeros(len(df)), "rf": np.zeros(len(df))}
    perm = []
    fgroups = feature_groups(feature_cols)
    gdrops = {g: [] for g in fgroups}
    rng = np.random.RandomState(seed)
    for fold, (tr, te) in enumerate(cv.split(df, y, groups)):
        Xtr, Xte = df.iloc[tr][feature_cols], df.iloc[te][feature_cols]
        ytr, yte = y[tr], y[te]

        oof["rule"][te] = rule_score(Xte)

        iso = IsolationForest(n_estimators=300, random_state=seed).fit(Xtr[ytr == 0])
        oof["iforest"][te] = -iso.score_samples(Xte)

        rf = make_rf(seed).fit(Xtr, ytr)
        oof["rf"][te] = rf.predict_proba(Xte)[:, 1]

        if len(np.unique(yte)) == 2:
            pi = permutation_importance(rf, Xte, yte, scoring="average_precision",
                                        n_repeats=5, random_state=seed, n_jobs=-1)
            perm.append(pi.importances_mean)
            for g, d in grouped_permutation_drops(rf, Xte, yte, fgroups, PERM_REPEATS, rng).items():
                gdrops[g].extend(d)
    imp = pd.Series(np.mean(perm, axis=0) if perm else np.zeros(len(feature_cols)), index=feature_cols)
    gimp = pd.DataFrame({
        "group": list(fgroups),
        "label_ko": [GROUP_LABEL_KO[g] for g in fgroups],
        "importance": [float(np.mean(gdrops[g])) if gdrops[g] else 0.0 for g in fgroups],
        "std": [float(np.std(gdrops[g])) if gdrops[g] else 0.0 for g in fgroups],
        "n_features": [len(fgroups[g]) for g in fgroups],
        "features": [fgroups[g] for g in fgroups],
    }).sort_values("importance", ascending=False).reset_index(drop=True)
    return oof, imp.sort_values(ascending=False), gimp, n_splits


def leave_one_family_out(df, feature_cols, thr, seed, k):
    """공격 계열 하나를 통째로 빼고 학습 -> 그 계열로 검증 (처음 보는 에이전트 일반화)"""
    fams = sorted(f for f in df.loc[df.label == 1, "family"].unique())
    if len(fams) < 2:
        return None
    benign_sess = df.loc[df.label == 0, "session_id"].unique()
    rng = np.random.RandomState(seed)
    rows = []
    for fam in fams:
        # 정상 세션도 일부(약 30%)를 검증용으로 떼어 FPR 측정
        test_benign = set(rng.choice(benign_sess, max(1, len(benign_sess) // 3), replace=False))
        te_mask = (df.family == fam) | df.session_id.isin(test_benign)
        tr_mask = ~te_mask & (df.label == 0) | (df.label == 1) & (df.family != fam)
        tr, te = df[tr_mask], df[te_mask]
        rf = make_rf(seed).fit(tr[feature_cols], tr.label)
        # 임계값은 [2] 세션 교차검증에서 FPR 목표로 고른 값을 그대로 사용
        s = rf.predict_proba(te[feature_cols])[:, 1]
        m = window_metrics(te.label.values, s, thr)
        sa = session_alerts(te, (s >= thr).astype(int), k)
        att = sa[sa.label == 1]
        rows.append({"held_out_family": fam, "window_recall": m["recall"], "window_fpr": m["fpr"],
                     "session_detect": att.alert.mean(), "ttd_median_sec": att.ttd_sec.median()})
    return pd.DataFrame(rows)


# =============================================================
# 5. 리포트 / 시각화
# =============================================================
def save_plots(out_dir, y, oof, thresholds, imp, gimp):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        from sklearn.metrics import precision_recall_curve
    except ImportError:
        return []
    paths = []
    fig, ax = plt.subplots(1, 2, figsize=(13, 5))
    for name, s in oof.items():
        if len(np.unique(s)) < 2:
            continue
        p, r, _ = precision_recall_curve(y, s)
        ax[0].plot(r, p, label=f"{name} (AP={average_precision_score(y, s):.3f})")
        f, t, _ = roc_curve(y, s)
        ax[1].plot(f, t, label=name)
    ax[0].set(xlabel="Recall", ylabel="Precision", title="Precision-Recall (session-grouped CV)")
    ax[1].set(xlabel="False Positive Rate", ylabel="True Positive Rate", title="ROC (zoom FPR<=0.1)", xlim=(0, 0.1))
    ax[0].legend(); ax[1].legend()
    fig.tight_layout(); p1 = out_dir / "cv_curves.png"; fig.savefig(p1, dpi=120); plt.close(fig); paths.append(p1)

    # 왼쪽: 그룹 단위 (메인) / 오른쪽: 피처 단위 (참고, 정보가 겹치는 피처는 0 근처로 나옴)
    #   Colab 에 한글 폰트가 없어 그래프 라벨은 영문 그룹 key 사용
    top = imp.head(12).sort_values()
    fig, ax = plt.subplots(1, 2, figsize=(14, max(4.5, 0.4 * len(top))),
                           gridspec_kw={"width_ratios": [1.1, 1]})
    g = gimp.sort_values("importance")
    labels = [f"{k} ({n})" for k, n in zip(g.group, g.n_features)]
    ax[0].barh(labels, g.importance, xerr=g["std"], color="#2563EB", ecolor="#94A3B8", capsize=3)
    ax[0].axvline(0, color="#64748B", lw=0.8)
    ax[0].set(title="Grouped permutation importance\n(shuffle all features of a group together)",
              xlabel="drop in PR-AUC on held-out sessions")
    ax[1].barh(top.index, top.values, color="#94A3B8")
    ax[1].axvline(0, color="#64748B", lw=0.8)
    ax[1].set(title="Single-feature permutation importance (reference)\n"
                    "~0 = other features carry the same info", xlabel="drop in PR-AUC")
    fig.tight_layout(); p2 = out_dir / "permutation_importance.png"; fig.savefig(p2, dpi=120); plt.close(fig); paths.append(p2)
    return paths


def main():
    cwd = pathlib.Path.cwd()  # 경로 기본값은 실행한 현재 폴더 기준

    ap = argparse.ArgumentParser(description="세션 단위 교차검증 기반 공격 탐지 모델 학습/평가")
    ap.add_argument("--features", nargs="*", default=None, help="피처 CSV 파일/폴더 (기본: ./features)")
    ap.add_argument("--out-dir", default=str(cwd / "models"), help="모델·리포트 저장 폴더 (기본: ./models)")
    ap.add_argument("--target-fpr", type=float, default=0.025, help="창 단위 오탐률 목표 (기본 2.5%%)")
    ap.add_argument("--alert-k", type=int, default=2, help="연속 k개 창 탐지 시 세션 경보 (기본 2 = 1분)")
    ap.add_argument("--n-splits", type=int, default=5)
    ap.add_argument("--exclude-features", nargs="*", default=[], help="학습에서 뺄 피처")
    ap.add_argument("--no-context", action="store_true", help="직전 2분 맥락 피처 사용 안 함")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    out_dir = pathlib.Path(args.out_dir); out_dir.mkdir(parents=True, exist_ok=True)
    df, files = load_features(args.features, cwd / "features")
    base_cols = [c for c in df.columns if c not in META_COLS and c not in args.exclude_features]
    if not args.no_context:
        df = add_context_features(df, base_cols)
    feature_cols = [c for c in df.columns if c not in META_COLS and c not in args.exclude_features]
    df[feature_cols] = df[feature_cols].fillna(0)

    print("=" * 70)
    print(" [AI SIEM] 공격 탐지 모델 학습/평가 (세션 단위 교차검증)")
    print("=" * 70)
    print(f" * 피처 파일 {len(files)}개, 창 {len(df)}개, 피처 {len(feature_cols)}개")
    if df["label"].nunique() < 2:
        sys.exit(f"[중단] 정상/공격 데이터가 모두 필요합니다. 현재 라벨: {df['label'].value_counts().to_dict()}")

    problems, shortcuts = diagnose(df, feature_cols)
    n_sess = df.groupby("label")["session_id"].nunique()
    if n_sess.min() < 2:
        sys.exit("\n[중단] 세션 단위 교차검증에는 정상/공격 각각 최소 2개 세션(권장 5개 이상)이 필요합니다.\n"
                 f"       현재 세션 수: 정상 {n_sess.get(0, 0)}개, 공격 {n_sess.get(1, 0)}개\n"
                 "       팀원 6명이 1 PC = 1 고객 방식으로 수집하면 정상 세션이 6개씩 생깁니다.")

    # ---------------- 교차검증 ----------------
    oof, imp, gimp, n_splits = cross_validate(df, feature_cols, args.n_splits, args.target_fpr, args.seed)
    y = df["label"].values
    print(f"\n[2] 세션 단위 {n_splits}-Fold 교차검증 (창 단위, 임계값은 FPR≤{args.target_fpr:.1%} 기준)")
    print("-" * 70)
    print(f"  {'모델':<10}{'재현율':>8}{'오탐률':>8}{'정밀도':>8}{'ROC-AUC':>9}{'PR-AUC':>8}   임계값")
    results, thresholds = {}, {}
    for name, s in oof.items():
        thr = 0.5 if name == "rule" else pick_threshold(y, s, args.target_fpr)
        m = window_metrics(y, s, thr)
        results[name], thresholds[name] = m, thr
        print(f"  {name:<10}{m['recall']:>8.1%}{m['fpr']:>8.1%}{m['precision']:>8.1%}"
              f"{m.get('roc_auc', np.nan):>9.3f}{m.get('pr_auc', np.nan):>8.3f}   {thr:.3f}")
    print("  * 임계값을 같은 교차검증 결과로 고르므로 실제보다 약간 낙관적일 수 있습니다.")

    # ---------------- 세션 단위 ----------------
    rf_pred = (oof["rf"] >= thresholds["rf"]).astype(int)
    sa = session_alerts(df, rf_pred, args.alert_k)
    att, ben = sa[sa.label == 1], sa[sa.label == 0]
    print(f"\n[3] 세션 단위 경보 (RF, 연속 {args.alert_k}개 창 = {args.alert_k * 30}초 탐지 시 경보)")
    print("-" * 70)
    print(f"  공격 세션 탐지율 : {att.alert.mean():.1%} ({int(att.alert.sum())}/{len(att)})")
    print(f"  TTD 중앙값       : {att.ttd_sec.median():.0f}초 (공격 세션 시작 ~ 첫 경보, 목표 60초)")
    print(f"  정상 세션 오경보 : {ben.alert.mean():.1%} ({int(ben.alert.sum())}/{len(ben)}),"
          f" 시간당 {ben.alert.sum() / max(ben.hours.sum(), 1e-9):.2f}건")
    for fam, g in att.groupby("family"):
        print(f"    - {fam:<10} 탐지 {g.alert.mean():.0%}, TTD 중앙값 {g.ttd_sec.median():.0f}초")
    missed = att[~att.alert]
    if len(missed):
        print("  놓친 공격 세션: " + ", ".join(missed.session_id.tolist()[:10]))

    # ---------------- 처음 보는 공격 도구 ----------------
    lofo = leave_one_family_out(df, feature_cols, thresholds["rf"], args.seed, args.alert_k)
    print("\n[4] 처음 보는 공격 도구 일반화 (Leave-One-Family-Out)")
    print("-" * 70)
    if lofo is None:
        print("  공격 계열이 1종류뿐이라 생략합니다. (pentagi / artex / claude 등 2종류 이상 필요)")
    else:
        for _, r in lofo.iterrows():
            print(f"  {r.held_out_family:<10} 제외 학습 -> 창 재현율 {r.window_recall:.1%}, 오탐률 {r.window_fpr:.1%},"
                  f" 세션 탐지 {r.session_detect:.0%}, TTD {r.ttd_median_sec:.0f}초")

    # ---------------- 중요도 ----------------
    print("\n[5] 그룹 단위 Permutation Importance (그룹 피처를 함께 섞었을 때 PR-AUC 하락폭)")
    print("-" * 70)
    for _, r in gimp.iterrows():
        print(f"  {r.label_ko:<16}{r.importance:>8.4f} ±{r['std']:.4f}  {'■' * int(max(r.importance, 0) * 100)}")
        print(f"      ({', '.join(r.features)})")
    if (gimp.importance.abs() < 1e-9).all():
        print("  (모든 그룹이 0: 여러 그룹이 같은 정보를 담고 있어 한 그룹을 섞어도 성능이 안 떨어지는 상태."
              " 데이터가 너무 쉽다는 신호입니다)")
    print("\n    [참고] 피처 하나씩 섞었을 때 (정보가 겹치는 피처는 0 근처로 나옴 = '안 쓰였다'는 뜻 아님)")
    for c, v in imp.head(8).items():
        print(f"      {c:<32}{v:>8.4f}")

    # ---------------- 최종 모델 저장 ----------------
    import joblib
    final = make_rf(args.seed).fit(df[feature_cols], df["label"])
    model_path = out_dir / "attack_detector_rf.joblib"
    joblib.dump({"model": final, "features": feature_cols, "threshold": thresholds["rf"],
                 "alert_k": args.alert_k, "context_window": None if args.no_context else CONTEXT_WINDOW,
                 "trained_on": [f.name for f in files]}, model_path)
    plots = save_plots(out_dir, y, oof, thresholds, imp, gimp)
    report = {
        "cv": {k: {kk: (None if isinstance(vv, float) and np.isnan(vv) else vv) for kk, vv in v.items()}
               for k, v in results.items()},
        "thresholds": thresholds,
        "session": {"attack_detect": float(att.alert.mean()), "ttd_median_sec": float(att.ttd_sec.median()),
                    "benign_false_alarm": float(ben.alert.mean())},
        "lofo": None if lofo is None else lofo.to_dict(orient="records"),
        "group_importance": gimp.to_dict(orient="records"),
        "feature_importance": {k: float(v) for k, v in imp.items()},
        "warnings": problems,
    }
    (out_dir / "eval_report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2, default=float),
                                             encoding="utf-8")
    print("\n" + "=" * 70)
    print(f" 모델 저장   : {model_path}")
    print(f" 평가 리포트 : {out_dir / 'eval_report.json'}")
    for p in plots:
        print(f" 그래프      : {p}")
    print("=" * 70)


if __name__ == "__main__":
    main()
