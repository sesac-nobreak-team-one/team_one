"""02_train_rf.py — Random Forest 학습 및 4대 평가지표 산출 (계획서 §5-6).

01_preprocess.py 가 생성한 ml/data/features/*_features.csv (또는 단일 CSV)를 바탕으로
Random Forest 모델을 학습하고 계획서 §6의 4대 핵심 보안 지표를 산출합니다:
  ① 탐지율(Recall) ≥ 0.80
  ② 정상 오탐률(FPR) < 0.025 (최대 0.05)
  ③ 최초 탐지 시간(Time-to-Detect, TTD) 30~60초 이내
  ④ 피처 중요도(Feature Importance) 분석 및 시각화 저장
"""

import argparse
import os
import sys
import pathlib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix

# 콘솔 UTF-8 설정
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

META_COLS = {"session_id", "window_idx", "client_ip", "window_start", "label"}

def split_dataset(df, test_frac=0.25, test_sessions=None):
    """
    세션 수에 따라 유연하게 학습/테스트 분할:
    - 세션이 라벨당 2개 이상일 때: 세션 단위 분할 (Session Split, 데이터 누수 방지)
    - 세션이 라벨당 1개일 때: 각 세션의 시간순 뒤쪽 test_frac을 테스트로 분할 (Time-series Window Split)
    """
    labels = sorted(df["label"].unique())
    session_counts = {l: df[df["label"] == l]["session_id"].nunique() for l in labels}
    
    can_session_split = all(cnt >= 2 for cnt in session_counts.values())
    
    if test_sessions:
        print(f"[*] 사용자 지정 테스트 세션 적용: {test_sessions}")
        df_test = df[df["session_id"].isin(test_sessions)].copy()
        df_train = df[~df["session_id"].isin(test_sessions)].copy()
        split_mode = "Session Split (User Specified)"
    elif can_session_split:
        # 계획서 명세: 라벨별 마지막 세션들을 테스트로 지정
        test_sids = []
        for l in labels:
            sids = sorted(df[df["label"] == l]["session_id"].unique())
            k = max(1, round(len(sids) * test_frac))
            test_sids.extend(sids[-k:])
        df_test = df[df["session_id"].isin(test_sids)].copy()
        df_train = df[~df["session_id"].isin(test_sids)].copy()
        split_mode = f"Session Split ({len(test_sids)} test sessions: {test_sids})"
    else:
        # 세션 수가 부족한 경우: 각 세션 내에서 시간순(Window Index) 기준 Train 75% / Test 25% 분할
        train_rows = []
        test_rows = []
        for sid, group in df.groupby("session_id"):
            group = group.sort_values("window_start")
            n = len(group)
            n_test = max(1, round(n * test_frac)) if n > 1 else 0
            n_train = n - n_test
            train_rows.append(group.iloc[:n_train])
            test_rows.append(group.iloc[n_train:])
            
        df_train = pd.concat(train_rows, ignore_index=True)
        df_test = pd.concat(test_rows, ignore_index=True)
        split_mode = f"Time-series Window Split (세션별 앞 {int((1-test_frac)*100)}% 학습, 뒤 {int(test_frac*100)}% 검증)"

    return df_train, df_test, split_mode

def load_feature_files(feature_args, default_features_dir, legacy_features_csv):
    """
    지정된 파일/폴더 목록 또는 기본 ml/data/features/ 폴더에서 개별 피처 CSV들을 로드합니다.
    """
    csv_paths = []
    if feature_args:
        for arg in feature_args:
            p = pathlib.Path(arg)
            if p.is_dir():
                csv_paths.extend(sorted(p.glob("*.csv")))
            elif p.is_file():
                csv_paths.append(p)
            else:
                sys.exit(f"[ERROR] 지정한 피처 경로를 찾을 수 없습니다: {arg}")
    else:
        if default_features_dir.is_dir():
            csv_paths = sorted(default_features_dir.glob("*_features.csv"))
        if not csv_paths and legacy_features_csv.is_file():
            csv_paths = [legacy_features_csv]

    if not csv_paths:
        sys.exit(f"[ERROR] 피처 파일 없음: {default_features_dir} — 먼저 01_preprocess.py 실행 필요")

    dfs = []
    print("[*] 로드된 피처 파일 목록:")
    for p in csv_paths:
        sub_df = pd.read_csv(p, encoding="utf-8-sig")
        print(f"   - {p.name} ({len(sub_df)}개 창)")
        dfs.append(sub_df)

    return pd.concat(dfs, ignore_index=True)

def main():
    curr = pathlib.Path(__file__).resolve().parent
    base_dir = curr.parent.parent if curr.parent.name == "src" else curr.parent
    default_features_dir = base_dir / "data" / "features"
    legacy_features_csv = base_dir / "data" / "features_dataset.csv"
    default_model = base_dir / "models" / "pentagi_rf.joblib"
    default_png = base_dir / "models" / "feature_importance.png"

    ap = argparse.ArgumentParser(description="RF 학습 및 4대 평가지표 산출 (계획서 §5-6)")
    ap.add_argument("--features", nargs="*", default=None, help="학습에 사용할 피처 CSV 파일 또는 폴더 경로들 (기본: ml/data/features/*.csv)")
    ap.add_argument("--test-frac", type=float, default=0.25, help="테스트 비율 (기본: 0.25)")
    ap.add_argument("--test-sessions", nargs="*", default=None, help="테스트 세션 id 직접 지정")
    ap.add_argument("--out", default=str(default_model), help="저장할 모델 파일 경로")
    ap.add_argument("--importance-png", default=str(default_png), help="저장할 중요도 차트 경로")
    args = ap.parse_args()

    df = load_feature_files(args.features, default_features_dir, legacy_features_csv)
    df["label"] = df["label"].astype(int)
    feature_cols = [c for c in df.columns if c not in META_COLS]

    if df["label"].nunique() < 2:
        sys.exit(f"[중단] 라벨이 한 종류뿐입니다. 정상(0)과 공격(1) 데이터가 모두 필요합니다. 현재: {dict(df['label'].value_counts())}")

    df_train, df_test, split_mode = split_dataset(df, test_frac=args.test_frac, test_sessions=args.test_sessions)

    if df_train.empty or df_test.empty or df_train["label"].nunique() < 2 or df_test["label"].nunique() < 2:
        sys.exit("[중단] 분할 후 학습 또는 테스트 셋에 클래스가 부족합니다.")

    X_train, y_train = df_train[feature_cols], df_train["label"]
    X_test, y_test = df_test[feature_cols], df_test["label"]

    print("=" * 65)
    print(" [AI SIEM] Random Forest 모델 학습 및 4대 지표 평가")
    print("=" * 65)
    print(f" * 피처 개수        : {len(feature_cols)}개 {feature_cols}")
    print(f" * 데이터 분할 방식 : {split_mode}")
    print(f" * 학습 데이터      : {len(df_train)}개 창 (정상 {sum(y_train==0)}, 공격 {sum(y_train==1)})")
    print(f" * 검증 데이터      : {len(df_test)}개 창 (정상 {sum(y_test==0)}, 공격 {sum(y_test==1)})")
    print("=" * 65)

    # Random Forest 모델 생성 및 학습 (클래스 불균형 가중치 balanced 적용)
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        class_weight="balanced",
        random_state=42
    )
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    print("\n[혼동 행렬 (Confusion Matrix)]")
    print("               예측: 정상(0)    예측: 공격(1)")
    print(f"  실제 정상(0)   {tn:>10}       {fp:>10}")
    print(f"  실제 공격(1)   {fn:>10}       {tp:>10}\n")
    print(classification_report(y_test, y_pred, target_names=["정상(0)", "공격(1)"], digits=4))

    # ③ Time-to-Detect (TTD) 계산
    dft = df_test.copy()
    dft["_ts"] = pd.to_datetime(dft["window_start"])
    dft["_pred"] = y_pred
    ttds = []
    for sid, g in dft[dft["label"] == 1].groupby("session_id"):
        g = g.sort_values("_ts")
        hits = g[g["_pred"] == 1]
        if not hits.empty:
            ttd_sec = (hits["_ts"].iloc[0] - g["_ts"].iloc[0]).total_seconds()
            ttds.append(ttd_sec)

    print("=" * 65)
    print(" [계획서 §6 핵심 성과 4대 지표 달성 결과]")
    print("=" * 65)
    recall_pass = "달성" if recall >= 0.80 else "미달"
    print(f" ① 탐지율 (Recall)          : {recall * 100:.2f}%  (목표 >= 80%)  -> [{recall_pass}]")

    fpr_pass = "달성" if fpr < 0.025 else ("주의" if fpr <= 0.05 else "미달")
    print(f" ② 정상 오탐률 (FPR)        : {fpr * 100:.2f}%  (목표 < 2.5%)  -> [{fpr_pass}]")

    if ttds:
        med_ttd = np.median(ttds)
        ttd_pass = "달성" if med_ttd <= 60 else "주의"
        print(f" ③ 최초 탐지 시간 (TTD)     : {med_ttd:.0f}초 (중앙값) (목표 30~60초) -> [{ttd_pass}]")
    else:
        print(" ③ 최초 탐지 시간 (TTD)     : 공격 세션 미탐")

    print("\n ④ 특징 중요도 (Feature Importance 순위):")
    imp = sorted(zip(feature_cols, model.feature_importances_), key=lambda t: -t[1])
    for rank, (c, v) in enumerate(imp, 1):
        bar = "■" * int(v * 30)
        print(f"   {rank:02d}. {c:<22} : {v:.4f}  {bar}")
    print("=" * 65)

    # 모델 저장
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    import joblib
    joblib.dump({"model": model, "features": feature_cols}, args.out)
    print(f"\n[저장 완료] AI 탐지 모델: {args.out}")

    # 중요도 차트 저장
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        names = [c for c, _ in imp][::-1]
        vals = [v for _, v in imp][::-1]
        plt.figure(figsize=(10, 6))
        plt.barh(names, vals, color="#2563EB")
        plt.title("Feature Importance — AI SIEM Detection", fontsize=14)
        plt.xlabel("Importance Score")
        plt.tight_layout()
        os.makedirs(os.path.dirname(os.path.abspath(args.importance_png)), exist_ok=True)
        plt.savefig(args.importance_png, dpi=200)
        print(f"[저장 완료] 특징 중요도 시각화 차트: {args.importance_png}")
    except Exception as e:
        print(f"(차트 생성 생략: {e})")

if __name__ == "__main__":
    main()
