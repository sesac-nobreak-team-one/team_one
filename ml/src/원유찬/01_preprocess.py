import csv
import json
import datetime
import pathlib
import re
import pandas as pd
import numpy as np

def parse_wazuh_csv(csv_path, label, session_id):
    """
    Wazuh OpenSearch에서 다운로드한 CSV (다중 컬럼 형태 및 2컬럼 형태 모두 지원)를 파싱하여
    개별 HTTP 요청 레코드 리스트로 반환합니다.
    """
    records = []
    df = pd.read_csv(csv_path, low_memory=False)
    
    for _, row in df.iterrows():
        # 1. _source.full_log 분석
        full_log = str(row.get('_source.full_log', '')).strip()
        
        # 1-1. JSON 형식 (app.log 비즈니스 로그)
        if full_log.startswith('{') and full_log.endswith('}'):
            try:
                d = json.loads(full_log)
                ts_str = d.get('timestamp')
                dt = datetime.datetime.fromisoformat(ts_str) if ts_str else None
                path = d.get('path', '')
                if any(path.endswith(ext) for ext in ['.png', '.jpg', '.jpeg', '.gif', '.css', '.js', '.ico', '.woff']):
                    continue
                records.append({
                    'timestamp': dt,
                    'client_ip': d.get('client_ip', 'unknown'),
                    'method': d.get('method', 'GET'),
                    'path': path,
                    'status': int(d.get('status', 200)),
                    'response_bytes': int(d.get('response_bytes', 0)),
                    'duration_ms': float(d.get('duration_ms', 0.0)),
                    'user_agent': d.get('user_agent', ''),
                    'label': label,
                    'session_id': session_id
                })
                continue
            except Exception:
                pass
                
        # 1-2. Apache Combined Access Log 형식 (shop_access.log)
        m = re.match(r'(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+([^"\s]+)\s+[^"]*"\s+(\d+)\s+(\d+)\s+"[^"]*"\s+"([^"]*)"', full_log)
        if m:
            ip, ts_str, method, path, status, bytes_val, ua = m.groups()
            try:
                dt = datetime.datetime.strptime(ts_str.split()[0], '%d/%b/%Y:%H:%M:%S')
                if any(path.endswith(ext) for ext in ['.png', '.jpg', '.jpeg', '.gif', '.css', '.js', '.ico', '.woff']):
                    continue
                records.append({
                    'timestamp': dt,
                    'client_ip': ip,
                    'method': method,
                    'path': path,
                    'status': int(status),
                    'response_bytes': int(bytes_val),
                    'duration_ms': 0.0,
                    'user_agent': ua,
                    'label': label,
                    'session_id': session_id
                })
                continue
            except Exception:
                pass
                
        # 1-3. OpenSearch 분할 컬럼 직접 추출 (Fallback)
        path_col = str(row.get('_source.data.path', '')).strip() or str(row.get('_source.data.url', '')).strip()
        status_col = str(row.get('_source.data.status', '')).strip() or str(row.get('_source.data.id', '')).strip()
        ip_col = str(row.get('_source.data.client_ip', '')).strip() or str(row.get('_source.data.srcip', '')).strip()
        
        if path_col and status_col and status_col.isdigit():
            ts_val = str(row.get('_source.@timestamp', '')).strip()
            try:
                clean_ts = ts_val.replace('@', '').strip()
                dt = datetime.datetime.strptime(clean_ts.split('.')[0], '%b %d, %Y  %H:%M:%S')
                records.append({
                    'timestamp': dt,
                    'client_ip': ip_col if ip_col else 'unknown',
                    'method': str(row.get('_source.data.method', 'GET')).strip() or 'GET',
                    'path': path_col,
                    'status': int(status_col),
                    'response_bytes': 0,
                    'duration_ms': 0.0,
                    'user_agent': str(row.get('_source.data.user_agent', '')).strip(),
                    'label': label,
                    'session_id': session_id
                })
            except Exception:
                pass
                
    return records

def to_utc_naive(ts):
    if ts is None:
        return None
    if isinstance(ts, datetime.datetime):
        if ts.tzinfo is not None:
            return ts.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        return ts
    return ts

def extract_30s_window_features(records, window_seconds=30):
    """
    HTTP 요청 레코드 리스트를 클라이언트 IP별, 30초 시간 창(Window) 단위로 묶어
    머신러닝 학습용 8대 행동 특징값(Feature)을 계산합니다.
    """
    if not records:
        return pd.DataFrame()
        
    df_raw = pd.DataFrame(records)
    df_raw['timestamp'] = df_raw['timestamp'].apply(to_utc_naive)
    df_raw = df_raw.dropna(subset=['timestamp']).sort_values('timestamp').reset_index(drop=True)
    
    # 127.0.0.1 아파치 내부 더미 연결 제외
    df_raw = df_raw[df_raw['client_ip'] != '127.0.0.1']
    if df_raw.empty:
        return pd.DataFrame()
        
    start_time = df_raw['timestamp'].min()
    end_time = df_raw['timestamp'].max()
    
    features_list = []
    
    for ip, ip_group in df_raw.groupby('client_ip'):
        session_label = ip_group['label'].iloc[0]
        session_id = ip_group['session_id'].iloc[0]
        
        curr_window_start = start_time
        window_idx = 0
        
        while curr_window_start <= end_time:
            curr_window_end = curr_window_start + datetime.timedelta(seconds=window_seconds)
            window_df = ip_group[(ip_group['timestamp'] >= curr_window_start) & (ip_group['timestamp'] < curr_window_end)]
            
            req_count = len(window_df)
            if req_count > 0:
                if req_count > 1:
                    timestamps = window_df['timestamp'].values
                    intervals = np.diff(timestamps).astype('float64') / 1e9
                    interval_mean = float(np.mean(intervals))
                    interval_std = float(np.std(intervals))
                else:
                    interval_mean = float(window_seconds)
                    interval_std = 0.0
                    
                error_404_count = len(window_df[window_df['status'] == 404])
                error_404_ratio = error_404_count / req_count
                
                error_abnormal_count = len(window_df[window_df['status'] >= 400])
                error_abnormal_ratio = error_abnormal_count / req_count
                
                unique_url_count = window_df['path'].nunique()
                unique_ua_count = window_df['user_agent'].nunique()
                
                post_count = len(window_df[window_df['method'] == 'POST'])
                ratio_post = post_count / req_count
                
                bytes_mean = float(window_df['response_bytes'].mean())
                
                features_list.append({
                    'session_id': session_id,
                    'window_idx': window_idx,
                    'client_ip': ip,
                    'window_start': curr_window_start.strftime('%Y-%m-%d %H:%M:%S'),
                    'req_count': req_count,
                    'interval_mean': round(interval_mean, 4),
                    'interval_std': round(interval_std, 4),
                    'error_404_ratio': round(error_404_ratio, 4),
                    'error_abnormal_ratio': round(error_abnormal_ratio, 4),
                    'unique_url_count': unique_url_count,
                    'unique_ua_count': unique_ua_count,
                    'ratio_post': round(ratio_post, 4),
                    'bytes_mean': round(bytes_mean, 2),
                    'label': session_label  # 0: 정상, 1: PentAGI
                })
                
            curr_window_start = curr_window_end
            window_idx += 1
            
    return pd.DataFrame(features_list)

def main():
    # 파일 위치 기준 동적 경로 설정 (team_one/ml)
    base_dir = pathlib.Path(__file__).resolve().parent.parent
    raw_dir = base_dir / "data" / "raw_logs"
    out_dir = base_dir / "data"
    
    print("=" * 60)
    print("[Wazuh 원본 로그 -> 30초 창 머신러닝 특징값 변환 시작]")
    print(f"기준 경로: {base_dir}")
    print("=" * 60)
    
    all_features = []
    csv_files = list(raw_dir.glob("*.csv"))
    if not csv_files:
        print("[ERROR] 처리할 CSV 파일이 raw_logs 폴더에 없습니다.")
        return
        
    for f in csv_files:
        fname = f.name.lower()
        if "attack" in fname or "pentagi" in fname:
            label = 1
            s_type = "공격(PentAGI)"
        else:
            label = 0
            s_type = "정상(Human)"
            
        session_id = f.stem
        print(f"[FILE] 처리 중: {f.name} -> 분류: {s_type} (Label={label})")
        
        records = parse_wazuh_csv(f, label=label, session_id=session_id)
        df_feat = extract_30s_window_features(records, window_seconds=30)
        
        if not df_feat.empty:
            print(f"   - 30초 시간 창 샘플 {len(df_feat)}개 추출 완료!")
            all_features.append(df_feat)
        else:
            print("   - 유효한 데이터가 없습니다.")
            
    if all_features:
        final_df = pd.concat(all_features, ignore_index=True)
        out_csv = out_dir / "features_dataset.csv"
        final_df.to_csv(out_csv, index=False, encoding='utf-8-sig')
        print("\n" + "=" * 60)
        print(f"[SUCCESS] 머신러닝 학습용 최종 데이터셋 저장 완료: {out_csv}")
        print(f"총 추출된 30초 창 샘플 수: {len(final_df)}개")
        print("클래스별 샘플 분포:")
        print(final_df['label'].value_counts().rename({0: '정상(0)', 1: '공격(1)'}))
        print("=" * 60)
        print("\n[PREVIEW] 추출된 데이터 미리보기:")
        display_cols = ['session_id', 'window_start', 'req_count', 'interval_std', 'error_404_ratio', 'unique_url_count', 'label']
        print(final_df[display_cols].to_string())

if __name__ == "__main__":
    main()
