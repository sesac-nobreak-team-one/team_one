# 서버 CPU 사용률 수집 (Wazuh)

대시보드 10번의 '서버 상태 · CPU 사용률' 패널에 값을 채우기 위한 설정입니다. Wazuh는 기본으로 CPU 사용률을 수집하지 않습니다. 그래서 설정 전에는 패널에 **'수집 설정 필요'**가 보입니다.

**이 폴더의 파일은 아직 어느 서버에도 적용하지 않았습니다.** 아래 순서대로 직접 적용하세요.

## 동작 방식

```
각 서버 Wazuh 에이전트 ──(60초마다 vmstat)──▶ "ossec: output: 'cpu_usage': 37"
        ▼
Wazuh 매니저: 디코더가 숫자를 data.cpu_usage 로 꺼냄 → 룰 100600(기록) / 100601(90% 이상 경보)
        ▼
Wazuh 인덱서 wazuh-archives-* (data.cpu_usage 를 숫자로 저장)
        ▼
Grafana: 서버(agent.name)별 평균 → 최근 값 + 추이선
```

- 서버마다 1분에 이벤트 1건이 늘어납니다. 서버 10대 기준으로 하루 약 14,400건입니다.
- 100600은 레벨 0이라 경보 목록(alerts)에는 쌓이지 않고 전체 로그(archives)에만 남습니다.
- 90% 이상이면 100601(레벨 8) 경보가 납니다. 같은 서버에서는 5분에 한 번만 울립니다.

## 파일

| 파일 | 어디에 | 내용 |
| :--- | :--- | :--- |
| `agent_ossec_localfile.xml` | 각 서버 에이전트 `/var/ossec/etc/ossec.conf` | 60초마다 CPU 사용률을 재는 명령 |
| `cpu_decoders.xml` | 매니저 `/var/ossec/etc/decoders/` | 출력에서 숫자를 `data.cpu_usage`로 꺼냄 |
| `cpu_rules.xml` | 매니저 `/var/ossec/etc/rules/` | 룰 100600(기록), 100601(90% 이상 경보). 그룹 `server_metrics` |
| `index_template_cpu.json` | 인덱서 API | 앞으로 만들어질 인덱스에서 `data.cpu_usage`를 숫자로 저장 |
| `index_mapping_today.json` | 인덱서 API | 오늘 인덱스에 같은 매핑을 미리 추가 |

## 적용 순서

**순서가 중요합니다.** 매핑(1단계)보다 수집(3단계)을 먼저 켜면 오늘 인덱스에 `data.cpu_usage`가 문자로 저장됩니다. 그러면 그날 인덱스에서는 평균을 낼 수 없습니다(아래 '문제 해결' 참고).

### 1. 인덱서: 숫자 매핑 (매니저 서버에서)

```bash
# 앞으로 만들어질 날짜별 인덱스용 템플릿
curl -k -u admin:<인덱서 비밀번호> -X PUT "https://localhost:9200/_template/wazuh-server-metrics" \
     -H 'Content-Type: application/json' -d @index_template_cpu.json

# 오늘 인덱스에도 미리 추가 (날짜는 오늘로 바꿈)
curl -k -u admin:<인덱서 비밀번호> -X PUT "https://localhost:9200/wazuh-archives-4.x-2026.11.03/_mapping" \
     -H 'Content-Type: application/json' -d @index_mapping_today.json
```

- Wazuh 기본 템플릿(`wazuh`, order 0)은 그대로 두고, order 1 템플릿을 하나 더 얹는 방식입니다. Wazuh를 업그레이드해도 지워지지 않습니다.
- 인덱스 이름이 `wazuh-archives-4.x-날짜`가 아니면 `GET _cat/indices/wazuh-archives*`로 확인해서 바꿉니다.

### 2. 매니저: 디코더 · 룰

```bash
cp cpu_decoders.xml /var/ossec/etc/decoders/
cp cpu_rules.xml    /var/ossec/etc/rules/
chown wazuh:wazuh /var/ossec/etc/decoders/cpu_decoders.xml /var/ossec/etc/rules/cpu_rules.xml

# 시험: 아래 줄을 붙여 넣으면 decoder 'ossec', cpu_usage: 37, rule 100600 이 나와야 함
/var/ossec/bin/wazuh-logtest
ossec: output: 'cpu_usage': 37
# 95 를 넣으면 rule 100601 (레벨 8)

systemctl restart wazuh-manager
```

### 3. 각 서버 에이전트: 수집 켜기

`agent_ossec_localfile.xml`의 `<localfile>` 블록을 `/var/ossec/etc/ossec.conf`의 `<ossec_config>` 안에 붙여 넣고 재시작합니다.

```bash
vmstat 1 2 | tail -1 | awk '{print 100-$15}'   # 먼저 숫자 하나가 나오는지 확인
systemctl restart wazuh-agent
```

- 여러 서버에 한 번에 넣으려면 매니저의 `/var/ossec/etc/shared/default/agent.conf`(중앙 설정)에 넣을 수도 있습니다. 이 경우 명령 실행을 허용하도록 각 에이전트의 `/var/ossec/etc/local_internal_options.conf`에 `logcollector.remote_commands=1`이 있어야 합니다.
- Linux 에이전트 기준입니다. Windows 서버는 명령을 `powershell -c "(Get-CimInstance Win32_Processor | Measure-Object LoadPercentage -Average).Average"`로 바꿉니다.

### 4. 확인

- 1~2분 뒤 Wazuh 대시보드의 Discover(archives)에서 `rule.id:100600`을 검색해 `data.cpu_usage`가 보이는지 봅니다.
- Grafana 대시보드 10번의 '서버 상태 · CPU 사용률'에 서버별 숫자와 추이선이 나오면 끝입니다. 서버 이름은 Wazuh 에이전트 이름(`agent.name`)입니다.

## 문제 해결

| 증상 | 원인과 해결 |
| :--- | :--- |
| 계속 '수집 설정 필요' | archives에 `rule.groups:server_metrics` 기록이 없습니다. 에이전트 재시작 여부, `wazuh-logtest` 결과, 에이전트 로그(`/var/ossec/logs/ossec.log`의 logcollector 오류)를 확인합니다. |
| 패널 오류 "Field [data.cpu_usage] of type [keyword] is not supported for aggregation [avg]" | 매핑 전에 수집을 켜서 그날 인덱스에 문자로 저장됐습니다. 다음 날 인덱스부터는 정상입니다. 바로 고치려면 Grafana 기간을 매핑 적용 이후로 잡거나, 그 인덱스를 다시 색인(reindex)합니다. |
| 값이 늘 0 또는 100 | 그 서버의 vmstat 열 순서가 다릅니다(예: 경량 컨테이너의 busybox). `vmstat 1 2`의 머리글에서 `id` 열 번호를 찾아 `$15`를 바꿉니다. |

## 다른 방법

Prometheus와 node_exporter를 이미 쓰고 있다면, 이 설정 대신 그 데이터 소스로 패널 쿼리를 바꾸는 편이 더 정밀합니다(초 단위, CPU 코어별). 쿼리 예: `100 - avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[1m])) * 100`. 이 프로젝트는 데이터를 Wazuh 하나로 모으고 있어서 Wazuh 방식을 기본으로 했습니다.
