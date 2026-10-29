# 웹서버 Apache 로그 형식 변경 내역 (웹 담당 팀 공유용)

- 작업일: 2026-10-29 (KST 10:58경 반영)
- 작업자: 원유찬 (ML 파트)
- 대상 서버: DMZ 웹서버 `~/sesac_shop_web_php`

## 바꾼 파일

**`deploy/apache-vhost.conf` 파일의 11번째 줄 하나만** 바꿨습니다. 이 파일은 컨테이너 안의 `/etc/apache2/sites-available/000-default.conf`로 마운트되어 있습니다.

PHP 소스, `compose.web.yml`, Docker 이미지, WAF 설정은 전혀 건드리지 않았습니다.

```diff
- LogFormat "%a %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\" %{UNIQUE_ID}e" shop_combined
+ LogFormat "%a %l %u [%{%d/%b/%Y:%H:%M:%S}t.%{msec_frac}t %{%z}t] \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\" %{UNIQUE_ID}e" shop_combined
```

`%t`(초 단위 시각)를 밀리초가 포함된 시각으로 바꾼 것뿐이고, 나머지 필드와 순서는 그대로입니다.

| | 예시 |
|---|---|
| 변경 전 | `192.168.0.151 - - [29/Oct/2026:10:51:41 +0900] "GET /products.php HTTP/1.1" 200 1365 ...` |
| 변경 후 | `172.30.0.1 - - [29/Oct/2026:10:58:35.232 +0900] "GET /index.php HTTP/1.1" 302 194 ...` |

## 왜 바꿨나

머신러닝 피처 중 요청 간격(`interval_mean`, `interval_std`)을 계산하려면 밀리초 단위 시각이 필요합니다. 초 단위로는 같은 초 안에 들어온 요청들의 간격이 모두 0으로 계산됩니다.

## 영향 범위

- **Wazuh**: `wazuh-logtest`로 확인한 결과 `web-accesslog` 디코더가 정상적으로 파싱합니다.
- **기존 기능**: 영향 없습니다. 실제 클라이언트 IP 기록(`%a`, mod_remoteip)과 UNIQUE_ID도 그대로 남습니다.
- **반영 방법**: `sudo docker compose -f compose.web.yml restart web`으로 web 컨테이너만 재시작했습니다.

## 원본 저장소 담당 팀에 요청

이 파일의 원본은 웹 담당 팀 저장소에 있습니다. 그쪽에서 다시 배포하면 이번 변경이 원래대로 돌아갑니다. **원본 `deploy/apache-vhost.conf`에도 위 한 줄을 반영해 주세요.**

## 되돌리는 방법

서버에 백업 파일을 남겨 두었습니다.

```bash
cd ~/sesac_shop_web_php
diff deploy/apache-vhost.conf.bak deploy/apache-vhost.conf     # 변경 내용 확인
cp deploy/apache-vhost.conf.bak deploy/apache-vhost.conf        # 원상복구
sudo docker compose -f compose.web.yml restart web
```
