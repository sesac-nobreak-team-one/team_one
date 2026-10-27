# Wazuh 보안관제 서버 구축 착수 보고서

> 담당: 팀원 4 (XDR 엔지니어 · 로그 수집 연동) · 작성일: 2026-10-27
> 범위: Wazuh 서버 설치부터 네트워크 확정, 로그 수집(Archives), 중앙 에이전트 설정, 방화벽 Syslog 수신 준비까지

---

## 1. 개요

| 항목 | 내용 |
|---|---|
| 목적 | WEB·DB·방화벽 로그를 한곳에 모아 BOLA(IDOR)·Shadow API·자동화 공격을 탐지하고, ML 학습용 전체 로그(Archives)를 확보 |
| 구성 방식 | Wazuh 4.14 단일 노드 올인원 (Server + Indexer + Dashboard) |
| 현재 상태 | 서버 구축·네트워크 확정·수집 설정 완료. WEB·DB 에이전트 연결 대기 |

## 2. 최종 구성

| 항목 | 값 |
|---|---|
| 가상화 | VMware Workstation (VirtualBox에서 이전) |
| OS | Ubuntu Server 22.04.5 LTS |
| 자원 | RAM 8 GB · vCPU 4 · Disk 50 GB (D 드라이브) |
| Wazuh 버전 | 4.14.9 |
| NIC | ens33 · Bridged (Realtek 물리 NIC 지정) |
| IP / GW / DNS | 192.168.10.30/24 · 192.168.10.1 · 8.8.8.8 |
| 위치 | LAN 구역 (FortiGate port2) |

### 네트워크 토폴로지 (팀 확정안)

| 구역 | 방화벽 포트 | 게이트웨이 | 서버 |
|---|---|---|---|
| WAN | port1 | 192.168.0.141 | (상위 192.168.0.1) |
| LAN | port2 | 192.168.10.1 | DB 192.168.10.20, **Wazuh 192.168.10.30** |
| DMZ | port3 | 192.168.20.1 | WEB 192.168.20.10 |

### 사용 포트

| 포트 | 프로토콜 | 용도 | 상태 |
|---|---|---|---|
| 443 | TCP | 대시보드 | LISTEN |
| 1514 | TCP | 에이전트 로그 수신 (wazuh-remoted) | LISTEN 0.0.0.0 |
| 1515 | TCP | 에이전트 등록 (wazuh-authd) | LISTEN 0.0.0.0 |
| 514 | UDP | 방화벽 Syslog 수신 | LISTEN 192.168.10.30 |

---

## 3. 구축 과정

### 3.1 연습 환경 구성 (10/22, VirtualBox)
1. Ubuntu Server 22.04.5 ISO로 VM 생성 (8 GB / 4 CPU / 50 GB)
2. 수동 설치 중 콘솔 키보드 입력 멈춤 → **무인 설치(Unattended)** 로 전환
3. 설치 중 C 드라이브 용량 부족(잔여 1 GB)으로 VM 중단 → VM 저장 위치를 **D 드라이브**로 변경 후 재설치

### 3.2 Wazuh 설치
```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```
- 하드웨어 요구사항 검사 통과 → Indexer → Manager → Filebeat → Dashboard 순 설치 (약 13분)
- 완료 시 출력된 admin 비밀번호 기록 (이후 변경, 3.10 참고)

![설치 직후 대시보드 첫 화면 (에이전트 0대, 서버 자체 이벤트만 수집)](images/01_dashboard_first_login.png)

### 3.3 에이전트 연동 연습 (api-test VM)
1. 연습용 Ubuntu VM(api-test) 생성, 두 VM을 호스트 전용 네트워크로 연결
2. DHCP 대역 불일치 문제로 고정 IP 사용 (Wazuh 192.168.8.10 / api-test 192.168.8.20)
3. 대시보드 **Deploy new agent** 로 설치 명령어 생성 → SSH로 api-test 접속해 설치
4. 대시보드에서 `api-test` **Active** 확인 (등록 직후 pending → 약 30초 후 active)

![연습 에이전트 api-test 연결 성공 (192.168.8.20, Ubuntu 22.04.5, v4.14.9)](images/02_agent_api_test_active.png)

**탐지 검증**: 존재하지 않는 계정으로 SSH 로그인 반복 실패

| rule.id | 설명 | level |
|---|---|---|
| 5710 | 존재하지 않는 사용자 로그인 시도 | 5 |
| 5503 | PAM 로그인 실패 | 5 |
| 2502 | 비밀번호 반복 실패 (상관분석) | 10 |

→ 공격 시각과 알림 시각이 동일 초 (MTTD 1초 미만)

### 3.4 VMware로 이전 (10/23)
팀 표준이 VMware Workstation이라 VM을 이전.
1. VirtualBox → **가상 시스템 내보내기** (OVF 1.0, `D:\export\wazuh-server.ova`, 약 10 GB)
2. VMware → **File → Open** 으로 OVA 가져오기 (규격 경고 → Retry)
3. NIC 이름 변경(`enp0s3` → `ens33`)으로 네트워크 미동작 → netplan 수정
4. 재부팅 시 설정이 되돌아가지 않도록 cloud-init 네트워크 설정 비활성화
```bash
echo 'network: {config: disabled}' | sudo tee /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg
```
5. VMware Virtual Network Editor에서 VMnet0 Bridged 대상을 **Automatic → Realtek PCIe GbE** 로 고정

![VMware로 가져온 wazuh-server (8 GB / 4 CPU / 50 GB, D 드라이브)](images/03_vmware_imported.png)

![VM 네트워크 어댑터 설정 (Bridged)](images/04_vmware_network_bridged.png)

이전 후에도 기존 알림 데이터(Medium 227, Low 299)가 그대로 유지됨을 확인. 연습용 api-test는 VirtualBox에 남아 Disconnected로 표시.

![VMware 이전 후 대시보드 (기존 데이터 유지)](images/05_dashboard_after_migration.png)

### 3.5 네트워크 확정 과정

| 순서 | IP | 비고 |
|---|---|---|
| 1 | 192.168.0.146 (DHCP) | 강의장망 브리지 연결 확인 |
| 2 | 192.168.0.146 고정 + 192.168.30.0/24 경로 | 초기 관제망 설계안 |
| 3 | 192.168.30.10 → 192.168.30.20 | 관제망 IP 조정 |
| 4 | **192.168.10.30** | 팀 토폴로지 확정 (LAN) |

최종 netplan (`/etc/netplan/50-cloud-init.yaml`)
```yaml
network:
  version: 2
  ethernets:
    ens33:
      dhcp4: no
      addresses: [192.168.10.30/24]
      routes:
        - to: default
          via: 192.168.10.1
      nameservers:
        addresses: [8.8.8.8]
```
게이트웨이 확인: `ping -c 3 192.168.10.1` → 0% packet loss

### 3.6 전체 로그(Archives) 수집 활성화
ML 학습에는 룰에 걸리지 않은 정상·로직 공격 로그도 필요하므로 전체 로그를 저장.
1. `/var/ossec/etc/ossec.conf` 의 `<global>`
```xml
<logall>yes</logall>
<logall_json>yes</logall_json>
```
2. `/etc/filebeat/filebeat.yml` 의 `archives: enabled: true`
3. `sudo systemctl restart wazuh-manager filebeat`
4. 대시보드 **Index patterns** 에 `wazuh-archives-*` 등록 (Time field: timestamp)
5. Discover에서 `wazuh-archives-*` 조회 확인

### 3.7 커널 설정
```bash
sudo sysctl -w vm.max_map_count=262144
echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf
```

### 3.8 중앙 에이전트 설정 (agent.conf)
Wazuh 서버에서 한 번 설정하면 연결된 모든 Linux 에이전트에 자동 배포.
파일: `/var/ossec/etc/shared/default/agent.conf`
```xml
<agent_config os="Linux">
  <localfile>
    <log_format>json</log_format>
    <location>/home/ubuntu/sesac_shop_web_php/logs/app.log</location>
  </localfile>
  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/apache2/access.log</location>
  </localfile>
  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/apache2/error.log</location>
  </localfile>
  <localfile>
    <log_format>json</log_format>
    <location>/var/lib/docker/containers/*/*-json.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>
  <syscheck>
    <disabled>no</disabled>
    <frequency>300</frequency>
    <directories realtime="yes" check_all="yes">/home/ubuntu/sesac_shop_web_php</directories>
    <directories realtime="yes" check_all="yes">/var/www/html</directories>
  </syscheck>
</agent_config>
```
- `os="Linux"` : Windows 에이전트(shop-php-dev)에 Linux 경로가 배포되지 않도록 제한
- 검증: `sudo /var/ossec/bin/verify-agent-conf`

### 3.9 방화벽 Syslog 수신 리스너 (UDP 514)
`/var/ossec/etc/ossec.conf` 끝에 블록 추가
```xml
<ossec_config>
  <remote>
    <connection>syslog</connection>
    <port>514</port>
    <protocol>udp</protocol>
    <allowed-ips>192.168.10.1</allowed-ips>
    <local_ip>192.168.10.30</local_ip>
  </remote>
</ossec_config>
```
확인: `sudo ss -ulnp | grep 514` → `192.168.10.30:514 wazuh-remoted`

### 3.10 admin 비밀번호 변경
LAN 구역에서 인터넷이 차단되어 공식 도구(wazuh-passwords-tool.sh)를 받을 수 없어 수동으로 변경.
1. `hash.sh -p '<새 비밀번호>'` 로 해시 생성
2. `/etc/wazuh-indexer/opensearch-security/internal_users.yml` 의 admin hash 교체 (백업 후 sed)
3. `indexer-security-init.sh` 실행 → `Done with success`
4. Filebeat도 admin 계정을 쓰므로 keystore 갱신
```bash
echo '<새 비밀번호>' | sudo filebeat keystore add password --stdin --force
sudo systemctl restart filebeat
sudo filebeat test output   # talk to server... OK
```

---

## 4. 수집 확인된 로그 (2번 팀원 API 서버)

에이전트 `shop-php-dev` (Windows) 연결 후 Archives에서 API 감사 로그 수신 확인.

![shop-php-dev 에이전트 상세 (Windows 11, active, SCA·취약점 자동 점검)](images/06_agent_shop_php_dev.png)

연결 직후 들어온 이벤트: 에이전트 시작/중지(503/506), CIS Windows 11 벤치마크 점검(19005~19009) 등 488건.

![shop-php-dev 수신 이벤트 목록](images/07_events_shop_php_dev.png)

| 필드 | 예시 |
|---|---|
| data.path | /api/v2/orders, /api/v2/login |
| data.method | POST |
| data.user_id | 1 (로그인 전 null) |
| data.status | 201, 200 |
| data.client_ip | 127.0.0.1 |
| data.user_agent | Chrome/156 |

개선 요청 사항
- `client_ip` 가 모두 127.0.0.1 → 실제 요청자 IP(X-Forwarded-For) 기록 필요
- BOLA 탐지용 `owner_id`(조회 대상 소유자), `owner_match`(true/false) 필드 추가 필요

---

## 5. 트러블슈팅 기록

| 증상 | 원인 | 해결 |
|---|---|---|
| 설치 화면 비밀번호 입력 중 키보드 멈춤 | VM 콘솔 입력 포커스 문제 | 무인 설치로 전환 |
| VM 설치 중 Guru Meditation 중단 | C 드라이브 잔여 1 GB | VM 위치를 D 드라이브로 이전 |
| `wazuh-install.sh: No such file` | `-sO` 옵션 오타로 파일 미저장 | 다운로드·실행 명령 분리 |
| 대시보드 API connection 오류 | 부팅 시 wazuh-manager 기동 timeout | `systemctl restart wazuh-manager` |
| 호스트에서 VM SSH 시간 초과 | 호스트 전용 DHCP 대역(56.x)과 어댑터 주소(8.1) 불일치 | 고정 IP로 전환 |
| 두 VM이 같은 IP 사용 | netplan 복사 시 IP 미수정 | api-test를 .20으로 변경 |
| SSH Connection refused | openssh-server 미설치 | `apt install openssh-server` |
| VMware 이전 후 네트워크 DOWN | NIC 이름 변경 (enp0s3 → ens33) | netplan 인터페이스명 수정 |
| `netplan apply` 오류 (line 2) | 주석 줄의 `#` 누락 | 주석 5줄 삭제 |
| 브리지 연결 후 IP 미할당 | Bridged Automatic이 가상 NIC 선택 | Realtek 물리 NIC 지정 |
| netplan 적용 실패 | `via:` 뒤 공백 누락 | `via: 192.168.10.1` |
| wazuh-manager 기동 실패 (1226) | syslog 블록의 `<ossec_config>` 누락, `</remote>` 오타 | XML 태그 수정 |
| 192.168.30.10:1514 True인데 로그 미수신 | 다른 호스트가 응답 | tcpdump로 목적지 IP 확인 |
| 공식 비밀번호 도구 다운로드 실패 | LAN 인터넷 차단 (DNS 해석 불가) | 해시 수동 교체 + filebeat keystore 갱신 |

---

## 6. 검증 결과

| 항목 | 결과 |
|---|---|
| 대시보드 로그인 | 성공 |
| 에이전트 연결 (api-test, shop-php-dev) | Active |
| SSH 무차별 대입 탐지 | rule 2502 (level 10) 발생 |
| Archives 수집 | `archives.json` 및 `wazuh-archives-*` 조회 성공 |
| Filebeat → Indexer | `talk to server... OK` |
| 1514 / 1515 / 514 리스닝 | 확인 |
| 게이트웨이 통신 | 192.168.10.1 ping 0% loss |

---

## 7. 남은 작업

| 작업 | 담당 | 비고 |
|---|---|---|
| WEB(192.168.20.10)·DB(192.168.10.20) VM 구축 | 확인 필요 | IP 중복 방지를 위해 담당 확정 후 진행 |
| WEB·DB 에이전트 설치 (4.14.9 고정) | 팀원 4 | 매니저 주소 192.168.10.30 |
| DB General Log 활성화 및 수집 | 팀원 4 | MariaDB |
| FortiGate Syslog 전송 설정 | 팀원 1 | 192.168.10.30:514/udp |
| 방화벽 정책: DMZ → LAN 1514·1515 | 팀원 1 | WEB 에이전트용 |
| 방화벽 정책: 192.168.0.147 → 192.168.10.30 1514·1515 | 팀원 1 | 2번 PC 에이전트용, NAT 해제 |
| LAN·DMZ 인터넷 허용 | 팀원 1 | 패키지 설치용 |
| API 로그용 탐지 룰 작성 | 팀원 4·5 | client_ip, owner_id 필드 확정 후 |

> 계정·비밀번호는 보안상 이 문서에 기록하지 않으며 팀 내부 채널로 별도 공유한다.
