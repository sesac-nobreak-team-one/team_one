# 🤝 프로젝트 협업 가이드
---

## 1. 기본 작업 흐름

```bash
# 1. 최신 main 동기화
git checkout main
git pull origin main

# 2. 작업 브랜치 생성 (작업 성격에 맞는 접두사 사용)
git checkout -b <분류>/<작업요약>
# 예: infra/wazuh-agent-rule
# 예: detection/shadow-api-scanner
# 예: docs/troubleshoot-closed-network
```

---

## 2. 작업 분류 및 커밋 규칙

복잡한 개발 규칙 대신, 아래 4가지 분류를 주로 사용합니다.

| 분류 | 대상 | 커밋 메시지 예시 |
| :--- | :--- | :--- |
| `infra` | 네트워크, 방화벽, Docker, Wazuh, Shuffle 설정 변경 | `infra: Wazuh 에이전트 Apache 에러로그 수집 경로 추가` |
| `detection` | API 스캐닝, SBOM 생성, Wazuh 탐지 룰, Grafana 대시보드 | `detection: API 스캐닝 기반 Wazuh 커스텀 룰 및 SBOM 생성기 추가` |
| `exp` | 공격 시나리오 실행, 탐지 및 차단 실험 결과 갱신 | `exp: IDOR 공격 세션 로그 수집 및 탐지 결과 기록` |
| `docs` | 트러블슈팅 리포트, 환경 구성 가이드, 아키텍처 문서화 | `docs: 03_방화벽 VIP 포트포워딩 설정 장애 해결 리포트 작성` |

---

## 3. 환경 구축 및 실험 시 지켜야 할 원칙

### ① 설정 변경 시 (IaC & Config)
- 가상머신 내부에서 직접 수정한 설정(`ossec.conf`, `docker-compose.yml`, 방화벽 룰 등)은 반드시 해당 레포지토리의 `infra/` 또는 `detection/` 경로 파일에도 반영합니다.
- 변경 이유와 변경된 값(IP, 포트, 권한 등)을 PR 설명에 간략히 적어 다른 팀원도 재현할 수 있게 합니다.

### ② 장애 및 에러 해결 시 (Troubleshooting)
- 환경 구축 중 발생한 오류를 해결했다면 `docs/troubleshooting/0X_내용.md`로 정리하여 기록합니다.

### ③ 절대 커밋하면 안 되는 파일 (.gitignore 확인)
- **가상머신 전체 파일**: `.vmdk`, `.vmx`, `.iso`, 스냅샷 파일
- **보안 민감 정보**: 실제 외부 IP, 방화벽 관리자 패스워드, API 비밀키 (문서에는 `192.168.x.x`, `****` 등으로 마스킹)

---

## 4. 리뷰 및 머지(Merge)
- PR이 등록되면 팀 관리자(팀장/소유자)가 내용을 확인하고 **Files changed 탭 ➜ Review changes ➜ Approve** 후 머지합니다.
