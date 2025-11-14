# Keycloak 이벤트 관리 및 Syslog 전송 유틸리티

Keycloak REST API를 활용하여 사용자 이벤트와 관리자 이벤트를 수집하고, Syslog 서버로 전송하는 통합 관리 스크립트입니다.

---

## 주요 기능

### `kc_manager.sh` - 통합 Keycloak 관리 스크립트

#### 이벤트 관리
- **사용자 이벤트 다운로드** (증분 방식)
  - 로그인, 로그아웃, 인증 실패 등 사용자 활동 이벤트 수집
  - 중복 방지 메커니즘 (마지막 처리 시간 기반)
  - 페이지네이션 지원 (대용량 이벤트 처리)

- **관리자 이벤트 다운로드** (증분 방식)
  - 사용자 생성/수정/삭제 등 관리자 작업 이력 수집
  - 독립적인 상태 관리

#### Syslog 통합
- **Syslog 포맷 변환**
  - RFC3164 형식 준수
  - 사용자/관리자 이벤트별 필드 매핑
  
- **외부 Syslog 서버 전송**
  - SIEM 시스템 연동
  - 중앙 집중식 로그 관리
  - 보안 감사 및 규정 준수

#### 기타 기능
- 사용자 세션 정보 수집
- 사용자 그룹 정보 다운로드
- 인증 플로우 정보 조회
- Elasticsearch 데이터 업로드

---

## Keycloak 설정 절차

### 1. Client 생성 (Service Account용)
- 관리콘솔 > [해당 Realm] > Clients > Create
- Client ID: 예) `automation-service-account`
- Client type: `OpenID Connect`
- Access Type: `Confidential`
- Service Accounts Enabled: `ON`

### 2. Client Credentials 확인
- [생성한 Client] > Credentials > `Client Secret` 확인  
  → `server.conf`의 `CLIENT_ID`, `CLIENT_SECRET`에 사용

### 3. Service Account에 Admin 권한 부여
- [생성한 Client] > Service Account Roles  
- 다음 역할(Role) 할당:
  - `view-users` - 사용자 조회
  - `view-realm` - 렐름 정보 조회
  - `query-users` - 사용자 검색
  - `query-groups` - 그룹 조회
  - `view-events` - 이벤트 조회 (필수)
- 보안상 최소 권한만 부여 권장

### 4. API 엔드포인트 확인
- 관리 Keycloak 서버의 URL을 `KC_SERVER`에 입력  
  예: `https://auth.example.com`

---

## 설정 파일

### `server.conf` 설정 예시

```bash
# Keycloak 서버 설정
KC_SERVER='https://auth.example.com'
KC_REALM='hq'
CLIENT_ID='automation-service-account'
CLIENT_SECRET='your-client-secret-here'

# Elasticsearch 설정 (선택사항)
ES_URL="http://localhost:9200"
ES_INDEX="keycloak-events"

# Syslog 서버 설정 (이벤트 전송용)
SYSLOG_SERVER='192.168.35.178'
SYSLOG_PORT='6514'
SYSLOG_PROGRAM='GenianIAM'
```

---

## 사용 방법

### 도움말 보기
```bash
./kc_manager.sh help
```

**출력**:
```
Usage: ./kc_manager.sh [command] [options]

  collect_all [--include-excluded]            # 전체 프로세스 실행 (수집 + ES 업로드)
  upload_only [bulk_file]                     # 지정 bulk 파일을 ES로 업로드
  upload_sessions <sessions.json>             # 세션 JSON을 ES로 업로드
  download_groups [out.json] [--include-excluded]   # 사용자 그룹 정보 다운로드
  download_sessions [out.json] [--include-excluded] # 사용자 세션 정보 다운로드
  download_user_events [out.json]      # 사용자 이벤트 다운로드 (증분)
  download_admin_events [out.json]     # 관리자 이벤트 다운로드 (증분)
  show_events_state                    # 이벤트 상태 정보 표시
  send_user_events_syslog <file.json>  # 사용자 이벤트를 Syslog로 전송
  send_admin_events_syslog <file.json> # 관리자 이벤트를 Syslog로 전송
  send_syslog <sessions.json>          # 세션 정보를 Syslog로 전송
  download_auth_flow [flow]            # 인증 플로우(browser 등) 다운로드
  help                                 # 도움말 표시
```

---

## 사용 예시

### 1. 사용자 이벤트 다운로드

```bash
./kc_manager.sh download_user_events
```

**출력 예시**:
```
=== Keycloak 사용자 이벤트 다운로드 ===
서버: https://auth.example.com
렐름: hq
클라이언트 ID: automation-service-account
출력 파일: /path/to/events/user_events-2025.11.14_12.30.00.json

잠금 획득 중...
토큰 발급 중...
토큰 발급 성공!
첫 번째 실행: 모든 이벤트를 다운로드합니다.

사용자 이벤트 다운로드 중...
페이지 1: 50개 이벤트 수집 (누적: 50개)
페이지 2: 더 이상 이벤트가 없습니다.

총 50개의 이벤트를 다운로드했습니다.
JSON 파일로 저장 중: /path/to/events/user_events-2025.11.14_12.30.00.json
파일 크기: 15000 bytes

상태 파일 업데이트 중...
상태 파일 업데이트 성공
  - 마지막 이벤트 시간: 2025-11-14 12:30:00
  - 마지막 이벤트 ID: abc123...
  - 총 처리된 이벤트: 50

=== 다운로드 완료 ===
저장된 파일: /path/to/events/user_events-2025.11.14_12.30.00.json
다운로드된 이벤트: 50개
```

**특징**:
- 첫 실행 시 모든 이벤트 다운로드
- 이후 실행 시 마지막 처리 시간 이후의 이벤트만 다운로드 (증분 방식)
- 상태 파일 자동 관리 (`state/keycloak_user_events_hq.state`)

---

### 2. 관리자 이벤트 다운로드

```bash
./kc_manager.sh download_admin_events
```

사용자 이벤트와 동일한 방식으로 작동하며, 독립적인 상태 파일로 관리됩니다.

---

### 2-1. 사용자 필터링 옵션

기본적으로 퇴사자 및 시스템 계정은 제외되지만, `--include-excluded` 옵션을 사용하면 모든 사용자를 포함할 수 있습니다.

#### 사용자 그룹 다운로드 (제외 사용자 포함)
```bash
./kc_manager.sh download_groups output.json --include-excluded
```

#### 사용자 세션 다운로드 (제외 사용자 포함)
```bash
./kc_manager.sh download_sessions output.json --include-excluded
```

#### 전체 통계 수집 (제외 사용자 포함)
```bash
./kc_manager.sh collect_all --include-excluded
```

**제외 기준**:
- 퇴사자: `lastName` 필드에 "퇴사" 또는 "입사취소" 포함
- 시스템 계정: `server.conf`의 `EXCLUDED_USERNAMES` 배열에 정의된 사용자명

---

### 3. 이벤트 상태 확인

```bash
./kc_manager.sh show_events_state
```

**출력 예시**:
```
=== 사용자 이벤트 상태 정보 ===
상태 파일: /path/to/state/keycloak_user_events_hq.state

마지막 이벤트 시간: 2025-11-14 12:30:00 (Epoch: 1763089800000)
마지막 이벤트 ID: abc123...
마지막 처리 시각: 2025-11-14T03:30:00.000Z
총 처리된 이벤트: 50
========================

=== 관리자 이벤트 상태 정보 ===
상태 파일: /path/to/state/keycloak_admin_events_hq.state

마지막 이벤트 시간: 2025-11-14 12:30:00 (Epoch: 1763089800000)
마지막 이벤트 ID: def456...
마지막 처리 시각: 2025-11-14T03:30:00.000Z
총 처리된 이벤트: 30
========================
```

---

### 4. Syslog 전송

#### 사용자 이벤트 전송
```bash
./kc_manager.sh send_user_events_syslog events/user_events-2025.11.14_12.30.00.json
```

#### 관리자 이벤트 전송
```bash
./kc_manager.sh send_admin_events_syslog events/admin_events-2025.11.14_12.30.00.json
```

**출력 예시**:
```
=== Keycloak 이벤트 Syslog 전송 ===
이벤트 타입: user
입력 파일: events/user_events-2025.11.14_12.30.00.json

총 50개의 이벤트를 처리합니다.

Syslog 서버: 192.168.35.178:6514
프로그램 이름: GenianIAM

=== 전송 완료 ===
성공: 50개
실패: 0개
총: 50개
```

**Syslog 포맷**:
```
TIMESTAMP="2025-11-14 12:30:00" PROGRAM="GenianIAM" HOST="192.168.35.178" USERID="abc123..." LOGDATE="2025-11-14 11:30:00" SIP="192.168.1.100" AUTH_METHOD="LOGIN"
```

---

## 자동화 (Cron)

### Cron 설정 예시

```bash
# crontab -e

# 매 시간마다 사용자 이벤트 수집
0 * * * * cd /path/to/keycloak_utils && ./kc_manager.sh download_user_events >> /var/log/keycloak_events.log 2>&1

# 매 시간 5분에 관리자 이벤트 수집
5 * * * * cd /path/to/keycloak_utils && ./kc_manager.sh download_admin_events >> /var/log/keycloak_events.log 2>&1

# 매 시간 10분에 최신 이벤트 Syslog 전송
10 * * * * cd /path/to/keycloak_utils && LATEST=$(ls -t events/user_events-*.json | head -1) && ./kc_manager.sh send_user_events_syslog "$LATEST" >> /var/log/keycloak_events.log 2>&1
```

---

## 내부 동작

### 이벤트 다운로드 프로세스

1. **상태 파일 조회**
   - 마지막 처리 시간 확인 (`state/keycloak_user_events_hq.state`)
   - 첫 실행 시 "0" (모든 이벤트)

2. **토큰 발급**
   - Service Account를 사용한 Client Credentials 인증
   - Access Token 발급

3. **API 호출**
   - `/admin/realms/{realm}/events?dateFrom={last_time}&first={offset}&max=1000`
   - 페이지네이션 처리 (1000개씩, 최대 100페이지)

4. **JSON 저장**
   - `events/` 디렉토리에 타임스탬프 포함 파일명으로 저장
   - 예: `user_events-2025.11.14_12.30.00.json`

5. **상태 업데이트**
   - 마지막 이벤트 시간, ID, 총 처리 개수 저장
   - 백업 파일 생성 (손상 시 복구용)

### Syslog 전송 프로세스

1. **JSON 파일 읽기**
   - 파일 존재 및 유효성 검사
   - 이벤트 개수 확인

2. **이벤트별 변환**
   - 사용자 이벤트: `userId`, `ipAddress`, `type` 추출
   - 관리자 이벤트: `authDetails.userId`, `authDetails.ipAddress`, `operationType` 추출
   - Syslog 포맷으로 변환

3. **logger 명령어로 전송**
   - RFC3164 형식 사용
   - TCP 포트로 전송
   - 성공/실패 카운트

### 상태 관리

- **잠금 메커니즘**: 동시 실행 방지 (`.lock` 파일)
- **백업/복구**: 상태 파일 손상 시 자동 복구
- **증분 다운로드**: `dateFrom` 파라미터로 중복 방지

---

## 디렉토리 구조

```
keycloak_utils/
├── kc_manager.sh          # 메인 스크립트
├── server.conf            # 설정 파일
├── events/                # 다운로드된 이벤트 JSON 파일 (자동 생성)
│   ├── user_events-2025.11.14_12.30.00.json
│   └── admin_events-2025.11.14_12.30.00.json
├── state/                 # 상태 파일 (자동 생성)
│   ├── keycloak_user_events_hq.state
│   ├── keycloak_user_events_hq.state.backup
│   ├── keycloak_admin_events_hq.state
│   └── keycloak_admin_events_hq.state.backup
└── README.md              # 본 문서
```

---

## 사용 사례

### 1. 이벤트 모니터링 및 감사
- 사용자 로그인/로그아웃 이벤트 추적
- 관리자 작업 이력 감사 (사용자 생성/수정/삭제 등)
- 보안 이벤트 실시간 모니터링

### 2. Syslog 통합
- 외부 SIEM 시스템과 연동
- 중앙 집중식 로그 관리
- 보안 정책 준수 및 규정 대응

### 3. 자동화 및 스케줄링
- Cron을 통한 주기적 이벤트 수집
- 증분 다운로드로 효율적인 데이터 동기화
- 이벤트 데이터의 장기 보관 및 분석

### 4. 문제 해결 및 디버깅
- 인증 실패 원인 분석
- 사용자 활동 패턴 파악
- 시스템 이상 징후 탐지

---

## 주의 사항

### 필수 요구사항
- Keycloak API 권한이 충분한 Service Account 필요
- `jq` 명령어가 시스템에 설치되어 있어야 함
- `curl` 명령어가 시스템에 설치되어 있어야 함
- `logger` 명령어가 시스템에 설치되어 있어야 함 (Syslog 전송용)

### Syslog 관련
- `server.conf`에 `SYSLOG_SERVER`, `SYSLOG_PORT`, `SYSLOG_PROGRAM` 설정 필요
- Syslog 서버가 실행 중이고 네트워크 연결이 가능해야 함
- 방화벽에서 Syslog 포트(기본 6514) 허용 필요
- 대량 이벤트 전송 시 Syslog 서버의 처리 용량 고려 필요

### 이벤트 관리 관련
- 이벤트 다운로드는 증분 방식으로 동작하므로 상태 파일(`state/`) 보존 필요
- 상태 파일 손상 시 처음부터 모든 이벤트를 다시 다운로드함
- 동시 실행 방지를 위한 잠금 메커니즘이 있으므로 한 번에 하나의 프로세스만 실행
- 다운로드된 이벤트 파일(`events/`)은 Git에서 제외되므로 별도 백업 필요
- Keycloak 이벤트 보관 정책에 따라 오래된 이벤트는 조회되지 않을 수 있음

### 성능 관련
- 이벤트 수가 많을 경우 API 호출량 증가로 실행에 시간이 소요될 수 있음
- 페이지네이션은 최대 100페이지(100,000개 이벤트)까지 처리
- 더 많은 이벤트가 있는 경우 더 자주 실행하여 증분 다운로드 권장

### 보안 관련
- `server.conf` 파일의 클라이언트 시크릿 정보 보안 유지 필요
- Service Account는 최소 권한 원칙에 따라 필요한 권한만 부여
  - 이벤트 조회: `view-events` 권한 필수
  - 관리자 이벤트 조회: `view-events` 또는 `manage-events` 권한 필요
- 스크립트 실행 시 네트워크 연결 상태 확인 필요
- Syslog로 전송되는 이벤트에는 민감한 정보(사용자 ID, IP 주소 등)가 포함되므로 전송 경로 암호화 권장

---

## 트러블슈팅

### Syslog 전송 실패

**증상**: "경고: 이벤트 전송 실패" 메시지

**원인**:
- Syslog 서버 연결 불가
- 방화벽 차단
- 잘못된 포트 번호

**해결**:
```bash
# 1. 서버 연결 확인
nc -zv $SYSLOG_SERVER $SYSLOG_PORT

# 2. 방화벽 확인
sudo iptables -L -n | grep $SYSLOG_PORT

# 3. server.conf 설정 확인
cat server.conf | grep SYSLOG
```

### 필드 값이 "unknown"

**증상**: Syslog에 `USERID="unknown"` 등으로 표시

**원인**:
- JSON 필드가 null 또는 누락
- 잘못된 이벤트 타입 지정

**해결**:
```bash
# JSON 구조 확인
jq '.[0]' events/user_events-*.json

# 필드 존재 여부 확인
jq '.[0] | has("userId")' events/user_events-*.json
```

### 동시 실행 오류

**증상**: "오류: 다른 프로세스가 실행 중입니다."

**원인**: 이전 프로세스가 아직 실행 중이거나 비정상 종료로 잠금 파일이 남아있음

**해결**:
```bash
# 잠금 파일 확인
ls -la state/*.lock

# 실행 중인 프로세스 확인
ps aux | grep kc_manager

# 프로세스가 없다면 잠금 파일 수동 삭제
rm state/*.lock
```

---

## 참고 문서

- [Keycloak 공식 문서 - Admin REST API](https://www.keycloak.org/docs-api/latest/rest-api/index.html)
- [Keycloak 공식 문서 - 이벤트 관리](https://www.keycloak.org/docs/latest/server_admin/#auditing-and-events)
- [RFC3164 - The BSD syslog Protocol](https://www.ietf.org/rfc/rfc3164.txt)

---

## 라이선스

본 스크립트는 내부 사용을 목적으로 작성되었습니다.

---

## 버전 정보

- **버전**: 1.0.0
- **최종 업데이트**: 2025-11-14
- **작성자**: 기세호
