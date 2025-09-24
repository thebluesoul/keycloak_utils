# Keycloak 관리 유틸리티 스크립트 모음

본 폴더는 Keycloak REST API를 활용하여 다양한 사용자 관리 작업을 수행하는 스크립트들을 포함합니다.

---

## 포함된 스크립트

### 1. `session_cnt.sh` - 활성 사용자(세션) 집계
- Keycloak 관리콘솔 > Sessions 화면과 동일한 활성 사용자(로그인 세션 보유 user) 개수 출력
- Client별 세션 중복 없이 **User 기준**으로 집계
- 진행 상황을 `.`으로 출력

### 2. `get_user_info.sh` - 단일 사용자 정보 조회
- 특정 사용자 ID로 상세 프로필 정보 조회
- 사용자명, 이름, 이메일, 활성 상태, 소속 그룹 정보 출력
- 스크립트 내부에 기본 사용자 ID 설정 가능

### 3. `get_users_info.sh` - 다중 사용자 정보 조회
- 여러 사용자 ID를 한 번에 조회
- 각 사용자의 프로필 정보와 그룹 경로 정보 출력
- 명령행 인자로 사용자 ID 목록 전달

### 4. `passkey_federated_users.sh` - 패스키 등록 현황 분석
- 페더레이션 사용자 중 패스키를 등록한 사용자 수 집계
- 서비스 계정, 퇴사자 구분하여 통계 제공
- 패스키 등록률 백분율 계산
- 부서별 패스키 등록 현황을 `/tmp/groups.txt`에 저장
  ```
  [][ubuntu:172x29x70x97]:keycloak_utils$ cat /tmp/groups.txt
  022bb67e-f1f2-4c4d-a723-615a94deee9a /A회사/연구부문/운영팀
  그룹_002 /A회사/사업부문/기술팀
  ```

### 5. `export-keycloak-user-stats-to-es.sh` - Elasticsearch 사용자 통계 수집
- Keycloak 사용자 데이터를 Elasticsearch로 수집하는 스크립트
- 우선순위 기반 @timestamp 생성 (Passkey → OTP → 계정생성)
- 사용자 그룹 정보 수집 및 JSON 파싱 오류 수정
- --upload-only 옵션으로 기존 벌크 데이터 파일 업로드 지원 (파일 경로 지정 가능)
- 벌크 API를 통한 효율적인 Elasticsearch 데이터 전송

### 6. `server.conf` - 공통 설정 파일
- 모든 스크립트에서 공통으로 사용하는 Keycloak 서버 설정
- 서버 URL, Realm, 클라이언트 인증 정보 포함

---

## Keycloak 설정 절차

1. **Client 생성 (Service Account용)**
    - 관리콘솔 > [해당 Realm] > Clients > Create
    - Client ID: 예) `automation-service-account`
    - Client type: `OpenID Connect`
    - Access Type: `Confidential`
    - Service Accounts Enabled: `ON`

2. **Client Credentials 확인**
    - [생성한 Client] > Credentials > `Client Secret` 확인  
      → `server.conf`의 `CLIENT_ID`, `CLIENT_SECRET`에 사용

3. **Service Account에 Admin 권한 부여**
    - [생성한 Client] > Service Account Roles  
    - 다음 역할(Role) 할당:
        - `view-users`
        - `view-realm`
        - `query-users`
        - `query-groups`
        - (`view-events` ← 이벤트 조회 시)
    - 보안상 최소 권한만 부여 권장

4. **API 엔드포인트(서버 주소) 확인**
    - 관리 Keycloak 서버의 URL을 `KC_SERVER`에 입력  
      예: `https://auth.example.com`

---

## 사용 방법

### 공통 설정
1. `server.conf` 파일 설정 (예시)
    ```
    KC_SERVER='https://auth.example.com'
    KC_REALM='example-realm'
    TARGET_REALM='example-realm'
    CLIENT_ID='automation-service-account'
    CLIENT_SECRET='xxxxx...'
    ```

2. 모든 스크립트에 실행 권한 부여
    ```bash
    chmod +x *.sh
    ```

### 개별 스크립트 사용법

#### session_cnt.sh - 활성 세션 사용자 수 집계
```bash
./session_cnt.sh
```

#### get_user_info.sh - 단일 사용자 정보 조회
```bash
# 스크립트 내부 기본 ID 사용
./get_user_info.sh

# 특정 사용자 ID 지정
./get_user_info.sh 00000000-0000-0000-0000-000000000000
```

#### get_users_info.sh - 다중 사용자 정보 조회
```bash
./get_users_info.sh USER_ID_1 USER_ID_2 USER_ID_3
```

#### passkey_federated_users.sh - 패스키 등록 현황 분석
```bash
./passkey_federated_users.sh
```

#### export-keycloak-user-stats-to-es.sh - Elasticsearch 사용자 통계 수집
```bash
# 기본 실행 (데이터 수집 후 Elasticsearch에 업로드)
./export-keycloak-user-stats-to-es.sh

# 기존 벌크 데이터 파일만 업로드 (기본 파일: es_bulk_data.json)
./export-keycloak-user-stats-to-es.sh --upload-only
# 또는 단축 옵션
./export-keycloak-user-stats-to-es.sh -up

# 특정 벌크 데이터 파일 업로드
./export-keycloak-user-stats-to-es.sh --upload-only /path/to/custom_bulk_data.json
# 또는 단축 옵션
./export-keycloak-user-stats-to-es.sh -up /path/to/custom_bulk_data.json
```

---

## 출력 예시

### session_cnt.sh
```bash
$ ./session_cnt.sh 
.....................................................
............................................................
example-realm realm 관리콘솔 기준 세션 총 개수: 25
$
```

### get_user_info.sh
```bash
$ ./get_user_info.sh
1. 서비스 계정을 사용하여 Keycloak Admin API 토큰을 발급받습니다.
토큰 발급 성공!

2. 사용자 프로필 정보를 조회합니다 (ID: 00000000-0000-0000-0000-000000000000)

--- 사용자 프로필 정보 ---
ID        : 00000000-0000-0000-0000-000000000000
Username  : john.doe
이름      : DoeJohn
이메일    : john.doe@example.com
활성 상태 : true
--------------------------

3. 사용자 그룹 정보를 조회합니다.

--- 소속 그룹 정보 ---
Name: employees
Path: /employees
---
Name: developers
Path: /employees/developers
---
----------------------
```

### get_users_info.sh
```bash
$ ./get_users_info.sh USER_ID_1 USER_ID_2
1. 서비스 계정을 사용하여 Keycloak Admin API 토큰을 발급받습니다.
토큰 발급 성공!

--- 사용자 프로필 정보 ---
ID        : USER_ID_1
Username  : user1
이름      : UserOne
이메일    : user1@example.com
활성 상태 : true
--------------------------
Path: /employees

--- 사용자 프로필 정보 ---
ID        : USER_ID_2
Username  : user2
이름      : UserTwo
이메일    : user2@example.com
활성 상태 : true
--------------------------
Path: /employees/managers

모든 사용자 정보 조회를 완료했습니다.
```

### passkey_federated_users.sh
```bash
$ ./passkey_federated_users.sh
1. 서비스 계정을 사용하여 Keycloak Admin API 토큰을 발급받습니다.
토큰 발급 성공!

2. Realm의 모든 사용자 ID를 조회합니다.

3. 각 사용자를 순회하며 페더레이션 사용자 여부 및 패스키 등록 여부를 확인합니다...
진행 상황: 236번째 사용자 확인 중... (패스키: 45, 서비스 계정: 12, 퇴사자: 8)

--- 최종 결과 ---
확인한 총 사용자 수: 236
패스키를 등록한 페더레이션 사용자 수: 45, 19.1%
서비스 제공을 위한 계정 수: 12
이름에 '(퇴사)'가 포함된 페더레이션 사용자 수: 8
----------------
```

### export-keycloak-user-stats-to-es.sh
```bash
$ ./export-keycloak-user-stats-to-es.sh
1. 서비스 계정을 사용하여 Keycloak Admin API 토큰을 발급받습니다.
토큰 발급 성공!

2. Realm의 모든 사용자 정보를 조회합니다.
총 사용자 수: 150

3. 각 사용자의 자격증명 및 그룹 정보를 수집합니다...
진행 상황: 150번째 사용자 처리 중...

4. Elasticsearch 벌크 API를 통해 데이터를 전송합니다...
Elasticsearch 업로드 성공: 150개 문서

--- 최종 결과 ---
처리된 사용자 수: 150
Elasticsearch 저장 성공: 150개 문서
벌크 데이터 파일: es_bulk_data.json
----------------
```

---

## 내부 동작

### 공통 동작
1. `server.conf`에서 주요 설정 변수 로드
2. client credentials 방식으로 access token 발급
3. Keycloak Admin API를 통한 데이터 조회 및 처리

### 개별 스크립트 동작

#### session_cnt.sh
1. 대상 realm의 모든 user id 목록 조회
2. 각 user별 활성 session 유무 체크(`/admin/realms/{realm}/users/{userId}/sessions`)
3. 한 명의 user가 하나라도 세션이 있으면 1로 카운트
4. 모든 유저 반복 후 활성 사용자(로그인 세션 보유 user) 총합 출력

#### get_user_info.sh / get_users_info.sh
1. 지정된 사용자 ID로 상세 정보 조회(`/admin/realms/{realm}/users/{userId}`)
2. 사용자 그룹 정보 조회(`/admin/realms/{realm}/users/{userId}/groups`)
3. JSON 파싱하여 사용자 정보 출력

#### passkey_federated_users.sh
1. realm의 모든 사용자 목록 조회
2. 각 사용자의 `federationLink` 필드 확인하여 페더레이션 사용자 식별
3. 페더레이션 사용자의 크리덴셜 정보 조회(`/admin/realms/{realm}/users/{userId}/credentials`)
4. `webauthn` 타입 크리덴셜 존재 여부로 패스키 등록 확인
5. 통계 집계 및 부서별 정보 저장

#### export-keycloak-user-stats-to-es.sh
1. realm의 모든 사용자 목록 조회
2. 각 사용자의 상세 정보, 자격증명, 그룹 정보를 순차적으로 수집
3. 우선순위 기반 @timestamp 생성 (Passkey → OTP → 계정생성)
4. JSON 데이터 검증 및 오류 처리
5. Elasticsearch 벌크 API를 통한 일괄 데이터 전송
6. 성공/실패 통계 및 벌크 데이터 파일 생성

---

## 참고 문서

- [Keycloak 공식 문서 - 세션 보기](https://www.keycloak.org/docs/latest/server_admin/#viewing-sessions)
- [Keycloak REST API - Users Resource](https://www.keycloak.org/docs-api/21.1.1/rest-api/index.html#_users_resource)

---

## 사용 사례

### session_cnt.sh
1. 현재 Keycloak realm에 로그인한 사용자(실시간) 집계
2. 모니터링, 자동화 스크립트/대시보드 집계 활용
3. 인증 트래픽 분석, 서비스 규모 파악
4. 운영 중인 Keycloak 서비스의 활성 사용자 트렌드 모니터링

### get_user_info.sh / get_users_info.sh
1. 특정 사용자의 상세 정보 확인
2. 사용자 그룹 소속 현황 파악
3. 사용자 계정 상태 검증
4. 대량 사용자 정보 일괄 조회

### passkey_federated_users.sh
1. 패스키 등록 현황 모니터링
2. 보안 정책 준수율 측정
3. 부서별 패스키 도입 현황 분석
4. 페더레이션 사용자 관리 현황 파악
5. 서비스 계정 및 퇴사자 계정 정리

### export-keycloak-user-stats-to-es.sh
1. Keycloak 사용자 데이터의 Elasticsearch 수집
2. Kibana 대시보드를 위한 시계열 데이터 준비
3. 사용자 인증 패턴 및 트렌드 분석
4. 패스키 도입 현황의 시각화 및 모니터링
5. 대용량 사용자 데이터의 체계적 저장 및 관리

---

## 주의 사항

### 공통 주의사항
- Keycloak API 권한이 충분한 Service Account 필요
- `jq` 명령어가 시스템에 설치되어 있어야 함
- `curl` 명령어가 시스템에 설치되어 있어야 함
- `bc` 명령어가 시스템에 설치되어 있어야 함 (export-keycloak-user-stats-to-es.sh용)

### 성능 관련
- 유저 수가 많을 경우(수천~수만 명) API 호출량 증가로 실행에 시간이 소요될 수 있음
- `passkey_federated_users.sh`는 모든 사용자를 순회하므로 대용량 환경에서 시간이 오래 걸릴 수 있음
- `get_users_info.sh`는 사용자 수에 비례하여 API 호출이 증가함
- `export-keycloak-user-stats-to-es.sh`는 Elasticsearch 벌크 API를 사용하므로 네트워크 대역폭 고려 필요

### Elasticsearch 관련
- `server.conf`에 `ES_URL`과 `ES_INDEX` 설정이 필요함
- Elasticsearch 서버가 실행 중이어야 함
- 벌크 데이터 파일(`es_bulk_data.json`)은 Git에서 제외됨
- 대용량 데이터 처리 시 Elasticsearch 클러스터의 메모리 및 디스크 공간 확인 필요

### 보안 관련
- `server.conf` 파일의 클라이언트 시크릿 정보 보안 유지 필요
- Service Account는 최소 권한 원칙에 따라 필요한 권한만 부여
- 스크립트 실행 시 네트워크 연결 상태 확인 필요

---

