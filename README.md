# Keycloak 활성 사용자(세션) 집계 스크립트

본 스크립트는 Keycloak REST API를 활용하여 지정한 realm의 **현재 로그인(활성 세션 보유) 사용자 수**를 관리콘솔(Session 탭)과 동일하게 집계합니다.

---

## 주요 특징

- Keycloak 관리콘솔 > Sessions 화면의 숫자와 동일한 활성 사용자(로그인 세션 보유 user) 개수 출력
- Client별 세션 중복 없이 **User 기준**으로 집계
- REST API 기반, 자동화에 적합
- 진행 상황을 `.`으로 출력

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

1. `server.conf` 파일 생성 (예시)
    ```
    KC_SERVER='https://auth.example.com'
    KC_REALM='example-realm'
    TARGET_REALM='example-realm'
    CLIENT_ID='automation-service-account'
    CLIENT_SECRET='xxxxx...'
    ```

2. 실행 권한 부여 및 실행
    ```bash
    chmod +x session_cnt.sh
    ./session_cnt.sh
    ```

---

## 출력 예시

```bash
$ ./session_cnt.sh 
.....................................................
............................................................
ztna-sase realm 관리콘솔 기준 세션 총 개수: 25
$
```

---

## 내부 동작

1. `server.conf`에서 주요 설정 변수 로드
2. client credentials 방식으로 access token 발급
3. 대상 realm의 모든 user id 목록 조회
4. 각 user별 활성 session 유무 체크(`/admin/realms/{realm}/users/{userId}/sessions`)
5. 한 명의 user가 하나라도 세션이 있으면 1로 카운트
6. 모든 유저 반복 후 활성 사용자(로그인 세션 보유 user) 총합 출력

---

## 참고 문서

- [Keycloak 공식 문서 - 세션 보기](https://www.keycloak.org/docs/latest/server_admin/#viewing-sessions)
- [Keycloak REST API - Users Resource](https://www.keycloak.org/docs-api/21.1.1/rest-api/index.html#_users_resource)

---

## 사용 사례

1. 현재 Keycloak realm에 로그인한 사용자(실시간) 집계
2. 모니터링, 자동화 스크립트/대시보드 집계 활용
3. 인증 트래픽 분석, 서비스 규모 파악
4. 운영 중인 Keycloak 서비스의 활성 사용자 트렌드 모니터링
5. 대규모 사용자 환경의 실사용자 수 통계 산출

---

## 주의 사항

- 유저 수가 많을 경우(수천~수만 명) API 호출량 증가로 실행에 시간이 소요될 수 있음
- Keycloak API 권한이 충분한 Service Account 필요

---

