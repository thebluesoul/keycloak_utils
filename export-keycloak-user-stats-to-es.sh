#!/bin/bash

# 디버그 모드 활성화
[ "x$DEBUG" = "x1" ] && set -x

# 사용법 출력 함수
usage() {
    echo "사용법: $0 [옵션] [파일경로]"
    echo ""
    echo "옵션:"
    echo "  --upload-only, -up    지정된 JSON 파일을 Elasticsearch에 업로드만 수행"
    echo "  --help               이 도움말을 표시"
    echo ""
    echo "예시:"
    echo "  $0                                    # 전체 프로세스 실행 (사용자 데이터 수집 + Elasticsearch 업로드)"
    echo "  $0 --upload-only /tmp/es_bulk_data.json  # 지정된 bulk 파일만 Elasticsearch에 업로드"
    echo "  $0 -up /tmp/es_bulk_data.json           # 짧은 형태로 지정된 bulk 파일 업로드"
    echo "  $0 --upload-only                      # 기본 bulk 파일(/tmp/es_bulk_data.json) 업로드"
    echo "  $0 -up                                # 짧은 형태로 기본 bulk 파일 업로드"
}

# 명령행 인수 처리
UPLOAD_ONLY=false
UPLOAD_FILE=""

# 인수 파싱
while [[ $# -gt 0 ]]; do
    case $1 in
        --upload-only|-up)
            UPLOAD_ONLY=true
            shift
            ;;
        --help)
            usage
            exit 0
            ;;
        -*)
            echo "알 수 없는 옵션: $1"
            usage
            exit 1
            ;;
        *)
            # 파일 경로로 인식
            if [ "$UPLOAD_ONLY" = true ] && [ -z "$UPLOAD_FILE" ]; then
                UPLOAD_FILE="$1"
            else
                echo "오류: 예상치 못한 인수: $1"
                usage
                exit 1
            fi
            shift
            ;;
    esac
done

# --- 1. 설정 파일 로드 ---
CONF_PATH="./server.conf"
if [ ! -f "$CONF_PATH" ]; then
  echo "오류: 설정 파일이 존재하지 않습니다: $CONF_PATH"
  exit 1
fi
# server.conf 파일의 변수들을 현재 쉘 환경으로 가져옵니다.
. "$CONF_PATH"

# --- 2. 설정 변수 할당 및 확인 ---
KEYCLOAK_URL=${KC_SERVER}
REALM=${KC_REALM}
SERVICE_ACCOUNT_CLIENT_ID=${CLIENT_ID}
SERVICE_ACCOUNT_CLIENT_SECRET=${CLIENT_SECRET}
ELASTICSEARCH_URL=${ES_URL}
# server.conf 파일의 ES_INDEX 값을 사용하고, 만약 값이 없으면 날짜 기반의 기본값을 사용합니다.
ES_INDEX_NAME=${ES_INDEX:-"keycloak-passkey-stats-$(date +%Y.%m.%d)"}
ES_BULK_FILE="/tmp/es_bulk_data.json"

# Elasticsearch URL 설정 확인
if [ -z "$ELASTICSEARCH_URL" ]; then
    echo "오류: Elasticsearch URL이 설정되지 않았습니다. server.conf 파일에 ES_URL을 추가하세요."
    exit 1
fi

# --upload-only 옵션 처리
if [ "$UPLOAD_ONLY" = true ]; then
    # 업로드할 파일 경로 결정
    if [ -n "$UPLOAD_FILE" ]; then
        BULK_FILE="$UPLOAD_FILE"
        echo "업로드 전용 모드: 지정된 파일을 Elasticsearch에 업로드합니다."
        echo "파일 경로: $BULK_FILE"
    else
        BULK_FILE="$ES_BULK_FILE"
        echo "업로드 전용 모드: 기본 bulk 파일을 Elasticsearch에 업로드합니다."
        echo "파일 경로: $BULK_FILE"
    fi
    
    # bulk 파일 존재 확인
    if [ ! -f "$BULK_FILE" ]; then
        echo "오류: bulk 파일이 존재하지 않습니다: $BULK_FILE"
        echo "파일 경로를 확인하거나, 먼저 전체 프로세스를 실행하여 bulk 파일을 생성하세요."
        exit 1
    fi
    
    # bulk 파일 크기 확인
    FILE_SIZE=$(stat -c%s "$BULK_FILE" 2>/dev/null || echo "0")
    if [ "$FILE_SIZE" -eq 0 ]; then
        echo "오류: bulk 파일이 비어있습니다: $BULK_FILE"
        exit 1
    fi
    
    echo "bulk 파일 크기: $FILE_SIZE bytes"
    echo "Elasticsearch로 데이터를 전송합니다..."
    
    # Elasticsearch bulk API로 데이터 전송
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${ELASTICSEARCH_URL}/_bulk" -H "Content-Type: application/x-ndjson" --data-binary "@${BULK_FILE}")
    
    if [ "$HTTP_CODE" -ge 200 ] && [ "$HTTP_CODE" -lt 300 ]; then
        echo "성공: Elasticsearch로 데이터 전송을 완료했습니다. (HTTP Code: $HTTP_CODE)"
        echo "업로드된 문서 수를 확인하려면 다음 명령을 실행하세요:"
        echo "curl -s \"${ELASTICSEARCH_URL}/_cat/indices/${ES_INDEX_NAME}?v\""
    else
        echo "오류: Elasticsearch로 데이터 전송 중 에러가 발생했습니다. (HTTP Code: $HTTP_CODE)"
        echo "오류 응답을 확인하려면 아래 명령어를 직접 실행해보세요."
        echo "curl -X POST \"${ELASTICSEARCH_URL}/_bulk\" -H \"Content-Type: application/x-ndjson\" --data-binary \"@${BULK_FILE}\" | jq"
    fi
    
    exit 0
fi

> "$ES_BULK_FILE" # 임시 파일 초기화

echo "1. 서비스 계정 토큰 발급 중..."
ACCESS_TOKEN=$(curl -s -X POST "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" -d "client_id=${SERVICE_ACCOUNT_CLIENT_ID}" -d "client_secret=${SERVICE_ACCOUNT_CLIENT_SECRET}" | jq -r .access_token)

if [ -z "$ACCESS_TOKEN" ] || [ "$ACCESS_TOKEN" == "null" ]; then
    echo "오류: 서비스 계정 토큰 발급 실패."
    exit 1
fi
echo "토큰 발급 성공!"

echo "2. Realm의 모든 사용자 상세 정보 조회 중..."
# briefRepresentation=false 옵션으로 모든 사용자 정보를 한 번에 가져옵니다.
USERS_INFO=$(curl -s -X GET "${KEYCLOAK_URL}/admin/realms/${REALM}/users?max=1000&briefRepresentation=false" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}")

USER_COUNT=$(echo "$USERS_INFO" | jq '. | length')
if [ "$USER_COUNT" -eq 0 ]; then
    echo "사용자를 찾을 수 없습니다."
    exit 0
fi
echo "총 ${USER_COUNT}명의 사용자 데이터를 처리합니다..."

# 사용자 수만큼 반복하여 각 사용자를 개별적으로 처리합니다.
for i in $(seq 0 $((USER_COUNT - 1))); do
    # jq를 사용하여 i번째 사용자 정보를 가져옵니다.
    USER_INFO=$(echo "$USERS_INFO" | jq -c ".[$i]")
    USER_ID=$(echo "$USER_INFO" | jq -r '.id')

    # ES 문서 생성을 위한 변수 초기화
    IS_FEDERATED=false
    HAS_PASSKEY=false
    USER_CATEGORY="Internal"
    CREDENTIALS="[]" # 원본 저장을 위해 초기화
    USER_GROUPS="[]" # 기본값으로 초기화 (페더레이션 사용자가 아닌 경우)

    if echo "$USER_INFO" | jq -e '.federationLink' > /dev/null; then
        IS_FEDERATED=true
        LAST_NAME=$(echo "$USER_INFO" | jq -r '.lastName // ""')
        EMAIL=$(echo "$USER_INFO" | jq -r '.email // ""')

        if [[ "$LAST_NAME" == *"(퇴사)"* ]]; then
            USER_CATEGORY="Resigned"
        elif [[ -z "$EMAIL" || "$EMAIL" == "null" || "$EMAIL" == "" ]]; then
            USER_CATEGORY="Service Account"
        else
            # 페더레이션 사용자인 경우, 크리덴셜 정보 조회 (별도 API 호출 필요)
            CREDENTIALS_RAW=$(curl -s -X GET "${KEYCLOAK_URL}/admin/realms/${REALM}/users/${USER_ID}/credentials" -H "Authorization: Bearer ${ACCESS_TOKEN}")
            # [수정] API 응답이 비정상적일 때도 안전하게 빈 배열 '[]'을 생성합니다.
            CREDENTIALS=$(echo "$CREDENTIALS_RAW" | jq -c '. // []')

            if echo "$CREDENTIALS_RAW" | jq -e '.[] | select(.type | contains("webauthn"))' > /dev/null; then
                HAS_PASSKEY=true
                USER_CATEGORY="Passkey User"
            else
                USER_CATEGORY="Federated (No Passkey)"
            fi

            USER_GROUPS_RAW=$(curl -s -X GET "${KEYCLOAK_URL}/admin/realms/${REALM}/users/${USER_ID}/groups" -H "Authorization: Bearer ${ACCESS_TOKEN}")
            # [수정] jq의 -c 옵션과 // [] 구문을 사용하여 항상 안전한 JSON 배열을 생성합니다.
            USER_GROUPS=$(echo "$USER_GROUPS_RAW" | jq -c '[.[] | .path] // []')
        fi
    fi
    
    # Elasticsearch Bulk API 형식으로 데이터 생성
    echo "{\"index\": {\"_index\": \"$ES_INDEX_NAME\", \"_id\": \"$USER_ID\"}}" >> "$ES_BULK_FILE"
    
    # JSON 유효성 검사
    if ! echo "$USER_INFO" | jq . > /dev/null 2>&1; then
        echo "USER_INFO가 유효한 JSON이 아닙니다 (사용자 $i, ID: $USER_ID)"
        echo "USER_INFO 내용: $USER_INFO"
        continue
    fi
    
    if ! echo "$CREDENTIALS" | jq . > /dev/null 2>&1; then
        echo "CREDENTIALS가 유효한 JSON이 아닙니다 (사용자 $i, ID: $USER_ID)"
        echo "CREDENTIALS 내용: $CREDENTIALS"
        continue
    fi
    
    if ! echo "$USER_GROUPS" | jq . > /dev/null 2>&1; then
        echo "USER_GROUPS가 유효한 JSON이 아닙니다 (사용자 $i, ID: $USER_ID)"
        echo "USER_GROUPS 내용: $USER_GROUPS"
        continue
    fi

    # @timestamp 생성 로직 (우선순위 기반)
    # 1순위: 첫 번째 Passkey(webauthn) 생성 시간
    # 2순위: Passkey가 없을 경우, 첫 번째 OTP 생성 시간  
    # 3순위: 둘 다 없을 경우, 사용자 계정 생성 시간
    EVENT_TIMESTAMP_MS=$(echo "$USER_INFO" | jq -r '.createdTimestamp')
    
    # 1순위: Passkey(webauthn) 생성 시간 확인
    PASSKEY_TIMESTAMP=$(echo "$CREDENTIALS" | jq -r '.[] | select(.type == "webauthn-passwordless") | .createdDate' | head -1)
    if [ -n "$PASSKEY_TIMESTAMP" ] && [ "$PASSKEY_TIMESTAMP" != "null" ]; then
        EVENT_TIMESTAMP_MS="$PASSKEY_TIMESTAMP"
    else
        # 2순위: OTP 생성 시간 확인
        OTP_TIMESTAMP=$(echo "$CREDENTIALS" | jq -r '.[] | select(.type == "otp") | .createdDate' | head -1)
        if [ -n "$OTP_TIMESTAMP" ] && [ "$OTP_TIMESTAMP" != "null" ]; then
            EVENT_TIMESTAMP_MS="$OTP_TIMESTAMP"
        fi
        # 3순위: 사용자 계정 생성 시간 (이미 EVENT_TIMESTAMP_MS에 설정됨)
    fi
    
    # 밀리초를 ISO 8601 형식으로 변환
    EVENT_TIMESTAMP_ISO=$(echo "scale=3; $EVENT_TIMESTAMP_MS / 1000" | bc | xargs -I {} date -u -d "@{}" +%Y-%m-%dT%H:%M:%S.%3NZ)

    jq -n -c \
      --arg timestamp "$EVENT_TIMESTAMP_ISO" \
      --arg has_passkey "$HAS_PASSKEY" \
      --arg user_category "$USER_CATEGORY" \
      --argjson user_details "$USER_INFO" \
      --argjson credentials_details "$CREDENTIALS" \
      --argjson groups "$USER_GROUPS" \
      '{
        "@timestamp": $timestamp,
        "keycloak": {
          "user": $user_details,
          "credentials": $credentials_details,
          "groups": $groups
        },
        "enrichment": {
          "has_passkey": ($has_passkey == "true"),
          "user_category": $user_category
        }
      }' >> "$ES_BULK_FILE"
done

# [수정] 벌크 데이터 파일의 마지막에 최종 줄 바꿈 문자를 추가하여 요청 형식이 깨지지 않도록 보장합니다.
echo "" >> "$ES_BULK_FILE"

echo -e "\n\n3. 생성된 데이터를 Elasticsearch로 전송합니다."

# [수정] curl의 -w 옵션으로 HTTP 상태 코드를 직접 받아와 정확하게 성공/실패를 판별합니다.
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${ELASTICSEARCH_URL}/_bulk" -H "Content-Type: application/x-ndjson" --data-binary "@${ES_BULK_FILE}")

if [ "$HTTP_CODE" -ge 200 ] && [ "$HTTP_CODE" -lt 300 ]; then
    echo "성공: Elasticsearch로 데이터 전송을 완료했습니다. (HTTP Code: $HTTP_CODE)"
else
    echo "오류: Elasticsearch로 데이터 전송 중 에러가 발생했습니다. (HTTP Code: $HTTP_CODE)"
    echo "오류 응답을 확인하려면 아래 명령어를 직접 실행해보세요."
    echo "curl -X POST \"${ELASTICSEARCH_URL}/_bulk\" -H \"Content-Type: application/x-ndjson\" --data-binary \"@${ES_BULK_FILE}\" | jq"
fi

# rm "$ES_BULK_FILE" # 임시 파일 삭제
echo "모든 작업이 완료되었습니다."
