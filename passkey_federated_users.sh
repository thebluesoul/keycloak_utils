#!/bin/bash

[ "x$DEBUG" = "x1" ] && set -x

CONF_PATH="./server.conf"
if [ ! -f "$CONF_PATH" ]; then
  echo "conf 파일이 존재하지 않습니다: $CONF_PATH"
  exit 1
fi

# conf 파일 읽기
. "$CONF_PATH"


# --- 설정 변수 (사용자 환경에 맞게 수정) ---

KEYCLOAK_URL=${KC_SERVER}
REALM=${KC_REALM}
SERVICE_ACCOUNT_CLIENT_ID=${CLIENT_ID}
SERVICE_ACCOUNT_CLIENT_SECRET=${CLIENT_SECRET}


# --- 스크립트 시작 ---

echo "1. 서비스 계정을 사용하여 Keycloak Admin API 토큰을 발급받습니다."
ACCESS_TOKEN=$(curl -s -X POST "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=${SERVICE_ACCOUNT_CLIENT_ID}" \
  -d "client_secret=${SERVICE_ACCOUNT_CLIENT_SECRET}" | jq -r .access_token)

if [ -z "$ACCESS_TOKEN" ] || [ "$ACCESS_TOKEN" == "null" ]; then
    echo "오류: 서비스 계정 토큰을 발급받지 못했습니다. 클라이언트 ID와 Secret을 확인하세요."
    exit 1
fi
echo "토큰 발급 성공!"
echo ""

echo "2. Realm의 모든 사용자 ID를 조회합니다."

USER_IDS=$(curl -s -X GET "${KEYCLOAK_URL}/admin/realms/${REALM}/users?max=1000" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" | jq -r '.[].id')

if [ -z "$USER_IDS" ]; then
    echo "사용자를 찾을 수 없습니다."
    exit 0
fi
echo ""

PASSKEY_COUNT=0
RESIGNED_COUNT=0
SERVICE_ACCOUNT_COUNT=0
USER_COUNT=0

echo "3. 각 사용자를 순회하며 페더레이션 사용자 여부 및 패스키 등록 여부를 확인합니다..."
for USER_ID in $USER_IDS; do
    ((USER_COUNT++))
    # 스크립트에서 한 줄의 내용을 계속 갱신하여 진행 상태를 보여줄 때
    echo -ne "진행 상황: ${USER_COUNT}번째 사용자 확인 중... (패스키: ${PASSKEY_COUNT}, 서비스 계정: ${SERVICE_ACCOUNT_COUNT}, 퇴사자: ${RESIGNED_COUNT})\r"

    # 사용자의 상세 정보 조회
    USER_INFO=$(curl -s -X GET "${KEYCLOAK_URL}/admin/realms/${REALM}/users/${USER_ID}" \
      -H "Authorization: Bearer ${ACCESS_TOKEN}")

    # 'federationLink' 필드가 있는지 확인하여 페더레이션 사용자인지 판별
    FEDERATION_LINK=$(echo "$USER_INFO" | jq -r '.federationLink')

    if [ -n "$FEDERATION_LINK" ] && [ "$FEDERATION_LINK" != "null" ]; then

        LAST_NAME=$(echo "$USER_INFO" | jq -r '.lastName')
        if [[ "$LAST_NAME" == *"(퇴사)"* ]]; then
            ((RESIGNED_COUNT++))
            continue
        fi

        EMAIL=$(echo "$USER_INFO" | jq -r '.email')
        if [[ -z "$EMAIL" || "$EMAIL" == "null" ]]; then
            ((SERVICE_ACCOUNT_COUNT++))
            continue
        fi

        # 페더레이션 사용자인 경우, 크리덴셜 정보 조회
        CREDENTIALS=$(curl -s -X GET "${KEYCLOAK_URL}/admin/realms/${REALM}/users/${USER_ID}/credentials" \
          -H "Authorization: Bearer ${ACCESS_TOKEN}")

        # 크리덴셜 타입 중 'webauthn' 문자열이 포함된 항목이 있는지 확인
        HAS_PASSKEY=$(echo "$CREDENTIALS" | jq -r '.[] | select(.type | contains("webauthn")) | .id')

        if [ -n "$HAS_PASSKEY" ]; then
            ((PASSKEY_COUNT++))

            # 패스키를 설치한 부서 정보를 추출
            USER_GROUP=$(curl -s -X GET "${KEYCLOAK_URL}/admin/realms/${REALM}/users/${USER_ID}/groups" \
            -H "Authorization: Bearer ${ACCESS_TOKEN}")
            
            USER_GROUP_PATH=$(echo "$USER_GROUP" | jq -r '.[].path')
            echo "$USER_ID $USER_GROUP_PATH" >> /tmp/groups.txt
        fi
    fi
done

PASSKEY_COUNT_PERCENT=$(echo "scale=1; $PASSKEY_COUNT * 100 / 236" | bc)

echo -e "\n\n--- 최종 결과 ---"
echo "확인한 총 사용자 수: ${USER_COUNT}"
echo "패스키를 등록한 페더레이션 사용자 수: ${PASSKEY_COUNT}, ${PASSKEY_COUNT_PERCENT}%"
echo "서비스 제공을 위한 계정 수: ${SERVICE_ACCOUNT_COUNT}"
echo "이름에 '(퇴사)'가 포함된 페더레이션 사용자 수: ${RESIGNED_COUNT}"
echo "----------------"
