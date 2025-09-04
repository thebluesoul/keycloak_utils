#!/bin/bash

# 디버그 모드 활성화 (필요시 주석 해제)
[ "x$DEBUG" = "x1" ] && set -x

# --- 설정 및 변수 ---

# 사용자 ID를 이 변수에 입력하거나 스크립트 실행 시 인자로 받습니다.
TARGET_USER_ID="00000000-0000-0000-0000-000000000000"

# 스크립트 실행 시 첫 번째 인자가 있으면 TARGET_USER_ID로 사용
if [ -n "$1" ]; then
  TARGET_USER_ID="$1"
fi

CONF_PATH="./server.conf"
if [ ! -f "$CONF_PATH" ]; then
  echo "오류: 설정 파일이 존재하지 않습니다: $CONF_PATH"
  exit 1
fi

# 설정 파일 읽기
. "$CONF_PATH"

# Keycloak 접속 정보
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

echo "2. 사용자 프로필 정보를 조회합니다 (ID: ${TARGET_USER_ID})"
# 사용자 상세 정보 조회
USER_INFO=$(curl -s -X GET "${KEYCLOAK_URL}/admin/realms/${REALM}/users/${TARGET_USER_ID}" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}")

# 사용자가 없는 경우 오류 처리
if [ -z "$USER_INFO" ] || [[ $(echo "$USER_INFO" | jq -r '.id') == "null" ]]; then
    echo "오류: 해당 ID의 사용자를 찾을 수 없습니다."
    exit 1
fi

# 사용자 정보 파싱 및 출력
USERNAME=$(echo "$USER_INFO" | jq -r '.username')
FIRST_NAME=$(echo "$USER_INFO" | jq -r '.firstName')
LAST_NAME=$(echo "$USER_INFO" | jq -r '.lastName')
EMAIL=$(echo "$USER_INFO" | jq -r '.email')
ENABLED=$(echo "$USER_INFO" | jq -r '.enabled')

echo ""
echo "--- 사용자 프로필 정보 ---"
echo "ID        : ${TARGET_USER_ID}"
echo "Username  : ${USERNAME}"
echo "이름      : ${LAST_NAME}${FIRST_NAME}"
echo "이메일    : ${EMAIL}"
echo "활성 상태 : ${ENABLED}"
echo "--------------------------"
echo ""


echo "3. 사용자 그룹 정보를 조회합니다."
# 사용자 그룹 정보 조회
USER_GROUPS=$(curl -s -X GET "${KEYCLOAK_URL}/admin/realms/${REALM}/users/${TARGET_USER_ID}/groups" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}")

if [ -z "$USER_GROUPS" ] || [ "$USER_GROUPS" == "[]" ]; then
    echo "이 사용자는 속한 그룹이 없습니다."
else
    echo ""
    echo "--- 소속 그룹 정보 ---"
    # jq를 사용하여 그룹 이름과 경로를 테이블 형식으로 예쁘게 출력
    echo "$USER_GROUPS" | jq -r '.[] | "Name: \(.name)\nPath: \(.path)\n---"'
    echo "----------------------"
fi