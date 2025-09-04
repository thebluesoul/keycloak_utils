#!/bin/bash

# 디버그 모드 활성화 (필요시 주석 해제)
[ "x$DEBUG" = "x1" ] && set -x

# --- 설정 ---

CONF_PATH="./server.conf"
if [ ! -f "$CONF_PATH" ]; then
  echo "오류: 설정 파일이 존재하지 않습니다: $CONF_PATH"
  exit 1
fi

# 스크립트에 사용자 ID 인자가 하나도 없으면 사용법을 안내하고 종료
if [ "$#" -eq 0 ]; then
    echo "사용법: $0 <USER_ID_1> [USER_ID_2] ..."
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

# 입력받은 모든 사용자 ID에 대해 반복 처리
for TARGET_USER_ID in "$@"; do
    # 사용자 상세 정보 조회
    USER_INFO=$(curl -s -X GET "${KEYCLOAK_URL}/admin/realms/${REALM}/users/${TARGET_USER_ID}" \
      -H "Authorization: Bearer ${ACCESS_TOKEN}")

    # 사용자가 없는 경우 오류 처리 후 다음 ID로 넘어감
    if [ -z "$USER_INFO" ] || [[ $(echo "$USER_INFO" | jq -r '.id') == "null" ]]; then
        echo "오류: ID [${TARGET_USER_ID}]에 해당하는 사용자를 찾을 수 없습니다."
        echo "--------------------------"
        continue # 다음 루프 계속
    fi

    # 사용자 정보 파싱
    USERNAME=$(echo "$USER_INFO" | jq -r '.username')
    FIRST_NAME=$(echo "$USER_INFO" | jq -r '.firstName')
    LAST_NAME=$(echo "$USER_INFO" | jq -r '.lastName')
    EMAIL=$(echo "$USER_INFO" | jq -r '.email')
    ENABLED=$(echo "$USER_INFO" | jq -r '.enabled')

    # 사용자 프로필 정보 출력
    echo "--- 사용자 프로필 정보 ---"
    echo "ID        : ${TARGET_USER_ID}"
    echo "Username  : ${USERNAME}"
    echo "이름      : ${LAST_NAME}${FIRST_NAME}"
    echo "이메일    : ${EMAIL}"
    echo "활성 상태 : ${ENABLED}"
    echo "--------------------------"

    # 사용자 그룹 정보 조회 및 출력
    USER_GROUPS=$(curl -s -X GET "${KEYCLOAK_URL}/admin/realms/${REALM}/users/${TARGET_USER_ID}/groups" \
      -H "Authorization: Bearer ${ACCESS_TOKEN}")

    if [ -z "$USER_GROUPS" ] || [ "$USER_GROUPS" == "[]" ]; then
        echo "Path: 소속된 그룹 없음"
    else
        # jq를 사용하여 각 그룹의 경로(path)만 지정된 형식으로 출력
        echo "$USER_GROUPS" | jq -r '.[] | "Path: \(.path)"'
    fi
    echo "" # 사용자 간 구분을 위한 공백 라인

done

echo "모든 사용자 정보 조회를 완료했습니다."