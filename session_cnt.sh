#!/bin/bash

[ "x$DEBUG" = "x1" ] && set -x

CONF_PATH="./server.conf"
if [ ! -f "$CONF_PATH" ]; then
  echo "conf 파일이 존재하지 않습니다: $CONF_PATH"
  exit 1
fi

# conf 파일 읽기
. "$CONF_PATH"

TOKEN=$(curl -s "$KC_SERVER/realms/$KC_REALM/protocol/openid-connect/token" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET" \
  -d "grant_type=client_credentials" \
  -H "Content-Type: application/x-www-form-urlencoded" | jq -r .access_token)

USER_IDS=$(curl -s -H "Authorization: Bearer $TOKEN" \
  "$KC_SERVER/admin/realms/$TARGET_REALM/users?max=2000" | jq -r '.[].id')

COUNT=0
for USER_ID in $USER_IDS; do
  SESSION_COUNT=$(curl -s -H "Authorization: Bearer $TOKEN" \
    "$KC_SERVER/admin/realms/$TARGET_REALM/users/$USER_ID/sessions" | jq 'length')
  if [ "$SESSION_COUNT" -gt 0 ]; then
    COUNT=$((COUNT+1))
  fi
  echo -n "."
done

echo ""

echo "$TARGET_REALM realm 관리콘솔 기준 세션 총 개수: $COUNT"
