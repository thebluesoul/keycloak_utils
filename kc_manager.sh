#!/bin/bash

# 디버그 모드 활성화
[ "x$DEBUG" = "x1" ] && set -x

# 제외할 시스템 계정 사용자명 목록
EXCLUDED_USERNAMES=(
    "cloudgov"
    "tac3monitoring"
    "admin"
    "dev-support"
    "cloudoperator"
    "cloudmonitor2"
    "cloudmonitor"
    "hielf-admin"
    "operator@my.genians.co.kr"
    "test"
    "test_devlbt"
    "unknown"
    "admin@genians.com"
    "depttestuser"
)

# 설정 변수 (글로벌)
KEYCLOAK_URL=""
REALM=""
SERVICE_ACCOUNT_CLIENT_ID=""
SERVICE_ACCOUNT_CLIENT_SECRET=""
ELASTICSEARCH_URL=""
ES_INDEX_NAME=""
ES_BULK_FILE=""

# 설정 파일 로드 및 검증 함수
function load_config() {
    local conf_path="./server.conf"
    if [ ! -f "$conf_path" ]; then
        echo "오류: 설정 파일이 존재하지 않습니다: $conf_path"
        return 1
    fi
    
    . "$conf_path"
    
    # 설정 변수 할당
    KEYCLOAK_URL=${KC_SERVER}
    REALM=${KC_REALM}
    SERVICE_ACCOUNT_CLIENT_ID=${CLIENT_ID}
    SERVICE_ACCOUNT_CLIENT_SECRET=${CLIENT_SECRET}
    ELASTICSEARCH_URL=${ES_URL}
    ES_INDEX_NAME=${ES_INDEX:-"keycloak-passkey-stats-$(date +%Y.%m.%d)"}
    ES_BULK_FILE="/tmp/es_bulk_data-$(date +%Y.%m.%d_%H.%M.%S).json"
    
    # 필수 설정 확인
    if [ -z "$ELASTICSEARCH_URL" ]; then
        echo "오류: Elasticsearch URL이 설정되지 않았습니다. server.conf 파일에 ES_URL을 추가하세요."
        return 1
    fi
    
    return 0
}

# Keycloak 서비스 계정 토큰 발급 함수
function get_keycloak_token() {
    local token=$(curl -s -X POST "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials" \
        -d "client_id=${SERVICE_ACCOUNT_CLIENT_ID}" \
        -d "client_secret=${SERVICE_ACCOUNT_CLIENT_SECRET}" | jq -r .access_token)
    
    if [ -z "$token" ] || [ "$token" == "null" ]; then
        echo "오류: 서비스 계정 토큰 발급 실패." >&2
        return 1
    fi
    
    echo "$token"
    return 0
}

# 사용자 필터링 함수 (퇴사자 및 시스템 계정 제외)
function should_exclude_user() {
    local username="$1"
    local last_name="$2"
    local include_excluded="${3:-false}"
    
    if [ "$include_excluded" = "true" ]; then
        return 1
    fi
    
    # 퇴사자 확인
    if [[ "$last_name" == *"퇴사"* ]] || [[ "$last_name" == *"입사취소"* ]]; then
        return 0
    fi
    
    # 시스템 계정 확인
    if [[ " ${EXCLUDED_USERNAMES[@]} " =~ " ${username} " ]]; then
        return 0
    fi
    
    return 1
}

# 파일 존재 및 크기 검증 함수
function validate_file() {
    local file_path="$1"
    local file_type="${2:-파일}"
    
    if [ ! -f "$file_path" ]; then
        echo "오류: ${file_type}이 존재하지 않습니다: $file_path" >&2
        return 1
    fi
    
    local file_size=$(stat -c%s "$file_path" 2>/dev/null || echo "0")
    if [ "$file_size" -eq 0 ]; then
        echo "오류: ${file_type}이 비어있습니다: $file_path" >&2
        return 1
    fi
    
    return 0
}

# Elasticsearch bulk 업로드 함수
function upload_to_elasticsearch() {
    local bulk_file="$1"
    local index_name="$2"
    
    if ! validate_file "$bulk_file" "bulk 파일"; then
        return 1
    fi
    
    local file_size=$(stat -c%s "$bulk_file" 2>/dev/null || echo "0")
    echo "bulk 파일 크기: $file_size bytes"
    echo "Elasticsearch로 데이터를 전송합니다..."
    
    local http_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${ELASTICSEARCH_URL}/_bulk" \
        -H "Content-Type: application/x-ndjson" \
        --data-binary "@${bulk_file}")
    
    if [ "$http_code" -ge 200 ] && [ "$http_code" -lt 300 ]; then
        echo "성공: Elasticsearch로 데이터 전송을 완료했습니다. (HTTP Code: $http_code)"
        if [ -n "$index_name" ]; then
        echo "업로드된 문서 수를 확인하려면 다음 명령을 실행하세요:"
            echo "curl -s \"${ELASTICSEARCH_URL}/_cat/indices/${index_name}?v\""
        fi
        return 0
    else
        echo "오류: Elasticsearch로 데이터 전송 중 에러가 발생했습니다. (HTTP Code: $http_code)" >&2
        echo "오류 응답을 확인하려면 아래 명령어를 직접 실행해보세요." >&2
        echo "curl -X POST \"${ELASTICSEARCH_URL}/_bulk\" -H \"Content-Type: application/x-ndjson\" --data-binary \"@${bulk_file}\" | jq" >&2
        return 1
    fi
}

# JSON을 Elasticsearch bulk 형식으로 변환 함수
function convert_json_to_bulk() {
    local json_file="$1"
    local bulk_file="$2"
    local index_name="$3"
    local id_field="${4:-user_id}"
    
    > "$bulk_file"
    
    jq -c '.[]' "$json_file" | while read -r line; do
        local doc_id=$(echo "$line" | jq -r ".${id_field}")
        echo "{\"index\": {\"_index\": \"$index_name\", \"_id\": \"$doc_id\"}}" >> "$bulk_file"
        echo "$line" >> "$bulk_file"
    done
    
    return 0
}

# 업로드 전용 모드 처리 함수
function handle_upload_only() {
    local upload_file="$1"
    local bulk_file
    
    if [ -n "$upload_file" ]; then
        bulk_file="$upload_file"
        echo "업로드 전용 모드: 지정된 파일을 Elasticsearch에 업로드합니다."
    else
        bulk_file="$ES_BULK_FILE"
        echo "업로드 전용 모드: 기본 bulk 파일을 Elasticsearch에 업로드합니다."
    fi
    
    echo "파일 경로: $bulk_file"
    
    if ! validate_file "$bulk_file" "bulk 파일"; then
        echo "파일 경로를 확인하거나, 먼저 전체 프로세스를 실행하여 bulk 파일을 생성하세요." >&2
        return 1
    fi
    
    upload_to_elasticsearch "$bulk_file" "$ES_INDEX_NAME"
    return $?
}

# 세션 업로드 전용 모드 처리 함수
function handle_upload_sessions() {
    local sessions_file="$1"
    
    if [ -z "$sessions_file" ]; then
        echo "오류: 세션 파일 경로를 지정해주세요." >&2
        echo "사용법: $0 --upload-sessions /path/to/sessions.json" >&2
        return 1
    fi
    
    echo "세션 업로드 전용 모드: 지정된 세션 파일을 Elasticsearch에 업로드합니다."
    echo "파일 경로: $sessions_file"
    
    if ! validate_file "$sessions_file" "세션 파일"; then
        return 1
    fi
    
    local index_name=$(basename "$sessions_file" .json)
    echo "인덱스명: $index_name"
    
    local bulk_file="${sessions_file}.bulk"
    local current_timestamp=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)
    
    > "$bulk_file"
    
    jq -c '.[]' "$sessions_file" | while read -r line; do
        local user_id=$(echo "$line" | jq -r '.user_id')
        local enhanced_line=$(echo "$line" | jq -c --arg timestamp "$current_timestamp" '. + {"@timestamp": $timestamp}')
        echo "{\"index\": {\"_index\": \"$index_name\", \"_id\": \"$user_id\"}}" >> "$bulk_file"
        echo "$enhanced_line" >> "$bulk_file"
    done
    
    if ! validate_file "$bulk_file" "bulk 파일"; then
        return 1
    fi
    
    local result=$?
    upload_to_elasticsearch "$bulk_file" "$index_name"
    result=$?
    
    rm -f "$bulk_file"
    return $result
}

# 사용자 그룹 정보 조회 함수
function get_user_groups() {
    local user_id="$1"
    local access_token="$2"
    
    local groups_raw=$(curl -s -X GET "${KEYCLOAK_URL}/admin/realms/${REALM}/users/${user_id}/groups" \
        -H "Authorization: Bearer ${access_token}")
    
    echo "$groups_raw" | jq -c '[.[] | {id: .id, name: .name, path: .path}] // []'
}

# 주요 그룹 추출 함수
function extract_primary_group() {
    local groups_raw="$1"
    
    local primary_group=$(echo "$groups_raw" | jq -r '.[] | select(.name | startswith("/지니언스(주)")) | .name' | head -1 | sed 's/.*\///')
    
    if [ -z "$primary_group" ] || [ "$primary_group" = "null" ]; then
        primary_group="미분류"
    fi
    
    echo "$primary_group"
}

# 그룹 정보 다운로드 처리 함수
function handle_download_groups() {
    local groups_file="${1:-/tmp/user_groups.json}"
    
    echo "그룹 다운로드 모드: 사용자 그룹 정보를 저장합니다."
    echo "파일 경로: $groups_file"
    
    local access_token=$(get_keycloak_token)
    if [ $? -ne 0 ]; then
        return 1
    fi
    echo "토큰 발급 성공!"
    
    echo "Realm의 모든 사용자 정보 조회 중..."
    local users_info=$(curl -s -X GET "${KEYCLOAK_URL}/admin/realms/${REALM}/users?max=1000&briefRepresentation=false" \
        -H "Authorization: Bearer ${access_token}")
    
    local user_count=$(echo "$users_info" | jq '. | length')
    if [ "$user_count" -eq 0 ]; then
        echo "사용자를 찾을 수 없습니다."
        return 0
    fi
    
    echo "총 ${user_count}명의 사용자 그룹 정보를 수집합니다..."
    echo "[]" > "$groups_file"
    
    for i in $(seq 0 $((user_count - 1))); do
        local user_info=$(echo "$users_info" | jq -c ".[$i]")
        local user_id=$(echo "$user_info" | jq -r '.id')
        local username=$(echo "$user_info" | jq -r '.username')
        local email=$(echo "$user_info" | jq -r '.email // ""')
        local first_name=$(echo "$user_info" | jq -r '.firstName // ""')
        local last_name=$(echo "$user_info" | jq -r '.lastName // ""')
        
        if should_exclude_user "$username" "$last_name"; then
            echo "진행 상황: $((i + 1))/${user_count} - 사용자: $username (제외)"
            continue
        fi
        
        echo "진행 상황: $((i + 1))/${user_count} - 사용자: $username"
        
        local groups_raw=$(curl -s -X GET "${KEYCLOAK_URL}/admin/realms/${REALM}/users/${user_id}/groups" \
            -H "Authorization: Bearer ${access_token}")
        local user_groups=$(get_user_groups "$user_id" "$access_token")
        local primary_group=$(extract_primary_group "$groups_raw")
        
        local user_group_data=$(jq -n -c \
            --arg user_id "$user_id" \
            --arg username "$username" \
            --arg email "$email" \
            --arg first_name "$first_name" \
            --arg last_name "$last_name" \
            --argjson groups "$user_groups" \
            --arg primary_group "$primary_group" \
          '{
            user_id: $user_id,
            username: $username,
            email: $email,
            first_name: $first_name,
            last_name: $last_name,
            groups: $groups,
            group_count: ($groups | length),
            group_paths: [$groups[].path],
            department_name: $primary_group
          }')
        
        jq --argjson new_user "$user_group_data" '. + [$new_user]' "$groups_file" > "${groups_file}.tmp" && \
            mv "${groups_file}.tmp" "$groups_file"
    done
    
    echo ""
    echo "그룹 정보 수집 완료!"
    echo "저장된 파일: $groups_file"
    echo "총 사용자 수: $user_count"
    
    local processed_users=$(jq '. | length' "$groups_file")
    local total_groups=$(jq '[.[].groups[].name] | unique | length' "$groups_file")
    local users_with_groups=$(jq '[.[] | select(.group_count > 0)] | length' "$groups_file")
    local users_without_groups=$(jq '[.[] | select(.group_count == 0)] | length' "$groups_file")
    
    echo "처리된 사용자 수: $processed_users명 (퇴사자 제외)"
    echo "고유 그룹 수: $total_groups"
    echo "그룹이 있는 사용자: $users_with_groups명"
    echo "그룹이 없는 사용자: $users_without_groups명"
    
    echo ""
    echo "부서별 사용자 수:"
    jq -r '.[].department_name' "$groups_file" | sort | uniq -c | sort -nr
    
    echo ""
    echo "그룹별 사용자 수 상위 10개:"
    jq -r '.[].groups[].name' "$groups_file" | sort | uniq -c | sort -nr | head -10
    
    echo ""
    echo "파일 내용 미리보기 (처음 3명):"
    jq '.[0:3]' "$groups_file"
    
    return 0
}

# 사용자 세션 정보 조회 함수
function get_user_sessions() {
    local user_id="$1"
    local access_token="$2"
    
    local sessions_raw=$(curl -s -X GET "${KEYCLOAK_URL}/admin/realms/${REALM}/users/${user_id}/sessions" \
        -H "Authorization: Bearer ${access_token}")
    
    echo "$sessions_raw" | jq -c '. // []'
}

# 세션 정보 다운로드 처리 함수
function handle_download_sessions() {
    local sessions_file="${1:-/tmp/user_sessions-$(date +%Y.%m.%d_%H.%M.%S).json}"
    
    echo "세션 다운로드 모드: 사용자 세션 정보를 저장합니다."
    echo "파일 경로: $sessions_file"
    
    local access_token=$(get_keycloak_token)
    if [ $? -ne 0 ]; then
        return 1
    fi
    echo "토큰 발급 성공!"
    
    echo "Realm의 모든 사용자 정보 조회 중..."
    local users_info=$(curl -s -X GET "${KEYCLOAK_URL}/admin/realms/${REALM}/users?max=1000&briefRepresentation=false" \
        -H "Authorization: Bearer ${access_token}")
    
    local user_count=$(echo "$users_info" | jq '. | length')
    if [ "$user_count" -eq 0 ]; then
        echo "사용자를 찾을 수 없습니다."
        return 0
    fi
    
    echo "총 ${user_count}명의 사용자 세션 정보를 수집합니다..."
    echo "[]" > "$sessions_file"
    
    for i in $(seq 0 $((user_count - 1))); do
        local user_info=$(echo "$users_info" | jq -c ".[$i]")
        local user_id=$(echo "$user_info" | jq -r '.id')
        local username=$(echo "$user_info" | jq -r '.username')
        local email=$(echo "$user_info" | jq -r '.email // ""')
        local first_name=$(echo "$user_info" | jq -r '.firstName // ""')
        local last_name=$(echo "$user_info" | jq -r '.lastName // ""')
        
        if should_exclude_user "$username" "$last_name"; then
            echo "진행 상황: $((i + 1))/${user_count} - 사용자: $username (제외)"
            continue
        fi

        echo "진행 상황: $((i + 1))/${user_count} - 사용자: $username"
        
        local user_sessions=$(get_user_sessions "$user_id" "$access_token")
        local session_count=$(echo "$user_sessions" | jq 'length')
        local current_timestamp=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)
        
        local user_session_data=$(jq -n -c \
            --arg user_id "$user_id" \
            --arg username "$username" \
            --arg email "$email" \
            --arg first_name "$first_name" \
            --arg last_name "$last_name" \
            --argjson sessions "$user_sessions" \
            --arg session_count "$session_count" \
            --arg timestamp "$current_timestamp" \
          '{
            "@timestamp": $timestamp,
            user_id: $user_id,
            username: $username,
            email: $email,
            first_name: $first_name,
            last_name: $last_name,
            sessions: $sessions,
            session_count: ($session_count | tonumber),
            has_active_session: (($session_count | tonumber) > 0)
          }')

        jq --argjson new_user "$user_session_data" '. + [$new_user]' "$sessions_file" > "${sessions_file}.tmp" && \
            mv "${sessions_file}.tmp" "$sessions_file"
    done

    echo ""
    echo "세션 정보 수집 완료!"
    echo "저장된 파일: $sessions_file"
    echo "총 사용자 수: $user_count"
    
    local processed_users=$(jq '. | length' "$sessions_file")
    local users_with_sessions=$(jq '[.[] | select(.has_active_session == true)] | length' "$sessions_file")
    local users_without_sessions=$(jq '[.[] | select(.has_active_session == false)] | length' "$sessions_file")
    local total_active_sessions=$(jq '[.[].sessions[]] | length' "$sessions_file")
    
    echo "처리된 사용자 수: $processed_users명 (퇴사자 및 시스템 계정 제외)"
    echo "활성 세션이 있는 사용자: $users_with_sessions명"
    echo "활성 세션이 없는 사용자: $users_without_sessions명"
    echo "총 활성 세션 수: $total_active_sessions개"
    
    echo ""
    echo "세션별 사용자 수 상위 10개:"
    jq -r '.[] | select(.has_active_session == true) | "\(.username): \(.session_count)개 세션"' "$sessions_file" | sort -k2 -nr | head -10
    
    echo ""
    echo "파일 내용 미리보기 (처음 3명):"
    jq '.[0:3]' "$sessions_file"

    echo ""
    # echo "Elasticsearch에 세션 데이터를 업로드합니다..."
    
    local index_name=$(basename "$sessions_file" .json)
    local bulk_file="${sessions_file}.bulk"
    
    convert_json_to_bulk "$sessions_file" "$bulk_file" "$index_name" "user_id"

    # 사용자 세션정보를 로컬에 파일로 저장만 하도록 한다. 업로드는 별도의 옵션으로 처리한다.    
    # local result=$?
    # if [ $result -eq 0 ]; then
    #     upload_to_elasticsearch "$bulk_file" "$index_name"
    #     result=$?
    # fi
    
    rm -f "$bulk_file"
    return $result
}

# 사용자 크리덴셜 조회 함수
function get_user_credentials() {
    local user_id="$1"
    local access_token="$2"
    
    local credentials_raw=$(curl -s -X GET "${KEYCLOAK_URL}/admin/realms/${REALM}/users/${user_id}/credentials" \
        -H "Authorization: Bearer ${access_token}")
    
    echo "$credentials_raw" | jq -c '. // []'
}

# 사용자 카테고리 분류 함수
function categorize_user() {
    local user_info="$1"
    local credentials_raw="$2"
    local user_groups_raw="$3"
    
    local is_federated=false
    local has_passkey=false
    local user_category="Internal"
    local credentials="[]"
    local user_groups="[]"
    local department_name="미분류"
    
    if echo "$user_info" | jq -e '.federationLink' > /dev/null; then
        is_federated=true
        local last_name=$(echo "$user_info" | jq -r '.lastName // ""')
        local email=$(echo "$user_info" | jq -r '.email // ""')
        
        if [[ "$last_name" == *"퇴사"* ]]; then
            user_category="Resigned"
        elif [[ -z "$email" || "$email" == "null" || "$email" == "" ]]; then
            user_category="Service Account"
        else
            credentials="$credentials_raw"
            
            if echo "$credentials_raw" | jq -e '.[] | select(.type | contains("webauthn"))' > /dev/null; then
                has_passkey=true
                user_category="Passkey User"
            else
                user_category="Federated (No Passkey)"
            fi
            
            user_groups=$(echo "$user_groups_raw" | jq -c '[.[] | .path] // []')
            
            local primary_group=$(echo "$user_groups_raw" | jq -r '.[] | select(.path | contains("/지니언스(주)")) | .path | split("/") | .[-1]')
            if [ -n "$primary_group" ] && [ "$primary_group" != "null" ]; then
                department_name="$primary_group"
            fi
        fi
    fi
    
    echo "$has_passkey|$user_category|$credentials|$user_groups|$department_name"
}

# 타임스탬프 생성 함수
function generate_event_timestamp() {
    local user_info="$1"
    local credentials="$2"
    
    local event_timestamp_ms=$(echo "$user_info" | jq -r '.createdTimestamp')
    
    local passkey_timestamp=$(echo "$credentials" | jq -r '.[] | select(.type == "webauthn-passwordless") | .createdDate' | head -1)
    if [ -n "$passkey_timestamp" ] && [ "$passkey_timestamp" != "null" ]; then
        event_timestamp_ms="$passkey_timestamp"
    else
        local otp_timestamp=$(echo "$credentials" | jq -r '.[] | select(.type == "otp") | .createdDate' | head -1)
        if [ -n "$otp_timestamp" ] && [ "$otp_timestamp" != "null" ]; then
            event_timestamp_ms="$otp_timestamp"
        fi
    fi
    
    local event_timestamp_iso=$(echo "scale=3; $event_timestamp_ms / 1000" | bc | xargs -I {} date -u -d "@{}" +%Y-%m-%dT%H:%M:%S.%3NZ)
    echo "$event_timestamp_iso"
}

# 전체 사용자 통계 수집 함수
function collect_all_user_stats() {
    local access_token=$(get_keycloak_token)
    if [ $? -ne 0 ]; then
        return 1
    fi
    echo "토큰 발급 성공!"
    
    echo "Realm의 모든 사용자 상세 정보 조회 중..."
    local users_info=$(curl -s -X GET "${KEYCLOAK_URL}/admin/realms/${REALM}/users?max=1000&briefRepresentation=false" \
        -H "Authorization: Bearer ${access_token}")
    
    local user_count=$(echo "$users_info" | jq '. | length')
    if [ "$user_count" -eq 0 ]; then
        echo "사용자를 찾을 수 없습니다."
        return 0
    fi
    
    echo "총 ${user_count}명의 사용자 데이터를 처리합니다..."
    
    > "$ES_BULK_FILE"
    
    for i in $(seq 0 $((user_count - 1))); do
        local user_info=$(echo "$users_info" | jq -c ".[$i]")
        local user_id=$(echo "$user_info" | jq -r '.id')
        local username=$(echo "$user_info" | jq -r '.username')
        
        if should_exclude_user "$username" ""; then
            echo "진행 상황: $((i + 1))/${user_count} - 사용자: $username (시스템 계정 - 제외)"
        continue
    fi
    
        local credentials="[]"
        local user_groups="[]"
        
        if echo "$user_info" | jq -e '.federationLink' > /dev/null; then
            local last_name=$(echo "$user_info" | jq -r '.lastName // ""')
            local email=$(echo "$user_info" | jq -r '.email // ""')
            
            if [[ "$last_name" == *"퇴사"* ]]; then
        continue
    fi

            if [[ -n "$email" && "$email" != "null" && "$email" != "" ]]; then
                local credentials_raw=$(get_user_credentials "$user_id" "$access_token")
                credentials="$credentials_raw"
                
                local user_groups_raw=$(curl -s -X GET "${KEYCLOAK_URL}/admin/realms/${REALM}/users/${user_id}/groups" \
                    -H "Authorization: Bearer ${access_token}")
                user_groups=$(echo "$user_groups_raw" | jq -c '[.[] | .path] // []')
            fi
        fi
        
        local category_result=$(categorize_user "$user_info" "$credentials" "$user_groups")
        IFS='|' read -r has_passkey user_category creds groups department_name <<< "$category_result"
        
        if ! echo "$user_info" | jq . > /dev/null 2>&1 || \
           ! echo "$creds" | jq . > /dev/null 2>&1 || \
           ! echo "$groups" | jq . > /dev/null 2>&1; then
            echo "경고: JSON 유효성 검사 실패 (사용자 $i, ID: $user_id)" >&2
            continue
        fi
        
        local event_timestamp=$(generate_event_timestamp "$user_info" "$creds")
        
        echo "{\"index\": {\"_index\": \"$ES_INDEX_NAME\", \"_id\": \"$user_id\"}}" >> "$ES_BULK_FILE"

    jq -n -c \
            --arg timestamp "$event_timestamp" \
            --arg has_passkey "$has_passkey" \
            --arg user_category "$user_category" \
            --arg department_name "$department_name" \
            --argjson user_details "$user_info" \
            --argjson credentials_details "$creds" \
            --argjson groups "$groups" \
      '{
        "@timestamp": $timestamp,
        "keycloak": {
          "user": $user_details,
          "credentials": $credentials_details,
          "groups": $groups
        },
        "enrichment": {
          "has_passkey": ($has_passkey == "true"),
          "user_category": $user_category,
          "department_name": $department_name
        }
      }' >> "$ES_BULK_FILE"
    done

    echo "" >> "$ES_BULK_FILE"
    echo ""
    echo "생성된 데이터를 Elasticsearch로 전송합니다."
    
    upload_to_elasticsearch "$ES_BULK_FILE" "$ES_INDEX_NAME"
    return $?
}

# Syslog 전송 함수
function handle_send_syslog() {
    local json_file="$1"
    local processed=0
    local errors=0

    if [ -z "$json_file" ]; then
        echo "오류: JSON 파일 경로를 지정해주세요." >&2
        return 1
    fi

    if [ ! -f "$json_file" ]; then
        echo "오류: JSON 파일이 존재하지 않습니다: $json_file" >&2
        return 1
    fi

    if ! jq -e . >/dev/null 2>&1 < "$json_file"; then
        echo "오류: 잘못된 JSON 형식입니다: $json_file" >&2
        return 1
    fi

    if [ "$(jq '. | length' "$json_file")" -eq 0 ]; then
        echo "오류: JSON 파일에 데이터가 없습니다" >&2
        return 1
    fi

    local syslog_server="${SYSLOG_SERVER}"
    local syslog_port="${SYSLOG_PORT}"
    local syslog_program="${SYSLOG_PROGRAM}"

    if [ -z "$syslog_server" ] || [ -z "$syslog_port" ] || [ -z "$syslog_program" ]; then
        echo "오류: Syslog 설정이 완료되지 않았습니다." >&2
        echo "SYSLOG_SERVER, SYSLOG_PORT, SYSLOG_PROGRAM을 server.conf에 설정하세요." >&2
        return 1
    fi

    local jq_filter='
        def extract_domain(url):
            if url | test("^https?://") then
                url | ltrimstr("https://") | ltrimstr("http://") | split("/")[0] | split(":")[0]
            else
                url
            end;
        
        .[] | .username as $uname |
        if .sessions and (.sessions | length > 0) then
            .sessions[] |
            [$uname, "session", .ipAddress, (.lastAccess / 1000), (.clients | to_entries | map(.value | extract_domain(.)) | join(", "))] | @tsv
        else
            empty
        end
    '

    while IFS=$'\t' read -r username type ip_address last_access_epoch clients; do
        local syslog_msg
        if [[ "$type" == "no_sessions" ]]; then
            syslog_msg="user=$username status=no_sessions"
        else
            local last_access_kst=$(date -d "@${last_access_epoch%.*}" '+%Y-%m-%d %H:%M:%S %Z' 2>/dev/null)
            if [ -z "$last_access_kst" ]; then
                echo "경고: 타임스탬프 변환 실패 (user: $username, epoch: $last_access_epoch)" >&2
                ((errors++))
                continue
            fi
            local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
            syslog_msg="TIMESTAMP=$timestamp USERID=$username SIP=$ip_address LOGDATE=\"$last_access_kst\" clients=\"$clients\""
        fi

        if ! logger --rfc3164 -n "$syslog_server" -P "$syslog_port" -t "$syslog_program" "$syslog_msg"; then
            echo "경고: syslog 전송 실패 (user: $username)" >&2
            ((errors++))
        else
            ((processed++))
            echo "syslog 전송 성공. (${processed} -- $syslog_msg)"
        fi
    done < <(jq -r "$jq_filter" "$json_file")

    echo "처리 완료: 성공=$processed, 오류=$errors"
    [ $errors -eq 0 ] || return 1
}

# 인증 플로우 다운로드 함수
function handle_download_auth_flow() {
    local flow_name="${1:-browser}"
    local output_file="${2:-/tmp/${flow_name}_auth_flow-$(date +%Y.%m.%d_%H.%M.%S).json}"
    
    echo "=== Keycloak 인증 플로우 정보 수집 ==="
    echo "렐름: $REALM"
    echo "인증 플로우: $flow_name"
    echo "출력 파일: $output_file"
    echo ""
    
    local access_token=$(get_keycloak_token)
    if [ $? -ne 0 ]; then
        return 1
    fi
    echo "토큰 발급 성공!"
    
    echo "인증 플로우 정보 조회 중..."
    local auth_flow_info=$(curl -s -X GET "${KEYCLOAK_URL}/admin/realms/${REALM}/authentication/flows" \
        -H "Authorization: Bearer ${access_token}")
    
    local flow_exists=$(echo "$auth_flow_info" | jq -r --arg flow_name "$flow_name" '.[] | select(.alias == $flow_name) | .alias')
    if [ -z "$flow_exists" ]; then
        echo "오류: 인증 플로우 '$flow_name'을 찾을 수 없습니다." >&2
        echo "사용 가능한 인증 플로우:" >&2
        echo "$auth_flow_info" | jq -r '.[].alias' | sort
        return 1
    fi
    
    echo "인증 플로우 상세 정보 조회 중..."
    local flow_details=$(curl -s -X GET "${KEYCLOAK_URL}/admin/realms/${REALM}/authentication/flows/${flow_name}/executions" \
        -H "Authorization: Bearer ${access_token}")
    
    echo "JSON 파일 생성 중..."
    local current_timestamp=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)
    
    jq -n \
        --arg timestamp "$current_timestamp" \
        --arg realm "$REALM" \
        --arg flow_name "$flow_name" \
        --arg keycloak_url "$KEYCLOAK_URL" \
        --argjson flow_info "$auth_flow_info" \
        --argjson flow_details "$flow_details" \
        '{
            "@timestamp": $timestamp,
            "realm": $realm,
            "auth_flow_name": $flow_name,
            "keycloak_server": $keycloak_url,
            "flow_info": $flow_info,
            "flow_executions": $flow_details,
            "metadata": {
                "collection_time": $timestamp,
                "keycloak_server": $keycloak_url
            }
        }' > "$output_file"
    
    if [ -f "$output_file" ]; then
        local file_size=$(stat -c%s "$output_file" 2>/dev/null || echo "0")
        echo ""
        echo "=== 수집 완료 ==="
        echo "저장된 파일: $output_file"
        echo "파일 크기: $file_size bytes"
        echo ""
        return 0
    else
        echo "오류: JSON 파일 생성에 실패했습니다." >&2
        return 1
    fi
}


function cmd_help()
{
    echo "Usage: $0 [command] [options]"
    echo ""
    echo "  collect_all                        # 전체 프로세스 실행 (수집 + ES 업로드)"
    echo "  upload_only [bulk_file]            # 지정 bulk 파일을 ES로 업로드"
    echo "  upload_sessions <sessions.json>    # 세션 JSON을 ES로 업로드"
    echo "  download_groups [out.json]         # 사용자 그룹 정보 다운로드"
    echo "  download_sessions [out.json]       # 사용자 세션 정보 다운로드"
    echo "  send_syslog <sessions.json>        # 세션 정보를 Syslog로 전송"
    echo "  download_auth_flow [flow]          # 인증 플로우(browser 등) 다운로드"
    echo "  help                               # 도움말 표시"
}

# 하위 명령 구현
function cmd_collect_all()
{
    load_config || return 1
    collect_all_user_stats
}

function cmd_upload_only()
{
    load_config || return 1
    local bulk_file="${1:-$ES_BULK_FILE}"
    handle_upload_only "$bulk_file"
}

function cmd_upload_sessions()
{
    load_config || return 1
    local sessions_file="$1"
    handle_upload_sessions "$sessions_file"
}

function cmd_download_groups()
{
    load_config || return 1
    local out="${1:-/tmp/user_groups.json}"
    handle_download_groups "$out"
}

function cmd_download_sessions()
{
    load_config || return 1
    local out="${1:-/tmp/user_sessions-$(date +%Y.%m.%d_%H.%M.%S).json}"
    handle_download_sessions "$out"
}

function cmd_send_syslog()
{
    load_config || return 1
    local file="$1"
    handle_send_syslog "$file"
}

function cmd_download_auth_flow()
{
    load_config || return 1
    local flow_name="${1:-browser}"
    handle_download_auth_flow "$flow_name"
}

function cmd_()
{
    cmd_help
}

# 2번째 인자부터 끝까지 파라메터로 전달함.
cmd_$1 "${@:2}"