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

# 이벤트 API 호출 간격 (초) - 기본값 1초
EVENT_API_SLEEP_INTERVAL=1

# Syslog 필드명 (기본값, server.conf에서 재정의 가능)
SYSLOG_FIELD_TIMESTAMP="TIMESTAMP"
SYSLOG_FIELD_USERID="USERID"
SYSLOG_FIELD_SIP="SIP"
SYSLOG_FIELD_LOGDATE="LOGDATE"
SYSLOG_FIELD_AUTH_METHOD="AUTH_METHOD"

# 이벤트 상태 파일 경로 (글로벌)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EVENT_STATE_DIR="${SCRIPT_DIR}/state"
USER_EVENTS_STATE_FILE=""
ADMIN_EVENTS_STATE_FILE=""
EVENT_LOCK_FILE=""

# GeoIP 데이터베이스 경로 (필요 시 심볼릭 링크 권장)
GEOIP_BASE_DIR="${SCRIPT_DIR}/geolite"
GEOIP_CITY_DB="${GEOIP_BASE_DIR}/GeoLite2-City_20251114/GeoLite2-City.mmdb"
GEOIP_COUNTRY_DB="${GEOIP_BASE_DIR}/GeoLite2-Country_20251114/GeoLite2-Country.mmdb"
declare -A GEOIP_CACHE=()
MMDBLOOKUP_BIN=""

# epoch(ms 또는 s) → YYYY-MM-DD HH:MM:SS 변환 함수
function epoch_to_datetime() {
    local epoch_value="$1"

    if [ -z "$epoch_value" ] || ! [[ "$epoch_value" =~ ^[0-9]+$ ]]; then
        echo ""
        return 1
    fi

    local epoch_sec="$epoch_value"
    if [ ${#epoch_value} -gt 10 ]; then
        epoch_sec=$((epoch_value / 1000))
    fi

    local formatted
    formatted=$(date -d "@$epoch_sec" '+%Y-%m-%d %H:%M:%S' 2>/dev/null)
    if [ -z "$formatted" ]; then
        echo ""
        return 1
    fi

    echo "$formatted"
    return 0
}

# datetime → epoch milliseconds 변환 함수
function datetime_to_epoch_ms() {
    local datetime="$1"
    if [ -z "$datetime" ]; then
        echo ""
        return 1
    fi

    local epoch_s
    epoch_s=$(date -d "$datetime" +%s 2>/dev/null)
    if [ -z "$epoch_s" ]; then
        echo ""
        return 1
    fi

    echo $((epoch_s * 1000))
    return 0
}

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
    
    # Syslog 필드명 (server.conf에서 정의된 값 사용, 없으면 기본값 유지)
    SYSLOG_FIELD_TIMESTAMP=${SYSLOG_FIELD_TIMESTAMP:-"TIMESTAMP"}
    SYSLOG_FIELD_USERID=${SYSLOG_FIELD_USERID:-"USERID"}
    SYSLOG_FIELD_SIP=${SYSLOG_FIELD_SIP:-"SIP"}
    SYSLOG_FIELD_LOGDATE=${SYSLOG_FIELD_LOGDATE:-"LOGDATE"}
    SYSLOG_FIELD_AUTH_METHOD=${SYSLOG_FIELD_AUTH_METHOD:-"AUTH_METHOD"}

    # 이벤트 API 호출 간격 (server.conf에서 재정의 가능, 기본 1초)
    EVENT_API_SLEEP_INTERVAL=${EVENT_API_SLEEP:-1}
    if ! [[ "$EVENT_API_SLEEP_INTERVAL" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
        echo "경고: EVENT_API_SLEEP 값이 유효하지 않아 기본값 1초를 사용합니다." >&2
        EVENT_API_SLEEP_INTERVAL=1
    fi
    
    # 이벤트 상태 디렉토리 생성
    mkdir -p "$EVENT_STATE_DIR"
    
    # 이벤트 상태 파일 경로 설정
    USER_EVENTS_STATE_FILE="${EVENT_STATE_DIR}/keycloak_user_events_${REALM}.state"
    ADMIN_EVENTS_STATE_FILE="${EVENT_STATE_DIR}/keycloak_admin_events_${REALM}.state"
    USER_EVENT_LOCK_FILE="${EVENT_STATE_DIR}/keycloak_user_events_download_${REALM}.lock"
    ADMIN_EVENT_LOCK_FILE="${EVENT_STATE_DIR}/keycloak_admin_events_download_${REALM}.lock"
 
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

# Keycloak 서비스 계정 토큰 응답 전체를 반환하는 함수
function get_token_response() {
    local response=$(curl -s -X POST "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials" \
        -d "client_id=${SERVICE_ACCOUNT_CLIENT_ID}" \
        -d "client_secret=${SERVICE_ACCOUNT_CLIENT_SECRET}")
    
    if [ -z "$response" ] || ! echo "$response" | jq -e . >/dev/null 2>&1; then
        echo "오류: 서비스 계정 토큰 발급 실패." >&2
        return 1
    fi
    
    local error=$(echo "$response" | jq -r '.error // empty')
    if [ -n "$error" ] && [ "$error" != "null" ]; then
        local error_desc=$(echo "$response" | jq -r '.error_description // ""')
        echo "오류: 토큰 발급 실패 - $error" >&2
        if [ -n "$error_desc" ] && [ "$error_desc" != "null" ]; then
            echo "상세: $error_desc" >&2
        fi
        return 1
    fi
    
    echo "$response"
    return 0
}

# JWT 토큰 디코딩 함수
function decode_token() {
    local token="$1"
    
    if [ -z "$token" ] || [ "$token" = "null" ]; then
        echo "오류: 토큰이 제공되지 않았습니다." >&2
        return 1
    fi
    
    # JWT는 3부분으로 구성: header.payload.signature
    local parts=$(echo "$token" | tr '.' '\n' | wc -l)
    if [ "$parts" -ne 3 ]; then
        echo "오류: 유효하지 않은 JWT 토큰 형식입니다." >&2
        return 1
    fi
    
    # Payload 부분 디코딩 (2번째 부분)
    local payload=$(echo "$token" | cut -d'.' -f2)
    
    # Base64 디코딩 (패딩 추가)
    local padding=$((4 - ${#payload} % 4))
    if [ $padding -ne 4 ]; then
        payload="${payload}$(printf '%*s' $padding | tr ' ' '=')"
    fi
    
    echo "$payload" | base64 -d 2>/dev/null | jq . 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "오류: 토큰 디코딩 실패." >&2
        return 1
    fi
    
    return 0
}

# 토큰 정보를 사람이 읽을 수 있는 형식으로 표시하는 함수
function display_token_info() {
    local token="$1"
    
    if [ -z "$token" ]; then
        echo "오류: 토큰이 제공되지 않았습니다." >&2
        return 1
    fi
    
    local decoded=$(decode_token "$token")
    if [ $? -ne 0 ]; then
        return 1
    fi
    
    echo "=== 토큰 정보 ==="
    echo ""
    
    # 기본 정보
    local iss=$(echo "$decoded" | jq -r '.iss // "N/A"')
    local sub=$(echo "$decoded" | jq -r '.sub // "N/A"')
    local aud=$(echo "$decoded" | jq -r '.aud // "N/A"')
    local azp=$(echo "$decoded" | jq -r '.azp // "N/A"')
    
    echo "발급자 (iss): $iss"
    echo "주체 (sub): $sub"
    echo "대상 (aud): $aud"
    echo "인증된 당사자 (azp): $azp"
    echo ""
    
    # 시간 정보
    local iat=$(echo "$decoded" | jq -r '.iat // "N/A"')
    local exp=$(echo "$decoded" | jq -r '.exp // "N/A"')
    local nbf=$(echo "$decoded" | jq -r '.nbf // "N/A"')
    
    if [ "$iat" != "N/A" ] && [ "$iat" != "null" ]; then
        local iat_readable=$(date -d "@$iat" '+%Y-%m-%d %H:%M:%S %Z' 2>/dev/null || echo "N/A")
        echo "발급 시간 (iat): $iat ($iat_readable)"
    fi
    
    if [ "$exp" != "N/A" ] && [ "$exp" != "null" ]; then
        local exp_readable=$(date -d "@$exp" '+%Y-%m-%d %H:%M:%S %Z' 2>/dev/null || echo "N/A")
        local current_time=$(date +%s)
        local remaining=$((exp - current_time))
        
        echo "만료 시간 (exp): $exp ($exp_readable)"
        
        if [ $remaining -gt 0 ]; then
            local remaining_min=$((remaining / 60))
            local remaining_sec=$((remaining % 60))
            echo "남은 시간: ${remaining_min}분 ${remaining_sec}초"
        else
            echo "상태: 만료됨"
        fi
    fi
    
    if [ "$nbf" != "N/A" ] && [ "$nbf" != "null" ]; then
        local nbf_readable=$(date -d "@$nbf" '+%Y-%m-%d %H:%M:%S %Z' 2>/dev/null || echo "N/A")
        echo "유효 시작 시간 (nbf): $nbf ($nbf_readable)"
    fi
    
    echo ""
    
    # Realm 정보
    local realm_access=$(echo "$decoded" | jq -r '.realm_access.roles // []' 2>/dev/null)
    if [ -n "$realm_access" ] && [ "$realm_access" != "[]" ] && [ "$realm_access" != "null" ]; then
        echo "Realm 역할:"
        echo "$realm_access" | jq -r '.[]' | sed 's/^/  - /'
        echo ""
    fi
    
    # Resource access 정보
    local resource_access=$(echo "$decoded" | jq -r '.resource_access // {}' 2>/dev/null)
    if [ -n "$resource_access" ] && [ "$resource_access" != "{}" ] && [ "$resource_access" != "null" ]; then
        echo "리소스 접근 권한:"
        echo "$resource_access" | jq -r 'to_entries[] | "  \(.key): \(.value.roles // [])"' | sed 's/\[\]//g'
        echo ""
    fi
    
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

# 파일 크기를 사람이 읽기 쉬운 단위로 변환
function format_file_size() {
    local size_bytes="$1"

    if [ -z "$size_bytes" ] || ! [[ "$size_bytes" =~ ^[0-9]+$ ]]; then
        echo "0 bytes"
        return 1
    fi

    local size_kb=$((size_bytes / 1024))
    local size_mb=$((size_bytes / 1048576))
    local size_gb=$((size_bytes / 1073741824))

    if [ "$size_gb" -gt 0 ]; then
        local remainder=$(( (size_bytes % 1073741824) * 100 / 1073741824 ))
        printf "%d.%02d GB (%s bytes)\n" "$size_gb" "$remainder" "$size_bytes"
    elif [ "$size_mb" -gt 0 ]; then
        local remainder=$(( (size_bytes % 1048576) * 100 / 1048576 ))
        printf "%d.%02d MB (%s bytes)\n" "$size_mb" "$remainder" "$size_bytes"
    elif [ "$size_kb" -gt 0 ]; then
        local remainder=$(( (size_bytes % 1024) * 100 / 1024 ))
        printf "%d.%02d KB (%s bytes)\n" "$size_kb" "$remainder" "$size_bytes"
    else
        echo "${size_bytes} bytes"
    fi

    return 0
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

# 사설/예약 IP 여부 확인
function is_private_ip() {
    local ip="$1"

    if [ -z "$ip" ]; then
        return 0
    fi

    if [[ "$ip" =~ ^10\. ]] ||
       [[ "$ip" =~ ^192\.168\. ]] ||
       [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] ||
       [[ "$ip" =~ ^127\. ]] ||
       [[ "$ip" =~ ^169\.254\. ]] ||
       [[ "$ip" =~ ^::1$ ]] ||
       [[ "$ip" =~ ^fe80: ]] ||
       [[ "$ip" =~ ^fc00: ]]; then
        return 0
    fi

    return 1
}

# mmdblookup 바이너리 확인
function ensure_mmdblookup() {
    if [ -n "$MMDBLOOKUP_BIN" ]; then
        return 0
    fi

    MMDBLOOKUP_BIN=$(command -v mmdblookup || true)
    if [ -z "$MMDBLOOKUP_BIN" ]; then
        return 1
    fi

    return 0
}

# mmdblookup으로 특정 필드를 조회
function lookup_geoip_value() {
    local ip="$1"
    local db_file="$2"
    shift 2
    local field_path=("$@")

    if [ -z "$ip" ] || [ -z "$db_file" ] || [ ! -f "$db_file" ]; then
        return 1
    fi

    if ! ensure_mmdblookup; then
        return 1
    fi

    local output
    output=$("$MMDBLOOKUP_BIN" --file "$db_file" --ip "$ip" "${field_path[@]}" 2>/dev/null) || return 1

    local string_value
    string_value=$(echo "$output" | grep -oP '"\K[^"]+(?="\s*<utf8_string>)' | head -1)
    if [ -n "$string_value" ]; then
        echo "$string_value"
        return 0
    fi

    local number_value
    number_value=$(echo "$output" | grep -oP '[-]?[0-9]+(\.[0-9]+)?(?=\s*<(double|float|uint[0-9]+|int[0-9]+)>)' | head -1)
    if [ -n "$number_value" ]; then
        echo "$number_value"
        return 0
    fi

    return 1
}

# GeoIP 정보 조회 및 캐시
function get_geoip_info() {
    local ip="$1"

    if [ -z "$ip" ] || [ "$ip" = "unknown" ] || [ "$ip" = "null" ]; then
        return 1
    fi

    if is_private_ip "$ip"; then
        return 1
    fi

    if [ -n "${GEOIP_CACHE[$ip]+_}" ]; then
        echo "${GEOIP_CACHE[$ip]}"
        return 0
    fi

    if [ ! -f "$GEOIP_CITY_DB" ] && [ ! -f "$GEOIP_COUNTRY_DB" ]; then
        return 1
    fi

    if ! ensure_mmdblookup; then
        return 1
    fi

    local country_code=""
    local country_name=""
    local city_name=""
    local latitude=""
    local longitude=""

    if [ -f "$GEOIP_COUNTRY_DB" ]; then
        country_code=$(lookup_geoip_value "$ip" "$GEOIP_COUNTRY_DB" country iso_code || true)
        country_name=$(lookup_geoip_value "$ip" "$GEOIP_COUNTRY_DB" country names en || true)
    fi

    if [ -f "$GEOIP_CITY_DB" ]; then
        city_name=$(lookup_geoip_value "$ip" "$GEOIP_CITY_DB" city names en || true)
        latitude=$(lookup_geoip_value "$ip" "$GEOIP_CITY_DB" location latitude || true)
        longitude=$(lookup_geoip_value "$ip" "$GEOIP_CITY_DB" location longitude || true)

        if [ -z "$country_code" ]; then
            country_code=$(lookup_geoip_value "$ip" "$GEOIP_CITY_DB" country iso_code || true)
        fi
        if [ -z "$country_name" ]; then
            country_name=$(lookup_geoip_value "$ip" "$GEOIP_CITY_DB" country names en || true)
        fi
    fi

    if [ -z "$country_code" ] && [ -z "$country_name" ] && [ -z "$city_name" ] && [ -z "$latitude" ] && [ -z "$longitude" ]; then
        return 1
    fi

    local geo_json
    geo_json=$(jq -n -c \
        --arg ip "$ip" \
        --arg cc "$country_code" \
        --arg cn "$country_name" \
        --arg city "$city_name" \
        --arg lat "$latitude" \
        --arg lon "$longitude" '
        ({} 
        | (if $ip != "" then .ip = $ip else . end)
        | (if $cc != "" then .country_code = $cc else . end)
        | (if $cn != "" then .country_name = $cn else . end)
        | (if $city != "" then .city = $city else . end)
        | (if ($lat != "" and $lon != "") then .location = {lat: ($lat | tonumber), lon: ($lon | tonumber)} else . end)
        )')

    GEOIP_CACHE["$ip"]="$geo_json"
    echo "$geo_json"
    return 0
}

# 이벤트 잠금 획득 함수
function acquire_event_lock() {
    local lock_file="$1"
    local max_wait="${2:-300}"
    local waited=0
    
    while [ -f "$lock_file" ]; do
        if [ $waited -ge $max_wait ]; then
            echo "오류: 잠금 파일이 ${max_wait}초 동안 해제되지 않았습니다: $lock_file" >&2
            
            # 잠금 파일의 PID 확인
            if [ -r "$lock_file" ]; then
                local lock_pid=$(head -n 1 "$lock_file" 2>/dev/null)
                if [ -n "$lock_pid" ] && ! ps -p "$lock_pid" > /dev/null 2>&1; then
                    echo "경고: 잠금 파일의 프로세스(PID: $lock_pid)가 존재하지 않습니다. 잠금 파일을 제거합니다." >&2
                    rm -f "$lock_file"
                    break
                fi
            fi
            return 1
        fi
        
        echo "다른 프로세스가 실행 중입니다. 대기 중... (${waited}초/${max_wait}초)"
        sleep 5
        waited=$((waited + 5))
    done
    
    # 잠금 파일 생성 (현재 프로세스 ID와 타임스탬프 저장)
    echo "$$" > "$lock_file"
    echo "$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)" >> "$lock_file"
    
    return 0
}

# 이벤트 잠금 해제 함수
function release_event_lock() {
    local lock_file="$1"
    
    if [ -f "$lock_file" ]; then
        rm -f "$lock_file"
    fi
    
    return 0
}

# 이벤트 상태 파일 읽기 함수
function read_event_state() {
    local state_file="$1"
    local event_type="${2:-user}"
    
    # 상태 파일이 없으면 초기 상태 반환
    if [ ! -f "$state_file" ]; then
        echo "{}"
        return 0
    fi
    
    # 상태 파일 읽기 및 검증
    local state_content=$(cat "$state_file" 2>/dev/null)
    
    # JSON 유효성 검사
    if ! echo "$state_content" | jq -e . >/dev/null 2>&1; then
        echo "경고: 상태 파일이 손상되었습니다: $state_file" >&2
        
        # 백업 파일 확인
        local backup_file="${state_file}.backup"
        if [ -f "$backup_file" ]; then
            echo "백업 파일에서 복구를 시도합니다: $backup_file" >&2
            local backup_content=$(cat "$backup_file" 2>/dev/null)
            
            if echo "$backup_content" | jq -e . >/dev/null 2>&1; then
                echo "백업 파일에서 복구 성공" >&2
                echo "$backup_content"
                return 0
            fi
        fi
        
        echo "경고: 상태 파일을 초기화합니다." >&2
        echo "{}"
        return 0
    fi
    
    echo "$state_content"
    return 0
}

# 이벤트 상태 파일 쓰기 함수
function write_event_state() {
    local state_file="$1"
    local last_event_time="$2"
    local last_event_id="$3"
    local total_processed="${4:-0}"
    
    # 기존 상태 파일 백업
    if [ -f "$state_file" ]; then
        cp "$state_file" "${state_file}.backup" 2>/dev/null
    fi
    
    # 새로운 상태 저장
    local current_timestamp=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)
    
    jq -n \
        --arg time "$last_event_time" \
        --arg id "$last_event_id" \
        --arg processed "$current_timestamp" \
        --arg total "$total_processed" \
        '{
            last_event_time: $time,
            last_event_id: $id,
            last_processed: $processed,
            total_processed: ($total | tonumber)
        }' > "$state_file"
    
    if [ $? -ne 0 ]; then
        echo "오류: 상태 파일 쓰기 실패: $state_file" >&2
        
        # 백업 파일 복구
        if [ -f "${state_file}.backup" ]; then
            echo "백업 파일을 복구합니다." >&2
            mv "${state_file}.backup" "$state_file"
        fi
        return 1
    fi
    
    return 0
}

# 이벤트 상태 정보 조회 함수
function get_last_event_time() {
    local state_file="$1"
    local default_time="${2:-0}"
    
    local state=$(read_event_state "$state_file")
    local last_time=$(echo "$state" | jq -r ".last_event_time // \"$default_time\"")
    
    echo "$last_time"
}

# 이벤트 상태 정보 표시 함수
function show_event_state() {
    local state_file="$1"
    local event_type="${2:-이벤트}"
    
    if [ ! -f "$state_file" ]; then
        echo "${event_type} 상태 파일이 존재하지 않습니다."
        return 0
    fi
    
    local state=$(read_event_state "$state_file")
    
    echo "=== ${event_type} 상태 정보 ==="
    echo "상태 파일: $state_file"
    echo ""
    
    local last_time=$(echo "$state" | jq -r '.last_event_time // "없음"')
    local last_id=$(echo "$state" | jq -r '.last_event_id // "없음"')
    local last_processed=$(echo "$state" | jq -r '.last_processed // "없음"')
    local total=$(echo "$state" | jq -r '.total_processed // 0')
    
    # Epoch 타임스탬프를 사람이 읽을 수 있는 형식으로 변환
    if [ "$last_time" != "없음" ] && [ "$last_time" != "0" ]; then
        local readable_time=$(date -d "@$((last_time / 1000))" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "$last_time")
        echo "마지막 이벤트 시간: $readable_time (Epoch: $last_time)"
    else
        echo "마지막 이벤트 시간: $last_time"
    fi
    
    echo "마지막 이벤트 ID: $last_id"
    echo "마지막 처리 시각: $last_processed"
    echo "총 처리된 이벤트: $total"
    echo "========================"
    
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
    local formatted_size=$(format_file_size "$file_size")
    echo "bulk 파일 크기: $formatted_size"
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

# 대용량 JSON 배열을 스트리밍으로 한 줄씩 출력
function stream_json_array_items() {
    local json_file="$1"

    if [ -z "$json_file" ] || [ ! -f "$json_file" ]; then
        echo "오류: JSON 파일이 존재하지 않습니다: $json_file" >&2
        return 1
    fi

    jq -c '.[]' "$json_file"
}

# GeoIP 캐시 사전 구축 함수
function prebuild_geoip_cache() {
    local json_file="$1"
    
    echo "IP 주소 추출 중..."
    local unique_ips=$(jq -r '[.[].ipAddress // empty] | unique | .[]' "$json_file" 2>/dev/null)
    
    if [ -z "$unique_ips" ]; then
        echo "  IP 주소 없음"
        return 0
    fi
    
    local ip_count=$(echo "$unique_ips" | wc -l)
    echo "유니크 IP: ${ip_count}개"
    echo "GeoIP 정보 캐시 구축 중..."
    
    local cached=0
    local cache_success=0
    while IFS= read -r ip; do
        if [ -n "$ip" ] && [ "$ip" != "null" ]; then
            cached=$((cached + 1))
            if get_geoip_info "$ip" >/dev/null 2>&1; then
                cache_success=$((cache_success + 1))
            fi
            if [ $((cached % 10)) -eq 0 ]; then
                printf "\r  GeoIP 캐시: %d/%d건 처리" "$cached" "$ip_count"
            fi
        fi
    done <<< "$unique_ips"
    
    if [ $cached -gt 0 ]; then
        printf "\r  GeoIP 캐시: %d/%d건 완료 (성공: %d건)\n" "$cached" "$ip_count" "$cache_success"
    fi
    
    return 0
}

# 이벤트 JSON을 NDJSON으로 변환 (GeoIP 포함)
function convert_events_json_to_ndjson() {
    local json_file="$1"
    local bulk_file="$2"
    local index_name="$3"
    local id_field="${4:-id}"
    local progress_interval=500

    if ! validate_file "$json_file" "이벤트 JSON"; then
        return 1
    fi

    if ! jq -e . >/dev/null 2>&1 < "$json_file"; then
        echo "오류: 잘못된 JSON 형식입니다: $json_file" >&2
        return 1
    fi

    local event_count=$(jq 'length' "$json_file" 2>/dev/null || echo "0")
    if [ "$event_count" -eq 0 ]; then
        echo "경고: JSON 파일에 이벤트가 없습니다." >&2
        return 1
    fi

    prebuild_geoip_cache "$json_file"

    > "$bulk_file"
    echo "이벤트 JSON을 NDJSON 형식으로 변환 중... (총 ${event_count}개)"

    local convert_failed=0
    local processed=0
    local geoip_attempts=0
    local geoip_success=0
    local geoip_cache_hit=0
    local last_progress=0

    while IFS= read -r line; do
        local doc_id=$(echo "$line" | jq -r ".${id_field} // empty")
        if [ -z "$doc_id" ] || [ "$doc_id" = "null" ]; then
            doc_id=$(echo "$line" | jq -r '.id // empty')
        fi
        if [ -z "$doc_id" ] || [ "$doc_id" = "null" ]; then
            doc_id="$(date +%s%3N)-$processed"
        fi

        local ip_address=$(echo "$line" | jq -r '.ipAddress // empty')
        if [ -n "$ip_address" ] && [ "$ip_address" != "null" ]; then
            geoip_attempts=$((geoip_attempts + 1))
            if [ -n "${GEOIP_CACHE[$ip_address]+_}" ]; then
                geoip_cache_hit=$((geoip_cache_hit + 1))
                local geoip_json="${GEOIP_CACHE[$ip_address]}"
                if [ -n "$geoip_json" ]; then
                    line=$(echo "$line" | jq -c --argjson geo "$geoip_json" '. + {geoip: $geo}')
                    geoip_success=$((geoip_success + 1))
                fi
            fi
        fi

        echo "{\"index\": {\"_index\": \"$index_name\", \"_id\": \"$doc_id\"}}" >> "$bulk_file"
        echo "$line" >> "$bulk_file"
        processed=$((processed + 1))

        if [ $progress_interval -gt 0 ] && [ $((processed % progress_interval)) -eq 0 ]; then
            local progress_pct=$((processed * 100 / event_count))
            printf "\r  진행: %d/%d건 (%d%%)" "$processed" "$event_count" "$progress_pct"
            last_progress=$processed
        fi
    done < <(stream_json_array_items "$json_file") || convert_failed=1

    if [ $last_progress -lt $processed ]; then
        printf "\r  진행: %d/%d건 (100%%)\n" "$processed" "$event_count"
    else
        echo ""
    fi

    if [ $convert_failed -ne 0 ]; then
        echo "오류: NDJSON 변환 중 문제가 발생했습니다." >&2
        # rm -f "$bulk_file"
        return 1
    fi

    local bulk_size=$(stat -c%s "$bulk_file" 2>/dev/null || echo "0")
    if [ "$bulk_size" -eq 0 ]; then
        echo "오류: 변환된 bulk 파일이 비어 있습니다." >&2
        # rm -f "$bulk_file"
        return 1
    fi

    local formatted_size=$(format_file_size "$bulk_size")
    echo "변환 완료: bulk 파일 크기 $formatted_size"
    if [ $geoip_attempts -gt 0 ]; then
        echo "GeoIP 처리: ${geoip_success}/${geoip_attempts}건 성공 (캐시 히트: ${geoip_cache_hit}건)"
    fi
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

# 이벤트 파일 업로드 처리
function handle_upload_events() {
    local events_file="$1"
    local index_name="${2:-}"
    local event_type="${3:-user}"

    if [ -z "$events_file" ]; then
        echo "오류: 이벤트 파일 경로를 지정해주세요." >&2
        echo "사용법: $0 upload_${event_type}_events <events.json> [index_name]" >&2
        return 1
    fi

    if ! validate_file "$events_file" "이벤트 파일"; then
        return 1
    fi

    if [ -z "$index_name" ]; then
        local file_basename
        file_basename=$(basename "$events_file")
        index_name="${file_basename%.json}"
        if [ "$index_name" = "$file_basename" ]; then
            index_name="${file_basename%.JSON}"
        fi
        if [ "$index_name" = "$file_basename" ]; then
            if [ "$event_type" = "user" ]; then
                index_name="keycloak-user-events-$(date +%Y.%m.%d)"
            else
                index_name="keycloak-admin-events-$(date +%Y.%m.%d)"
            fi
        fi
    fi

    echo "=== 이벤트 파일 Elasticsearch 업로드 ==="
    echo "파일: $events_file"
    echo "인덱스: $index_name"

    local bulk_file
    bulk_file=$(mktemp "/tmp/kc_events_bulk_XXXXXX.ndjson")
    echo "bulk 파일: $bulk_file"
    
    if [ -z "$bulk_file" ]; then
        echo "오류: 임시 파일을 생성할 수 없습니다." >&2
        return 1
    fi

    if ! convert_events_json_to_ndjson "$events_file" "$bulk_file" "$index_name" "id"; then
        rm -f "$bulk_file"
        return 1
    fi

    local upload_result=0
    upload_to_elasticsearch "$bulk_file" "$index_name" || upload_result=$?

    # rm -f "$bulk_file"

    if [ $upload_result -eq 0 ]; then
        echo "업로드 완료"
        return 0
    fi

    return 1
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
    local include_excluded="${2:-false}"
    
    echo "그룹 다운로드 모드: 사용자 그룹 정보를 저장합니다."
    echo "파일 경로: $groups_file"
    echo "필터링 모드: $([ "$include_excluded" = "true" ] && echo "제외 사용자 포함" || echo "제외 사용자 제외")"
    
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
        
        if should_exclude_user "$username" "$last_name" "$include_excluded"; then
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
    local include_excluded="${2:-false}"
    
    echo "세션 다운로드 모드: 사용자 세션 정보를 저장합니다."
    echo "파일 경로: $sessions_file"
    echo "필터링 모드: $([ "$include_excluded" = "true" ] && echo "제외 사용자 포함" || echo "제외 사용자 제외")"
    
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
        
        if should_exclude_user "$username" "$last_name" "$include_excluded"; then
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
    local result=$?
    
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
    local include_excluded="${1:-false}"
    
    echo "필터링 모드: $([ "$include_excluded" = "true" ] && echo "제외 사용자 포함" || echo "제외 사용자 제외")"
    
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
        
        if should_exclude_user "$username" "" "$include_excluded"; then
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

# 사용자 이벤트 다운로드 함수
function handle_download_user_events() {
    local output_file="${1:-/tmp/user_events-$(date +%Y.%m.%d_%H.%M.%S).json}"
    
    echo "=== Keycloak 사용자 이벤트 다운로드 ==="
    echo "서버: $KEYCLOAK_URL"
    echo "렐름: $REALM"
    echo "클라이언트 ID: $SERVICE_ACCOUNT_CLIENT_ID"
    echo "출력 파일: $output_file"
    echo ""
    
    # 1. 잠금 획득
    echo "잠금 획득 중..."
    if ! acquire_event_lock "$USER_EVENT_LOCK_FILE" 300; then
        echo "오류: 다른 프로세스가 실행 중입니다." >&2
        return 1
    fi
    
    # trap을 사용한 자동 정리
    trap "release_event_lock '$USER_EVENT_LOCK_FILE'" EXIT
    
    # 2. 토큰 발급
    echo "토큰 발급 중..."
    local access_token=$(get_keycloak_token)
    if [ $? -ne 0 ]; then
        echo "오류: 토큰 발급 실패" >&2
        return 1
    fi
    echo "토큰 발급 성공!"
    
    # 3. 마지막 이벤트 시간 조회
    local last_time=$(get_last_event_time "$USER_EVENTS_STATE_FILE" "0")
    
    if [ "$last_time" = "0" ]; then
        echo "첫 번째 실행: 모든 이벤트를 다운로드합니다."
    else
        local readable_time=$(date -d "@$((last_time / 1000))" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "$last_time")
        echo "마지막 처리 시간: $readable_time (Epoch: $last_time)"
        echo "이후 이벤트만 다운로드합니다."
    fi
    echo ""
    
    # 4. 이벤트 다운로드 (페이지네이션 처리)
    echo "사용자 이벤트 다운로드 중..."
    local all_events="[]"
    local first=0
    local max=1000
    local total_downloaded=0
    local page_count=0
    
    while true; do
        page_count=$((page_count + 1))
        
        # API 호출
        local events=$(curl -s -X GET \
            "${KEYCLOAK_URL}/admin/realms/${REALM}/events?first=${first}&max=${max}&dateFrom=${last_time}" \
            -H "Authorization: Bearer ${access_token}")
        
        # HTTP 에러 확인
        if [ $? -ne 0 ]; then
            echo "오류: API 호출 실패 (페이지 ${page_count})" >&2
            return 1
        fi
        
        # JSON 유효성 검사
        if ! echo "$events" | jq -e . >/dev/null 2>&1; then
            echo "오류: 잘못된 JSON 응답 (페이지 ${page_count})" >&2
            return 1
        fi
        
        # 이벤트 개수 확인
        local event_count=$(echo "$events" | jq 'length')
        
        if [ "$event_count" -eq 0 ]; then
            echo "페이지 ${page_count}: 더 이상 이벤트가 없습니다."
            break
        fi
        
        echo "페이지 ${page_count}: ${event_count}개 이벤트 수집 (누적: $((total_downloaded + event_count))개)"
        
        # 이벤트 병합
        all_events=$(echo "$all_events" "$events" | jq -s 'add')
        total_downloaded=$((total_downloaded + event_count))
        first=$((first + max))
        
        # 무한 루프 방지 (최대 100페이지)
        if [ $page_count -ge 100 ]; then
            echo "경고: 최대 페이지 수(100)에 도달했습니다." >&2
            break
        fi
        
        # API 호출 간격 (rate limiting 방지)
        sleep "$EVENT_API_SLEEP_INTERVAL"
    done
    
    echo ""
    echo "총 ${total_downloaded}개의 이벤트를 다운로드했습니다."
    
    # 5. JSON 파일로 저장
    if [ $total_downloaded -eq 0 ]; then
        echo "새로운 이벤트가 없습니다."
        echo "[]" > "$output_file"
    else
        echo "JSON 파일로 저장 중: $output_file"
        echo "$all_events" | jq '.' > "$output_file"
        
        if [ $? -ne 0 ]; then
            echo "오류: JSON 파일 저장 실패" >&2
            return 1
        fi
        
        local file_size=$(stat -c%s "$output_file" 2>/dev/null || echo "0")
        echo "파일 크기: $file_size bytes"
    fi
    
    # 6. 상태 파일 업데이트
    if [ $total_downloaded -gt 0 ]; then
        echo ""
        echo "상태 파일 업데이트 중..."
        
        # 가장 최근 이벤트의 시간과 ID 추출 (시간 기준 내림차순 정렬)
        local newest_time=$(echo "$all_events" | jq -r 'sort_by(.time) | reverse | .[0].time // "0"')
        local newest_id=$(echo "$all_events" | jq -r 'sort_by(.time) | reverse | .[0].id // ""')
        
        if [ "$newest_time" != "0" ] && [ -n "$newest_id" ]; then
            # 기존 상태 읽기
            local old_state=$(read_event_state "$USER_EVENTS_STATE_FILE")
            local old_total=$(echo "$old_state" | jq -r '.total_processed // 0')
            local new_total=$((old_total + total_downloaded))
            
            write_event_state "$USER_EVENTS_STATE_FILE" "$newest_time" "$newest_id" "$new_total"
            
            if [ $? -eq 0 ]; then
                echo "상태 파일 업데이트 성공"
                local readable_time=$(date -d "@$((newest_time / 1000))" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "$newest_time")
                echo "  - 마지막 이벤트 시간: $readable_time"
                echo "  - 마지막 이벤트 ID: $newest_id"
                echo "  - 총 처리된 이벤트: $new_total"
            else
                echo "경고: 상태 파일 업데이트 실패" >&2
            fi
        fi
    fi
    
    # 7. 잠금 해제 (trap에서 자동 처리)
    echo ""
    echo "=== 다운로드 완료 ==="
    echo "저장된 파일: $output_file"
    echo "다운로드된 이벤트: ${total_downloaded}개"
    
    return 0
}

# 관리자 이벤트 다운로드 함수
function handle_download_admin_events() {
    local output_file="${1:-/tmp/admin_events-$(date +%Y.%m.%d_%H.%M.%S).json}"
    
    echo "=== Keycloak 관리자 이벤트 다운로드 ==="
    echo "서버: $KEYCLOAK_URL"
    echo "렐름: $REALM"
    echo "클라이언트 ID: $SERVICE_ACCOUNT_CLIENT_ID"
    echo "출력 파일: $output_file"
    echo ""
    
    # 1. 잠금 획득
    echo "잠금 획득 중..."
    if ! acquire_event_lock "$ADMIN_EVENT_LOCK_FILE" 300; then
        echo "오류: 다른 프로세스가 실행 중입니다." >&2
        return 1
    fi
    
    # trap을 사용한 자동 정리
    trap "release_event_lock '$ADMIN_EVENT_LOCK_FILE'" EXIT
    
    # 2. 토큰 발급
    echo "토큰 발급 중..."
    local access_token=$(get_keycloak_token)
    if [ $? -ne 0 ]; then
        echo "오류: 토큰 발급 실패" >&2
        return 1
    fi
    echo "토큰 발급 성공!"
    
    # 3. 마지막 이벤트 시간 조회
    local last_time=$(get_last_event_time "$ADMIN_EVENTS_STATE_FILE" "0")
    
    if [ "$last_time" = "0" ]; then
        echo "첫 번째 실행: 모든 이벤트를 다운로드합니다."
    else
        local readable_time=$(date -d "@$((last_time / 1000))" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "$last_time")
        echo "마지막 처리 시간: $readable_time (Epoch: $last_time)"
        echo "이후 이벤트만 다운로드합니다."
    fi
    echo ""
    
    # 4. 이벤트 다운로드 (페이지네이션 처리)
    echo "관리자 이벤트 다운로드 중..."
    local all_events="[]"
    local first=0
    local max=1000
    local total_downloaded=0
    local page_count=0
    
    while true; do
        page_count=$((page_count + 1))
        
        # API 호출 (admin-events 엔드포인트 사용)
        local events=$(curl -s -X GET \
            "${KEYCLOAK_URL}/admin/realms/${REALM}/admin-events?first=${first}&max=${max}&dateFrom=${last_time}" \
            -H "Authorization: Bearer ${access_token}")
        
        # HTTP 에러 확인
        if [ $? -ne 0 ]; then
            echo "오류: API 호출 실패 (페이지 ${page_count})" >&2
            return 1
        fi
        
        # JSON 유효성 검사
        if ! echo "$events" | jq -e . >/dev/null 2>&1; then
            echo "오류: 잘못된 JSON 응답 (페이지 ${page_count})" >&2
            return 1
        fi
        
        # 이벤트 개수 확인
        local event_count=$(echo "$events" | jq 'length')
        
        if [ "$event_count" -eq 0 ]; then
            echo "페이지 ${page_count}: 더 이상 이벤트가 없습니다."
            break
        fi
        
        echo "페이지 ${page_count}: ${event_count}개 이벤트 수집 (누적: $((total_downloaded + event_count))개)"
        
        # 이벤트 병합
        all_events=$(echo "$all_events" "$events" | jq -s 'add')
        total_downloaded=$((total_downloaded + event_count))
        first=$((first + max))
        
        # 무한 루프 방지 (최대 100페이지)
        if [ $page_count -ge 100 ]; then
            echo "경고: 최대 페이지 수(100)에 도달했습니다." >&2
            break
        fi
        
        # API 호출 간격 (rate limiting 방지)
        sleep "$EVENT_API_SLEEP_INTERVAL"
    done
    
    echo ""
    echo "총 ${total_downloaded}개의 이벤트를 다운로드했습니다."
    
    # 5. JSON 파일로 저장
    if [ $total_downloaded -eq 0 ]; then
        echo "새로운 이벤트가 없습니다."
        echo "[]" > "$output_file"
    else
        echo "JSON 파일로 저장 중: $output_file"
        echo "$all_events" | jq '.' > "$output_file"
        
        if [ $? -ne 0 ]; then
            echo "오류: JSON 파일 저장 실패" >&2
            return 1
        fi
        
        local file_size=$(stat -c%s "$output_file" 2>/dev/null || echo "0")
        echo "파일 크기: $file_size bytes"
    fi
    
    # 6. 상태 파일 업데이트
    if [ $total_downloaded -gt 0 ]; then
        echo ""
        echo "상태 파일 업데이트 중..."
        
        # 가장 최근 이벤트의 시간과 ID 추출 (시간 기준 내림차순 정렬)
        local newest_time=$(echo "$all_events" | jq -r 'sort_by(.time) | reverse | .[0].time // "0"')
        local newest_id=$(echo "$all_events" | jq -r 'sort_by(.time) | reverse | .[0].id // ""')
        
        if [ "$newest_time" != "0" ] && [ -n "$newest_id" ]; then
            # 기존 상태 읽기
            local old_state=$(read_event_state "$ADMIN_EVENTS_STATE_FILE")
            local old_total=$(echo "$old_state" | jq -r '.total_processed // 0')
            local new_total=$((old_total + total_downloaded))
            
            write_event_state "$ADMIN_EVENTS_STATE_FILE" "$newest_time" "$newest_id" "$new_total"
            
            if [ $? -eq 0 ]; then
                echo "상태 파일 업데이트 성공"
                local readable_time=$(date -d "@$((newest_time / 1000))" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "$newest_time")
                echo "  - 마지막 이벤트 시간: $readable_time"
                echo "  - 마지막 이벤트 ID: $newest_id"
                echo "  - 총 처리된 이벤트: $new_total"
            else
                echo "경고: 상태 파일 업데이트 실패" >&2
            fi
        fi
    fi
    
    # 7. 잠금 해제 (trap에서 자동 처리)
    echo ""
    echo "=== 다운로드 완료 ==="
    echo "저장된 파일: $output_file"
    echo "다운로드된 이벤트: ${total_downloaded}개"
    
    return 0
}

# 사용자 이벤트 파일을 시간 범위로 필터링하는 함수
function filter_user_events_by_time_range() {
    local input_file="$1"
    local output_file="$2"
    local start_datetime="$3"
    local end_datetime="$4"

    if [ -z "$input_file" ] || [ -z "$output_file" ] || [ -z "$start_datetime" ] || [ -z "$end_datetime" ]; then
        echo "오류: 입력/출력 파일과 시작/종료 시간을 모두 지정해야 합니다." >&2
        return 1
    fi

    if [ ! -f "$input_file" ]; then
        echo "오류: 입력 파일을 찾을 수 없습니다: $input_file" >&2
        return 1
    fi

    local start_ms=""
    local end_ms=""
    local has_start=1
    local has_end=1

    if [ "$start_datetime" = "*" ] || [ -z "$start_datetime" ]; then
        has_start=0
        start_ms=0
    else
        start_ms=$(datetime_to_epoch_ms "$start_datetime")
        if [ -z "$start_ms" ]; then
            echo "오류: 시작 시간을 epoch(ms)로 변환할 수 없습니다. 예시: \"2025-11-14 00:00:00\"" >&2
            return 1
        fi
    fi

    if [ "$end_datetime" = "*" ] || [ -z "$end_datetime" ]; then
        has_end=0
        end_ms=0
    else
        end_ms=$(datetime_to_epoch_ms "$end_datetime")
        if [ -z "$end_ms" ]; then
            echo "오류: 종료 시간을 epoch(ms)로 변환할 수 없습니다. 예시: \"2025-11-14 00:00:00\"" >&2
            return 1
        fi
    fi

    if [ "$has_start" -eq 1 ] && [ "$has_end" -eq 1 ] && [ "$start_ms" -gt "$end_ms" ]; then
        echo "오류: 시작 시간이 종료 시간보다 클 수 없습니다." >&2
        return 1
    fi

    local tmp_file="${output_file}.tmp"

    local start_label end_label
    if [ "$has_start" -eq 1 ]; then
        start_label="${start_datetime} (포함)"
    else
        start_label="* (제한 없음)"
    fi
    if [ "$has_end" -eq 1 ]; then
        end_label="${end_datetime} (제외)"
    else
        end_label="* (무제한)"
    fi

    echo "필터링 중... (범위: [${start_label}, ${end_label}))"
    local jq_filter_file
    jq_filter_file=$(mktemp "/tmp/kc_event_filter.XXXXXX")
    cat <<'EOF' > "$jq_filter_file"
[
  .[] |
  (try (.time | tonumber) catch 0) as $event_time |
  select(
    (
      ($has_start == 0) or
      ($event_time >= $start)
    ) and
    (
      ($has_end == 0) or
      ($event_time < $end_ts)
    )
  )
]
EOF

    if ! jq -c \
        --argjson start "$start_ms" \
        --argjson end_ts "$end_ms" \
        --argjson has_start "$has_start" \
        --argjson has_end "$has_end" \
        -f "$jq_filter_file" "$input_file" > "$tmp_file"; then
        echo "오류: jq 필터링 중 문제가 발생했습니다." >&2
        rm -f "$tmp_file"
        rm -f "$jq_filter_file"
        return 1
    fi

    rm -f "$jq_filter_file"

    mv "$tmp_file" "$output_file"
    local filtered_count
    filtered_count=$(jq 'length' "$output_file" 2>/dev/null || echo 0)
    echo "필터링 완료: ${filtered_count}개 이벤트가 ${output_file}에 저장되었습니다."
    echo "※ 범위 규칙: 시작 시각 이상(>=), 종료 시각 미만(<) — [start, end)"
    echo "이 파일을 기존 명령으로 전송하세요:"
    echo "  $0 send_user_events_syslog \"$output_file\""

    return 0
}

# Realm ID로 realm name을 조회하는 함수
function get_realm_name_by_id() {
    local realm_id="$1"
    local access_token="$2"
    
    if [ -z "$realm_id" ] || [ "$realm_id" = "unknown" ] || [ "$realm_id" = "null" ] || [ -z "$access_token" ]; then
        echo ""
        return 1
    fi
    
    # 모든 realm 목록 조회 (Realm ID로 직접 조회하는 엔드포인트가 없으므로)
    local realms_list=$(curl -s -X GET \
        "${KEYCLOAK_URL}/admin/realms" \
        -H "Authorization: Bearer ${access_token}" 2>/dev/null)
    
    if [ $? -eq 0 ] && echo "$realms_list" | jq -e . >/dev/null 2>&1; then
        # Realm ID로 필터링하여 realm name 찾기
        local realm_name=$(echo "$realms_list" | jq -r --arg realm_id "$realm_id" \
            '.[] | select(.id == $realm_id) | .realm // empty' 2>/dev/null)
        
        if [ -n "$realm_name" ] && [ "$realm_name" != "null" ]; then
            echo "$realm_name"
            return 0
        fi
    fi
    
    echo ""
    return 1
}

# Syslog 메시지 포맷을 생성하는 공통 함수
function build_syslog_message() {
    local username="$1"
    local logdate="$2"
    local ip_address="$3"
    local auth_method="$4"
    local error_msg="$5"  # 선택적 파라미터
    local event_id="$6"   # 선택적 파라미터
    local client_id="$7"  # 선택적 파라미터
    
    # 현재 타임스탬프 생성
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # AUTH_METHOD를 소문자로 변환
    local auth_method_lower=$(echo "$auth_method" | tr '[:upper:]' '[:lower:]')
    
    # Syslog 메시지 포맷 생성 (필드명 변수 사용)
    local syslog_message="${SYSLOG_FIELD_USERID}=${username} ${SYSLOG_FIELD_LOGDATE}=${logdate} ${SYSLOG_FIELD_SIP}=${ip_address} ${SYSLOG_FIELD_AUTH_METHOD}=${auth_method_lower}"
    
    # ID 필드 추가 (있는 경우)
    if [ -n "$event_id" ] && [ "$event_id" != "null" ] && [ "$event_id" != "unknown" ]; then
        syslog_message="${syslog_message} ID=${event_id:0:8}"
    fi
    
    # clientId 필드 추가 (있는 경우)
    if [ -n "$client_id" ] && [ "$client_id" != "null" ] && [ "$client_id" != "unknown" ]; then
        syslog_message="${syslog_message} CLIENTID=${client_id}"
    fi
    
    # error 메시지가 있으면 추가
    if [ -n "$error_msg" ] && [ "$error_msg" != "null" ] && [ "$error_msg" != "none" ]; then
        syslog_message="${syslog_message} ERRMSG=${error_msg}"
    fi
    
    echo "$syslog_message"
}

# userId로부터 username을 추출하는 함수
# 우선순위: details.username > userId(json) > userId(api) > code_id(json) > userId
function get_username_from_event() {
    local event="$1"
    local access_token="$2"
    local json_file="$3"  # 전체 이벤트 파일 경로 (검색용)
    
    # 1. details.username 확인 (최우선)
    local username=$(echo "$event" | jq -r '.details.username // empty')
    if [ -n "$username" ] && [ "$username" != "null" ]; then
        echo "$username"
        return 0
    fi
    
    local user_id=$(echo "$event" | jq -r '.userId // empty')
    
    # 2. userId로 현재 JSON 파일에서 다른 이벤트 검색
    if [ -n "$user_id" ] && [ "$user_id" != "null" ] && [ -f "$json_file" ]; then
        username=$(jq -r --arg user_id "$user_id" '
            .[] |
            select(.userId == $user_id and .details.username != null and .details.username != "") |
            .details.username
        ' "$json_file" 2>/dev/null | head -1)
        
        if [ -n "$username" ] && [ "$username" != "null" ]; then
            echo "$username"
            return 0
        fi
    fi
    
    # 3. userId로 Admin API 호출 (파일에서 못 찾은 경우)
    if [ -n "$user_id" ] && [ "$user_id" != "null" ]; then
        if [ -n "$access_token" ]; then
            local user_info=$(curl -s -X GET \
                "${KEYCLOAK_URL}/admin/realms/${REALM}/users/${user_id}" \
                -H "Authorization: Bearer ${access_token}" 2>/dev/null)
            
            if [ $? -eq 0 ] && echo "$user_info" | jq -e . >/dev/null 2>&1; then
                username=$(echo "$user_info" | jq -r '.username // empty')
                if [ -n "$username" ] && [ "$username" != "null" ]; then
                    echo "$username"
                    return 0
                fi
            fi
        fi
    fi
    
    # 4. code_id로 같은 세션의 성공한 이벤트에서 username 찾기
    local code_id=$(echo "$event" | jq -r '.details.code_id // empty')
    if [ -n "$code_id" ] && [ "$code_id" != "null" ] && [ -f "$json_file" ]; then
        local related_username=$(jq -r --arg code_id "$code_id" '
            .[] |
            select(.details.code_id == $code_id and .userId != null and .details.username != null and .details.username != "") |
            .details.username
        ' "$json_file" 2>/dev/null | head -1)
        
        if [ -n "$related_username" ]; then
            echo "$related_username"
            return 0
        fi
    fi
    
    # 5. 모든 방법으로 username을 찾지 못한 경우, userId라도 반환
    if [ -n "$user_id" ] && [ "$user_id" != "null" ]; then
        echo "$user_id"
        return 0
    fi
    
    # 6. 모든 방법 실패 시
    echo "unknown"
    return 0
}

# 사용자 이벤트를 Syslog 포맷으로 변환하는 함수
function convert_user_event_to_syslog() {
    local event="$1"
    local syslog_server="$2"
    local syslog_program="$3"
    local access_token="$4"
    local json_file="$5"  # 전체 이벤트 파일 경로 (code_id 검색용)
    
    # 필드 추출
    local event_id=$(echo "$event" | jq -r '.id // "unknown"')
    local user_id=$(echo "$event" | jq -r '.userId // "unknown"')
    local ip_address=$(echo "$event" | jq -r '.ipAddress // "unknown"')
    local event_type=$(echo "$event" | jq -r '.type // "unknown"')
    local event_time=$(echo "$event" | jq -r '.time // "0"')
    local error_msg=$(echo "$event" | jq -r '.error // "none"')
    local client_id=$(echo "$event" | jq -r '.clientId // "unknown"')
    
    # username 추출 (우선순위: details.username > userId > code_id)
    local username=$(get_username_from_event "$event" "$access_token" "$json_file")
    
    # 이벤트 시간을 사람이 읽을 수 있는 형식으로 변환
    local logdate=""
    if [ "$event_time" != "0" ] && [ "$event_time" != "null" ]; then
        logdate=$(date -d "@$((event_time / 1000))" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "unknown")
    else
        logdate="unknown"
    fi
    
    # Syslog 메시지 생성 (error, ID, clientId 포함)
    build_syslog_message "$username" "$logdate" "$ip_address" "$event_type" "$error_msg" "$event_id" "$client_id"
}

# 관리자 이벤트를 Syslog 포맷으로 변환하는 함수
function convert_admin_event_to_syslog() {
    local event="$1"
    local syslog_server="$2"
    local syslog_program="$3"
    local access_token="$4"
    local json_file="$5"  # 전체 이벤트 파일 경로 (향후 확장용)
    
    # 필드 추출 (관리자 이벤트는 authDetails 안에 정보가 있음)
    local event_id=$(echo "$event" | jq -r '.id // "unknown"')
    
    # event_id가 없으면 함수 종료
    if [ -z "$event_id" ] || [ "$event_id" = "unknown" ] || [ "$event_id" = "null" ]; then
        if [ "$DEBUG" = "1" ]; then
            echo "DEBUG: event_id가 없어서 이벤트를 건너뜁니다." >&2
        fi
        return 1
    fi
    
    local user_id=$(echo "$event" | jq -r '.authDetails.userId // "unknown"')
    local ip_address=$(echo "$event" | jq -r '.authDetails.ipAddress // "unknown"')
    local operation_type=$(echo "$event" | jq -r '.operationType // "unknown"')
    local resource_type=$(echo "$event" | jq -r '.resourceType // "unknown"')
    local event_time=$(echo "$event" | jq -r '.time // "0"')
    local error_msg=$(echo "$event" | jq -r '.error // "none"')
    local client_id=$(echo "$event" | jq -r '.authDetails.clientId // "unknown"')
    
    # username 추출 (관리자 이벤트는 details.username이 없으므로 API 호출)
    local username="$user_id"
    if [ "$user_id" != "unknown" ] && [ -n "$access_token" ]; then
        # 1. 기본 realm에서 먼저 검색
        local user_info=$(curl -s -X GET \
            "${KEYCLOAK_URL}/admin/realms/${REALM}/users/${user_id}" \
            -H "Authorization: Bearer ${access_token}" 2>/dev/null)
        
        if [ $? -eq 0 ] && echo "$user_info" | jq -e . >/dev/null 2>&1; then
            local fetched_username=$(echo "$user_info" | jq -r '.username // empty')
            
            if [ -n "$fetched_username" ] && [ "$fetched_username" != "null" ]; then
                username="$fetched_username"
            fi
        else
            # 2. 기본 realm에서 찾지 못한 경우, authDetails.realmId에 해당하는 realm에서 검색
            local event_realm_id=$(echo "$event" | jq -r '.authDetails.realmId // empty')
            
            if [ -n "$event_realm_id" ] && [ "$event_realm_id" != "null" ] && [ "$event_realm_id" != "unknown" ]; then
                # Realm ID로 realm name 조회
                local event_realm_name=$(get_realm_name_by_id "$event_realm_id" "$access_token")
                
                # Realm name을 찾지 못한 경우 (권한이 없거나 realm이 존재하지 않음)
                if [ -z "$event_realm_name" ]; then
                    if [ "$DEBUG" = "1" ]; then
                        echo "DEBUG: Realm ID(${event_realm_id})에 해당하는 realm name을 찾을 수 없음. 접근 권한이 없거나 realm이 존재하지 않을 수 있습니다." >&2
                    fi
                elif [ "$event_realm_name" != "${REALM}" ]; then
                    # 다른 realm에서 사용자 검색
                    if [ "$DEBUG" = "1" ]; then
                        echo "DEBUG: 기본 realm(${REALM})에서 사용자를 찾지 못함. authDetails.realmId(${event_realm_id})에 해당하는 realm(${event_realm_name})에서 검색 시도" >&2
                    fi
                    
                    user_info=$(curl -s -X GET \
                        "${KEYCLOAK_URL}/admin/realms/${event_realm_name}/users/${user_id}" \
                        -H "Authorization: Bearer ${access_token}" 2>/dev/null)
                    
                    if [ $? -eq 0 ] && echo "$user_info" | jq -e . >/dev/null 2>&1; then
                        fetched_username=$(echo "$user_info" | jq -r '.username // empty')
                        
                        if [ -n "$fetched_username" ] && [ "$fetched_username" != "null" ]; then
                            username="$fetched_username"
                            if [ "$DEBUG" = "1" ]; then
                                echo "DEBUG: realm(${event_realm_name})에서 사용자 찾음: ${username}" >&2
                            fi
                        fi
                    fi
                fi
            fi
        fi
    fi
    
    # 이벤트 시간을 사람이 읽을 수 있는 형식으로 변환
    local logdate=""
    if [ "$event_time" != "0" ] && [ "$event_time" != "null" ]; then
        logdate=$(date -d "@$((event_time / 1000))" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "unknown")
    else
        logdate="unknown"
    fi
    
    # AUTH_METHOD는 operationType과 resourceType을 조합
    local auth_method="${operation_type}"
    if [ "$resource_type" != "unknown" ] && [ "$resource_type" != "null" ]; then
        auth_method="${operation_type}:${resource_type}"
    fi
    
    # Syslog 메시지 생성 (error, ID, clientId 포함)
    build_syslog_message "$username" "$logdate" "$ip_address" "$auth_method" "$error_msg" "$event_id" "$client_id"
}

# 이벤트 JSON 파일을 읽어서 Syslog로 전송하는 함수
function handle_send_events_to_syslog() {
    local json_file="$1"
    local event_type="${2:-user}"  # user 또는 admin
    
    echo "=== Keycloak 이벤트 Syslog 전송 ==="
    echo "이벤트 타입: $event_type"
    echo "입력 파일: $json_file"
    echo ""
    
    # 파일 존재 확인
    if [ ! -f "$json_file" ]; then
        echo "오류: JSON 파일이 존재하지 않습니다: $json_file" >&2
        return 1
    fi
    
    # JSON 유효성 검사
    if ! jq -e . >/dev/null 2>&1 < "$json_file"; then
        echo "오류: 잘못된 JSON 형식입니다: $json_file" >&2
        return 1
    fi
    
    # 이벤트 개수 확인
    local event_count=$(jq 'length' "$json_file")
    if [ "$event_count" -eq 0 ]; then
        echo "경고: JSON 파일에 이벤트가 없습니다." >&2
        return 0
    fi
    
    echo "총 ${event_count}개의 이벤트를 처리합니다."
    echo ""
    
    # Syslog 설정 확인
    local syslog_server="${SYSLOG_SERVER}"
    local syslog_port="${SYSLOG_PORT}"
    local syslog_program="${SYSLOG_PROGRAM}"
    
    if [ -z "$syslog_server" ] || [ -z "$syslog_port" ] || [ -z "$syslog_program" ]; then
        echo "오류: Syslog 설정이 완료되지 않았습니다." >&2
        echo "SYSLOG_SERVER, SYSLOG_PORT, SYSLOG_PROGRAM을 server.conf에 설정하세요." >&2
        return 1
    fi
    
    echo "Syslog 서버: ${syslog_server}:${syslog_port}"
    echo "프로그램 이름: ${syslog_program}"
    echo ""
    
    # Keycloak 토큰 발급 (username 조회용)
    echo "Keycloak 토큰 발급 중..."
    echo "Keycloak 서버: $KEYCLOAK_URL"
    echo "렐름: $REALM"
    
    local access_token=$(get_keycloak_token)
    if [ $? -ne 0 ]; then
        echo "경고: 토큰 발급 실패. username 조회가 제한될 수 있습니다." >&2
        access_token=""
    else
        echo "토큰 발급 성공!"
    fi
    echo ""
    
    # 이벤트 처리
    local processed=0
    local errors=0
    local skipped=0
    local index=0
    
    # jq로 이벤트를 하나씩 읽어서 처리
    while IFS= read -r event; do
        index=$((index + 1))
        
        # 이벤트 정보 추출 (진행상황 표시용)
        local event_id=$(echo "$event" | jq -r '.id // "unknown"')
        local event_ip=$(echo "$event" | jq -r '.ipAddress // .authDetails.ipAddress // "unknown"')
        
        # 이벤트 타입에 따라 변환 함수 선택
        local syslog_message=""
        local convert_result=0
        
        if [ "$event_type" = "user" ]; then
            syslog_message=$(convert_user_event_to_syslog "$event" "$syslog_server" "$syslog_program" "$access_token" "$json_file")
            convert_result=$?
        elif [ "$event_type" = "admin" ]; then
            syslog_message=$(convert_admin_event_to_syslog "$event" "$syslog_server" "$syslog_program" "$access_token" "$json_file")
            convert_result=$?
        else
            echo "오류: 알 수 없는 이벤트 타입: $event_type" >&2
            return 1
        fi
        
        # 변환 함수가 건너뛰기를 요청한 경우 (return 1)
        if [ $convert_result -ne 0 ] || [ -z "$syslog_message" ]; then
            ((skipped++))
            # ID 표시 형식 (8자 초과 시 ... 추가)
            local id_display="${event_id:0:8}"
            if [ ${#event_id} -gt 8 ]; then
                id_display="${id_display}..."
            fi
            echo "[${index}/${event_count}] 건너뜀 - ID: ${id_display} | IP: ${event_ip}"
            continue
        fi
        
        # syslog_message에서 username 추출 (중복 호출 방지, 변수 사용)
        local event_username=$(echo "$syslog_message" | grep -oP "${SYSLOG_FIELD_USERID}=\K[^ ]+" || echo "unknown")
        
        # ID 표시 형식 (8자 초과 시 ... 추가)
        local id_display="${event_id:0:8}"
        if [ ${#event_id} -gt 8 ]; then
            id_display="${id_display}..."
        fi
        
        # Syslog 전송 (메시지를 따옴표 없이 전달)
        # NOTE: syslog_message 변수를 따옴표 없이 전송해야 서버에서 오류 없이 파싱이 가능함.
        if logger --rfc3164 -n "$syslog_server" -P "$syslog_port" -t "$syslog_program" $syslog_message 2>/dev/null; then
            ((processed++))
            # 진행 상황 출력 (각 이벤트마다)
            echo "[${index}/${event_count}] 전송 성공 - ID: ${id_display} | User: ${event_username:0:30} | IP: ${event_ip}"
        else
            ((errors++))
            echo "[${index}/${event_count}] 전송 실패 - ID: ${id_display} | User: ${event_username:0:30} | IP: ${event_ip}" >&2
        fi
        
        # API 호출 간격 (과부하 방지)
        # keycloak event 다운로드시에 event api 호출 간격을 1초로 설정하였음. 이를 참조하여 동일하게 적용함.
        # sleep "$EVENT_API_SLEEP_INTERVAL"
        sleep 0.1
    done < <(jq -c '.[]' "$json_file")
    
    echo ""
    echo "=== 전송 완료 ==="
    echo "성공: ${processed}개"
    echo "실패: ${errors}개"
    if [ $skipped -gt 0 ]; then
        echo "건너뜀: ${skipped}개"
    fi
    echo "총: ${event_count}개"
    
    [ $errors -eq 0 ] && return 0 || return 1
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

# 하위 명령 구현
function cmd_collect_all()
{
    load_config || return 1
    
    # --include-excluded 옵션 처리
    local include_excluded="false"
    while [[ "$#" -gt 0 ]]; do
        case $1 in
            --include-excluded)
                include_excluded="true"
                shift
                ;;
            *)
                echo "오류: 알 수 없는 옵션: $1" >&2
                echo "사용법: $0 collect_all [--include-excluded]" >&2
                return 1
                ;;
        esac
    done
    
    collect_all_user_stats "$include_excluded"
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

function cmd_upload_user_events()
{
    load_config || return 1
    local events_file="$1"
    local index_name="$2"
    handle_upload_events "$events_file" "$index_name" "user"
}

function cmd_upload_admin_events()
{
    load_config || return 1
    local events_file="$1"
    local index_name="$2"
    handle_upload_events "$events_file" "$index_name" "admin"
}

function cmd_download_groups()
{
    load_config || return 1
    
    # 옵션 파싱
    local out="/tmp/user_groups.json"
    local include_excluded="false"
    
    while [[ "$#" -gt 0 ]]; do
        case $1 in
            --include-excluded)
                include_excluded="true"
                shift
                ;;
            *)
                # 옵션이 아니면 출력 파일명으로 간주
                out="$1"
                shift
                ;;
        esac
    done
    
    handle_download_groups "$out" "$include_excluded"
}

function cmd_download_sessions()
{
    load_config || return 1
    
    # 옵션 파싱
    local out="/tmp/user_sessions-$(date +%Y.%m.%d_%H.%M.%S).json"
    local include_excluded="false"
    
    while [[ "$#" -gt 0 ]]; do
        case $1 in
            --include-excluded)
                include_excluded="true"
                shift
                ;;
            *)
                # 옵션이 아니면 출력 파일명으로 간주
                out="$1"
                shift
                ;;
        esac
    done
    
    handle_download_sessions "$out" "$include_excluded"
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

function cmd_download_user_events()
{
    load_config || return 1
    
    # events 디렉토리 생성
    local events_dir="${SCRIPT_DIR}/events"
    mkdir -p "$events_dir"
    
    local out="${1:-${events_dir}/user_events-$(date +%Y.%m.%d_%H.%M.%S).json}"
    handle_download_user_events "$out"
}

function cmd_download_admin_events()
{
    load_config || return 1
    
    # events 디렉토리 생성
    local events_dir="${SCRIPT_DIR}/events"
    mkdir -p "$events_dir"
    
    local out="${1:-${events_dir}/admin_events-$(date +%Y.%m.%d_%H.%M.%S).json}"
    handle_download_admin_events "$out"
}

function cmd_show_events_state()
{
    load_config || return 1
    echo ""
    show_event_state "$USER_EVENTS_STATE_FILE" "사용자 이벤트"
    echo ""
    show_event_state "$ADMIN_EVENTS_STATE_FILE" "관리자 이벤트"
    echo ""
}

function cmd_send_user_events_syslog()
{
    load_config || return 1
    local json_file="$1"
    
    if [ -z "$json_file" ]; then
        echo "오류: JSON 파일 경로를 지정해주세요." >&2
        echo "사용법: $0 send_user_events_syslog <user_events.json>" >&2
        return 1
    fi
    
    handle_send_events_to_syslog "$json_file" "user"
}

function cmd_send_admin_events_syslog()
{
    load_config || return 1
    local json_file="$1"
    
    if [ -z "$json_file" ]; then
        echo "오류: JSON 파일 경로를 지정해주세요." >&2
        echo "사용법: $0 send_admin_events_syslog <admin_events.json>" >&2
        return 1
    fi
    
    handle_send_events_to_syslog "$json_file" "admin"
}

function cmd_filter_user_events()
{
    load_config || return 1

    if [ $# -lt 3 ]; then
        echo "사용법: $0 filter_user_events <input_file> <start_datetime|*> <end_datetime|*> [output_file]" >&2
        echo "예시:  $0 filter_user_events ./events/user_events.json \"2025-11-11 16:50:17\" \"2025-11-11 16:59:00\"" >&2
        echo "       $0 filter_user_events ./events/user_events.json \"2025-11-11 16:50:17\" \"*\"" >&2
        echo "       $0 filter_user_events ./events/user_events.json \"*\" \"2025-11-17 09:00:00\"" >&2
        return 1
    fi

    local input_file="$1"
    local start_datetime="$2"
    local end_datetime="$3"
    local output_file="${4:-}"

    if [ ! -f "$input_file" ]; then
        echo "오류: 입력 파일이 존재하지 않습니다: $input_file" >&2
        return 1
    fi

    if [ -z "$output_file" ]; then
        local events_dir="${SCRIPT_DIR}/events"
        mkdir -p "$events_dir"
        output_file="${events_dir}/user_events_filtered-$(date +%Y.%m.%d_%H.%M.%S).json"
    fi

    filter_user_events_by_time_range "$input_file" "$output_file" "$start_datetime" "$end_datetime"
}

function cmd_convert_events_ndjson()
{
    load_config || return 1

    if [ -z "$1" ]; then
        echo "사용법: $0 convert_events_ndjson <input.json> [output.ndjson] [index_name] [user|admin]" >&2
        return 1
    fi

    local input_file="$1"
    local output_file="$2"
    local index_name="$3"
    local event_type="${4:-user}"

    if [ ! -f "$input_file" ]; then
        echo "오류: 입력 파일이 존재하지 않습니다: $input_file" >&2
        return 1
    fi

    local events_dir="${SCRIPT_DIR}/events"
    mkdir -p "$events_dir"

    if [ -z "$output_file" ]; then
        local base_name
        base_name=$(basename "$input_file")
        local prefix="${base_name%.*}"
        local timestamp
        timestamp=$(date +%Y.%m.%d_%H.%M.%S)
        if [ -z "$prefix" ] || [ "$prefix" = "$base_name" ]; then
            prefix="${event_type}_events"
        fi
        output_file="${events_dir}/${prefix}_${timestamp}.ndjson"
    fi

    if [ -z "$index_name" ]; then
        local base_output
        base_output=$(basename "$output_file")
        index_name="${base_output%.ndjson}"
        if [ -z "$index_name" ] || [ "$index_name" = "$base_output" ]; then
            if [ "$event_type" = "admin" ]; then
                index_name="keycloak-admin-events-$(date +%Y.%m.%d)"
            else
                index_name="keycloak-user-events-$(date +%Y.%m.%d)"
            fi
        fi
    fi

    echo "입력 파일: $input_file"
    echo "출력 파일: $output_file"
    echo "인덱스명: $index_name"

    if convert_events_json_to_ndjson "$input_file" "$output_file" "$index_name" "id"; then
        echo "NDJSON 변환 완료: $output_file"
        return 0
    fi

    return 1
}

function cmd_get_token()
{
    load_config || return 1
    
    echo "=== Keycloak 토큰 발급 ==="
    echo "서버: $KEYCLOAK_URL"
    echo "Realm: $REALM"
    echo "클라이언트 ID: $SERVICE_ACCOUNT_CLIENT_ID"
    echo ""
    
    local token_response=$(get_token_response)
    if [ $? -ne 0 ]; then
        return 1
    fi
    
    local access_token=$(echo "$token_response" | jq -r '.access_token // empty')
    local refresh_token=$(echo "$token_response" | jq -r '.refresh_token // empty')
    local expires_in=$(echo "$token_response" | jq -r '.expires_in // "N/A"')
    local refresh_expires_in=$(echo "$token_response" | jq -r '.refresh_expires_in // "N/A"')
    local token_type=$(echo "$token_response" | jq -r '.token_type // "N/A"')
    local scope=$(echo "$token_response" | jq -r '.scope // "N/A"')
    
    echo "=== 토큰 발급 성공 ==="
    echo ""
    echo "토큰 타입: $token_type"
    echo "유효 기간: ${expires_in}초"
    if [ "$refresh_expires_in" != "N/A" ] && [ "$refresh_expires_in" != "null" ]; then
        echo "Refresh 토큰 유효 기간: ${refresh_expires_in}초"
    fi
    if [ "$scope" != "N/A" ] && [ "$scope" != "null" ] && [ -n "$scope" ]; then
        echo "Scope: $scope"
    fi
    echo ""
    
    if [ -n "$access_token" ] && [ "$access_token" != "null" ]; then
        echo "=== Access Token 정보 ==="
        display_token_info "$access_token"
        echo ""
        echo "=== Access Token (전체) ==="
        echo "$access_token"
        echo ""
    fi
    
    if [ -n "$refresh_token" ] && [ "$refresh_token" != "null" ]; then
        echo "=== Refresh Token ==="
        echo "$refresh_token"
        echo ""
        echo "토큰 갱신 방법:"
        echo "  $0 refresh_token \"$refresh_token\""
        echo ""
    else
        echo "참고: Client Credentials Grant는 일반적으로 refresh token을 반환하지 않습니다."
        echo "토큰이 만료되면 다시 get_token 명령을 실행하세요."
        echo ""
    fi
    
    return 0
}

function cmd_refresh_token()
{
    load_config || return 1
    
    local refresh_token="$1"
    
    if [ -z "$refresh_token" ]; then
        echo "오류: Refresh token이 제공되지 않았습니다." >&2
        echo "사용법: $0 refresh_token <refresh_token>" >&2
        echo ""
        echo "또는 get_token 명령으로 발급받은 refresh token을 사용하세요."
        return 1
    fi
    
    echo "=== Keycloak 토큰 갱신 ==="
    echo "서버: $KEYCLOAK_URL"
    echo "Realm: $REALM"
    echo "클라이언트 ID: $SERVICE_ACCOUNT_CLIENT_ID"
    echo ""
    
    local response=$(curl -s -X POST "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=refresh_token" \
        -d "refresh_token=${refresh_token}" \
        -d "client_id=${SERVICE_ACCOUNT_CLIENT_ID}" \
        -d "client_secret=${SERVICE_ACCOUNT_CLIENT_SECRET}")
    
    if [ -z "$response" ] || ! echo "$response" | jq -e . >/dev/null 2>&1; then
        echo "오류: 토큰 갱신 실패." >&2
        return 1
    fi
    
    local error=$(echo "$response" | jq -r '.error // empty')
    if [ -n "$error" ] && [ "$error" != "null" ]; then
        local error_desc=$(echo "$response" | jq -r '.error_description // ""')
        echo "오류: 토큰 갱신 실패 - $error" >&2
        if [ -n "$error_desc" ] && [ "$error_desc" != "null" ]; then
            echo "상세: $error_desc" >&2
        fi
        return 1
    fi
    
    local access_token=$(echo "$response" | jq -r '.access_token // empty')
    local new_refresh_token=$(echo "$response" | jq -r '.refresh_token // empty')
    local expires_in=$(echo "$response" | jq -r '.expires_in // "N/A"')
    local refresh_expires_in=$(echo "$response" | jq -r '.refresh_expires_in // "N/A"')
    local token_type=$(echo "$response" | jq -r '.token_type // "N/A"')
    
    echo "=== 토큰 갱신 성공 ==="
    echo ""
    echo "토큰 타입: $token_type"
    echo "유효 기간: ${expires_in}초"
    if [ "$refresh_expires_in" != "N/A" ] && [ "$refresh_expires_in" != "null" ]; then
        echo "Refresh 토큰 유효 기간: ${refresh_expires_in}초"
    fi
    echo ""
    
    if [ -n "$access_token" ] && [ "$access_token" != "null" ]; then
        echo "=== 새 Access Token 정보 ==="
        display_token_info "$access_token"
        echo ""
        echo "=== 새 Access Token (전체) ==="
        echo "$access_token"
        echo ""
    fi
    
    if [ -n "$new_refresh_token" ] && [ "$new_refresh_token" != "null" ]; then
        echo "=== 새 Refresh Token ==="
        echo "$new_refresh_token"
        echo ""
        echo "다음 갱신 방법:"
        echo "  $0 refresh_token \"$new_refresh_token\""
        echo ""
    fi
    
    return 0
}

function cmd_token_info()
{
    load_config || return 1
    
    local token="$1"
    
    if [ -z "$token" ]; then
        # 토큰이 제공되지 않으면 새로 발급
        echo "토큰이 제공되지 않아 새로 발급합니다..."
        echo ""
        local token_response=$(get_token_response)
        if [ $? -ne 0 ]; then
            return 1
        fi
        token=$(echo "$token_response" | jq -r '.access_token // empty')
        
        if [ -z "$token" ] || [ "$token" = "null" ]; then
            echo "오류: 토큰을 발급받을 수 없습니다." >&2
            return 1
        fi
        echo ""
    fi
    
    display_token_info "$token"
    
    return 0
}

function cmd_epoch_to_datetime()
{
    if [ $# -eq 0 ]; then
        echo "사용법: $0 epoch_to_datetime <epoch_ms_or_s>" >&2
        echo "예시:  $0 epoch_to_datetime 1762846449897" >&2
        return 1
    fi

    if [ $# -gt 1 ]; then
        echo "오류: 인자는 하나의 epoch 값만 허용됩니다." >&2
        echo "사용법: $0 epoch_to_datetime <epoch_ms_or_s>" >&2
        return 1
    fi

    local epoch_value="$1"
    if ! [[ "$epoch_value" =~ ^[0-9]+$ ]]; then
        echo "오류: 숫자 형식의 epoch 값을 입력하세요." >&2
        return 1
    fi

    local formatted
    formatted=$(epoch_to_datetime "$epoch_value")
    if [ -z "$formatted" ]; then
        echo "오류: epoch 값을 변환할 수 없습니다." >&2
        return 1
    fi

    echo "$formatted"
    return 0
}

function cmd_help()
{
    echo "Usage: $0 [command] [options]"
    echo ""
    echo "  collect_all [--include-excluded]            # 전체 프로세스 실행 (수집 + ES 업로드)"
    echo "  upload_only [bulk_file]                     # 지정 bulk 파일을 ES로 업로드"
    echo "  upload_sessions <sessions.json>             # 세션 JSON을 ES로 업로드"
    echo "  upload_user_events <file.json> [index]      # 사용자 이벤트 JSON → NDJSON 후 ES 업로드"
    echo "  upload_admin_events <file.json> [index]     # 관리자 이벤트 JSON → NDJSON 후 ES 업로드"
    echo "  download_groups [out.json] [--include-excluded]   # 사용자 그룹 정보 다운로드"
    echo "  download_sessions [out.json] [--include-excluded] # 사용자 세션 정보 다운로드"
    echo "  download_user_events [out.json]      # 사용자 이벤트 다운로드 (증분)"
    echo "  download_admin_events [out.json]     # 관리자 이벤트 다운로드 (증분)"
    echo "  show_events_state                    # 이벤트 상태 정보 표시"
    echo "  send_user_events_syslog <file.json>  # 사용자 이벤트를 Syslog로 전송"
    echo "  send_admin_events_syslog <file.json> # 관리자 이벤트를 Syslog로 전송"
    echo "  convert_events_ndjson <input.json> [output.ndjson] [index] [user|admin]"
    echo "                                           # 이벤트 JSON을 GeoIP 포함 NDJSON으로 변환"
    echo "  filter_user_events <source.json> <start|*> <end|*> [output.json]"
    echo "                                           # 사용자 이벤트 JSON을 시간 범위로 필터링 (시작 포함, 종료 제외)"
    echo "                                           # '*' 입력 시 해당 구간은 무제한으로 처리"
    echo "                                           # 예시: \"2025-11-11 16:50:17\" \"2025-11-11 16:59:00\""
    echo "  epoch_to_datetime <epoch_ms>         # epoch(밀리초/초)을 YYYY-MM-DD HH:MM:SS로 변환"
    echo "  send_syslog <sessions.json>          # 세션 정보를 Syslog로 전송"
    echo "  download_auth_flow [flow]            # 인증 플로우(browser 등) 다운로드"
    echo "  get_token                            # 토큰 발급 및 정보 표시"
    echo "  refresh_token [refresh_token]        # Refresh token으로 토큰 갱신"
    echo "  token_info [access_token]            # 토큰 정보 확인 (만료 시간, 권한 등)"
    echo "  help                                 # 도움말 표시"
}

function cmd_()
{
    cmd_help
}

# 2번째 인자부터 끝까지 파라메터로 전달함.
cmd_$1 "${@:2}"
