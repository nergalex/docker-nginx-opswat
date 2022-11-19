#!/bin/bash
# Prevent curl use mdicapsrv lib
shopt -s expand_aliases
alias curl="LD_LIBRARY_PATH= curl"

####################
## Utils
####################
check_env() {
    local required_keys=()
    local required_vars=()
    local ret_code=0
    if ! echo $IGNITION_JSON | jq -e . &> /dev/null; then
        echo "Warning: Ignore IGNITION_JSON because of invalid"
        IGNITION_JSON=;
    fi
    local keys=($(echo $IGNITION_JSON | jq -r 'keys[]'))
    for i in "${!required_keys[@]}"; do
        local key=${required_keys[$i]}
        local var=${required_vars[$i]}
        if [[ -z ${!var} && ! " ${keys[*]} " =~ " ${key} " ]]; then
            echo "$key is missing. Please set via $var or IGNITION_JSON before running container."
            ret_code=1
        fi
    done
    return $ret_code
}

set_config_value() {
    local config_file=$1
    local section=${2%/*}
    local key=${2#*/}
    local value=$3
    if [[ -z $value ]]; then return; fi
    python3 -c "
import configparser;
c = configparser.ConfigParser();
c.read('$config_file');
if not c.has_section('$section'):
    c.add_section('$section');
c.set('$section', '$key', '$value');
c.write(open('$config_file', 'w'));"
}

get_config_value() {
    local config_file=$1
    local section=${2%/*}
    local key=${2#*/}
    python3 -c "
import configparser;
c = configparser.ConfigParser();
c.read('$config_file');
v = '';
try: v = c.get('$section', '$key');
except: pass;
print(v);"
}

# Get License Deployment ID
get_deployment_id() {
    if [[ -z $APIKEY ]]; then return 1; fi
    DEPLOYMENT_ID=$(curl -k -s -X GET "$protocol://localhost:$REST_PORT/admin/license" -H "apikey: $APIKEY" | jq -r ".deployment")
}

# Check ICAP Server process is running
is_process_running() {
    local pid=$1
#    ps fuxwa
#    sleep 10000
    if ps -p $pid > /dev/null
    then
        return 0
    fi
    return 1
}

####################
## Tasks
####################
# check and modify configure environment
modify_execute_config()
{
    touch ${SYSTEM_DIR}/mdicapsrv
    chmod +x ${SYSTEM_DIR}/mdicapsrv 
    echo "#!/bin/bash"                                              > ${SYSTEM_DIR}/mdicapsrv
    echo "export QT_PLUGIN_PATH=${QT_PLUGIN_PATH}"                  >> ${SYSTEM_DIR}/mdicapsrv
    echo "export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}"                >> ${SYSTEM_DIR}/mdicapsrv 
    echo "export DATA_DIR=${DATA_DIR}"                              >> ${SYSTEM_DIR}/mdicapsrv
    echo "export RUNTIME_PATH=${RUNTIME_PATH}"                      >> ${SYSTEM_DIR}/mdicapsrv
    echo "export TEMP_PATH=${TEMP_PATH}"                            >> ${SYSTEM_DIR}/mdicapsrv
    echo "export AUDIT_DATA_RETENTION=${AUDIT_DATA_RETENTION}"      >> ${SYSTEM_DIR}/mdicapsrv
    echo "export HISTORY_DATA_RETENTION=${HISTORY_DATA_RETENTION}"  >> ${SYSTEM_DIR}/mdicapsrv
    echo "export LOG_PATH=${LOG_PATH}"                              >> ${SYSTEM_DIR}/mdicapsrv
    echo "export ICAP_CONF=${ICAP_CONF}"                            >> ${SYSTEM_DIR}/mdicapsrv
    echo "export RUN_USER=${RUN_USER}"                              >> ${SYSTEM_DIR}/mdicapsrv
    echo "${INSTALL_ROOT}/etc/init.d/mdicapsrv \$1"                 >> ${SYSTEM_DIR}/mdicapsrv
}

# Function runs when container stop
_term() {
    if [[ -z $APIKEY && -s "$APIKEY_PATH" ]]; then
        APIKEY=$(cat "$APIKEY_PATH")
    fi
    if [[ $APIKEY ]]; then
        if curl -k -I "https://localhost:$REST_PORT/admin/license/deactivation" &> /dev/null; then
            curl -k -s -H "apikey: $APIKEY" -X POST "https://localhost:$REST_PORT/admin/license/deactivation" &> /dev/null
        else
            curl -k -s -H "apikey: $APIKEY" -X POST "http://localhost:$REST_PORT/admin/license/deactivation" &> /dev/null
        fi
    fi
    service mdicapsrv stop
}

# Update default path from ICAP_DATA_PATH
update_runtime_path_from_env() {
    if [[ ! -d ${ICAP_DATA_PATH}  ]]; then
        mkdir -p ${ICAP_DATA_PATH}
    fi

    if [[ $DATA_DIR == ${DEFAULT_DATA_DIR} ]]; then
        DATA_DIR=${ICAP_DATA_PATH}/var/lib/mdicapsrv
    fi
    if [[ $RUNTIME_PATH == ${DEFAULT_RUNTIME_PATH} ]]; then
        RUNTIME_PATH=${ICAP_DATA_PATH}/var/run/mdicapsrv
    fi 
    if [[ $TEMP_PATH == ${DEFAULT_TEMP_PATH} ]]; then
        TEMP_PATH=${ICAP_DATA_PATH}/var/tmp/mdicapsrv
    fi
    if [[ $LOG_PATH == ${DEFAULT_LOG_PATH} ]]; then
        LOG_PATH=${ICAP_DATA_PATH}/var/log/mdicapsrv
    fi
    IGNITION_FILE=${ICAP_DATA_PATH}/opswat/mdicapsrv.conf
    IGNITION_PATH=$(dirname ${IGNITION_FILE})
    ICAP_CONF=${ICAP_DATA_PATH}/mdicapsrv.conf
    if [[ ! -s ${ICAP_CONF}  ]]; then
        cp -f ${DEFAULT_ICAP_CONF} ${ICAP_CONF}
    fi
}

# Create ignition file if not exists
init_ignition_file() {
    if [[ ! -s $IGNITION_FILE ]]; then
        if ! check_env; then
            exit 1
        fi
        mkdir -p $(dirname "$IGNITION_FILE")
        touch $IGNITION_FILE
        chmod 755 $IGNITION_FILE
    fi
     # Remove eula key that has no section for processing in python
    sed -i '/eula=true/d' "$IGNITION_FILE"

    # Write ENV var keys to ignition file
    if [[ $MD_USER && $MD_PWD ]]; then
        if [[ -z $MD_EMAIL ]]; then MD_EMAIL=admin@local; fi
        set_config_value "$IGNITION_FILE" "user/name" "$MD_USER"
        set_config_value "$IGNITION_FILE" "user/password" "$MD_PWD"
        set_config_value "$IGNITION_FILE" "user/email" "$MD_EMAIL"
        set_config_value "$IGNITION_FILE" "user/apikey" "$APIKEY"
    fi

    # Write JSON keys to ignition file
    if [[ $IGNITION_JSON ]]; then
        for key in $(echo $IGNITION_JSON | jq -r 'keys[]'); do
            set_config_value "$IGNITION_FILE" "$key" "$(echo $IGNITION_JSON | jq -r ".\"$key\"")"
        done
    fi

    # Add the eula key]
    if [[ -s $IGNITION_FILE ]]; then
        sed -i '1s;^;eula=true\n;' "$IGNITION_FILE"
    else
        echo "eula=true" > "$IGNITION_FILE"
    fi
}

# Init ICAP for first run
init_icap() {
    update_runtime_path_from_env
    init_ignition_file
    modify_icap_config
    update_env_by_config
    modify_execute_config

    # Upgrade DB
    ${INSTALL_ROOT}/usr/sbin/mdicapsrv-upgrade-db ${ICAP_CONF} &> /dev/null
}

# Modify ICAP config according to ENV vars
modify_icap_config() {
    if [[ ! -s $ICAP_CONF ]]; then
        return 1
    fi
    # Write ENV var keys to ICAP conf file
    set_config_value "$ICAP_CONF" "global/restaddress" "$REST_ADDRESS"
    set_config_value "$ICAP_CONF" "global/restport" "$REST_PORT"
    set_config_value "$ICAP_CONF" "global/icapaddress" "$ICAP_ADDRESS"
    set_config_value "$ICAP_CONF" "global/icapport" "$ICAP_PORT"
    set_config_value "$ICAP_CONF" "global/icaps_port" "$ICAPS_PORT"

    set_config_value "$ICAP_CONF" "internal/data_directory" "$DATA_DIR"
    set_config_value "$ICAP_CONF" "global/tempdirectory" "$TEMP_PATH"
    set_config_value "$ICAP_CONF" "internal/runtime_directory" "$RUNTIME_PATH"
    set_config_value "$ICAP_CONF" "internal/nginxprefix" "$INSTALL_ROOT"
    set_config_value "$ICAP_CONF" "internal/nginxlibrarypath" "$LIBRARY_PATH"
    set_config_value "$ICAP_CONF" "internal/nginx_conf_path" "$RUNTIME_PATH"
    set_config_value "$ICAP_CONF" "internal/nginx_client_body_temp_path" "$TEMP_PATH/client-body"
    set_config_value "$ICAP_CONF" "logger/nginx_logfile" "$LOG_PATH/nginx-mdicapsrv.log"
    set_config_value "$ICAP_CONF" "internal/ignition_file_location" "$IGNITION_FILE"
    set_config_value "$ICAP_CONF" "logger/logfile" "$LOG_PATH/mdicapsrv.log"
    set_config_value "$ICAP_CONF" "logger/loglevel" "info"

    # Modify ICAP config by JSON keys
    if ! echo $ICAP_CONF_JSON | jq -e . &> /dev/null; then
        echo "Warning: Ignore ICAP_CONF_JSON because of invalid"
        ICAP_CONF_JSON=;
    fi
    if [[ $ICAP_CONF_JSON ]]; then
        for key in $(echo $ICAP_CONF_JSON | jq -r 'keys[]'); do
            set_config_value "$ICAP_CONF" "$key" "$(echo $ICAP_CONF_JSON | jq -r ".\"$key\"")"
        done
    fi
}

# Update ENV vars for calling API
update_env_by_config() {
    REST_PORT=$(get_config_value "$ICAP_CONF" "global/restport")
    IGNITION_FILE=$(get_config_value "$ICAP_CONF" "internal/ignition_file_location")
    DATA_DIR=$(get_config_value "$ICAP_CONF" "internal/data_directory")
    RUNTIME_PATH=$(get_config_value "$ICAP_CONF" "internal/runtime_directory")
    TEMP_PATH=$(get_config_value "$ICAP_CONF" "global/tempdirectory")
    sed -i '/eula=true/d' "$IGNITION_FILE"
    MD_USER=$(get_config_value "$IGNITION_FILE" "user/name")
    MD_PWD=$(get_config_value "$IGNITION_FILE" "user/password")
    APIKEY=$(get_config_value "$IGNITION_FILE" "user/apikey")
    if [[ -s $IGNITION_FILE ]]; then
        sed -i '1s;^;eula=true\n;' "$IGNITION_FILE"
    else
        echo "eula=true" > "$IGNITION_FILE"
    fi
}

# Check paths for existance and permissions
check_path() {
    local path_vars=("DATA_DIR" "RUNTIME_PATH" "TEMP_PATH" "LOG_PATH")
    local ret_code=0
    for var in "${path_vars[@]}"; do
        local path=${!var}
        if [[ ${path} ]]; then
            if [[ -d ${path} ]]; then mkdir -p ${path}; fi

            if [[ ! -d ${path} ]] && ! /usr/bin/install -o ${RUN_USER} -g ${RUN_GROUP} -m 755 -d "${path}" &> /dev/null; then
                echo "Cannot create '$path' directory. Please try again with another path."
                ret_code=1
            elif [[ ! -w ${path} ]]; then
                echo "'$path' directory doesn't have write permission. If this directory is mounted, please make sure it has sufficient permission."
                ret_code=1
            fi
        fi
    done
    return $ret_code
}

# Wait for rest port open
wait_rest() {
    local wait_protocol=$1
    for i in {0..2}; do
        until curl -k -s -I "https://localhost:$REST_PORT/login" &> /dev/null; ret=$?; [[ $ret != 7 ]]; 
        do 
            sleep 1
            if ! is_process_running $PROCESS_ID; 
            then 
                return 1 
            fi
        done


        if openssl s_client -connect localhost:$REST_PORT < /dev/null &> /dev/null; then
            protocol="https"
        else
            protocol="http"
        fi
        if [[ -z $wait_protocol || "$protocol" == "$wait_protocol" ]]; then
            break
        fi
        sleep 5
    done
    return 0
}

# Wait user ignition
wait_user_ignition() {
    while [[ ! -z $APIKEY ]]
    do
        local response=$(curl -k -s -w "\n%{http_code}" -H "apikey: $APIKEY" -X GET "$protocol://localhost:$REST_PORT/version")
        local status_code=$(echo "$response" | tail -n 1)
        if [[ $status_code != 403 ]]; then
            break
        fi
        sleep 1
    done
}

# Add APIKEY to admin user - Setup APIKEY with username, password
setup_apikey() {
    if [[ -z $APIKEY ]]; then return 1; fi
    local login
    login=$(curl -k -s -H "Content-Type: application/json" -d "{\"user\":\"$MD_USER\",\"password\":\"$MD_PWD\"}" -X POST "$protocol://localhost:$REST_PORT/login")
    local sessionid=$(echo $login | jq -r '.session_id // empty')
    if [[ -z $sessionid ]]; then return 1; fi
    local userid=$(curl -k -s -H "apikey: $sessionid" -X GET "$protocol://localhost:$REST_PORT/user" | jq -r .id)
    if [[ -z $userid ]]; then return 1; fi
    curl -k -s -H "Content-Type: application/json" -H "apikey: $sessionid" -d "{\"api_key\":\"$APIKEY\"}" -X PUT "$protocol://localhost:$REST_PORT/admin/user/$userid" &> /dev/null
}

# Enable HTTPS/ICAPS
activate_ssl_tls() {
    if [[ -z ${HTTPS_CERT_PATH} && -z ${ICAPS_CERT_PATH} ]]; then return 1; fi

    if [[ -z $protocol ]]; then return 1; fi
    if [[ -z $APIKEY ]]; then
        echo "Warning: APIKEY hasn't been set. Skip activating SSL/TLS!"
        return 1; 
    fi

    ENABLE_ICAPS=1
    ENABLE_HTTPS=1

    if [[ ! -d ${HTTPS_CERT_PATH} ]]; then
        if [[ ! -z ${HTTPS_CERT_PATH} ]]; then 
            echo "Warning: '${HTTPS_CERT_PATH}' is not a folder. Skip activating HTTPS!"
        fi
        ENABLE_HTTPS=0
    fi
    if [[ ! -d ${ICAPS_CERT_PATH} ]]; then
        if [[ ! -z ${ICAPS_CERT_PATH} ]]; then 
            echo "Warning: '${ICAPS_CERT_PATH}' is not a folder. Skip activating ICAPS!"
        fi
        ENABLE_ICAPS=0
    fi

    if (( ($ENABLE_HTTPS | $ENABLE_ICAPS) == 0 )); then
        return 1
    fi

    local https_crt_pattern="${HTTPS_CERT_PATH}/*.crt"
    local https_key_pattern="${HTTPS_CERT_PATH}/*.key"
    local https_crt_file
    local https_key_file
    local https_certname
    if [[ $ENABLE_HTTPS == 1 ]]; then
        if compgen -G "${https_crt_pattern}" &> /dev/null && compgen -G "${https_key_pattern}" &> /dev/null; then
            local https_crt_files=($https_crt_pattern)
            local https_key_files=($https_key_pattern)
            https_crt_file=${https_crt_files[0]}
            https_key_file=${https_key_files[0]}
            local https_crt_filename=$(basename "${https_crt_file}")
            local https_key_filename=$(basename "${https_key_file}")
            if [[ ${https_crt_filename%.*} != ${https_key_filename%.*} ]]; then
                echo "Warning: Not found any valid cert files. Please make sure to have 2 files <https_certname>.crt and <https_certname>.key. Skip activating HTTPS!"
                return 1
            else
                https_certname=${https_crt_filename%.*}
            fi
        else
            echo "Warning: Not found any valid cert files. Please make sure to have 2 files <https_certname>.crt and <https_certname>.key. Skip activating HTTPS!"
            return 1
        fi
    fi

    local icaps_crt_pattern="${ICAPS_CERT_PATH}/*.crt"
    local icaps_key_pattern="${ICAPS_CERT_PATH}/*.key"
    local icaps_crt_file
    local icaps_key_file
    local icaps_certname
    if [[ $ENABLE_ICAPS == 1 ]]; then
        if compgen -G "${icaps_crt_pattern}" &> /dev/null && compgen -G "${icaps_key_pattern}" &> /dev/null; then
            local icaps_crt_files=($icaps_crt_pattern)
            local icaps_key_files=($icaps_key_pattern)
            icaps_crt_file=${icaps_crt_files[0]}
            icaps_key_file=${icaps_key_files[0]}
            local icaps_crt_filename=$(basename "${icaps_crt_file}")
            local icaps_key_filename=$(basename "${icaps_key_file}")
            if [[ ${icaps_crt_filename%.*} != ${icaps_key_filename%.*} ]]; then
                echo "Warning: Not found any valid cert files. Please make sure to have 2 files <icaps_certname>.crt and <icaps_certname>.key. Skip activating HTTPS!"
                return 1
            else
                icaps_certname=${icaps_crt_filename%.*}
            fi
        else
            echo "Warning: Not found any valid cert files. Please make sure to have 2 files <icaps_certname>.crt and <icaps_certname>.key. Skip activating HTTPS!"
            return 1
        fi
    fi

	# Add certificate
    for i in {0..3}; do 
        local response=$(curl -k -s -H "apikey: $APIKEY" -w "\n%{http_code}" -X GET "$protocol://localhost:$REST_PORT/admin/config/certs")
        local status_code=$(echo "$response" | tail -n 1)
        local content=$(echo "$response" | sed '$ d')
        if [[ $status_code != 200 ]]; then
            if [[ $i < 3 ]]; then
                echo "Warning: Getting certificates list failed. Retry in 10 seconds. Response ($status_code): $content"
                sleep 10
                continue
            else
                echo "Warning: Getting certificates list failed. Response ($status_code): $content"
                return 1
            fi
        fi
		# Add HTTPS Certificate
    	if [[ $ENABLE_HTTPS == 1 ]]; then
			if [[ $(echo "$content" | jq ".certs | map(select(.name == \"$https_certname\")) | length") > 0 ]]; then
				echo "Info: Certificate with name '$https_certname' for HTTPS existed. Skip adding!"
			else
				new_certs=$(echo "$content" | jq -r ".certs += [{\"name\":\"$https_certname\",\"cert\":\"$https_crt_file\",\"key\":\"$https_key_file\"}]")
				response=$(curl -k -s -H "apikey: $APIKEY" -H "Content-Type: application/json" -d "$new_certs" -w "\n%{http_code}" -X PUT "$protocol://localhost:$REST_PORT/admin/config/certs")
				status_code=$(echo "$response" | tail -n 1)
				content=$(echo "$response" | sed '$ d')
				if [[ $status_code != 200 ]]; then
					if [[ $i < 3 ]]; then
						echo "Warning: Adding certificate failed when activating HTTPS. Retry in 10 seconds. Response ($status_code): $content"
						sleep 10
						continue
					else
						echo "Warning: Adding certificate failed when activating HTTPS. Response ($status_code): $content"
						return 1
					fi
				fi
			fi
		fi
		# Add HTTPS Certificate
    	if [[ $ENABLE_ICAPS == 1 ]]; then
			if [[ $(echo "$content" | jq ".certs | map(select(.name == \"$icaps_certname\")) | length") > 0 ]]; then
				echo "Info: Certificate with name '$icaps_certname' for ICAPS existed. Skip adding!"
			else
				new_certs=$(echo "$content" | jq -r ".certs += [{\"name\":\"$icaps_certname\",\"cert\":\"$icaps_crt_file\",\"key\":\"$icaps_key_file\"}]")
				response=$(curl -k -s -H "apikey: $APIKEY" -H "Content-Type: application/json" -d "$new_certs" -w "\n%{http_code}" -X PUT "$protocol://localhost:$REST_PORT/admin/config/certs")
				status_code=$(echo "$response" | tail -n 1)
				content=$(echo "$response" | sed '$ d')
				if [[ $status_code != 200 ]]; then
					if [[ $i < 3 ]]; then
						echo "Warning: Adding certificate failed when activating HTTPS. Retry in 10 seconds. Response ($status_code): $content"
						sleep 10
						continue
					else
						echo "Warning: Adding certificate failed when activating HTTPS. Response ($status_code): $content"
						return 1
					fi
				fi
			fi
		fi
		
		# Enable SSL/TLS
		local enabled_https_str="true"
		local enabled_icaps_str="true"
		if [[ $ENABLE_HTTPS == 0 ]]; then enabled_https_str="false"; fi
		if [[ $ENABLE_ICAPS == 0 ]]; then enabled_icaps_str="false"; fi
		local ICAPS_BODY=$(jq --null-input \
					--arg cert "$icaps_certname" \
					--argjson enabled "$enabled_icaps_str" \
					'{"cert": $cert, "enabled": $enabled, "ssl_protocols": ["TLSv1.2"]}')
		local PAYLOAD_BODY=$(jq --null-input \
					--arg cert "$https_certname" \
					--argjson enabled "$enabled_https_str" \
					--argjson icaps "$ICAPS_BODY" \
					'{"cert": $cert, "enabled": $enabled, "ssl_protocols": ["TLSv1.2"], "icaps": $icaps}')
        response=$(curl -k -s -H "apikey: $APIKEY" -H "Content-Type: application/json" -d "${PAYLOAD_BODY}" -w "\n%{http_code}" -X PUT "$protocol://localhost:$REST_PORT/admin/config/ssl")
        status_code=$(echo "$response" | tail -n 1)
        content=$(echo "$response" | sed '$ d')

        if [[ $status_code != 200 ]]; then
            if [[ $i < 3 ]]; then
                echo "Warning: Activating SSL/TLS failed. Retry in 10 seconds. Response ($status_code): $content"
                sleep 10
                continue
            else
                echo "Warning: Activating SSL/TLS failed. Response ($status_code): $content"
                return 1
            fi
        else
            break
        fi
    done
}

# Add auto license activation
activate_license() {
    if [[ -z $LICENSE_KEY ]]; then return 1; fi
    if [[ -z $protocol ]]; then return 1; fi
    if [[ -z $APIKEY ]]; then
        echo "Warning: APIKEY hasn't been set. Skip activating license!"
        return 1; 
    fi

    for i in {0..3}; do 
        local response=$(curl -k -s -H "apikey: $APIKEY" -H "Content-Type: application/json" -d "{\"activationKey\":\"$LICENSE_KEY\",\"comment\":\"\",\"quantity\":1}" -w "\n%{http_code}" -X POST "$protocol://localhost:$REST_PORT/admin/license/activation")
        local status_code=$(echo "$response" | tail -n 1)
        local content=$(echo "$response" | sed '$ d')
        if [[ $status_code == 200 ]]; then
            break
        else
            if [[ $i < 3 ]]; then
                echo "Warning: License activation failed. Retry in 10 seconds. Response ($status_code)"
                sleep 10
            else
                echo "Warning: License activation failed. Response ($status_code)"
                return 1
            fi
        fi
    done
}

# Add auto license deactivation
deactivate_license() {
    if [[ -z $LICENSE_KEY ]]; then return 1; fi
    if [[ -z $DEPLOYMENT_ID ]]; then return 1; fi
    if [[ -z $APIKEY ]]; then return 1; fi
    if [[ -z $ACTIVATION_SERVER ]]; then
        ACTIVATION_SERVER="activation.dl.opswat.com"
    fi

    for i in {0..2};
    do 
        local response=$(curl -k -s -w "\n%{http_code}" -X GET "https://$ACTIVATION_SERVER/deactivation?deployment=$DEPLOYMENT_ID&key=$LICENSE_KEY")
        local status_code=$(echo "$response" | tail -n 1)
        if [[ $status_code == 200 || $status_code == 404 ]]; then
            break
        else
            echo "License deactivation response $content with status code $status_code"
        fi
    done
}

# Setup system user for Permission
setup_system_user() {
    if [[ $(id -u) != 0 ]]; then
        RUN_UID=$(id -u)
        RUN_GID=$(id -g)
    fi

    if ! grep -q "${RUN_GROUP}" /etc/group; then
        echo "${RUN_GROUP}:x:${RUN_GID}:" >> /etc/group
    fi
    if ! grep -q "${RUN_USER}" /etc/passwd; then
        echo "${RUN_USER}:x:${RUN_UID}:${RUN_GID}::/home/${RUN_USER}:/bin/bash" >> /etc/passwd
    fi
}

# Import config from file
function join_by { local IFS="$1"; shift; echo "$*"; }

import_config() {
	if [[ -z $IMPORT_CONF_FILE   ]]; then return 1; fi
	if [[ ! -f $IMPORT_CONF_FILE ]]; then return 1; fi
	if [[ -z $IMPORT_CONF_FILE_TARGET ]]; then return 1; fi
	if [[ -z $protocol ]]; then return 1; fi
    if [[ -z $APIKEY ]]; then
        echo "Warning: APIKEY hasn't been set. Skip import configuration!"
        return 1; 
    fi
	
	local lst_path_params=()

	for key in $(echo $IMPORT_CONF_FILE_TARGET | jq -r '.[]'); do
		lst_path_params+=("${key}=1")
	done
	local str_path_params=$( join_by '&' ${lst_path_params[@]} )

	for i in {0..3}; do 
        local response=$(curl -k -s -H "apikey: $APIKEY" -H "Content-Type: application/json" --data-binary "@$IMPORT_CONF_FILE" -w "\n%{http_code}" -X PUT "$protocol://localhost:$REST_PORT/admin/import/configs?$str_path_params")
        local status_code=$(echo "$response" | tail -n 1)
        local content=$(echo "$response" | sed '$ d')
        if [[ $status_code == 200 ]]; then
            break
        elif [[ $status_code == 400 ]]; then
            echo "Warning: Import configuration failed. Response ($status_code) $content"
            _term
            return 1
        else
            if [[ $i < 3 ]]; then
                echo "Warning: Import configuration failed. Retry in 10 seconds. Response ($status_code)"
                sleep 10
            else
                echo "Warning: Import configuration failed. Response ($status_code)"
                return 1
            fi
        fi
    done

}

# Test MD-Core connections
test_md_core_connection() {
    if [[ -z $IMPORT_CONF_FILE   ]]; then return 1; fi
	if [[ ! -f $IMPORT_CONF_FILE ]]; then return 1; fi
	if [[ -z $IMPORT_CONF_FILE_TARGET ]]; then return 1; fi
	if [[ -z $protocol ]]; then return 1; fi
    if [[ -z $TEST_MD_CORE_CONNECTION ]]; then return 1; fi
    if [[ $TEST_MD_CORE_CONNECTION == "false" ]]; then return 1; fi
    if [[ -z $APIKEY ]]; then
        echo "Warning: APIKEY hasn't been set. Skip test MD Core connection!"
        return 1; 
    fi

    local response=$(curl -k -s -H "apikey: $APIKEY" -w "\n%{http_code}" -X GET "$protocol://localhost:$REST_PORT/admin/inventory/serverprofile")
    local status_code=$(echo "$response" | tail -n 1)
    local content=$(echo "$response" | sed '$ d')
    if [[ $status_code != 200 ]]; then
        echo "Error: Getting server profiles list failed. Response ($status_code): $content"
        _term
        return 1
    fi
    local length_profile=$(echo $content | jq -r '.servers | length')
    if [[ $length_profile -le 0 ]]; then
        echo "Info: No server profiles exist. Skip test MD Core connection!"
        return 0
    fi

    for try in {0..3}; do 
        local test_passed="true"
        for ((i=0;i<$length_profile;i++)); do 
            payload=$(echo $content | jq -r ".servers[$i]")
            local resp=$(curl -k -s -H "apikey: $APIKEY" -w "\n%{http_code}" -d "$payload" -X POST "$protocol://localhost:$REST_PORT/admin/inventory/serverprofile/test")
            local st=$(echo "$resp" | tail -n 1)
            local ct=$(echo "$resp" | sed '$ d')
            if [[ $st != 200 ]]; then
                echo "Warning: Test server profiles failed. Response ($st): $ct"
                test_passed="false"
            else
                if [[ $(echo $ct | jq -r '.passed') != "true" ]]; then
                    echo "Warning: Test server profiles failed. Response ($st): $ct"
                    test_passed="false"
                else
                    echo "Info: Test server profiles successfully. Response ($st): $ct"
                fi
            fi
        done

        if [[ $test_passed == "true" ]]; then
            break
        else
            if [[ $try < 3 ]]; then
                echo "Warning: Test server profiles failed. Retry in 10 seconds. Response ($st): $ct"
                sleep 10
            else
                echo "Error: Test server profiles failed. Response ($st): $ct"
                _term
                return 1
            fi
        fi
    done

}

# Add trust root cerfiticate to server
add_cert_to_server() {
    if [[ -z $ICAP_TRUST_CERTS_PATH    ]]; then return 1; fi
    if [[ ! -d $ICAP_TRUST_CERTS_PATH  ]]; then return 1; fi

    cp -rf ${ICAP_TRUST_CERTS_PATH}/* ${OS_CERTS_INSTALL_PATH} 2>/dev/null
    TMPDIR=${ICAP_DATA_PATH} update-ca-certificates
}

# Set retention default 1 week
set_retention(){
    # Set default clean up time is 168 hours
    if [[ -z $APIKEY ]]; then
        echo "Warning: APIKEY hasn't been set. Skip set data retention default 1 week!"
        return 1; 
    fi
    local pay_load_audit="{\"cleanuprange\": $AUDIT_DATA_RETENTION}"
    local pay_load_history="{\"cleanuprange\": $HISTORY_DATA_RETENTION}"
    local resp_audit=$(curl -k -s -H "apikey: $APIKEY" -H "Content-Type: application/json" -w "\n%{http_code}" -X PUT "$protocol://localhost:$REST_PORT/admin/config/auditlog" -d "$pay_load_audit")
    local resp_config=$(curl -k -s -H "apikey: $APIKEY" -H "Content-Type: application/json" -w "\n%{http_code}" -X PUT "$protocol://localhost:$REST_PORT/admin/config/history" -d "$pay_load_history")
    local status_code=$(echo "$resp_audit" | tail -n 1)
    local content=$(echo "$resp_audit" | sed '$ d')
    if [[ $status_code != 200 ]]; then
        echo "Warning: Can not set retention default 1 week for ICAP history clean up ($status_code) $content"
    fi
    status_code=$(echo "$resp_config" | tail -n 1)
    content=$(echo "$resp_config" | sed '$ d')
    if [[ $status_code != 200 ]]; then
        echo "Warning: Can not set retention default 1 week for config history clean up ($status_code) $content"
    fi
}
####################
## Main
####################

#### Handle signal
trap _term SIGTERM SIGINT SIGQUIT

#### Initialize
setup_system_user
add_cert_to_server

init_icap

if ! check_path; then
    exit 1
fi

#### Run application
service mdicapsrv start
tail -f --retry ${LOG_PATH}/mdicapsrv.log 2> /dev/null &
PROCESS_ID=$(pgrep -o mdicapsrv)

wait_rest
if ! is_process_running $PROCESS_ID; then
    exit 1
fi

#### Post run application tasks
# setup_apikey 
wait_user_ignition
activate_ssl_tls
if [[ $ENABLE_HTTPS == 1 ]]; then 
	wait_rest https 
fi
activate_license
get_deployment_id
import_config
test_md_core_connection
set_retention

#### Wait application finished
while [ -e /proc/$PROCESS_ID ]
do
    sleep .6
done

#### Pre stop container tasks
deactivate_license
