#!/bin/bash
set -eou pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"

for inc in $(ls $DIR/includes | sort -n); do
    source $DIR/includes/$inc
done

export HOSTNAME=$(hostname)

export RUNDECK_HOME=${RUNDECK_HOME:-/home/rundeck}
export HOME=$RUNDECK_HOME

echo "********** ${HOME}"

# Store custom exec command if set so it will not be lost when unset later
EXEC_CMD="${RUNDECK_EXEC_CMD:-}"

export REMCO_HOME=${REMCO_HOME:-/etc/remco}
export REMCO_RESOURCE_DIR=${REMCO_HOME}/resources.d
export REMCO_TEMPLATE_DIR=${REMCO_HOME}/templates
export REMCO_TMP_DIR=/tmp/remco-partials

# Create temporary directories for config partials
mkdir -p ${REMCO_TMP_DIR}/framework
mkdir -p ${REMCO_TMP_DIR}/rundeck-config
mkdir -p ${REMCO_TMP_DIR}/artifact-repositories

remco -config "${REMCO_HOME}/config.toml"

# Generate a new server UUID
if [[ "${RUNDECK_SERVER_UUID}" = "RANDOM" ]] ; then
    RUNDECK_SERVER_UUID=$(uuidgen)
fi
echo "rundeck.server.uuid = ${RUNDECK_SERVER_UUID}" > ${REMCO_TMP_DIR}/framework/server-uuid.properties

# Combine partial config files
cat ${REMCO_TMP_DIR}/framework/* >> etc/framework.properties
cat ${REMCO_TMP_DIR}/rundeck-config/* >> server/config/rundeck-config.properties
cat ${REMCO_TMP_DIR}/artifact-repositories/* >> server/config/artifact-repositories.yaml


# Store settings that may be unset in script variables
SETTING_RUNDECK_FORWARDED="${RUNDECK_SERVER_FORWARDED:-false}"

# Unset all RUNDECK_* environment variables
if [[ "${RUNDECK_ENVARS_UNSETALL:-true}" = "true" ]] ; then
    unset `env | awk -F '=' '{print $1}' | grep -e '^RUNDECK_'`
fi

# Unset specific environment variables
if [[ ! -z "${RUNDECK_ENVARS_UNSETS:-}" ]] ; then
    unset $RUNDECK_ENVARS_UNSETS
    unset RUNDECK_ENVARS_UNSETS
fi

# Support Arbitrary User IDs on OpenShift
if ! whoami &> /dev/null; then
    if [ -w /etc/passwd ]; then
        TMP_PASSWD=$(mktemp)
        cat /etc/passwd > "${TMP_PASSWD}"
        sed -i "\#rundeck#c\rundeck:x:$(id -u):0:rundeck user:${HOME}:/bin/bash" "${TMP_PASSWD}"
        cat "${TMP_PASSWD}" > /etc/passwd
        rm "${TMP_PASSWD}"
    fi
fi

# Exec custom command if provided
if [[ -n "${EXEC_CMD}" ]] ; then
    # shellcheck disable=SC2086
    exec $EXEC_CMD
fi

# ----------------------------------------------------------------
# START - Entrypoint actions for Shared File System - Before Rundeck
# ----------------------------------------------------------------

export SHARED_FILES_PATH=${SHARED_FILES_PATH:-}
export VOUCH_LOG_FILE="/vouch-proxy/vouch-proxy.log"
export VOUCH_DELAY=${VOUCH_DELAY:-10}

if [[ ! -z "${SHARED_FILES_PATH}" ]] ; then

    #Making folders if they don't exist
    if [ ! -d "${SHARED_FILES_PATH}/logs/rundeck" ]; then
        sudo mkdir -p "${SHARED_FILES_PATH}/logs/rundeck" 
    fi
    
    if [ ! -d "${SHARED_FILES_PATH}/logs/nginx" ]; then
        sudo mkdir -p "${SHARED_FILES_PATH}/logs/nginx" 
    fi
    
    if [ ! -d "${SHARED_FILES_PATH}/logs/vouch-proxy" ]; then
        sudo mkdir -p "${SHARED_FILES_PATH}/logs/vouch-proxy" 
    fi
    
    if [ ! -d "${SHARED_FILES_PATH}/libext" ]; then
        sudo mkdir -p "${SHARED_FILES_PATH}/libext" 
    fi

    if [ ! -d "${SHARED_FILES_PATH}/projects" ]; then
        sudo mkdir -p "${SHARED_FILES_PATH}/projects" 
    fi

    if [ ! -d "${SHARED_FILES_PATH}/backup" ]; then
        sudo mkdir -p "${SHARED_FILES_PATH}/backup" 
    fi
        
    #chown the directory for rundeck
    sudo chown -R rundeck:root "${SHARED_FILES_PATH}"

    #on start... take all the old logs and archive them up.
    tar --exclude="${SHARED_FILES_PATH}/libext" --exclude="${SHARED_FILES_PATH}/backup" -zcf "${SHARED_FILES_PATH}/backup/$(date +%Y-%m-%d_%H-%M-%S).tar.gz" "${SHARED_FILES_PATH}"
    sudo find "${SHARED_FILES_PATH}/logs/" -name "*.log" -type f -delete 

    #setting log file for Vouch
    export VOUCH_LOG_FILE="${SHARED_FILES_PATH}/logs/vouch-proxy/vouch-proxy.log"

fi

# ----------------------------------------------------------------
# END - Entrypoint actions for Shared File System - Before Rundeck
# ----------------------------------------------------------------


# ----------------------------------------------------------------
# START - Entrypoint actions for SSO
# ----------------------------------------------------------------

echo "Starting NGINX"

#sudo service nginx start &

/usr/sbin/nginx &

echo "Starting Rundeck"

# ----------------------------------------------------------------
# END - Entrypoint actions for SSO
# ----------------------------------------------------------------

java \
    -XX:+UnlockExperimentalVMOptions \
    -XX:MaxRAMPercentage="${JVM_MAX_RAM_PERCENTAGE}" \
    -Dlog4j.configurationFile="${HOME}/server/config/log4j2.properties" \
    -Dlogging.config="file:${HOME}/server/config/log4j2.properties" \
    -Dloginmodule.conf.name=jaas-loginmodule.conf \
    -Dloginmodule.name=rundeck \
    -Drundeck.jaaslogin=true \
    -Drundeck.jetty.connector.forwarded="${SETTING_RUNDECK_FORWARDED}" \
    "${@}" \
    -jar rundeck.war &

# ----------------------------------------------------------------
# START - Entrypoint actions for Shared File System - After Rundeck
# ----------------------------------------------------------------

if [[ ! -z "${SHARED_FILES_PATH}" ]] ; then
    #Wait for rundeck to startup...
    echo "Waiting for ${VOUCH_DELAY} seconds to start Vouch"
    sleep ${VOUCH_DELAY}s
    #sync libext just in case the WAR has new files
    echo "Syncing Libext"
    cp -ur "${HOME}/libext/"* "${SHARED_FILES_PATH}/libext" &
fi

echo "Starting Vouch"
/vouch-proxy/vouch-proxy 2>&1 | tee -a "${VOUCH_LOG_FILE}"  

# ----------------------------------------------------------------
# END - Entrypoint actions for Shared File System - After Rundeck
# ----------------------------------------------------------------