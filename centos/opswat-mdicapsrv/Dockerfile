### Build dependencies packages
FROM centos:7 AS builder
SHELL [ "/bin/bash", "-c" ]

# Install prerequisites
RUN yum -y update && \
    yum install -y make gcc perl-core pcre-devel wget zlib-devel
#########################################
#Install OpenSSL fix vulnerabilities  ###
#########################################
RUN wget https://www.openssl.org/source/openssl-1.1.1p.tar.gz --no-check-certificate && \
    tar -xzvf openssl-1.1.1p.tar.gz && \
    cd openssl-1.1.1p && \
    ./config --prefix=/openssl-dir --openssldir=/etc/ssl --libdir=lib no-shared zlib-dynamic && \
    make install
RUN yum clean all

### ICAP Build
FROM centos:7

SHELL [ "/bin/bash", "-c" ]

### Meta
LABEL build-version="${VERSION}"
LABEL maintainer="support@opswat.com"
LABEL name="OPSWAT MetaDefender ICAP Server"
LABEL vendor="OPSWAT"
LABEL license=""

# Product version for downloading installer package, ignored if use local installer
ARG VERSION=local

# User and path for installing ICAP and running
ENV RUN_USER        mdicapsrv
ENV RUN_GROUP       mdicapsrv
ENV RUN_UID         1000
ENV RUN_GID         1000
ENV INSTALL_ROOT    /opt/mdicapsrv

# MetaDefender ICAP internal configurations
ENV REST_PORT       8048
ENV ICAP_PORT       1344
ENV ICAPS_PORT      11344
ENV NGINX_PORT      8043
ENV NGINXS_PORT     8443

# Define apikey path to store apikey for deactivation
ENV APIKEY_PATH     ${INSTALL_ROOT}/etc/opswat/apikey

# Some convenient keys for building, do not change these
ENV VERSION                     ${VERSION}
ENV PACKAGE_NAME                mdicapsrv-${VERSION}-1.x86_64.rpm
ENV WORK_DIR                    /mdicapsrv
ENV PACKAGE_PATTERN             mdicapsrv-*.rpm
ENV PACKAGE_FILE                ${WORK_DIR}/mdicapsrv.rpm
ENV PATH_MATCH                  /[a-zA-Z0-9/.]*
ENV LIBRARY_PATH                ${INSTALL_ROOT}/usr/lib/mdicapsrv
ENV QT_PLUGIN_PATH              ${LIBRARY_PATH}/plugins
ENV LD_LIBRARY_PATH             ${LD_LIBRARY_PATH}:${LIBRARY_PATH}

# Unify writable folders into one configurable path
ENV ICAP_DATA_PATH              ${INSTALL_ROOT}/icap_data
ENV IGNITION_FILE               ${ICAP_DATA_PATH}/opswat/mdicapsrv.conf
ENV RUNTIME_PATH                ${ICAP_DATA_PATH}/var/run/mdicapsrv
ENV TEMP_PATH                   ${ICAP_DATA_PATH}/var/tmp/mdicapsrv
ENV LOG_PATH                    ${ICAP_DATA_PATH}/var/log/mdicapsrv
ENV DATA_DIR                    ${ICAP_DATA_PATH}/var/lib/mdicapsrv
ENV ICAP_CONF                   ${ICAP_DATA_PATH}/mdicapsrv.conf
ENV ICAP_CONF_JSON              ''
ENV ICAP_TRUST_CERTS_PATH       ${ICAP_DATA_PATH}/trust_certs
ENV OS_CERTS_STORE_PATH         /etc/pki/ca-trust
ENV OS_CERTS_INSTALL_PATH       /etc/pki/ca-trust/source/anchors/
ENV IMPORT_CONF_FILE            ${ICAP_DATA_PATH}/opswat/mdicapsrv-config.json
ENV IMPORT_CONF_FILE_TARGET     '["all"]'
ENV TEST_MD_CORE_CONNECTION     'false'
#Set the default for 1 week 
ENV AUDIT_DATA_RETENTION         168
ENV HISTORY_DATA_RETENTION       168
# Support password to encrypt/decrypt exported JSON
ENV IMPORT_CONFIG_FILE_PASS      ""

# Default dir
ENV DEFAULT_RUNTIME_PATH        ${ICAP_DATA_PATH}/var/run/mdicapsrv
ENV DEFAULT_TEMP_PATH           ${ICAP_DATA_PATH}/var/tmp/mdicapsrv
ENV DEFAULT_LOG_PATH            ${ICAP_DATA_PATH}/var/log/mdicapsrv
ENV DEFAULT_DATA_DIR            ${ICAP_DATA_PATH}/var/lib/mdicapsrv
ENV DEFAULT_ICAP_CONF           ${INSTALL_ROOT}/etc/mdicapsrv/mdicapsrv.conf

ENV SYSTEM_DIR                  ${INSTALL_ROOT}/system
ENV PW_PATH                     ${WORK_DIR}/pw
COPY --from=builder /openssl-dir /usr
# Install prerequisites
RUN yum -y install epel-release && \
    yum -y install jq && \
    yum clean all

# Prepare installer
ADD *.* ${WORK_DIR}/
RUN chmod 755 ${WORK_DIR}/entrypoint.sh && \
    if [[ ${VERSION} == "local" ]]; then mv $(compgen -G "${WORK_DIR}/${PACKAGE_PATTERN}") "${PACKAGE_FILE}"; \
    else curl -X GET https://metascanbucket.s3.amazonaws.com/Metadefender/ICAP_Server/${VERSION}-1/centos/${PACKAGE_NAME} --output ${PACKAGE_FILE}; fi

# Replace systemD with script based solution as Docker container cannot be run in privileged mode in ACI
RUN mv -f ${WORK_DIR}/systemctl.py /usr/bin/systemctl && \
    chmod 755 /usr/bin/systemctl

# Extract ICAP package
RUN mkdir -p ${INSTALL_ROOT} ${ICAP_DATA_PATH} && \
    rpm2cpio ${PACKAGE_FILE} | (cd ${INSTALL_ROOT}; cpio -idm --quiet) && \
    chmod -R +x ${LIBRARY_PATH} && \
    mkdir -p ${INSTALL_ROOT}/var/run/mdicapsrv && \
    mkdir -p ${INSTALL_ROOT}/var/tmp/mdicapsrv

# Patch for running with non-root user
RUN chmod 755 ${WORK_DIR}/patch.sh && \
    chmod 755 ${WORK_DIR}/* && \
    ${WORK_DIR}/patch.sh ${INSTALL_ROOT} ${LIBRARY_PATH}   ${DATA_DIR}    ${RUNTIME_PATH}    ${TEMP_PATH}    ${LOG_PATH}    ${ICAP_CONF}    ${DEFAULT_ICAP_CONF} && \
    ${WORK_DIR}/patch.sh ${INSTALL_ROOT} ${LIBRARY_PATH}  '${DATA_DIR}'  '${RUNTIME_PATH}'  '${TEMP_PATH}'  '${LOG_PATH}'  '${ICAP_CONF}'   ${INSTALL_ROOT}/etc/logrotate.d/mdicapsrv && \
    ${WORK_DIR}/patch.sh ${INSTALL_ROOT} ${LIBRARY_PATH}  '${DATA_DIR}'  '${RUNTIME_PATH}'  '${TEMP_PATH}'  '${LOG_PATH}'  '${ICAP_CONF}'   ${INSTALL_ROOT}/usr/bin/mdicapsrv-watchdog.sh && \
    ${WORK_DIR}/patch.sh ${INSTALL_ROOT} ${LIBRARY_PATH}  '${DATA_DIR}'  '${RUNTIME_PATH}'  '${TEMP_PATH}'  '${LOG_PATH}'  '${ICAP_CONF}'   ${INSTALL_ROOT}/usr/bin/mdicapsrv-collect-support-data.sh && \
    ${WORK_DIR}/patch.sh ${INSTALL_ROOT} ${LIBRARY_PATH}  '${DATA_DIR}'  '${RUNTIME_PATH}'  '${TEMP_PATH}'  '${LOG_PATH}'  '${ICAP_CONF}'   ${INSTALL_ROOT}/usr/lib/systemd/system/mdicapsrv.service && \
    sed -i -r "s/(User=mdicapsrv)/User=${RUN_USER}/g"                                                                                       ${INSTALL_ROOT}/usr/lib/systemd/system/mdicapsrv.service && \
    sed -i -r 's/(ExecStart=.*)/\1 ${ICAP_CONF}/g'                                                                                          ${INSTALL_ROOT}/usr/lib/systemd/system/mdicapsrv.service && \
    sed -i -r "/ExecStartPre=.*/d"                                                                                                          ${INSTALL_ROOT}/usr/lib/systemd/system/mdicapsrv.service && \
    sed -i -r "/PIDFile=.*/d"                                                                                                               ${INSTALL_ROOT}/usr/lib/systemd/system/mdicapsrv.service && \
    sed -i '2s;^;source ${SYSTEM_DIR}/mdicapsrv\n;'                                                                                         ${INSTALL_ROOT}/usr/bin/mdicapsrv-collect-support-data.sh

# Update ICAP config file with custom path
RUN echo "[internal]"                                       >> ${DEFAULT_ICAP_CONF} && \
    echo "nginxlibrarypath=${LIBRARY_PATH}"                 >> ${DEFAULT_ICAP_CONF} && \
    echo "nginxprefix=${INSTALL_ROOT}"                      >> ${DEFAULT_ICAP_CONF} && \
    echo "runtime_directory=${RUNTIME_PATH}"                >> ${DEFAULT_ICAP_CONF} && \
    echo "data_directory=${DATA_DIR}"                       >> ${DEFAULT_ICAP_CONF} && \
    echo "ignition_file_location=${IGNITION_FILE}"          >> ${DEFAULT_ICAP_CONF} && \
    mkdir -p ${SYSTEM_DIR}/dev ${SYSTEM_DIR}/tmp ${SYSTEM_DIR}/var/tmp ${SYSTEM_DIR}/var/log && \
    ln -sf /dev/null ${SYSTEM_DIR}/dev/null && \
    rm -rf /var/log /tmp /var/tmp && \
    ln -sf ${SYSTEM_DIR}/var/log /var/log && \
    ln -sf ${SYSTEM_DIR}/var/tmp /var/tmp && \
    ln -sf ${SYSTEM_DIR}/tmp /tmp

# Setup services
RUN cp -f ${INSTALL_ROOT}/usr/lib/systemd/system/mdicapsrv* /usr/lib/systemd/system/ && \
    systemctl enable mdicapsrv

### External
EXPOSE ${REST_PORT}
EXPOSE ${ICAP_PORT}
EXPOSE ${ICAPS_PORT}
EXPOSE ${NGINX_PORT}
EXPOSE ${NGINXS_PORT}

# Workaround for arbitrary UID/GID
RUN mkdir -p "${PW_PATH}" && \
    chmod 777 "${PW_PATH}" && \
    mv /etc/passwd /etc/group "${PW_PATH}" && \
    chmod 666 "${PW_PATH}/passwd" "${PW_PATH}/group" && \
    ln -sf "${PW_PATH}/passwd" /etc/passwd && \
    ln -sf "${PW_PATH}/group" /etc/group && \
    chmod 777 -R ${ICAP_DATA_PATH} ${OS_CERTS_STORE_PATH} ${OS_CERTS_INSTALL_PATH} ${SYSTEM_DIR}

VOLUME [ "${ICAP_DATA_PATH}", "${PW_PATH}", "${SYSTEM_DIR}", "${OS_CERTS_STORE_PATH}", "${OS_CERTS_INSTALL_PATH}"]

### Start
ENTRYPOINT ${WORK_DIR}/entrypoint.sh
