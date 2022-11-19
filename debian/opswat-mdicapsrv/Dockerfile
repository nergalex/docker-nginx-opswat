### Build dependencies packages
FROM debian:11 AS builder
SHELL [ "/bin/bash", "-c" ]
ENV WORK_DIR  /mdicapsrv
ENV OPENSSL_PATH ${WORK_DIR}/builder/openssl
ENV CURL_PATH ${WORK_DIR}/builder/curl
ENV PYTHON_PATH ${WORK_DIR}/builder/python

RUN apt update -y && \
    apt install -y gcc make wget libfindbin-libs-perl && \
    mkdir -p ${OPENSSL_PATH} ${CURL_PATH} && \
    wget https://www.openssl.org/source/openssl-1.1.1q.tar.gz -O ${WORK_DIR}/openssl-1.1.1q.tar.gz && \
    cd ${WORK_DIR} && tar -xvf openssl-1.1.1q.tar.gz && cd openssl-1.1.1q && \
    ./config -Wl,-rpath,'$(LIBRPATH)' --prefix=${OPENSSL_PATH} --openssldir=${OPENSSL_PATH} && make && make install && rm -rf ${WORK_DIR}/openssl-1.1.1q* && \
    cp -R ${OPENSSL_PATH}/lib/* /usr/local/lib && \
    cp -R ${OPENSSL_PATH}/include/* /usr/local/include && \
    cp -f ${OPENSSL_PATH}/bin/openssl /usr/local/bin/openssl && \
    rm -rf /usr/lib/x86_64-linux-gnu/libssl.so.1.1 && \
    rm -rf /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1 && \
    ln -sf ${OPENSSL_PATH}/lib/libcrypto.so.1.1 /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1 && \
    ln -sf ${OPENSSL_PATH}/lib/libssl.so.1.1 /usr/lib/x86_64-linux-gnu/libssl.so.1.1 && \
     # Upgrade Curl to version 7.84.0 => fixed issue CVE-2022-1292 for OpenSSL version 1.0.2u (dependency of Curl)
    apt remove curl -y && apt autoremove -y && \
    wget https://curl.se/download/curl-7.84.0.tar.gz -O ${WORK_DIR}/curl-7.84.0.tar.gz && \
    cd ${WORK_DIR} && tar -xvf curl-7.84.0.tar.gz && cd curl-7.84.0 && \
    ./configure --prefix=${CURL_PATH} --with-secure-transport --with-ssl --with-openssl && \
    make && make install && ln -sf ${CURL_PATH}/bin/curl /usr/local/bin/curl && rm -rf ${WORK_DIR}/curl-7.84.0* && \
    mkdir -p ${PYTHON_PATH} && \
    apt -y install build-essential libncurses5-dev zlib1g-dev libnss3-dev libgdbm-dev libssl-dev libsqlite3-dev libffi-dev libreadline-dev curl libbz2-dev && \
    wget https://www.python.org/ftp/python/3.10.5/Python-3.10.5.tgz  -O ${WORK_DIR}/Python-3.10.5.tgz && \
    cd ${WORK_DIR} && tar -xvf Python-3.10.5.tgz && cd Python-3.10.5 && \
    ./configure --enable-optimizations --prefix=${PYTHON_PATH} && make altinstall && rm -rf ${WORK_DIR}/Python-3.10.5*

### Stage Build ICAP
FROM debian:11

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

# Define apikey path to store apikey for deactivation
ENV APIKEY_PATH     ${INSTALL_ROOT}/etc/opswat/apikey

# Some convenient keys for building, do not change these
ENV VERSION                     ${VERSION}
ENV PACKAGE_NAME                mdicapsrv_${VERSION}%2Bstretch-1_amd64.deb
ENV WORK_DIR                    /mdicapsrv
ENV PACKAGE_PATTERN             mdicapsrv*.deb
ENV PACKAGE_FILE                ${WORK_DIR}/mdicapsrv.deb
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
ENV OS_CERTS_STORE_PATH         /etc/ssl/certs
ENV OS_CERTS_INSTALL_PATH       /usr/local/share/ca-certificates/
ENV IMPORT_CONF_FILE            ${ICAP_DATA_PATH}/opswat/mdicapsrv-config.json
ENV IMPORT_CONF_FILE_TARGET     '["all"]'
ENV TEST_MD_CORE_CONNECTION     'false'
#Set the default for 1 week 
ENV AUDIT_DATA_RETENTION         168
ENV HISTORY_DATA_RETENTION       168

# Default dir
ENV DEFAULT_RUNTIME_PATH        ${ICAP_DATA_PATH}/var/run/mdicapsrv
ENV DEFAULT_TEMP_PATH           ${ICAP_DATA_PATH}/var/tmp/mdicapsrv
ENV DEFAULT_LOG_PATH            ${ICAP_DATA_PATH}/var/log/mdicapsrv
ENV DEFAULT_DATA_DIR            ${ICAP_DATA_PATH}/var/lib/mdicapsrv
ENV DEFAULT_ICAP_CONF           ${INSTALL_ROOT}/etc/mdicapsrv/mdicapsrv.conf

ENV SYSTEM_DIR                  ${INSTALL_ROOT}/system
ENV PW_PATH                     ${WORK_DIR}/pw

ENV OPENSSL_PATH ${WORK_DIR}/builder/openssl
ENV CURL_PATH ${WORK_DIR}/builder/curl
ENV PYTHON_PATH ${WORK_DIR}/builder/python

COPY --from=builder ${WORK_DIR}/builder ${WORK_DIR}/builder
# Install prerequisites
RUN apt update -y && \
    apt install -y ca-certificates jq procps libldap-2.4-2 && \
    mkdir -p ${WORK_DIR} && \
    cp -R ${OPENSSL_PATH}/lib/* /usr/local/lib && \
    cp -R ${OPENSSL_PATH}/include/* /usr/local/include && \
    cp -f ${OPENSSL_PATH}/bin/openssl /usr/local/bin/openssl && \
    cp -f ${OPENSSL_PATH}/bin/openssl /usr/bin/openssl && \
    rm -rf /usr/lib/x86_64-linux-gnu/libssl.so.1.1 && \
    rm -rf /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1 && \
    cp -f ${OPENSSL_PATH}/lib/libcrypto.so.1.1 /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1 && \
    cp -f ${OPENSSL_PATH}/lib/libssl.so.1.1 /usr/lib/x86_64-linux-gnu/libssl.so.1.1 && \
    ln -sf ${CURL_PATH}/bin/curl /usr/local/bin/curl && \
    ln -sf ${CURL_PATH}/bin/curl /usr/bin/curl && \
    cp -f ${CURL_PATH}/lib/libcurl.so.4 /usr/lib/x86_64-linux-gnu/libcurl.so.4 && \
    ln -sf ${PYTHON_PATH}/bin/python3.10 /usr/local/bin/python3 && \
    ln -sf ${PYTHON_PATH}/bin/python3.10 /usr/bin/python3 && \
    ln -sf ${PYTHON_PATH}/bin/pip3.10 /usr/local/bin/pip3 && \
    ln -sf ${PYTHON_PATH}/bin/pip3.10 /usr/bin/pip3 && \
    apt-get clean all

# Prepare installer
ADD *.* ${WORK_DIR}/
RUN chmod 755 ${WORK_DIR}/entrypoint.sh && \
    if [[ ${VERSION} == "local" ]]; then mv $(compgen -G "${WORK_DIR}/${PACKAGE_PATTERN}") "${PACKAGE_FILE}"; \
    else curl -X GET https://metascanbucket.s3.amazonaws.com/Metadefender/ICAP_Server/${VERSION}-1/debian/debian%209/${PACKAGE_NAME} --output ${PACKAGE_FILE}; fi

# Extract ICAP package
RUN mkdir -p ${INSTALL_ROOT} ${ICAP_DATA_PATH} && \
    cd ${INSTALL_ROOT} && \
    dpkg -i ${PACKAGE_FILE} || sudo apt-get install -f && \
    chmod -R +x ${LIBRARY_PATH} && \
    mkdir -p ${INSTALL_ROOT}/var/run/mdicapsrv && \
    mkdir -p ${INSTALL_ROOT}/var/tmp/mdicapsrv

# Package for troubleshoot
RUN apt-get install --no-install-recommends --no-install-suggests -y \
                        vim  \
                        procps  \
                        binutils  \
                        net-tools  \
                        jq  \
                        tcpdump \
                        apt-utils

# NGINX module
#COPY mdicapsrv-feature_http_protocol_for_nginx_module.deb ${INSTALL_ROOT}
#RUN dpkg -i ${INSTALL_ROOT}/mdicapsrv-feature_http_protocol_for_nginx_module.deb && \
#    rm -f /mdicapsrv-feature_http_protocol_for_nginx_module.deb \
#COPY mdicapsrv-feature_http_protocol_for_nginx_module.deb /
#RUN dpkg-deb -x /mdicapsrv-feature_http_protocol_for_nginx_module.deb ${INSTALL_ROOT} && \
#    rm -f /mdicapsrv-feature_http_protocol_for_nginx_module.deb

# Patch for running with non-root user
RUN chmod 755 ${WORK_DIR}/patch.sh && \
    ${WORK_DIR}/patch.sh ${INSTALL_ROOT} ${LIBRARY_PATH}   ${DATA_DIR}    ${RUNTIME_PATH}    ${TEMP_PATH}    ${LOG_PATH}    ${ICAP_CONF}    ${DEFAULT_ICAP_CONF} && \
    ${WORK_DIR}/patch.sh ${INSTALL_ROOT} ${LIBRARY_PATH}  '${DATA_DIR}'  '${RUNTIME_PATH}'  '${TEMP_PATH}'  '${LOG_PATH}'  '${ICAP_CONF}'   ${INSTALL_ROOT}/etc/logrotate.d/mdicapsrv && \
    ${WORK_DIR}/patch.sh ${INSTALL_ROOT} ${LIBRARY_PATH}  '${DATA_DIR}'  '${RUNTIME_PATH}'  '${TEMP_PATH}'  '${LOG_PATH}'  '${ICAP_CONF}'   ${INSTALL_ROOT}/usr/bin/mdicapsrv-watchdog.sh && \
    ${WORK_DIR}/patch.sh ${INSTALL_ROOT} ${LIBRARY_PATH}  '${DATA_DIR}'  '${RUNTIME_PATH}'  '${TEMP_PATH}'  '${LOG_PATH}'  '${ICAP_CONF}'   ${INSTALL_ROOT}/usr/bin/mdicapsrv-collect-support-data.sh && \
    ${WORK_DIR}/patch.sh ${INSTALL_ROOT} ${LIBRARY_PATH}  '${DATA_DIR}'  '${RUNTIME_PATH}'  '${TEMP_PATH}'  '${LOG_PATH}'  '${ICAP_CONF}'   ${INSTALL_ROOT}/etc/init.d/mdicapsrv && \
    sed -i -r 's/(USER=mdicapsrv)/USER=${RUN_USER}/g'                                                                                       ${INSTALL_ROOT}/etc/init.d/mdicapsrv && \
    sed -i -r "s/(sysctl)/\#\1/g"                                                                                                           ${INSTALL_ROOT}/etc/init.d/mdicapsrv && \
    sed -i -r "s/(ulimit)/\#\1/g"                                                                                                           ${INSTALL_ROOT}/etc/init.d/mdicapsrv && \
    sed -i -r "s/daemon --user \$USER/daemon/g"                                                                                             ${INSTALL_ROOT}/etc/init.d/mdicapsrv && \
    sed -i -r 's/(DAEMON_OPTS=\"\")/DAEMON_OPTS=${ICAP_CONF}/g'                                                                             ${INSTALL_ROOT}/etc/init.d/mdicapsrv && \
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

# Fix library issue on Debian
RUN cp -f /usr/lib/x86_64-linux-gnu/libssl.so.1.1 ${LIBRARY_PATH} && \
    cp -f /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1 ${LIBRARY_PATH}

# Setup services
RUN ln -sf ${SYSTEM_DIR}/mdicapsrv /etc/init.d/mdicapsrv

### External
EXPOSE ${REST_PORT}
EXPOSE ${ICAP_PORT}
EXPOSE ${ICAPS_PORT}

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

