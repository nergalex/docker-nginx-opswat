#!/bin/bash

install_root=$1
library_path=$2
data_dir=$3
runtime_path=$4
temp_path=$5
log_path=$6
conf_path=$7
file=$8

DEFAULT_LIBRARY_PATH=/usr/lib/mdicapsrv
DEFAULT_DATA_DIR=/var/lib/mdicapsrv
DEFAULT_RUNTIME_PATH=/var/run/mdicapsrv
DEFAULT_TEMP_PATH=/var/tmp/mdicapsrv
DEFAULT_LOG_PATH=/var/log/mdicapsrv
DEFAULT_ICAP_CONF_PATH=/etc/mdicapsrv
OTHER_PATHS=(
    "/usr/bin"
    "/usr/sbin"
    "/etc/default"
    "/etc/init.d"
)

sed -i -r "s/(${DEFAULT_LIBRARY_PATH//\//\\/})/${library_path//\//\\/}/g"   "$file"
sed -i -r "s/(${DEFAULT_DATA_DIR//\//\\/})/${data_dir//\//\\/}/g"           "$file"
sed -i -r "s/(${DEFAULT_RUNTIME_PATH//\//\\/})/${runtime_path//\//\\/}/g"   "$file"
sed -i -r "s/(${DEFAULT_TEMP_PATH//\//\\/})/${temp_path//\//\\/}/g"         "$file"
sed -i -r "s/(${DEFAULT_LOG_PATH//\//\\/})/${log_path//\//\\/}/g"           "$file"
sed -i -r "s/(${DEFAULT_ICAP_CONF_PATH//\//\\/})/${conf_path//\//\\/}/g"    "$file"
for path in ${OTHER_PATHS[@]}; do
    sed -i -r "s/(${path//\//\\/})/${install_root//\//\\/}\\1/g" "$file"
done