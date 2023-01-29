#!/bin/sh
#
# This script launches nginx and the NGINX Controller Agent.
#
echo "------ version 2023.01.29.01 ------"

# Variables
agent_conf_file="/etc/nginx-agent/nginx-agent.conf"
agent_log_file="/var/log/nginx-agent/agent.log"
controller_host=""

handle_term()
{
    echo "received TERM signal"
    echo "stopping nginx-agent ..."
    kill -TERM "${agent_pid}" 2>/dev/null
    echo "stopping nginx ..."
    kill -TERM "${nginx_pid}" 2>/dev/null
}

trap 'handle_term' TERM

# Launch nginx
echo "starting nginx ..."
nginx -g "daemon off;" &

nginx_pid=$!

wait_workers()
{
    while ! pgrep -f 'nginx: worker process' >/dev/null 2>&1; do
        echo "waiting for nginx workers ..."
        sleep 2
    done
}

wait_workers

# Launch nginx-agent
test -n "${ENV_CONTROLLER_HOST}" && \
    controller_host=${ENV_CONTROLLER_HOST}

test -n "${ENV_CONTROLLER_INSTANCE_GROUP}" && \
    instance_group=${ENV_CONTROLLER_INSTANCE_GROUP}

if [ -n "${controller_host}" -o -n "${instance_group}" ]; then
    echo "updating ${agent_conf_file} ..."

    if [ ! -f "${agent_conf_file}" ]; then
      test -f "${agent_conf_file}.default" && \
      cp -p "${agent_conf_file}.default" "${agent_conf_file}" || \
      { echo "no ${agent_conf_file}.default found! exiting."; exit 1; }
    fi

    test -n "${controller_host}" && \
    echo " ---> using controller api url = ${controller_host}" && \
    sh -c "sed -i.old -e 's@^\s\shost:\s.*@  host: $controller_host@' \
	${agent_conf_file}"

    test -f "${agent_conf_file}" && \
    chmod 644 ${agent_conf_file} && \
    chown nginx ${agent_conf_file} > /dev/null 2>&1
fi

if [ -n "${instance_group}" ]; then
  echo "starting nginx-agent with instance group ${instance_group}..."
  /usr/bin/nginx-agent --instance-group ${instance_group} > /dev/null 2>&1 < /dev/null &
else
  echo "starting nginx-agent..."
  /usr/bin/nginx-agent > /dev/null 2>&1 < /dev/null &
fi

agent_pid=$!

if [ $? != 0 ]; then
    echo "couldn't start the agent, please check ${agent_log_file}"
    exit 1
fi

wait_term()
{
    wait ${agent_pid}
    trap '' EXIT INT TERM
    kill -QUIT "${nginx_pid}" 2>/dev/null
    echo "waiting for nginx to stop..."
    wait ${nginx_pid}
    kill -TERM "${agent_pid}" 2>/dev/null
    echo "terminating nginx-agent..."
    # unregister - start
    echo "UNREGISTER instance from ACM"
    export ENV_CONTROLLER_USER=${ENV_CONTROLLER_USER}
    export ENV_CONTROLLER_PASSWORD=${ENV_CONTROLLER_PASSWORD}
    export ENV_CONTROLLER_HOST=${ENV_CONTROLLER_HOST}
    export ENV_CONTROLLER_INSTANCE_GROUP=${ENV_CONTROLLER_INSTANCE_GROUP}
    sleep 60
    sh remove.sh
    echo "UNREGISTER done"
    # unregister - end
}

wait_term

echo "nginx-agent process has stopped, exiting."
