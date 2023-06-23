#!/bin/sh
#
# This script launches nginx and the NGINX Controller Agent.
#
echo "------ version 2023.06.23.01 ------"

handle_term()
{
    echo "received TERM signal"
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

wait_term()
{
    wait ${nginx_pid}
    trap '' EXIT INT TERM
    kill -QUIT "${nginx_pid}" 2>/dev/null
    echo "waiting for nginx to stop..."
}

wait_term

echo "nginx-agent process has stopped, exiting."
