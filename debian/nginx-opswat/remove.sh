curl --connect-timeout 30 --retry 10 --retry-delay 5 -sk -u "${ENV_CONTROLLER_USER}:${ENV_CONTROLLER_PASSWORD}" --header 'Content-Type: application/json' -X GET --url "https://${ENV_CONTROLLER_HOST}/api/platform/v1/instances?instGroupName=${ENV_CONTROLLER_INSTANCE_GROUP}" -o instances.json
ENV_SYS_UID=$(jq '.items[] | select(.displayName == "'$(hostname)'") | .systemUid' instances.json)
ENV_SYS_UID=$(echo "${ENV_SYS_UID}" | tr -d '"')
ENV_INSTANCE_UID=$(jq '.items[] | select(.displayName == "'$(hostname)'") | .uid' instances.json)
ENV_INSTANCE_UID=$(echo "${ENV_INSTANCE_UID}" | tr -d '"')
echo "system ID: ${ENV_SYS_UID}"
echo "instance ID: ${ENV_INSTANCE_UID}"
curl --connect-timeout 30 --retry 10 --retry-delay 5 -sk -u "${ENV_CONTROLLER_USER}:${ENV_CONTROLLER_PASSWORD}" -X DELETE --url "https://${ENV_CONTROLLER_HOST}/api/platform/v1/systems/${ENV_SYS_UID}/instances/${ENV_INSTANCE_UID}"
