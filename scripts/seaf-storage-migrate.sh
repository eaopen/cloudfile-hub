#!/bin/bash

SCRIPT=$(readlink -f "$0")
INSTALLPATH=$(dirname "${SCRIPT}")
TOPDIR=$(dirname "${INSTALLPATH}")
central_config_dir=${TOPDIR}/conf
seafile_data_dir=${TOPDIR}/seafile-data
migrator=${INSTALLPATH}/seafile/bin/seaf-storage-migrate

export SEAFILE_LD_LIBRARY_PATH=${INSTALLPATH}/seafile/lib/:${INSTALLPATH}/seafile/lib64:${LD_LIBRARY_PATH}
export SEAFILE_CENTRAL_CONF_DIR=${central_config_dir}

usage() {
    echo "usage: $(basename "$0") <repo_id> <target_storage_id>"
    echo "Stop Seafile first. Source objects are retained for rollback."
}

if [ "$#" -ne 2 ] || [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    usage
    exit 1
fi

if [ ! -d "${seafile_data_dir}" ]; then
    echo "Error: Seafile data directory does not exist."
    exit 1
fi

for process_pattern in "seaf-server" "/fileserver"; do
    if pgrep -f "${process_pattern}" >/dev/null 2>&1; then
        echo "Error: seaf-server and fileserver must be stopped before migration."
        exit 1
    fi
done

if [ -z "${JWT_PRIVATE_KEY}" ]; then
    if [ ! -f "${central_config_dir}/.env" ]; then
        echo "Error: ${central_config_dir}/.env does not exist."
        exit 1
    fi
    set -a
    # shellcheck disable=SC1090
    source "${central_config_dir}/.env"
    set +a
fi

LD_LIBRARY_PATH=${SEAFILE_LD_LIBRARY_PATH} "${migrator}" \
    -d "${seafile_data_dir}" \
    -F "${central_config_dir}" \
    "$1" "$2"
