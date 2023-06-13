#!/usr/bin/env bash
#------------------------------------------------------------------------------------------------------------------------------------------------
# Replaces a remote spin-service with localhost for local debugging and development.
#
# Usage: ./proxy.sh <spinnaker namespace> <service name>
# 
# This script requires openssh client to be installed, and a id_rsa key to be available in you ~/.ssh folder.
# In case of issues:
# be sure to use rsa key e.g. ssh-keygen -t rsa -b 4096 -C "your_email@example.com" instead of ssh-keygen -t ed2551
# When creating the rsa key set it without a password
# you can delete the localhost:2222 entry from known hosts if the service/pod had been tear down
# make sure your keys have 600 permissions (as in chmod 600 ./id_rsa; chmod 600./id_rsa.pub see https://stackoverflow.com/a/4450653/6252395)
#------------------------------------------------------------------------------------------------------------------------------------------------

SPIN_NS=$1
INPUT_SERVICE=$2

[[ $SPIN_NS == "" || $INPUT_SERVICE == "" ]] && echo "Usage: ./$(basename "$0") <spinnaker namespace> <service name>" && exit 1

ROOT_DIR="$(
  cd "$(dirname "$0")" >/dev/null 2>&1 || exit 1
  pwd -P
)"
OUT=/tmp/port-forward.log
INCOMING_PORT=""
PORT_FORWARDS=()
BKG_PIDS=()

function log() {
  RED='\033[0;31m'
  GREEN='\033[0;32m'
  ORANGE='\033[0;33m'
  CYAN='\033[0;36m'
  NC='\033[0m'
  LEVEL=$1
  MSG=$2
  case $LEVEL in
  "INFO") HEADER_COLOR=$GREEN MSG_COLOR=$NS ;;
  "WARN") HEADER_COLOR=$ORANGE MSG_COLOR=$ORANGE ;;
  "KUBE") HEADER_COLOR=$CYAN MSG_COLOR=$CYAN ;;
  "ERROR") HEADER_COLOR=$RED MSG_COLOR=$NS ;;
  esac
  printf "${HEADER_COLOR}[%-5.5s]${NC} ${MSG_COLOR}%b${NC}" "${LEVEL}" "${MSG}"
}

function info() {
  log "INFO" "$1"
}

function warn() {
  log "WARN" "$1"
}

function error() {
  log "ERROR" "$1" && cleanup && exit 1
}

function ask() {
  local yn
  while true ; do
    log ">>>>>" "$1 (y/n) "
    read -r yn
    case $yn in
      [Yy]* ) return ;;
      [Nn]* ) return 1 ;;
      * ) echo "Please answer y or n.";;
    esac
  done
}

function parse_input {
  [[ $INPUT_SERVICE =~ spin-.* ]] && SERVICE=$INPUT_SERVICE || SERVICE=spin-$INPUT_SERVICE
  if ! kubectl get ns "$SPIN_NS" > /dev/null 2>&1 ; then error "Namespace \"$SPIN_NS\" not found\n" ; fi
  # Check openssh keys
  if test -f "$ROOT_DIR/id_rsa.pub" ; then
    return # all good
  fi
  if test -f "$HOME/.ssh/id_rsa.pub" &&
    ask "Do wish to use your existing id_rsa.pub key?"; then
    cp "$HOME/.ssh/id_rsa.pub" "$ROOT_DIR/id_rsa.pub"
    return
  fi
  error "You need to provide a file \"id_rsa.pub\" on this directory to connect to connect by ssh to the proxy\n" ;
}

function get_pod_name {
  if ! PODS=$(kubectl -n $SPIN_NS get pod | grep -e "^$1" 2>/dev/null) ; then
    info "No pods were found matching \"$1\" in $SPIN_NS namespace\n"
    return 1
  else
    [[ $(echo "$PODS" | wc -l) -gt 1 ]] && warn "More than one pod found for $1, connecting to the first one\n" && PODS=$(echo "$PODS" | head -1)
    POD=$(echo "$PODS" | awk '{print $1}')
  fi
}

function resolve_ports {
  # Resolve spin-redis or redis pod name
  if ! PODS=$(kubectl -n $SPIN_NS get pod | grep -e "^spin-redis" 2>/dev/null) ; then
    PODS=$(kubectl -n $SPIN_NS get pod | grep -e "^redis" 2>/dev/null)
  fi
  POD=$(echo "$PODS" | awk '{print $1}') && PORT_FORWARDS+=("entry=($POD 6379)")

  case ${SERVICE%-*-*} in
  "spin-gate")
    INCOMING_PORT=8084
    get_pod_name "spin-orca" && PORT_FORWARDS+=("entry=($POD 8083)")
    get_pod_name "spin-front50" && PORT_FORWARDS+=("entry=($POD 8080)")
    get_pod_name "spin-echo" && PORT_FORWARDS+=("entry=($POD 8089)")
    get_pod_name "spin-clouddriver" && PORT_FORWARDS+=("entry=($POD 7002)")
    get_pod_name "spin-fiat" && PORT_FORWARDS+=("entry=($POD 7003)")
    ;;
  "spin-orca")
    INCOMING_PORT=8083
    get_pod_name "spin-front50" && PORT_FORWARDS+=("entry=($POD 8080)")
    get_pod_name "spin-echo" && PORT_FORWARDS+=("entry=($POD 8089)")
    get_pod_name "spin-rosco" && PORT_FORWARDS+=("entry=($POD 8087)")
    get_pod_name "spin-clouddriver" && PORT_FORWARDS+=("entry=($POD 7002)")
    ;;
  "spin-echo")
    INCOMING_PORT=8089
    get_pod_name "spin-front50" && PORT_FORWARDS+=("entry=($POD 8080)")
    get_pod_name "spin-orca" && PORT_FORWARDS+=("entry=($POD 8083)")
    ;;
  "spin-igor")
    INCOMING_PORT=8088
    get_pod_name "spin-echo" && PORT_FORWARDS+=("entry=($POD 8089)")
    get_pod_name "spin-front50" && PORT_FORWARDS+=("entry=($POD 8080)")
    get_pod_name "spin-orca" && PORT_FORWARDS+=("entry=($POD 8083)")
    get_pod_name "spin-clouddriver" && PORT_FORWARDS+=("entry=($POD 7002)")
    ;;
  "spin-rosco")
    INCOMING_PORT=8087
    get_pod_name "spin-echo" && PORT_FORWARDS+=("entry=($POD 8089)")
    get_pod_name "spin-front50" && PORT_FORWARDS+=("entry=($POD 8080)")
    get_pod_name "spin-orca" && PORT_FORWARDS+=("entry=($POD 8083)")
    get_pod_name "spin-clouddriver" && PORT_FORWARDS+=("entry=($POD 7002)")
    ;;
  "spin-clouddriver")
    INCOMING_PORT=7002
    get_pod_name "mysql" && PORT_FORWARDS+=("entry=($POD 3306)")
    get_pod_name "spin-fiat" && PORT_FORWARDS+=("entry=($POD 7003)")
    get_pod_name "spin-front50" && PORT_FORWARDS+=("entry=($POD 8080)")
    ;;
  "spin-front50")
    INCOMING_PORT=8080
    get_pod_name "mysql" && PORT_FORWARDS+=("entry=($POD 3306)")
    get_pod_name "minio" && PORT_FORWARDS+=("entry=($POD 9000)")
    ;;
  "spin-fiat")
    INCOMING_PORT=7003
    get_pod_name "mysql" && PORT_FORWARDS+=("entry=($POD 3306)")
    get_pod_name "spin-front50" && PORT_FORWARDS+=("entry=($POD 8080)")
    get_pod_name "spin-clouddriver" && PORT_FORWARDS+=("entry=($POD 7002)")
    get_pod_name "spin-igor" && PORT_FORWARDS+=("entry=($POD 8088)")
    ;;
  "spin-terraformer")
    INCOMING_PORT=7088
    get_pod_name "spin-clouddriver" && PORT_FORWARDS+=("entry=($POD 7002)")
    ;;
  *) error "Unknown service name: \"${SERVICE%-*-*}\"\n"
  esac
  get_pod_name "spin-proxy" && PORT_FORWARDS+=("entry=($POD 2222)")
}

function forward_port {
  CMD="kubectl -n $SPIN_NS port-forward $1 $2"
  log "KUBE" "$CMD\n"
  if ! PID=$(pgrep -f "$CMD") ; then
    $CMD >> "$OUT" 2>&1 & sleep 1
    disown
    if ! PID=$(pgrep -f "$CMD") ; then
      error "Could not forward port $2. If you want to omit it, comment the relevant line in \"resolve_ports\" function of this script.\nMake sure you have the permissions described in the role $ROOT_DIR/rbac.yml and the corresponding rolebinding for your user\n"
    else
      BKG_PIDS+=("entry=($1 $2 $PID)")
    fi
  else
    info "Found port $2 already forwarded with PID $PID\n"
    BKG_PIDS+=("entry=($1 $2 $PID)")
  fi
}

function forward_all_ports {
  info "Forwarding ports\n"
  for entry in "${PORT_FORWARDS[@]}"; do
    eval $entry
    forward_port "${entry[0]}" "${entry[1]}"
  done
  sleep 1
}

function deploy_proxy {
  info "Deploying proxy...\n"
  CMD="kubectl -n $SPIN_NS apply -k $ROOT_DIR"
  log "KUBE" "$CMD\n"
  ERR_OUT=$({ $CMD >> "$OUT" ; } 2>&1)
  EXIT_CODE=$?
  [[ $EXIT_CODE != 0 ]] && error "Unable to deploy proxy: $ERR_OUT\nMake sure you have the permissions described in the role $ROOT_DIR/rbac.yml and the corresponding rolebinding for your user\n"
  READY=$(kubectl -n $SPIN_NS get deployment spin-proxy -o json | jq '.status.readyReplicas')
  while [[ $READY != "1" ]] ; do
    sleep 2
    READY=$(kubectl -n $SPIN_NS get deployment spin-proxy -o json | jq '.status.readyReplicas')
  done
}

function open_ssh {
  info "Establishing ssh connection with proxy\n"
  CMD="ssh -i id_rsa -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -TNngR "$INCOMING_PORT:localhost:${OUTGOING_PORT:-$INCOMING_PORT}" ssh://spinnaker@localhost:2222"
  $CMD > "$OUT.ssh" 2>&1 & disown
  if ! PID=$(pgrep -f "$CMD") ; then
    error "Unable to open ssh connection\n$(cat "$OUT.ssh")\nVerify that you have openssh installed, and that 'open_ssh' function in this script refers to the id file you want to use.\n"
  fi
}

function make_selector_patch {
  patch=$(
    cat <<-EOF
spec:
  selector:
    app: spin
    cluster: $1
EOF
  )
}

function patch_services {
  info "Redirecting remote $SERVICE service to spin-proxy pods\n"
  make_selector_patch spin-proxy
  log "KUBE" "kubectl -n $SPIN_NS patch service $SERVICE...\n"
  ERR_OUT=$({ kubectl -n $SPIN_NS patch service $SERVICE --patch "$patch" ; } 2>&1)
  if [[ $? != 0 ]]; then
    error "$ERR_OUT\nMake sure you have the permissions described in the role $ROOT_DIR/rbac.yml and the corresponding rolebinding for your user\n"
  fi
}

function scale_deployment {
  log "KUBE" "kubectl -n $SPIN_NS scale --replicas=$1 deployment/$SERVICE\n"
  ERR_OUT=$({ kubectl -n $SPIN_NS scale --replicas=$1 deployment/$SERVICE ; } 2>&1)
  if [[ $? != 0 ]]; then
    error "$ERR_OUT\nMake sure you have the permissions described in the role $ROOT_DIR/rbac.yml and the corresponding rolebinding for your user\n"
  fi
}

function wait {
  spin[0]="-"
  spin[1]="\\"
  spin[2]="|"
  spin[3]="/"
  while true ; do
    for i in "${!BKG_PIDS[@]}"; do
      eval ${BKG_PIDS[$i]}
      if ! ps -p "${entry[2]}" > /dev/null 2>&1 ; then
        echo "" && info "Lost connection to ${entry[0]}:${entry[1]}, reconnecting\n"
        unset BKG_PIDS["$i"]
        forward_port "${entry[0]}" "${entry[1]}"
      fi
    done
    for i in "${spin[@]}" ; do
      info "Connected. You can now run your local $SERVICE: $i"
      echo -ne "\r"
      sleep 0.3
    done
  done
}

function cleanup {
  trap '' INT # Prevent infinite cycle when spamming Ctrl-C
  echo ""
  warn "Stopping port forwards\n"
  for entry in "${BKG_PIDS[@]}"; do
    eval $entry
    kill -9 "${entry[2]}" >> "$OUT" 2>&1
  done
  warn "Restoring remote $SERVICE: service\n"
  make_selector_patch "$SERVICE"
  log "KUBE" "kubectl -n $SPIN_NS patch service $SERVICE...\n"
  kubectl -n $SPIN_NS patch service $SERVICE --patch "$patch" >> "$OUT" 2>&1
  warn "Restoring remote $SERVICE: deployment\n"
  scale_deployment 1
  exit 0
}


echo "" > "$OUT"
parse_input
deploy_proxy
resolve_ports
trap cleanup INT
forward_all_ports
open_ssh
patch_services
scale_deployment 0
wait

