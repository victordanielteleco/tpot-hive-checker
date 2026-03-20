#!/usr/bin/env bash
#
# tpot-hive-checker.sh
#
# Diseñado para:
#   - Sistema operativo: Kali Linux
#   - Versión objetivo: Kali Linux 2025.4 (amd64 / rolling)
#   - Shell: bash
#
# Compatibilidad práctica:
#   - Debería funcionar también en Debian / Ubuntu si están instaladas
#     las herramientas requeridas.
#
# Objetivo:
#   Generar tráfico benigno y controlado contra una instalación T-Pot
#   estándar / hive para comprobar que los honeypots registran eventos
#   en Kibana / Discover.
#
# Qué hace:
#   - Ofrece un modo básico y uno completo.
#   - Pregunta la IP objetivo.
#   - Clasifica la IP como privada RFC1918, especial/reservada o pública real.
#   - Si es especial o pública, exige confirmación escribiendo "si".
#   - Muestra una tabla de lo que va a probar en cada modo.
#   - Ejecuta pruebas protocolarias benignas, mostrando:
#       * qué está haciendo
#       * para qué lo hace
#       * el comando exacto que ejecuta
#   - Guarda toda la salida en un log local.
#
# Qué NO hace:
#   - No explota vulnerabilidades.
#   - No lanza payloads destructivos.
#   - No modifica el objetivo.
#
# Uso:
#   chmod +x tpot-hive-checker.sh
#   ./tpot-hive-checker.sh
#

set -u
set -o pipefail

SCRIPT_NAME="$(basename "$0")"
START_TS="$(date +%Y%m%d_%H%M%S)"
LOG_FILE="tpot_hive_checker_${START_TS}.log"
TIMEOUT_SECONDS=5

TARGET=""
MODE=""

print_line() {
  printf '%*s\n' "${COLUMNS:-72}" '' | tr ' ' '='
}

print_section() {
  echo
  print_line
  echo "$1"
  print_line
}

log() {
  echo "$*" | tee -a "$LOG_FILE"
}

run_cmd() {
  local what="$1"
  local why="$2"
  local cmd="$3"

  log
  log "[*] Qué está haciendo: $what"
  log "[*] Para qué: $why"
  log "[*] Comando exacto: $cmd"
  log "------------------------------------------------------------"

  bash -lc "$cmd" 2>&1 | tee -a "$LOG_FILE" || true
}

is_valid_ipv4() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS='.' read -r o1 o2 o3 o4 <<< "$ip"
  for octet in "$o1" "$o2" "$o3" "$o4"; do
    if (( octet < 0 || octet > 255 )); then
      return 1
    fi
  done
  return 0
}

is_private_rfc1918() {
  local ip="$1"
  IFS='.' read -r o1 o2 o3 o4 <<< "$ip"

  (( o1 == 10 )) && return 0
  (( o1 == 172 && o2 >= 16 && o2 <= 31 )) && return 0
  (( o1 == 192 && o2 == 168 )) && return 0

  return 1
}

is_special_reserved_ipv4() {
  local ip="$1"
  IFS='.' read -r o1 o2 o3 o4 <<< "$ip"

  (( o1 == 0 )) && return 0
  (( o1 == 100 && o2 >= 64 && o2 <= 127 )) && return 0
  (( o1 == 127 )) && return 0
  (( o1 == 169 && o2 == 254 )) && return 0
  (( o1 == 192 && o2 == 0 && o3 == 0 )) && return 0
  (( o1 == 192 && o2 == 0 && o3 == 2 )) && return 0
  (( o1 == 198 && (o2 == 18 || o2 == 19) )) && return 0
  (( o1 == 198 && o2 == 51 && o3 == 100 )) && return 0
  (( o1 == 203 && o2 == 0 && o3 == 113 )) && return 0
  (( o1 >= 224 && o1 <= 239 )) && return 0
  (( o1 >= 240 && o1 <= 255 )) && return 0

  return 1
}

classify_ipv4() {
  local ip="$1"
  if is_private_rfc1918 "$ip"; then
    echo "privada RFC1918"
    return 0
  fi
  if is_special_reserved_ipv4 "$ip"; then
    echo "especial/reservada"
    return 0
  fi
  echo "pública real"
}

ask_target_ip() {
  local ip=""
  while true; do
    echo
    read -r -p "Introduce la IP objetivo: " ip
    if is_valid_ipv4 "$ip"; then
      TARGET="$ip"
      return 0
    fi
    echo "[!] La IP no es una IPv4 válida."
  done
}

confirm_target_if_needed() {
  local class
  local answer=""

  class="$(classify_ipv4 "$TARGET")"

  if [[ "$class" == "privada RFC1918" ]]; then
    echo "[i] La IP es privada RFC1918. No hace falta confirmación adicional."
    return 0
  fi

  echo
  echo "[!] AVISO: la IP objetivo es ${class}: $TARGET"
  echo "[!] Asegúrate de que tienes autorización para usar este script."
  echo "[!] Para continuar escribe exactamente: si"
  read -r -p "> " answer

  if [[ "$answer" != "si" ]]; then
    echo "[i] Operación cancelada."
    exit 1
  fi
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

check_required_commands() {
  local missing=0
  local required=(bash nmap curl nc ssh openssl)
  local optional=(adb redis-cli timeout telnet)

  print_section "Comprobando dependencias"

  for cmd in "${required[@]}"; do
    if command_exists "$cmd"; then
      log "[OK] Requerido: $cmd"
    else
      log "[!!] Falta requerido: $cmd"
      missing=1
    fi
  done

  for cmd in "${optional[@]}"; do
    if command_exists "$cmd"; then
      log "[OK] Opcional: $cmd"
    else
      log "[--] Opcional no encontrado: $cmd"
    fi
  done

  if (( missing != 0 )); then
    log
    log "[!] Faltan herramientas requeridas."
    log "[!] En Kali / Debian / Ubuntu puedes instalar lo básico con:"
    log "    sudo apt update && sudo apt install -y nmap curl netcat-openbsd openssh-client openssl adb redis-tools telnet"
    exit 1
  fi
}

print_table_header() {
  printf "%-24s | %-38s\n" "Honeypot" "Herramientas"
  printf -- "-------------------------+----------------------------------------\n"
}

print_fast_table() {
  print_table_header
  printf "%-24s | %-38s\n" "Cowrie" "ssh, nc"
  printf "%-24s | %-38s\n" "Dionaea" "nmap"
  printf "%-24s | %-38s\n" "ElasticPot" "curl"
  printf "%-24s | %-38s\n" "H0neytr4p" "curl"
  printf "%-24s | %-38s\n" "Honeyaml" "curl"
  printf "%-24s | %-38s\n" "Mailoney" "nc"
  printf "%-24s | %-38s\n" "Snare / Tanner" "curl"
  printf "%-24s | %-38s\n" "Wordpot" "curl"
}

print_full_table() {
  print_table_header
  printf "%-24s | %-38s\n" "ADBHoney" "adb o nmap"
  printf "%-24s | %-38s\n" "CiscoASA" "curl, nmap"
  printf "%-24s | %-38s\n" "Conpot" "nmap"
  printf "%-24s | %-38s\n" "Cowrie" "ssh, nc"
  printf "%-24s | %-38s\n" "Dicompot" "nmap"
  printf "%-24s | %-38s\n" "Dionaea" "nmap"
  printf "%-24s | %-38s\n" "ElasticPot" "curl"
  printf "%-24s | %-38s\n" "H0neytr4p" "curl"
  printf "%-24s | %-38s\n" "Heralding" "nc, openssl"
  printf "%-24s | %-38s\n" "Honeyaml" "curl"
  printf "%-24s | %-38s\n" "Honeytrap" "nmap"
  printf "%-24s | %-38s\n" "IPPHoney" "nmap, nc"
  printf "%-24s | %-38s\n" "Mailoney" "nc"
  printf "%-24s | %-38s\n" "Medpot" "nmap, nc"
  printf "%-24s | %-38s\n" "Miniprint" "nc"
  printf "%-24s | %-38s\n" "Redishoneypot" "redis-cli o nc"
  printf "%-24s | %-38s\n" "SentryPeer" "nmap, nc"
  printf "%-24s | %-38s\n" "Snare / Tanner" "curl"
  printf "%-24s | %-38s\n" "Wordpot" "curl"
}

show_mode_tables() {
  print_section "Resumen de pruebas disponibles"

  echo "[Modo básico]"
  print_fast_table

  echo
  echo "[Modo completo]"
  print_full_table
}

choose_mode() {
  local answer=""
  while true; do
    echo
    echo "Selecciona el tipo de comprobación:"
    echo "  1) Básica"
    echo "  2) Completa"
    read -r -p "> " answer

    case "$answer" in
      1) MODE="basica"; return 0 ;;
      2) MODE="completa"; return 0 ;;
      *) echo "[!] Opción no válida." ;;
    esac
  done
}

probe_http() {
  local name="$1"
  local port="$2"
  local scheme="$3"

  local curl_flags="--max-time ${TIMEOUT_SECONDS} -k -sS -D -"
  run_cmd \
    "Probando ${name} con una petición ${scheme^^} en ${port}" \
    "Generar un acceso web benigno y obtener cabeceras o respuesta para que el honeypot registre actividad" \
    "curl ${curl_flags} ${scheme}://${TARGET}:${port}/ -o /dev/null"
}

probe_nc_banner() {
  local name="$1"
  local port="$2"
  local payload="$3"

  run_cmd \
    "Abriendo una conexión TCP simple contra ${name} en ${port}" \
    "Provocar un handshake o lectura de banner para generar eventos sin explotar nada" \
    "printf '${payload}' | timeout ${TIMEOUT_SECONDS} nc -nv ${TARGET} ${port}"
}

probe_tls_banner() {
  local name="$1"
  local port="$2"

  run_cmd \
    "Abriendo una conexión TLS simple contra ${name} en ${port}" \
    "Generar un intento de handshake TLS para que el servicio lo registre" \
    "echo | timeout ${TIMEOUT_SECONDS} openssl s_client -quiet -connect ${TARGET}:${port}"
}

probe_nmap_tcp() {
  local name="$1"
  local ports="$2"

  run_cmd \
    "Escaneando puertos TCP de ${name}" \
    "Usar reconocimiento benigno de servicio para forzar banners y registros del honeypot" \
    "nmap -Pn -sS -sV -p ${ports} ${TARGET}"
}

probe_nmap_udp() {
  local name="$1"
  local ports="$2"

  run_cmd \
    "Escaneando puertos UDP de ${name}" \
    "Generar tráfico UDP benigno y detección de servicio para que quede trazado" \
    "sudo nmap -Pn -sU -sV --version-light -p ${ports} ${TARGET}"
}

probe_ssh_auth() {
  run_cmd \
    "Intentando acceso SSH para probar Cowrie" \
    "Generar un evento de autenticación fallida en el honeypot SSH/Telnet" \
    "timeout ${TIMEOUT_SECONDS} ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 test@${TARGET}"
}

probe_telnet_like() {
  run_cmd \
    "Abriendo conexión TCP al puerto 23 para probar Cowrie" \
    "Forzar un banner o conexión Telnet sin necesidad de interactuar manualmente" \
    "printf 'admin\r\n123456\r\n' | timeout ${TIMEOUT_SECONDS} nc -nv ${TARGET} 23"
}

probe_adb() {
  if command_exists adb; then
    run_cmd \
      "Intentando conexión ADB para probar ADBHoney" \
      "Generar un handshake ADB benigno si el cliente adb está disponible" \
      "timeout ${TIMEOUT_SECONDS} adb connect ${TARGET}:5555"
  else
    probe_nmap_tcp "ADBHoney" "5555"
  fi
}

probe_redis() {
  if command_exists redis-cli; then
    run_cmd \
      "Enviando PING a Redis para probar Redishoneypot" \
      "Generar una interacción mínima de protocolo Redis" \
      "timeout ${TIMEOUT_SECONDS} redis-cli -h ${TARGET} -p 6379 PING"
  else
    run_cmd \
      "Enviando PING en bruto a Redis para probar Redishoneypot" \
      "Generar una interacción mínima de protocolo Redis sin redis-cli" \
      "printf '*1\r\n\$4\r\nPING\r\n' | timeout ${TIMEOUT_SECONDS} nc -nv ${TARGET} 6379"
  fi
}

run_basic_suite() {
  print_section "Ejecutando comprobación básica"

  probe_ssh_auth
  probe_telnet_like
  probe_nmap_tcp "Dionaea" "21,42,81,135,445,1433,1723,1883,3306,27017"
  probe_http "ElasticPot" "9200" "http"
  probe_http "H0neytr4p" "443" "https"
  probe_http "Honeyaml" "3000" "http"
  probe_nc_banner "Mailoney" "25" "EHLO kali.local\r\nQUIT\r\n"
  probe_http "Snare / Tanner" "80" "http"
  probe_http "Wordpot" "8080" "http"
}

run_full_suite() {
  print_section "Ejecutando comprobación completa"

  probe_adb
  probe_http "CiscoASA" "8443" "https"
  probe_nmap_udp "CiscoASA" "5000"
  probe_nmap_tcp "Conpot" "10001,1025,50100"
  probe_nmap_udp "Conpot" "161,623"
  probe_ssh_auth
  probe_telnet_like
  probe_nmap_tcp "Dicompot" "104,11112"
  probe_nmap_tcp "Dionaea" "21,42,81,135,445,1433,1723,1883,3306,27017"
  probe_nmap_udp "Dionaea" "69"
  probe_http "ElasticPot" "9200" "http"
  probe_http "H0neytr4p" "443" "https"
  probe_nc_banner "Heralding POP3" "110" "QUIT\r\n"
  probe_nc_banner "Heralding IMAP" "143" "a1 LOGOUT\r\n"
  probe_tls_banner "Heralding SMTPS" "465"
  probe_tls_banner "Heralding IMAPS" "993"
  probe_tls_banner "Heralding POP3S" "995"
  probe_nc_banner "Heralding SOCKS" "1080" ""
  probe_nc_banner "Heralding PostgreSQL" "5432" ""
  probe_nc_banner "Heralding VNC" "5900" ""
  probe_http "Honeyaml" "3000" "http"

  run_cmd \
    "Lanzando un escaneo corto para intentar activar Honeytrap en puertos no ocupados" \
    "Honeytrap usa puertos dinámicos no ocupados; este sondeo intenta generar tráfico genérico observable" \
    "nmap -Pn -sS --top-ports 50 ${TARGET}"

  probe_nmap_tcp "IPPHoney" "631"
  probe_nc_banner "IPPHoney" "631" ""
  probe_nc_banner "Mailoney SMTP" "25" "EHLO kali.local\r\nQUIT\r\n"
  probe_nc_banner "Mailoney SMTP Submission" "587" "EHLO kali.local\r\nQUIT\r\n"
  probe_nmap_tcp "Medpot" "2575"
  probe_nc_banner "Medpot" "2575" ""

  run_cmd \
    "Enviando una trama simple a Miniprint" \
    "Generar actividad en el honeypot de impresora en el puerto 9100" \
    "printf 'TEST PAGE FROM KALI\r\n' | timeout ${TIMEOUT_SECONDS} nc -nv ${TARGET} 9100"

  probe_redis
  probe_nmap_tcp "SentryPeer" "5060"
  probe_nmap_udp "SentryPeer" "5060"
  probe_nc_banner "SentryPeer SIP" "5060" "OPTIONS sip:test@${TARGET} SIP/2.0\r\nVia: SIP/2.0/TCP kali.local\r\nFrom: <sip:kali@local>\r\nTo: <sip:test@${TARGET}>\r\nCall-ID: 12345\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n"
  probe_http "Snare / Tanner" "80" "http"
  probe_http "Wordpot" "8080" "http"
}

print_section "Cabecera"
echo "Script      : ${SCRIPT_NAME}"
echo "Diseño      : Kali Linux 2025.4 (rolling)"
echo "Shell       : bash"
echo "Log local   : ${LOG_FILE}"
echo "Objetivo    : generar eventos benignos en T-Pot estándar / hive"

show_mode_tables
choose_mode
ask_target_ip
confirm_target_if_needed

exec > >(tee -a "$LOG_FILE") 2>&1

print_section "Resumen inicial"
echo "[i] Objetivo: ${TARGET}"
echo "[i] Clasificación IP: $(classify_ipv4 "$TARGET")"
echo "[i] Modo elegido: ${MODE}"
echo "[i] Log local: ${LOG_FILE}"

check_required_commands

if [[ "$MODE" == "basica" ]]; then
  run_basic_suite
else
  run_full_suite
fi

print_section "Finalizado"
echo "[i] La prueba ha terminado."
echo "[i] Revisa Kibana / Discover y busca, por ejemplo:"
echo "     source.ip, destination.port, event.dataset"
echo "     cowrie, dionaea, elasticpot, honeyaml, mailoney, wordpot"
echo
echo "[i] Consejo: amplía la ventana de tiempo en Kibana a Last 15 minutes, Last 1 hour o Last 24 hours."
