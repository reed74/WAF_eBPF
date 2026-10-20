#!/usr/bin/env bash
# ==============================================================================
# Benchmark Experimental: Evaluacion de Latencia y Descarte en Microsegundos
# ==============================================================================
set -euo pipefail

TARGET_URL="${1:-http://127.0.0.1:8443}"
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${BLUE}========================================================================${NC}"
echo -e "${BLUE}     BENCHMARK DE ALTA RESOLUCION TEMPORAL: eBPF / XDP WAF             ${NC}"
echo -e "${BLUE}========================================================================${NC}"
echo "Destino evaluado: $TARGET_URL"
echo ""

measure_curl() {
    local method="$1"
    local endpoint="$2"
    local payload="$3"
    local desc="$4"

    echo -e "${YELLOW}>> Evaluando: $desc${NC}"
    
    local output
    output=$(curl -s -o /dev/null -w \
        "HTTP_CODE:%{http_code}\nDNS_TIME:%{time_namelookup}s\nTCP_CONNECT:%{time_connect}s\nPRE_TRANSFER:%{time_pretransfer}s\nSTART_TRANSFER:%{time_starttransfer}s\nTOTAL_TIME:%{time_total}s\n" \
        -X "$method" "$TARGET_URL$endpoint" \
        -H "Content-Type: text/plain" \
        -d "$payload" --connect-timeout 2 2>&1 || echo "HTTP_CODE:000\nTOTAL_TIME:0.000000s\nERROR:Connection_Terminated")

    local code total_sec total_us total_ms
    code=$(echo -e "$output" | grep "HTTP_CODE" | cut -d':' -f2)
    total_sec=$(echo -e "$output" | grep "TOTAL_TIME" | cut -d':' -f2 | tr -d 's')
    
    if command -v python3 >/dev/null 2>&1; then
        total_us=$(python3 -c "print(f'{float(\"$total_sec\") * 1000000:.2f}')")
        total_ms=$(python3 -c "print(f'{float(\"$total_sec\") * 1000:.3f}')")
    else
        total_us="N/A"
        total_ms="N/A"
    fi

    echo -e "   Codigo HTTP:     ${CYAN}$code${NC}"
    echo -e "   Latencia Total:  ${GREEN}${total_ms} ms (${total_us} µs / ${total_sec} s)${NC}"
    echo ""
}

echo -e "${CYAN}[FASE 1] Medicion de Linea Base (Peticion Legitima Conforme)${NC}"
measure_curl "POST" "/api/login" '{"user":"investigador","role":"analista"}' "Trafico Benigno (Permitido)"

echo -e "${CYAN}[FASE 2] Medicion de Ataque L7 (Intercepcion Sincrona sk_msg / SK_DROP)${NC}"
measure_curl "POST" "/api/login" "SELECT * FROM users WHERE id=1 OR 1=1 --" "Ataque SQLi (Primer Descarte Sincrono)"

sleep 1

echo -e "${CYAN}[FASE 3] Medicion de Descarte Perimetral en Kernel (Fast-Path XDP_DROP)${NC}"
measure_curl "GET" "/api/status" "" "Peticion Posterior desde Host Bloqueado (XDP_DROP en L2/L3)"

echo -e "${BLUE}========================================================================${NC}"
echo -e "${BLUE} Revisa la terminal del agente Go para ver el desglose en nanosegundos ${NC}"
echo -e "${BLUE}========================================================================${NC}"
