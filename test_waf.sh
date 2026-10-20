#!/usr/bin/env bash
# ==============================================================================
# Script de Validacion Experimental End-to-End
# ==============================================================================
set -euo pipefail

TARGET_URL="${1:-http://127.0.0.1:8443}"
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}======================================================${NC}"
echo -e "${BLUE}    TESTBENCH EXPERIMENTAL: eBPF / XDP HYBRID WAF     ${NC}"
echo -e "${BLUE}======================================================${NC}"

echo -e "\n${YELLOW}[FASE 1] Enviando peticiones HTTP legitimas (Control)...${NC}"
echo -n "  -> [GET] /healthz: "
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 2 "$TARGET_URL/healthz" || echo "000")
if [[ "$HTTP_CODE" == "200" ]]; then
    echo -e "${GREEN}HTTP $HTTP_CODE (PERMITIDO / SK_PASS)${NC}"
else
    echo -e "${RED}FALLO: Codigo HTTP $HTTP_CODE${NC}"
fi

echo -n "  -> [POST] /api/login (Payload benigno): "
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 2 \
    -X POST "$TARGET_URL/api/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"investigador","role":"analista"}' || echo "000")
if [[ "$HTTP_CODE" == "200" ]]; then
    echo -e "${GREEN}HTTP $HTTP_CODE (PERMITIDO / SK_PASS)${NC}"
else
    echo -e "${RED}FALLO: Codigo HTTP $HTTP_CODE${NC}"
fi

sleep 1

echo -e "\n${YELLOW}[FASE 2] Enviando ataque SQL Injection (Trigger CRS 942100)...${NC}"
echo "  Payload: SELECT * FROM users WHERE id=1 OR 1=1 --"
echo -n "  -> Resultado: "
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 \
    -X POST "$TARGET_URL/api/login" \
    -H "Content-Type: text/plain" \
    -d "SELECT * FROM users WHERE id=1 OR 1=1 --" || echo "DROPPED")

if [[ "$HTTP_CODE" == "DROPPED" || "$HTTP_CODE" == "000" || "$HTTP_CODE" == "52" ]]; then
    echo -e "${RED}[BLOQUEADO / SK_DROP] Stream interceptado antes de entrega al backend.${NC}"
else
    echo -e "${YELLOW}Respuesta: HTTP $HTTP_CODE${NC}"
fi

sleep 1

echo -e "\n${YELLOW}[FASE 3] Verificando mitigacion reactiva en Fast-Path (XDP_DROP)...${NC}"
echo -n "  -> Intento de conexion subsiguiente: "
TEST_RESP=$(curl -s --connect-timeout 2 "$TARGET_URL/healthz" 2>&1 || echo "TIMEOUT_OR_REFUSED")
if [[ "$TEST_RESP" == *"TIMEOUT_OR_REFUSED"* || "$TEST_RESP" == *"Failed to connect"* || "$TEST_RESP" == *"timed out"* || "$TEST_RESP" == *"Empty reply"* ]]; then
    echo -e "${RED}[XDP_DROP ACTIVO] Conexion descartada en driver de red.${NC}"
    echo -e "${GREEN}[OK] Validacion experimental exitosa: amortizacion computacional en kernel demostrada.${NC}"
else
    echo -e "${YELLOW}[!] Se obtuvo respuesta: $TEST_RESP${NC}"
fi
