package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// ============================================================================
// 1. ESTRUCTURAS DE DATOS (Alineadas con bpf/common.h)
// ============================================================================

type BlockMeta struct {
	TimestampNS   uint64
	DroppedPackets uint64
}

type SecurityEvent struct {
	KernelNS       uint64
	SrcIP          uint32
	SrcPort        uint16
	DstPort        uint16
	PayloadSnippet [128]byte
}

// ============================================================================
// 2. MOTOR MULTIRREGLA OWASP CRS (L7)
// ============================================================================

type ReglaCRS struct {
	ID          int
	Categoria   string
	Descripcion string
	Severidad   int
	Pattern     *regexp.Regexp
}

type ResultadoInspeccion struct {
	EsMalicioso   bool
	ReglaViolada  int
	Categoria     string
	Descripcion   string
	FragmentoCoin string
}

type MotorCRS struct {
	reglas []ReglaCRS
	mu     sync.RWMutex
}

func NuevoMotorCRS() *MotorCRS {
	motor := &MotorCRS{}
	motor.cargarFirmasPredefinidas()
	return motor
}

func (m *MotorCRS) cargarFirmasPredefinidas() {
	definiciones := []struct {
		id   int
		cat  string
		desc string
		sev  int
		expr string
	}{
		// Regla 942100: SQL Injection - Tautologias y operadores booleanos
		{
			id:   942100,
			cat:  "SQLi",
			desc: "Deteccion de operador booleano o tautologia SQL (OR/AND clasico)",
			sev:  3,
			expr: `(?i)(?:'|"|%27|%22)\s*(?:or|and|xor)\s*[\(\d\w'"\\]+.*?[=><]`,
		},
		// Regla 942110: SQL Injection - Sentencias de union o manipulacion
		{
			id:   942110,
			cat:  "SQLi",
			desc: "Sentencias de union, comentarios clasicos o comandos apilados",
			sev:  3,
			expr: `(?i)(?:union\s+(?:all\s+)?select|;\s*drop\s+table|;\s*shutdown|--\s*$|/\*.*?\*/)`,
		},
		// Regla 941100: Cross-Site Scripting (XSS)
		{
			id:   941100,
			cat:  "XSS",
			desc: "Inyeccion de etiquetas script o manipuladores de eventos JavaScript",
			sev:  3,
			expr: `(?i)(?:<script[^>]*>|javascript:[^"']*|onload\s*=|onerror\s*=|onclick\s*=)`,
		},
		// Regla 932100: Remote Command Execution (RCE)
		{
			id:   932100,
			cat:  "RCE",
			desc: "Encadenamiento de comandos shell Unix/Windows",
			sev:  3,
			expr: `(?i)(?:;|\||&&|` + "`" + `)\s*(?:cat\s+/etc/passwd|whoami|powershell|cmd\.exe|nc\s+-e)`,
		},
		// Regla 930100: Path Traversal / Local File Inclusion (LFI)
		{
			id:   930100,
			cat:  "LFI",
			desc: "Secuencias de escape de directorio hacia archivos del sistema",
			sev:  3,
			expr: `(?i)(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|/etc/passwd|/windows/win\.ini)`,
		},
	}

	for _, d := range definiciones {
		rgx, err := regexp.Compile(d.expr)
		if err != nil {
			log.Printf("[-] Error compilando regla CRS %d: %v", d.id, err)
			continue
		}
		m.reglas = append(m.reglas, ReglaCRS{
			ID:          d.id,
			Categoria:   d.cat,
			Descripcion: d.desc,
			Severidad:   d.sev,
			Pattern:     rgx,
		})
	}
}

func (m *MotorCRS) EvaluarPayload(payload string) ResultadoInspeccion {
	m.mu.RLock()
	defer m.mu.RUnlock()

	normalizado := strings.ReplaceAll(payload, "\r\n", " ")

	for _, regla := range m.reglas {
		if coincidencia := regla.Pattern.FindString(normalizado); coincidencia != "" {
			return ResultadoInspeccion{
				EsMalicioso:   true,
				ReglaViolada:  regla.ID,
				Categoria:     regla.Categoria,
				Descripcion:   regla.Descripcion,
				FragmentoCoin: coincidencia,
			}
		}
	}

	return ResultadoInspeccion{EsMalicioso: false}
}

func intToIP(val uint32) net.IP {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], val)
	return net.IPv4(b[0], b[1], b[2], b[3])
}

// ============================================================================
// 3. BUCLE DE INSPECCION Y TELEMETRIA DE ALTA RESOLUCION
// ============================================================================

func procesarAlertasRingBuffer(ctx context.Context, rd *ringbuf.Reader, blockedIPsMap *ebpf.Map) {
	motorCRS := NuevoMotorCRS()
	log.Println("[+] Motor multirregla OWASP CRS cargado e inicializado en memoria")

	var event SecurityEvent
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		record, err := rd.Read()
		if err != nil {
			if err == ringbuf.ErrClosed {
				return
			}
			log.Printf("[-] Error al leer muestra del RingBuffer: %v", err)
			continue
		}

		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("[-] Error deserializando SecurityEvent: %v", err)
			continue
		}

		receiveTime := time.Now()
		ipOrigen := intToIP(event.SrcIP)
		payload := strings.TrimRight(string(event.PayloadSnippet[:]), "\x00")

		t0Eval := time.Now()
		resultado := motorCRS.EvaluarPayload(payload)
		duracionEval := time.Since(t0Eval)

		if resultado.EsMalicioso {
			t0Update := time.Now()
			meta := BlockMeta{
				TimestampNS:   uint64(time.Now().UnixNano()),
				DroppedPackets: 0,
			}

			err := blockedIPsMap.Put(event.SrcIP, meta)
			duracionUpdate := time.Since(t0Update)

			log.Println("--------------------------------------------------------------------------------")
			log.Printf("[ALERTA CRITICA L7] Regla %d (%s): %s", resultado.ReglaViolada, resultado.Categoria, resultado.Descripcion)
			log.Printf("  -> Origen:       %s:%d -> Puerto Destino: %d", ipOrigen, event.SrcPort, event.DstPort)
			log.Printf("  -> Coincidencia: '%s'", resultado.FragmentoCoin)
			log.Printf("  -> Snippet:      '%s'", payload)
			log.Printf("  -> METRICAS TEMPORALES DE ALTA RESOLUCION:")
			log.Printf("     * Kernel sk_msg Timestamp:  %d ns", event.KernelNS)
			log.Printf("     * Evaluacion CRS (Go):      %d ns (%.3f us)", duracionEval.Nanoseconds(), float64(duracionEval.Nanoseconds())/1000.0)
			log.Printf("     * Inyeccion XDP Map:        %d ns (%.3f us)", duracionUpdate.Nanoseconds(), float64(duracionUpdate.Nanoseconds())/1000.0)
			log.Printf("     * Latencia Total Reaccion:  %d ns (%.3f us)", (duracionEval + duracionUpdate).Nanoseconds(), float64((duracionEval + duracionUpdate).Nanoseconds())/1000.0)
			if err != nil {
				log.Printf("[-] Error al inyectar IP en mapa eBPF blocked_ips: %v", err)
			} else {
				log.Printf("[REACTIVO] IP %s bloqueada en kernel. Trafico subsiguiente muere en XDP_DROP L2/L3.", ipOrigen)
			}
			log.Println("--------------------------------------------------------------------------------")
		} else {
			log.Printf("[INFO] Peticion conforme de %s:%d (Eval: %d ns)", ipOrigen, event.SrcPort, duracionEval.Nanoseconds())
		}
		_ = receiveTime
	}
}

// ============================================================================
// 4. MAIN
// ============================================================================

func main() {
	if len(os.Args) < 3 {
		fmt.Printf("Uso: sudo %s <interfaz_red> <cgroup2_path>\n", os.Args[0])
		fmt.Printf("Ejemplo: sudo %s veth-waf /sys/fs/cgroup\n", os.Args[0])
		fmt.Printf("         sudo %s lo /sys/fs/cgroup\n", os.Args[0])
		os.Exit(1)
	}

	ifaceName := os.Args[1]
	cgroupPath := os.Args[2]

	log.Println("[*] Inicializando agente WAF eBPF hibrido de alta resolucion...")

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("[-] Fallo critico al desbloquear memlock: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	specXDP, err := ebpf.LoadCollectionSpec("bpf/xdp_filter.bpf.o")
	if err != nil {
		log.Fatalf("[-] Error al cargar especificacion XDP: %v", err)
	}
	collXDP, err := ebpf.NewCollection(specXDP)
	if err != nil {
		log.Fatalf("[-] Error al instanciar coleccion XDP: %v", err)
	}
	defer collXDP.Close()

	specSock, err := ebpf.LoadCollectionSpec("bpf/sock_filter.bpf.o")
	if err != nil {
		log.Fatalf("[-] Error al cargar especificacion Sock: %v", err)
	}
	collSock, err := ebpf.NewCollection(specSock)
	if err != nil {
		log.Fatalf("[-] Error al instanciar coleccion Sock: %v", err)
	}
	defer collSock.Close()

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("[-] Error localizando interfaz %s: %v", ifaceName, err)
	}

	xdpProg := collXDP.Programs["xdp_ingress_filter"]
	var xdpLink link.Link

	if ifaceName == "lo" {
		xdpLink, err = link.AttachXDP(link.XDPOptions{
			Program:   xdpProg,
			Interface: iface.Index,
			Flags:     link.XDPGenericMode,
		})
	} else {
		xdpLink, err = link.AttachXDP(link.XDPOptions{
			Program:   xdpProg,
			Interface: iface.Index,
			Flags:     link.XDPDriverMode,
		})
		if err != nil {
			log.Printf("[!] Modo Driver no soportado en %s. Probando Generic: %v", ifaceName, err)
			xdpLink, err = link.AttachXDP(link.XDPOptions{
				Program:   xdpProg,
				Interface: iface.Index,
				Flags:     link.XDPGenericMode,
			})
		}
	}

	if err != nil {
		log.Printf("[!] Advertencia: Enlace bpf_link XDP no admitido en %s (%v). Se procesara L7 via SOCKMAP.", ifaceName, err)
	} else {
		defer xdpLink.Close()
		log.Printf("[+] Programa XDP acoplado con exito a la interfaz %s", ifaceName)
	}

	cgroupFD, err := unix.Open(cgroupPath, unix.O_DIRECTORY|unix.O_RDONLY, 0)
	if err != nil {
		log.Fatalf("[-] Error al abrir descriptor de cgroup2 en %s: %v", cgroupPath, err)
	}
	defer unix.Close(cgroupFD)

	sockOpsProg := collSock.Programs["bpf_sockmap_handler"]
	cgroupLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupSockOps,
		Program: sockOpsProg,
	})
	if err != nil {
		log.Fatalf("[-] Error acoplando sock_ops al cgroup %s: %v", cgroupPath, err)
	}
	defer cgroupLink.Close()
	log.Printf("[+] Programa sock_ops acoplado a cgroup2 (%s)", cgroupPath)

	skMsgProg := collSock.Programs["bpf_sk_msg_parser"]
	sockMap := collSock.Maps["sock_map"]
	msgLink, err := link.AttachRawLink(link.RawLinkOptions{
		Program: skMsgProg,
		Target:  sockMap.FD(),
		Attach:  ebpf.AttachSkMsgVerdict,
	})
	if err != nil {
		log.Fatalf("[-] Error adjuntando sk_msg al mapa SOCKMAP: %v", err)
	}
	defer msgLink.Close()
	log.Printf("[+] Pipeline sincrono kTLS/sk_msg activo para intercepcion sin fuga")

	eventsMap := collSock.Maps["events"]
	rd, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		log.Fatalf("[-] Error al crear Reader para RingBuffer: %v", err)
	}
	defer rd.Close()

	blockedIPsMap := collXDP.Maps["blocked_ips"]

	go procesarAlertasRingBuffer(ctx, rd, blockedIPsMap)

	log.Println("[*] Sistema WAF eBPF operativo. Pulsa Ctrl+C para finalizar.")
	<-ctx.Done()

	log.Println("\n[*] Recibida senal de terminacion. Desmontando hooks del kernel...")
}
