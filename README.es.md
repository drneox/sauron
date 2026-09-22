# SAURON ASM

**Plataforma de gestión de superficie de ataque externa (ASM)** — descubre, monitorea y evalúa todo lo que tu organización expone a internet, desde un solo dashboard.

Sauron mapea la huella externa de tu empresa (dominios, subdominios, IPs, puertos abiertos, endpoints, tecnologías, apps móviles, archivos expuestos, paneles de administración), la escanea en busca de vulnerabilidades y malas configuraciones, registra cómo cambia la superficie en el tiempo, y usa una capa de IA para separar la señal del ruido.

> 🇬🇧 [English version](README.md)

---

## Lo que hace

- **Inventario centrado en la empresa** — todo cuelga de una empresa: dominios raíz, subdominios, IPs, hosts vecinos (dominios co-alojados vía reverse IP), endpoints, tecnologías y apps móviles. Registro de primera/última vez visto con deltas reales entre escaneos.
- **Descubrimiento multi-fuente** — crt.sh (incluye coincidencia por organización O=), Certificate Spotter, Wayback Machine, permutaciones, grep.app, GitHub, reverse IP, y llaves opcionales de SecurityTrails / OTX / Hunter / HIBP.
- **Descubrimiento asistido por IA** — un LLM propone dominios probables de la empresa y los verifica (DNS/HTTP) antes de que entren al inventario; las apps móviles encontradas en App Store / Google Play son clasificadas por el LLM como oficiales / sospechosas / no relacionadas.
- **Flujo de revisión** — los activos sospechosos (p. ej. apps de terceros con marcas que colisionan) se pueden aprobar (pasan a monitoreo oficial) o rechazar, individualmente o en lote.
- **Herramientas reales de escaneo** — nuclei, subfinder, httpx, katana, naabu y trufflehog vienen dentro de la imagen del backend, junto a ~34 módulos propios: TLS, headers, cookies, seguridad de correo (SPF/DMARC), archivos expuestos, paneles admin, minería de secretos en JS, buckets cloud, exposición de APIs/docs (incl. Postman y GitHub), filtrado de credenciales, fuzzing inteligente con wordlists curadas + rutas dirigidas por LLM, y más.
- **Descubrimiento y escaneo de vulnerabilidades son pipelines separados** — cada uno con su interruptor y su recurrencia (diaria / semanal / mensual) por dominio, por empresa y global. Los escaneos de vulnerabilidades pueden saltarse el descubrimiento y evaluar solo los activos inventariados.
- **Agent Scan** — un agente de IA autónomo que razona sobre los resultados deterministas, decide los siguientes pasos y narra lo que hace en tiempo real.
- **Rating de seguridad** — letra estilo Xpanse por dominio y por empresa, con scoring consciente de saturación, gráficos de tendencia histórica y coherencia entre badge y letra.
- **Flujo de remediación** — hallazgos persistentes con fingerprint (abierto / aceptado / corregido), detección de auto-corregidos en escaneos completos posteriores, y mapeo de cumplimiento a NIST CSF, ISO 27001, PCI DSS y CIS Controls.
- **SauronBot** — un asistente de IA alegre dentro de la app (chat flotante o página completa) que responde preguntas sobre empresas, activos, escaneos, fechas y hallazgos, con guardarraíles contra prompt injection y redacción de secretos.
- **Dashboards consistentes** — el dashboard global y el de cada empresa son el mismo componente; uno solo viene pre-filtrado. Ambos permiten comparar rangos de fechas (deltas entre dos escaneos cualesquiera).
- **RBAC + gate de red** — usuarios con roles viewer / operator / admin, más un gate opcional de HTTP Basic con whitelist de IPs delante del login de la app.
- **Notificaciones** — webhook (Slack/Discord/genérico) ante nuevos activos, hallazgos críticos y cambios de letra.
- **Pool de proxies** — rotación opcional de IP de salida vía archivo de proxies o gateway rotatorio.
- **i18n** — interfaz completa en español e inglés, conmutable en caliente.

## Stack

| Capa     | Tecnología                                                            |
|----------|-----------------------------------------------------------------------|
| Backend  | FastAPI · Tortoise ORM · PostgreSQL 16 · httpx · cola asyncio         |
| Frontend | React 18 · TypeScript · Vite · Tailwind CSS · react-router · recharts |
| Tools    | nuclei · subfinder · httpx · katana · naabu · trufflehog (en imagen)  |
| IA       | Cualquier endpoint compatible con OpenAI (Azure AI Foundry, Azure OpenAI, …) |
| Deploy   | Docker Compose (db + backend + frontend nginx)                        |

## Inicio rápido

```bash
# 1. Configura el backend
cp backend/.env.example backend/.env
#    OBLIGATORIO: define POSTGRES_PASSWORD (también en un .env raíz para compose),
#    mantén AUTH_ENABLED=true — luego AI_API_KEY / AI_BASE_URL / AI_MODEL, gate de red, …

# 2. Levanta el stack
docker compose up -d --build

# 3. Abre la app
open http://localhost:5173
```

Con `AUTH_ENABLED=true` y cero usuarios, la primera visita ofrece el **bootstrap**: creas el primer admin y entras. Los roles se gestionan luego desde **Users**.

### Variables de entorno clave (`backend/.env`)

| Variable | Propósito |
|---|---|
| `DATABASE_URL` | DSN de Postgres (dentro de compose apunta al servicio `db`) |
| `AI_API_KEY` / `AI_BASE_URL` / `AI_MODEL` | Endpoint LLM (Azure AI Foundry / Azure OpenAI / cualquier API compatible con OpenAI) |
| `AUTH_ENABLED` | `true` exige Bearer token con RBAC (**obligatorio** en cualquier despliegue expuesto; `false` es solo para dev) |
| `SCAN_WORKERS` | Workers paralelos de escaneo en la cola asyncio |
| `EDGE_AUTH_ENABLED` / `EDGE_AUTH_USER` / `EDGE_AUTH_PASSWORD` / `EDGE_ALLOWED_IPS` | Gate HTTP Basic + whitelist de IPs (local/LAN siempre pasa) |
| `PROXY_ENABLED` / `PROXY_FILE` / `PROXY_GATEWAY` | Rotación de IP de salida |
| `NOTIFY_WEBHOOK_URL` / `NOTIFY_ON` / `DASHBOARD_URL` | Notificaciones de deltas |
| `SECURITYTRAILS_API_KEY` / `OTX_API_KEY` / `HIBP_API_KEY` / `HUNTER_API_KEY` / `GITHUB_TOKEN` | Fuentes opcionales de descubrimiento |

La lista completa y anotada está en [`backend/.env.example`](backend/.env.example).

## Cómo funciona

1. **Agrega una empresa** — solo el nombre; Sauron propone dominios candidatos (coincidencia por organización en crt.sh + brainstorm LLM) y tú confirmas cuáles son tuyos.
2. **Descubre** — subdominios, DNS, vecinos por reverse IP, apps móviles, endpoints y tecnologías se inventarian como activos con marcas de primera/última vez visto.
3. **Escanea** — los módulos deterministas y las herramientas reales evalúan cada activo inventariado; los hallazgos se categorizan (vulnerabilidad / mala configuración / exposición / info) y se fingerprintean para seguimiento de remediación.
4. **Monitorea** — los escaneos programados de descubrimiento y vulnerabilidades corren cada uno en su propia cadencia; los dashboards muestran deltas, tendencias de rating, postura de cumplimiento y avance de remediación. SauronBot responde preguntas sobre todo ello.

## Licencia

**Apache License 2.0** — ver [LICENSE](LICENSE). Copyright 2026 Carlos Ganoza.

Las herramientas de escaneo incluidas en la imagen del backend conservan sus propias licencias: nuclei, subfinder, httpx, katana y naabu son MIT (ProjectDiscovery); trufflehog es AGPL-3.0 — se ejecuta como binario CLI externo (agregación pura), por lo que su copyleft no se extiende a Sauron.

## Roadmap

Ver [ROADMAP.md](ROADMAP.md) para las funciones planificadas y pendientes conocidos.

## Créditos

Construido por **Carlos Ganoza**.
