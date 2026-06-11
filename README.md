# ◣ Centinela

**Plataforma de seguridad web autónoma: escáner de vulnerabilidades, pentester por reglas, guardián 24/7 y gestión de vulnerabilidades — todo sin una sola dependencia externa.**

> *Autonomous web security platform — vulnerability scanner, rule-based pentester, 24/7 watchdog and vulnerability management, with zero external dependencies.*

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencias-0-success)
![Tests](https://img.shields.io/badge/tests-35%20passing-success)
![License](https://img.shields.io/badge/license-MIT-green)
![Stdlib only](https://img.shields.io/badge/stdlib-only-informational)

Centinela analiza una aplicación web, encuentra vulnerabilidades reales, las **valida**,
las convierte en un **backlog gestionable**, te **avisa** cuando algo cambia y te **genera
la configuración para arreglarlo**. Corre como CLI, dashboard web, app de escritorio o API REST
— y está construido **100% con la librería estándar de Python** (sin `pip install` de nada).

📄 **[Mirá un informe de ejemplo](docs/sample-report.html)** generado por la herramienta (HTML/PDF con mapeo OWASP).

---

## ✨ Características

### Detección
- **13 familias de chequeos**: headers de seguridad, TLS/certificados, cookies, CORS, métodos HTTP, fugas de información, reflejo de parámetros.
- **Inyección**: SQLi (error-based), NoSQL injection, command injection, XSS reflejado (confirmado), LFI / path traversal, SSTI.
- **Autenticación**: análisis de JWT (detecta `alg:none`, secretos HMAC débiles por fuerza bruta, falta de expiración y datos sensibles en el payload).
- **Análisis context-aware**: detecta si el sitio es una vitrina estática o maneja login/pagos, y **ajusta la severidad** según el riesgo real (una nota A–F que *significa* algo).
- **Motor de plantillas estilo Nuclei**: agregás chequeos nuevos creando un `.json`, sin tocar el código (19 incluidas).
- **Recon de red**: enumeración de subdominios (DNS), escaneo de puertos, **banner-grabbing** con detección de versiones vulnerables (CVE).
- **SAST (análisis estático de código)**: escanea un repo/directorio local buscando secretos hardcodeados (AWS, Stripe, GitHub, claves privadas…) y patrones de código peligroso, con alta precisión (filtra placeholders, ignora comentarios).
- **Seguridad de DNS/email**: audita SPF y DMARC (¿se puede falsificar email desde tu dominio?) con un resolver DNS propio sobre UDP (stdlib, con EDNS0).
- **Crawler multi-página** y **escaneo autenticado** (con cookie/headers de sesión).

### Operación y gestión
- **Pentester autónomo por reglas**: razona el plan (recon → hipótesis → validación) sin LLM.
- **Modo guardián 24/7**: vigila tus sitios, compara contra una línea base y **alerta solo de lo nuevo o lo que empeoró**.
- **Gestión de vulnerabilidades**: cada hallazgo es un item con ciclo de vida (abierto / reconocido / falso-positivo / riesgo-aceptado / arreglado), responsable asignado y **auto-resolución**.
- **Modo defensa**: genera la config lista para pegar (Vercel / nginx / Apache / Netlify) que corrige los hallazgos.

### Plataforma
- **API REST** completa con **API-keys** y autenticación por roles (admin / analyst / viewer).
- **Integraciones**: alertas a Slack / Discord / Teams / email, notificaciones de escritorio, y **gate de CI/CD** (`--fail-on high` rompe el pipeline si hay vulnerabilidades).
- **Informes**: HTML/PDF y CSV con mapeo a **OWASP Top 10**, listos para una auditoría.
- **4 interfaces**: CLI, dashboard web (también accesible desde el celular), app de escritorio conversacional, y API.

---

## 🚀 Quickstart

Sin instalar nada (solo necesitás Python 3.10+):

```bash
git clone https://github.com/santiagomartinezvon65-lang/centinela.git
cd centinela

python cli.py scan https://tu-sitio.com --authorized      # escaneo rápido (nota A–F)
python cli.py pentest https://tu-sitio.com --authorized   # pentest completo
python cli.py recon tu-dominio.com --authorized           # red: subdominios + puertos + versiones vulnerables
python cli.py dns tu-dominio.com                           # DNS/email: ¿se puede falsificar tu email? (SPF/DMARC)
python cli.py code ./mi-repo                               # SAST: secretos y patrones peligrosos en el código
python cli.py serve                                        # dashboard web en http://127.0.0.1:8077
python cli.py gui                                          # app de escritorio: hablale al bot
```

Hablándole al bot (app de escritorio):
> *"metete en mi-sitio.com y haceme un pentest"* · *"qué vulnerabilidades hay"* · *"arreglá esto"*

---

## 🧪 Tests

```bash
python -m unittest discover -s tests
# Ran 35 tests ... OK
```

Incluye **tests de integración end-to-end**: uno levanta una app deliberadamente
vulnerable y verifica que el motor detecta XSS, SQLi y archivos sensibles expuestos
contra un objetivo vivo; otro arranca la API con autenticación y prueba el login por
cookie, las API-keys y el control de acceso por rol — no solo unit tests aislados.

---

## 🏗️ Arquitectura

Centinela sigue una arquitectura modular (Domain-Driven Design liviano): el núcleo (`core/`)
es lógica pura y testeable; las interfaces (`cli.py`, `web/`) son finas y orquestan el núcleo.

```
centinela/
├── core/
│   ├── http.py         # cliente HTTP/TLS (urllib + ssl + socket)
│   ├── checks.py       # chequeos de seguridad (headers, TLS, cookies, CORS…)
│   ├── scanner.py      # orquestador de escaneo determinístico
│   ├── crawler.py      # crawler same-origin
│   ├── profile.py      # perfilado context-aware + escalado de severidad
│   ├── engine.py       # pentester por reglas (SQLi/XSS/LFI/SSTI/forms/…)
│   ├── templates.py    # motor de plantillas (estilo Nuclei, JSON)
│   ├── recon.py        # recon de red (subdominios, puertos, banner+CVE)
│   ├── guard.py        # bot guardián 24/7 + diff inteligente de alertas
│   ├── vulns.py        # gestión de vulnerabilidades (ciclo de vida)
│   ├── notify.py       # alertas (Slack/Discord/Teams/email/escritorio)
│   ├── auth.py         # cuentas, roles, API-keys, sesiones (PBKDF2 + HMAC)
│   ├── remediate.py    # generador de config de remediación (modo defensa)
│   ├── report.py       # scoring A–F
│   ├── report_html.py  # informe HTML/PDF + CSV (OWASP)
│   ├── store.py        # persistencia (JSON) + historial
│   └── gui.py          # app de escritorio conversacional (Tkinter)
├── web/                # dashboard (HTML/CSS/JS vanilla)
├── templates/          # chequeos por plantilla (.json)
├── tests/              # suite de tests (unittest)
└── cli.py              # CLI + servidor + API REST
```

---

## 💡 Decisiones de diseño

- **Cero dependencias.** Todo con la stdlib de Python (`urllib`, `ssl`, `socket`, `http.server`,
  `hashlib`, `hmac`, `concurrent.futures`, `tkinter`). Se clona y corre — no hay supply chain que auditar,
  no hay `requirements` que se rompa. Para una herramienta de seguridad, eso es una característica, no una limitación.
- **Autónomo.** No depende de ningún servicio externo ni LLM: el "cerebro" del pentester es lógica determinística.
- **Seguro por diseño.** Contraseñas con PBKDF2 (200k iteraciones, salt por usuario), sesiones firmadas con HMAC,
  protección contra path traversal, gate de autorización ético en todos los escaneos activos.
- **Concurrente.** Los chequeos independientes corren en paralelo (`ThreadPoolExecutor`).

## 🆚 Comparación con herramientas tipo Strix

Centinela toma ideas de plataformas de pentesting autónomo como [Strix](https://github.com/usestrix/strix),
pero con una filosofía opuesta en un punto clave: **no depende de un LLM**.

| | **Centinela** | **Strix (y similares)** |
|---|---|---|
| "Cerebro" del pentester | Motor de reglas determinístico | Agentes LLM (Claude/GPT) |
| Requiere API key / pagar tokens | No — $0, corre offline | Sí |
| Instalación | `git clone` y listo (stdlib) | Docker + pipx + API keys |
| Reproducibilidad | Mismo input → mismo resultado | No determinístico |
| Explotación creativa de casos raros | Limitada a sus reglas | Más profunda (razona como humano) |
| Cobertura | Web + red + código + DNS/email | Principalmente web/código |

La traducción honesta: un agente LLM puede improvisar ataques que un motor de reglas no conoce —
pero a cambio cuesta plata por escaneo, necesita internet y un proveedor, y puede dar resultados
distintos cada vez. Centinela apuesta a **precisión validada y reproducible con costo cero**,
que es lo que un pipeline de CI/CD o un monitoreo 24/7 necesitan.

## ⚖️ Uso ético

Centinela es una herramienta **defensiva**. Usala únicamente sobre sistemas **propios o con
autorización explícita** (programas de bug bounty, laboratorios). El gate de autorización está
cableado en cada escaneo activo.

## 🎯 Habilidades demostradas

Este proyecto pone en práctica, de punta a punta:

- **Seguridad ofensiva (DAST):** detección y validación de OWASP Top 10 — inyección (SQLi/XSS/LFI/SSTI), exposición de datos, misconfiguración, componentes vulnerables.
- **Seguridad defensiva / criptografía:** hashing de contraseñas con PBKDF2, sesiones firmadas con HMAC, control de acceso por roles, manejo seguro de secretos.
- **Redes y protocolos:** HTTP/TLS de bajo nivel (sockets), escaneo de puertos, banner-grabbing, DNS.
- **Concurrencia:** escaneo paralelo con `ThreadPoolExecutor`.
- **Diseño de software:** arquitectura modular, núcleo testeable desacoplado de las interfaces.
- **Diseño de API:** API REST con autenticación, roles y versionado de recursos.
- **Testing y CI/CD:** suite de tests (incluye integración end-to-end) + pipeline de GitHub Actions.
- **Producto:** múltiples interfaces (CLI, web, escritorio), informes para auditoría, flujo de gestión de vulnerabilidades.

## 🧰 Tech stack

`Python 3.10+` · `stdlib only` · `Tkinter` (GUI) · `HTML/CSS/JS vanilla` (dashboard) · `unittest` · `GitHub Actions`

## 📄 Licencia

MIT — ver [LICENSE](LICENSE).

---

<sub>Construido de forma autónoma como proyecto de aprendizaje y portfolio. Feedback y PRs bienvenidos.</sub>
