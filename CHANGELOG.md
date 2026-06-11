# Changelog

Todas las novedades relevantes de Centinela. Formato basado en
[Keep a Changelog](https://keepachangelog.com/es-ES/).

## [1.0.0]

### Plataforma
- API REST completa con API-keys y autenticación por roles (admin / analyst / viewer).
- Cuentas, login (sesiones firmadas con HMAC) y contraseñas con PBKDF2.
- Dashboard web con pestañas **Escanear** y **Protección**; accesible desde el celular.
- App de escritorio conversacional (le hablás en español y ejecuta).

### Detección
- 13 familias de chequeos + inyección: SQLi, NoSQL, command injection, XSS, LFI/path traversal, SSTI.
- Análisis de JWT (alg:none, secretos HMAC débiles, sin expiración, datos sensibles en el payload).
- SAST: análisis estático de código local (secretos hardcodeados + patrones peligrosos) de alta precisión.
- Análisis context-aware (perfil del sitio) que ajusta la severidad.
- Motor de plantillas estilo Nuclei (chequeos en JSON, sin tocar código).
- Recon de red: subdominios (DNS), puertos, banner-grabbing con detección de versión vulnerable.
- Auditoría de DNS/email (SPF/DMARC) con resolver DNS propio sobre UDP (stdlib, EDNS0).
- Escaneo autenticado y crawler multi-página.

### Operación
- Modo guardián 24/7 con diff inteligente de alertas.
- Gestión de vulnerabilidades con ciclo de vida y auto-resolución.
- Modo defensa: generación de config de remediación (Vercel / nginx / Apache / Netlify).

### Integración y reporting
- Alertas a Slack / Discord / Teams / email + notificaciones de escritorio.
- Gate de CI/CD (`--fail-on`).
- Informes HTML/PDF y CSV con mapeo a OWASP Top 10.

### Calidad
- Suite de tests (unittest) y CI con GitHub Actions.
- Cero dependencias externas (solo librería estándar de Python).
