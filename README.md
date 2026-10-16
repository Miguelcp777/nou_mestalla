# Agrupación Nou Mestalla

Herramienta **no oficial** para organizar una agrupación de socios del Valencia CF en el proceso
"Camí a una nova casa" (Nou Mestalla, temporada 2027/28).

- **Agrupación y prioridad:** alta de miembros, cálculo del número de socio promedio (Fase 1), exportación CSV y resumen para WhatsApp.
- **Plano y precios:** réplica interactiva del plano oficial con el precio de cada sector y simulador de descuentos.
- **Hoja de ruta y FAQs:** fases oficiales y dudas frecuentes.

Es un único `index.html` estático (Tailwind CDN + Lucide + Vanilla JS). Los datos se guardan solo en el
navegador de cada usuario (localStorage). Fuente de los datos: valenciacf.com (octubre 2026).

## Base de datos cifrada (envío al capitán)

- Los socios pulsan **«Enviar al capitán»**: sus datos se cifran en el navegador (AES-256-GCM + RSA-OAEP-3072 con la
  clave pública del capitán) y se guardan en Netlify Blobs mediante la función `netlify/functions/api.mjs`.
- El capitán entra en **`/admin.html`** con su contraseña: la clave privada (cifrada con PBKDF2-SHA256 600k + AES-GCM)
  se descifra solo en su navegador. El servidor nunca ve datos en claro ni la contraseña.
- La activación inicial requiere la variable de entorno `SETUP_TOKEN` (configurada en Netlify).
- Para enviar datos hace falta el **código de la penya**; hay límite de intentos por IP.

Estructura: `public/` (web estática), `netlify/functions/` (API), `netlify.toml`.
Desarrollo local: `npm install` y `netlify dev`.
