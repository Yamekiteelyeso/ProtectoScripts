# Lexy Protect

Hosting de scripts con loadstring protegido, login (usuario/correo, Google, Discord), estadísticas (ejecuciones totales y por semana) y límite de 5 scripts por cuenta.

## Estructura

```
lexy-protect/
├── index.js
├── package.json
├── .env.example
└── index.html
```

## Correr en local

```bash
npm install
node --env-file=.env.example index.js   # Node 20+; o exportá las variables a mano
```

Abrí http://localhost:3000

## Desplegar en Railway

1. Subí la carpeta a GitHub y en Railway elegí **Deploy from GitHub repo**.
2. En **Variables** poné solo `JWT_SECRET` (un texto largo cualquiera). Lo demás es opcional.
3. En **Settings → Networking → Public Networking** tocá **Generate Domain**. Ese link (`...up.railway.app`) es el público. El `.railway.internal` es privado y no abre en el navegador.
4. Si Railway te pide el puerto, poné el que dice el log de Deploy (`puerto XXXX`), o creá la variable `PORT=8080` y usá 8080.
5. La base de datos es un archivo que se crea sola, no hay que configurarla. Para que **no se borre en cada deploy**, agregá un Volume al servicio (ruta `/data`). Railway avisa solo la ruta y el código la usa automáticamente.

## Login con Google y Discord

- Google: Google Cloud Console → Credenciales → ID de cliente OAuth. Redirect URI: `BASE_URL/auth/google/callback`
- Discord: Developer Portal → OAuth2. Redirect: `BASE_URL/auth/discord/callback`

Si no cargás las claves, esos botones aparecen deshabilitados y el login con usuario/correo sigue funcionando.

## Links tipo `nombre.lexyprotect...`

Railway no da subdominios comodín en `*.up.railway.app`. Por defecto el loadstring usa `BASE_URL/s/nombre`.
Si querés `nombre.tudominio.com`, apuntá un wildcard `*.tudominio.com` a Railway y poné `BASE_DOMAIN=tudominio.com`.

## Cómo protege

1. **Abierto para todos**: cualquiera ejecuta el script con su executor. No hay claves, tokens ni whitelist.
2. **Navegador**: si abrís el link en el navegador ves la página pública del script (con el loadstring), nunca el código.
3. **Bots**: Discord, curl, python, etc. reciben un bloqueo y se cuentan como "bloqueados". Solo se bloquean bots conocidos, nunca executors.
4. **Cargador en 2 etapas**: la etapa 1 (cambia en cada pedido) trae solo la clave; el código cifrado sale de una segunda URL con token de un solo uso que dura 30 s. Volcar la URL con `print(game:HttpGet(...))` o repetir el pedido no da el código.
5. **Anti-spy**: el cargador detecta HttpSpy, SimpleSpy, RemoteSpy, Hydroxide y Cobalt.
6. **Marca de agua** oculta en cada ejecución, HTTPS forzado y rate limit.

## Límite real (importante)

Ninguna protección es total: el script tiene que quedar en claro dentro del executor para poder correr, así que alguien con un executor que hookee `loadstring` puede volcarlo. Lexy Protect frena la copia casual, los bots y el `.get` desde Discord o el navegador, pero no es infalible. Si tu script es valioso, ofuscalo también antes de subirlo.

Si los filtros bloquean a un executor legítimo (por ejemplo Delta en móvil), ajustá `BOT_UA` y `suspicious()` en `index.js`.

## Base de datos

Los usuarios, scripts y estadísticas se guardan en SQLite (`DB_PATH`). Se crea sola. En Railway, para que no se borre en cada deploy, montá un Volume en `/data` y poné `DB_PATH=/data/lexy.db`.
