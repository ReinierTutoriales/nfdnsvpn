# nfdnsvpn

Bloqueador de anuncios y rastreadores para **toda la TV** (Android TV / Google TV) mediante una
VPN local. Todo se hace en el dispositivo: sin servidor, sin cuentas, sin root y sin descifrar
HTTPS. En el lanzador aparece como **NF DNS VPN**.

Premisas, arquitectura y fases: [`docs/PLAN.md`](docs/PLAN.md).

## Estado: fases 1–5 hechas; falta la 6 (medir en la TV)

Dos modos, elegibles con el botón **Modo** de la pantalla:

- **Completo (por defecto):** todo el tráfico salvo la red local pasa por una pila TCP/IP propia (smoltcp) y
  se reenvía. Fuerza el DNS de cualquier app y corta DoT y DNS por TCP en cualquier servidor.
  En PC mueve más de 1 Gbit/s con unos 10 MB de RAM; falta medirlo en la TV.
  Además lee el nombre del servidor de cada conexión HTTPS (SNI) o HTTP (`Host`) y corta las
  de anuncios, rastreadores y DNS cifrado aunque la app no haya usado nuestro DNS.
  También en QUIC/HTTP3: lee el nombre del primer paquete; si no puede, fuerza a la app a TCP.
  Blindado contra bypass del DNS: resolvedor propio, DNS al router, DoT/DoQ, DoH por nombre o
  por IP, y TLS o QUIC en puertos raros (ver `docs/PLAN.md`).
  Y si una app sirve sus propios anuncios o telemetría, se le puede **cortar internet por
  completo** desde Opciones (Android 10+), aunque deje de funcionar.
- **Ligero:** solo el DNS pasa por la app. Coste casi nulo, pero una app con DNS propio se lo
  puede saltar.

Lo que hacen ambos modos:

- Filtra el DNS de **todas las apps**: los dominios bloqueados reciben `0.0.0.0` / `::`.
- También filtra a las apps que usan DNS público fijo (Google, Cloudflare, Quad9, OpenDNS,
  AdGuard): esas IPs se envían al túnel, y el DNS cifrado (DoT/DoH) hacia ellas se corta para que
  la app vuelva al DNS normal.
- Desenmascara rastreadores escondidos tras un CNAME de un dominio propio.
- Listas (prioridad: bloquear): AdGuard DNS filter + HaGeZi Ultimate + telemetría de fabricantes
  (HaGeZi native: Samsung, LG, Amazon, Roku, Xiaomi…) + HaGeZi Encrypted DNS + IPs de DNS cifrado
  (descarga diaria) + una lista propia de servidores de anuncios de vídeo. Unos 340 000 dominios
  y 3400 IPs, unos 7,6 MB de RAM. Bloquea los 131 dominios del test de d3ward y ninguno de los 50
  dominios críticos de TV medidos.
- Pantalla mínima: un botón grande de activar/desactivar, el estado y el número de bloqueos.
- **Opciones** (opcional): cambiar de modo, permitir un dominio bloqueado eligiéndolo con el
  mando, elegir listas (incluidas HaGeZi Pro, más ligera, OISD small/big y las de uBlock Origin, de las que se usan sus
  reglas de dominio), quitar dominios permitidos, excluir apps que fallen, dejar apps sin internet, arranque al encender
  y estado/consumo.
- Ligera: las listas se compilan leyendo los archivos línea a línea (pico de unos 17 MB al
  compilar, 7 MB después) y nada se consulta en segundo plano mientras no miras la pantalla.
- Las listas se actualizan solas una vez al día sin cortar las conexiones.

## Instalar y usar

1. Abre la pestaña **Actions** del repositorio, entra en la última ejecución verde de **CI** y
   descarga el artefacto `nfdnsvpn-debug`. Dentro está `app-debug.apk`.
2. Instálalo con `adb install -r app-debug.apk` o con una app como Downloader / Send Files to TV.
3. Abre **NF DNS VPN** y pulsa el botón grande. La primera vez Android pide:
   - el **permiso de VPN** (obligatorio), y
   - que la app **no se detenga para ahorrar energía** (una sola vez).

Eso es todo: la protección vuelve sola al encender la TV si la dejaste activada, y las listas
se actualizan solas. **Opciones** (modo, listas, dominios permitidos, apps excluidas, estado y
consumo) es opcional: lo que viene por defecto es lo recomendado.

Lo único que una app no puede activar por sí misma en Android es «Bloquear conexiones sin VPN»
(cubre los segundos en que la protección se reinicia). Es opcional y Opciones lleva directo a
ese ajuste. El otro aviso posible: si el DNS privado de Android está en modo estricto, la
pantalla lo indica, porque se salta el filtro.

Cada build de CI se firma con una clave de depuración distinta: para instalar una versión nueva
encima de otra puede hacer falta desinstalar antes.

## Compilar

Requisitos: JDK 21, Android SDK con NDK `28.2.13676358`, Rust (`rustup`).

```bash
(cd native/nfdns-core && cargo test)   # núcleo Rust
sudo scripts/e2e-linux.sh              # túnel con un TUN real (Linux, root, iproute2, curl, aioquic)
sudo scripts/e2e-linux.sh --bench      # además latencia, cortes y eficiencia (varios minutos)
scripts/validate-lists.sh              # eficacia de las listas y falsos positivos
./gradlew testDebugUnitTest lintDebug  # tests JVM contra la librería nativa + lint
./gradlew assembleDebug                # app/build/outputs/apk/debug/app-debug.apk
```

Medir las listas reales con el núcleo:

```bash
cd native/nfdns-core
cargo run --release --example measure -- lista1.txt lista2.txt
```

## Estructura

| Ruta | Contenido |
|---|---|
| `native/vendor/netstack-smoltcp` | Pila TCP/IP (copia con un parche de consumo en reposo) |
| `native/nfdns-core` | Núcleo Rust: clasificador, DNS (con CNAME), SNI/Host, QUIC Initial, filtro de dominios, apps sin internet, túnel (pila TCP/IP y relay), JNI |
| `scripts/e2e-linux.sh` | Prueba de extremo a extremo del túnel en *network namespaces* |
| `app/src/main/java/.../vpn` | `ShieldVpnService` (TUN y rutas de cada modo), DNS de la red, ajustes, estado |
| `app/src/main/java/.../lists` | Descarga y caché de listas |
| `app/src/main/java/.../ui` | Pantalla de un botón y Opciones, para el mando |
| `app/src/main/assets/video-ads.txt` | Lista propia de servidores de anuncios de vídeo |
