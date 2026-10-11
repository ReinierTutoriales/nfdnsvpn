# nfdnsvpn

Bloqueador de anuncios y rastreadores para **toda la TV** (Android TV / Google TV) mediante una
VPN local. Todo se hace en el dispositivo: sin servidor, sin cuentas, sin root y sin descifrar
HTTPS. En el lanzador aparece como **NF DNS VPN**.

Premisas, arquitectura y fases: [`docs/PLAN.md`](docs/PLAN.md).

## Estado: fase 4 (QUIC e IPv6), pendiente de probar en la TV

Dos modos, elegibles con el botón **Modo** de la pantalla:

- **Ligero (por defecto):** solo el DNS pasa por la app. Coste casi nulo.
- **Completo:** todo el tráfico salvo la red local pasa por una pila TCP/IP propia (smoltcp) y
  se reenvía. Fuerza el DNS de cualquier app y corta DoT y DNS por TCP en cualquier servidor.
  En PC mueve más de 1 Gbit/s con unos 10 MB de RAM; falta medirlo en la TV.
  Además lee el nombre del servidor de cada conexión HTTPS (SNI) o HTTP (`Host`) y corta las
  de anuncios, rastreadores y DNS cifrado aunque la app no haya usado nuestro DNS.
  También en QUIC/HTTP3: lee el nombre del primer paquete; si no puede, fuerza a la app a TCP.

Lo que hacen ambos modos:

- Filtra el DNS de **todas las apps**: los dominios bloqueados reciben `0.0.0.0` / `::`.
- También filtra a las apps que usan DNS público fijo (Google, Cloudflare, Quad9, OpenDNS,
  AdGuard): esas IPs se envían al túnel, y el DNS cifrado (DoT/DoH) hacia ellas se corta para que
  la app vuelva al DNS normal.
- Desenmascara rastreadores escondidos tras un CNAME de un dominio propio.
- Listas: AdGuard DNS filter + HaGeZi Multi Pro + HaGeZi Encrypted DNS (descarga diaria) + una
  lista propia de servidores de anuncios de vídeo. Unos 304 000 dominios, unos 7 MB de RAM.
- Pantalla para el mando: activar/desactivar, contador de consultas y bloqueos, últimos dominios
  bloqueados, estado de las listas y aviso si el DNS privado del sistema se salta el filtro.

## Instalar en la TV

1. Abre la pestaña **Actions** del repositorio, entra en la última ejecución verde de **CI** y
   descarga el artefacto `nfdnsvpn-debug`. Dentro está `app-debug.apk`.
2. Instálalo con `adb install -r app-debug.apk` o con una app como Downloader / Send Files to TV.
3. Abre **NF DNS VPN**, pulsa **Activar protección** y acepta el aviso de VPN de Android.
4. Para que arranque sola al encender la TV: Ajustes › Red e Internet › VPN › NF DNS VPN ›
   **VPN siempre activa**.
5. Si el DNS privado del sistema está en modo estricto, desactívalo (la app lo avisa).

Cada build de CI se firma con una clave de depuración distinta: para instalar una versión nueva
encima de otra puede hacer falta desinstalar antes.

## Compilar

Requisitos: JDK 21, Android SDK con NDK `28.2.13676358`, Rust (`rustup`).

```bash
(cd native/nfdns-core && cargo test)   # núcleo Rust
sudo scripts/e2e-linux.sh              # túnel con un TUN real (Linux, root, iproute2, curl, aioquic)
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
| `native/nfdns-core` | Núcleo Rust: clasificador, DNS (con CNAME), SNI/Host, QUIC Initial, filtro de dominios, túnel (pila TCP/IP y relay), JNI |
| `scripts/e2e-linux.sh` | Prueba de extremo a extremo del túnel en *network namespaces* |
| `app/src/main/java/.../vpn` | `ShieldVpnService` (TUN y rutas de cada modo), DNS de la red, ajustes, estado |
| `app/src/main/java/.../lists` | Descarga y caché de listas |
| `app/src/main/java/.../ui` | Pantalla para el mando |
| `app/src/main/assets/video-ads.txt` | Lista propia de servidores de anuncios de vídeo |
