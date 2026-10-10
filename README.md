# nfdnsvpn

Bloqueador de anuncios y rastreadores para **toda la TV** (Android TV / Google TV) mediante una
VPN local. Todo se hace en el dispositivo: sin servidor, sin cuentas, sin root y sin descifrar
HTTPS. En el lanzador aparece como **VireoLuma Shield** (nombre provisional).

Premisas, arquitectura y fases: [`docs/PLAN.md`](docs/PLAN.md).

## Estado: fase 1 (modo ligero, solo DNS)

- Filtra el DNS de **todas las apps**: los dominios bloqueados reciben `0.0.0.0` / `::`.
- También filtra a las apps que usan DNS público fijo (Google, Cloudflare, Quad9, OpenDNS,
  AdGuard): esas IPs se envían al túnel, y el DNS cifrado (DoT/DoH) hacia ellas se corta para que
  la app vuelva al DNS normal.
- Listas: AdGuard DNS filter + HaGeZi Multi Pro (descarga diaria) + una lista propia de servidores
  de anuncios de vídeo. Unos 300 000 dominios, unos 7 MB de RAM.
- Pantalla para el mando: activar/desactivar, contador de consultas y bloqueos, últimos dominios
  bloqueados, estado de las listas y aviso si el DNS privado del sistema se salta el filtro.

## Instalar en la TV

1. Abre la pestaña **Actions** del repositorio, entra en la última ejecución verde de **CI** y
   descarga el artefacto `nfdnsvpn-debug`. Dentro está `app-debug.apk`.
2. Instálalo con `adb install -r app-debug.apk` o con una app como Downloader / Send Files to TV.
3. Abre **VireoLuma Shield**, pulsa **Activar protección** y acepta el aviso de VPN de Android.
4. Para que arranque sola al encender la TV: Ajustes › Red e Internet › VPN › VireoLuma Shield ›
   **VPN siempre activa**.
5. Si el DNS privado del sistema está en modo estricto, desactívalo (la app lo avisa).

Cada build de CI se firma con una clave de depuración distinta: para instalar una versión nueva
encima de otra puede hacer falta desinstalar antes.

## Compilar

Requisitos: JDK 21, Android SDK con NDK `28.2.13676358`, Rust (`rustup`).

```bash
(cd native/nfdns-core && cargo test)   # núcleo Rust
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
| `native/nfdns-core` | Núcleo Rust: paquetes IP/UDP/TCP, DNS, filtro de dominios, JNI |
| `app/src/main/java/.../vpn` | `ShieldVpnService` (TUN, reenvío DNS), DNS de subida, estado |
| `app/src/main/java/.../lists` | Descarga y caché de listas |
| `app/src/main/java/.../ui` | Pantalla para el mando |
| `app/src/main/assets/video-ads.txt` | Lista propia de servidores de anuncios de vídeo |
