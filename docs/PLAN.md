# nfdnsvpn — premisas y plan

Bloqueador de anuncios y rastreadores para **toda la TV** (Android TV / Google TV, objetivo
principal: onn 4K de 2 GB de RAM) mediante una VPN local (`VpnService`). Proyecto independiente: protege todas las apps
instaladas sin depender de ningún navegador.

## Premisas

1. **Nada sale del dispositivo.** La VPN es local: no hay servidor remoto, ni cuentas, ni
   telemetría. El tráfico permitido sale directamente a Internet por sockets protegidos.
2. **Sin root y sin descifrar HTTPS.** Se filtra por nombre de dominio (DNS), por nombre del
   servidor en el inicio de la conexión (SNI) y por IP. Nunca se instala un certificado.
3. **Todas las apps.** El filtro se aplica a todas las apps instaladas, con una lista de apps
   excluidas para las que fallen.
4. **Ligero.** Pensado para 2 GB: núcleo en Rust, listas compiladas en memoria compacta, y un modo
   ligero (solo DNS) además del túnel completo.
5. **Cerrar los huecos de bypass** que dejan otras soluciones: DNS forzado aunque la app use
   8.8.8.8 o 1.1.1.1, bloqueo de DoH/DoT, SNI, QUIC e IPv6.

## Lo que sí se bloquea

- Anuncios de terceros en apps y juegos (AdMob, Unity Ads, AppLovin…).
- Rastreadores y telemetría.
- Anuncios de vídeo insertados por la app desde un servidor publicitario aparte (CSAI): IMA,
  DoubleClick, FreeWheel, SpotX, Innovid.

## Lo que no se puede bloquear (ningún producto lo hace)

- Anuncios cosidos en el propio vídeo por el servidor (SSAI): Twitch, Pluto TV, canales en directo.
- Anuncios de YouTube en la app oficial (salen de `googlevideo.com`, igual que el vídeo). Para
  YouTube: SmartTube.
- Apps con certificado fijado (*pinning*): no se pueden descifrar; solo se les cortan los dominios
  de anuncios.
- Encrypted Client Hello (ECH): oculta el nombre del servidor; quedan el DNS y la lista de IPs.

## Arquitectura

```
 Apps de la TV ──► Interfaz TUN (VpnService)
                     │  paquetes IP
                     ▼
   Núcleo Rust (libnfdns.so), un hilo, tokio current-thread
   clasificador (route.rs)
     ├─ UDP 53 a cualquier IP ─► filtro ─► respuesta local o reenvío al DNS de la red
     ├─ TCP 53, puerto 853, otros puertos de resolvedores ─► RST / descarte
     └─ resto (modo completo) ─► pila TCP/IP smoltcp (netstack-smoltcp)
                                   ├─ TCP ─► relay con TcpStream real
                                   └─ UDP ─► NAT con UdpSocket real
                     │
                     ▼
     sockets normales: la app se excluye de la VPN ──► Internet
```

| Pieza | Lenguaje | Función |
|---|---|---|
| `ShieldVpnService` | Kotlin | Crea el TUN con las rutas del modo, arranca y para el túnel |
| `native/nfdns-core/src/route.rs` | Rust | Primera decisión para cada paquete |
| `native/nfdns-core/src/tunnel.rs` | Rust | Bucle de eventos: TUN, DNS, pila TCP/IP, relay TCP y NAT UDP |
| `native/nfdns-core/src/filter.rs` | Rust | Filtro de dominios compacto |
| `ListRepository` | Kotlin | Descarga las listas (gzip, ETag) y las guarda en disco |
| `MainActivity` | Kotlin | Interfaz para mando: encender, modo, contadores, últimos bloqueos |

## Modos

| Modo | Tráfico por la app | Cubre | Coste |
|---|---|---|---|
| Ligero | Solo DNS (y las IPs de resolvedores públicos conocidos) | Apps que usan DNS, y las que usan 8.8.8.8/1.1.1.1 | Casi cero |
| Completo | Todo salvo LAN y multicast | DNS forzado, DoT/DNS-TCP cortados en cualquier IP; SNI, QUIC e IPs en fases 3–4 | Medido en PC: ver fase 2 |

## Fases

| Fase | Entrega | Validación |
|---|---|---|
| 1 | Modo ligero (DNS) + interfaz mínima | Bloqueo visible en apps con anuncios de AdMob o Unity |
| 2 | Túnel completo con smoltcp + reenvío | Vídeo 4K sin cortes; RAM < 40 MB; latencia añadida < 5 ms |
| 3 | SNI + bloqueo de DoH/DoT/IP | Una app con DoH propio queda filtrada |
| 4 | QUIC + IPv6 completo | Sin fugas en pruebas tipo dnsleaktest |
| 5 | Listas configurables, actualizador diario, exclusiones, arranque al encender | 7 días encendida sin cierres |
| 6 | Medición en la onn y ajuste | Informe de CPU, RAM y anuncios bloqueados por app |

## Listas

| Lista | URL | Por defecto |
|---|---|---|
| AdGuard DNS filter | `https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt` | Sí |
| HaGeZi Ultimate (la más estricta de HaGeZi) | `https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/ultimate.txt` | Sí |
| HaGeZi native: telemetría de fabricantes (samsung, lgwebos, amazon, roku, xiaomi, tiktok, apple, huawei, oppo-realme, vivo, winoffice) | `https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.<fabricante>.txt` | Sí |
| HaGeZi Multi Pro (subconjunto más ligero de Ultimate) | `https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt` | No (opcional en Ajustes) |
| HaGeZi Encrypted DNS (servidores DoH/DoQ) | `https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/doh.txt` | Sí (fase 3) |
| IPs de DNS cifrado: HaGeZi `ips/doh.txt` + dibdot `doh-ipv4.txt` y `doh-ipv6.txt` | `https://raw.githubusercontent.com/hagezi/dns-blocklists/main/ips/doh.txt`, `https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master/doh-ipv{4,6}.txt` | Sí (anti-bypass) |
| OISD small | `https://small.oisd.nl/` | No (opcional en Ajustes) |
| OISD big | `https://big.oisd.nl/` | No (opcional en Ajustes) |
| uBlock Origin: filters, privacy, badware (solo sus reglas de dominio) | `https://ublockorigin.github.io/uAssets/filters/{filters,privacy,badware}.txt` | No (opcional en Ajustes): +240 dominios sobre las de por defecto |
| Anuncios de vídeo (propia) | `app/src/main/assets/video-ads.txt` | Sí |

Solo se usan las reglas de dominio: `||dominio^` (incluye subdominios), `@@||dominio^`
(excepción), líneas de `hosts` y dominios sueltos (dominio exacto). Las reglas con ruta, con
modificadores (`$third-party`…) o cosméticas se ignoran: sin descifrar no se ve la URL.

## Límites conocidos de la fase 1

- **DNS privado del sistema en modo estricto** envía el DNS cifrado al proveedor y se salta la
  VPN. La app lo detecta y avisa para desactivarlo.
- Una app con IP fija hacia un resolvedor que no esté en la lista de resolvedores conocidos se
  salta el filtro hasta la fase 3.
- Solo hay una VPN a la vez en Android: si hay otra activa, se desconecta.
- DNS sobre TCP hacia el resolvedor virtual recibe RST (no hay pila TCP hasta la fase 2). Solo se
  usa cuando una respuesta UDP llega truncada, algo raro con EDNS.

## Decisiones de la fase 1

| Tema | Decisión | Motivo |
|---|---|---|
| Nombre y paquete | "NF DNS VPN", `com.reiniertutoriales.nfdnsvpn` | Proyecto independiente, mismo nombre que el repositorio |
| DNS de subida | El de la red real (router); si no anuncia ninguno, Quad9 | La app se excluye de la VPN, así que ve la red real |
| Respuesta de bloqueo | `0.0.0.0` / `::` con TTL de 60 s; vacía para otros tipos | Un cambio de lista llega a las apps en un minuto |
| Resolvedores públicos | Sus IPs van al túnel; DNS se filtra, TCP recibe RST, QUIC se descarta | Cierra el DNS fijo y el DoT/DoH hacia ellos desde la fase 1 |
| Red medida | `setMetered(false)` | Desde Android 10 una VPN es medida por defecto y las apps de vídeo bajan la calidad |
| Servicio en primer plano | Tipo `specialUse` | `systemExempted` no se pudo verificar en el código de Android; `specialUse` no tiene requisitos en tiempo de ejecución |
| Arranque al encender | "VPN siempre activa" de Android; receptor propio en la fase 5 | — |

## Medidas del núcleo (fase 1, PC x86_64)

| Medida | Valor |
|---|---|
| Dominios únicos (AdGuard DNS + HaGeZi Pro) | 300 782 |
| Memoria del filtro compilado | 6,8 MB |
| Tiempo de compilación de las listas | ~0,17 s |
| Tiempo por consulta | ~0,3 µs |

En la onn el procesador es más lento: hay que repetir la medida en la fase 6.

## Fase 2: túnel completo

**Estado:** hecho y probado en Linux con un TUN real; pendiente de medir en la onn. El modo
completo está desactivado por defecto y se activa con el botón "Modo" de la pantalla.

### Decisiones

| Tema | Decisión | Motivo |
|---|---|---|
| Pila TCP/IP | `netstack-smoltcp` 0.2.4 (smoltcp 0.12, MIT/Apache) | Mantenida, construida sobre smoltcp como preveía el plan; evita escribir el emparejado de sockets a mano |
| Hilo | Un runtime tokio `current_thread` | Un solo núcleo de CPU en la onn; sin bloqueos ni cambios de contexto |
| Ambos modos | El mismo túnel Rust; solo cambian las rutas | Se elimina el reenvío DNS en Kotlin de la fase 1 |
| Rutas del modo completo | `0.0.0.0/0` menos 10/8, 172.16/12, 192.168/16, 169.254/16, 127/8, 0/8 y 224/3 (46 bloques) | El tráfico de red local (casting, descubrimiento, servidores multimedia) no lleva anuncios y se rompe con facilidad |
| IPv6 | `2000::/3` solo si la red real tiene ruta IPv6 por defecto | Si no, las apps intentarían IPv6 primero y fallarían |
| DNS forzado | Toda consulta UDP 53 se responde aquí, vaya a la IP que vaya | Las apps con resolvedor fijo quedan filtradas |
| DoT, DoQ y DNS por TCP | Puerto 853 (TCP y UDP) y TCP 53 cortados hacia cualquier IP | Así las apps vuelven al DNS UDP, que se filtra |
| Memoria por conexión | Búferes de 32 KiB: unos 160 KiB por conexión TCP | Con 64 KiB por defecto serían 320 KiB; la ventana local de 32 KiB da cientos de Mbit/s |
| Fin de cada relay | Cuando un sentido termina, el otro tiene 10 s; el cierre de escritura, 5 s | Ninguna tarea puede quedarse colgada esperando un cierre que no llega |
| NAT UDP | Un socket por flujo (app, destino), cerrado tras 120 s sin tráfico | Suficiente para QUIC y juegos entre keepalives |

### Medidas (PC x86_64, `scripts/e2e-linux.sh`)

| Medida | Valor |
|---|---|
| Descarga de 200 MB por la pila | 1242 Mbit/s |
| CPU del túnel para esos 200 MB | 1,25 s |
| RAM del proceso tras 5 ráfagas de 50 conexiones | 8,4 MB, estable entre ráfagas |
| DoT cortado | RST en 3 ms |

La prueba monta tres *network namespaces* (apps, túnel, servidores) para que, como en Android,
todo el tráfico de las apps entre en el TUN, incluidos los ACK que el kernel envía por su cuenta
al cerrar conexiones. Se ejecuta en cada build de CI.

### Riesgos abiertos

- **Sin medir en la onn:** CPU, RAM y fluidez del 4K son la validación de la fase 2.
- **ACK de conexiones ya cerradas en Android:** en Linux, enrutar por UID dejaba esos ACK fuera
  del túnel y smoltcp retenía la conexión en LAST_ACK. Android enruta con marcas de socket, que
  deberían conservarse, pero no está verificado en el dispositivo. Si falla, la RAM del túnel
  crecería con el uso; se vigila en la fase 6.
- **DNS a la IP del router:** en modo completo la LAN no pasa por el túnel, así que una app que
  pregunte directamente al router se salta el filtro. El resolvedor del sistema sí usa el nuestro.

## Fase 3: SNI, DoH y CNAME

**Estado:** hecho y probado en Linux con un TUN real (`scripts/e2e-linux.sh`, también en CI).

| Técnica | Cómo | Modo |
|---|---|---|
| Nombre del servidor en TCP | Antes de reenviar la conexión se lee lo primero que envía la app: el SNI del ClientHello TLS (aunque llegue en varios segmentos o registros, como los ClientHello post-cuánticos de ~1,8 KB) o la cabecera `Host` de HTTP. Si el nombre está bloqueado, la conexión se cierra | Completo |
| Sin latencia añadida | La conexión real se abre en paralelo mientras se lee el primer mensaje | Completo |
| Puertos inspeccionados | 80, 443, 8080 y 8443. Si el cliente no habla en 3 s (protocolo en el que habla primero el servidor), se reenvía sin inspeccionar | Completo |
| DNS cifrado (DoH/DoQ) | Lista HaGeZi Encrypted DNS (unos 3200 servidores): no se resuelven por DNS ni se conectan por SNI | Ambos (SNI solo en completo) |
| CNAME uncloaking | Si la respuesta del DNS de la red lleva un CNAME hacia un dominio bloqueado (rastreador disfrazado de dominio propio), se responde como bloqueado | Ambos |

**Con ECH** (Encrypted Client Hello) el SNI visible es el nombre público del proveedor
(p. ej. `cloudflare-ech.com`), no el real: ahí siguen valiendo el DNS y el CNAME.

**No incluido, a propósito:** listas de IPs de redes de anuncios. Los anuncios se sirven desde
CDN compartidas y bloquear sus IPs rompería contenido legítimo. Las conexiones por IP fija sin
nombre siguen pasando; con SNI se cubren las que usan TLS.

Medida con las tres listas por defecto: 304 017 dominios, 6,9 MB de filtro.

## Fase 4: QUIC e IPv6

**Estado:** QUIC hecho y probado en Linux con un TUN real; IPv6 probado solo en CI (el
contenedor de desarrollo no tiene IPv6 en el kernel).

| Técnica | Cómo |
|---|---|
| Nombre en QUIC (HTTP/3) | Los paquetes Initial del cliente se descifran con las claves que se derivan de su connection ID, que va en claro (RFC 9001 §5.2; probado con el vector oficial del Apéndice A). Se reensamblan los frames CRYPTO aunque el ClientHello ocupe varios paquetes y lleguen desordenados, y se lee el SNI |
| Decisión | El tráfico UDP al puerto 443 se retiene hasta 1 s u 8 datagramas. Nombre bloqueado: se descarta el flujo. Nombre permitido: se reenvía. Sin nombre legible (otra versión de QUIC u otro protocolo): se descarta y la app vuelve a TCP, donde se inspecciona el SNI |
| Reintentos | Un flujo descartado se mantiene 30 s tragando datagramas, para no reinspeccionar cada reintento |
| Contador | "QUIC rechazado" en pantalla (modo completo) |
| IPv6 | Mismo tratamiento que IPv4: DNS al resolvedor virtual `fd00:6e66::1`, TCP y UDP por la pila. La ruta `2000::/3` solo se añade si la red real tiene IPv6 (fase 2) |

**Prueba:** `aioquic` como servidor y cliente a través del túnel: el SNI permitido completa el
handshake; el bloqueado no recibe respuesta.

## Fase 5: ajustes y uso diario

**Estado:** hecho; compila y pasa tests y lint. La parte de Android (pantallas, arranque al
encender, exclusiones) solo se puede probar en el dispositivo.

| Función | Cómo |
|---|---|
| Elegir listas | Ajustes › Listas de bloqueo: AdGuard DNS, HaGeZi Ultimate, HaGeZi native, HaGeZi Encrypted DNS e IPs de DNS cifrado (activas por defecto); HaGeZi Pro, OISD small/big y uBlock Origin (opcionales). La lista propia de vídeo siempre está activa |
| Lista blanca sin teclado | "Permitir un dominio bloqueado" en la pantalla principal muestra los últimos bloqueados; se elige con el mando. Se aplica como `@@||dominio^` (también subdominios) y se quita en Ajustes |
| Apps excluidas | Ajustes › Apps excluidas: lista de apps con icono en el lanzador; su tráfico no pasa por la VPN (`addDisallowedApplication`) |
| Apps sin internet | Ajustes › Apps sin internet (Android 10+): se descartan todas las conexiones de la app (ver «Apps sin internet») |
| Aplicar cambios | Listas y lista blanca: se cambia el filtro en caliente, sin cortar conexiones. Exclusiones: se reinicia el túnel (las rutas y apps se fijan al crearlo) |
| Actualización diaria | Mientras la VPN está activa, cada 6 h se mira si alguna lista tiene más de un día; si es así, se descarga y el filtro nuevo sustituye al anterior sin reiniciar |
| Arranque al encender | `BootReceiver` (también tras actualizar la app) arranca la protección si estaba activa al apagar y el permiso de VPN ya está concedido |
| Medición (para la fase 6) | En pantalla, con la VPN activa: RAM (PSS) y CPU acumulada del proceso |

## Fase 6: medición en la onn

Es la prueba en el dispositivo, sin código nuevo previsto salvo ajustes que salgan de ella:

1. Instalar el APK del último CI, activar la protección (modo ligero) y anotar RAM y CPU.
2. Comprobar el bloqueo en apps con anuncios de AdMob o Unity y en el lanzador.
3. Pasar a modo completo, reproducir 4K al menos 30 min y anotar RAM, CPU, conexiones activas
   y "QUIC rechazado".
4. Dejarla 24 h encendida: la RAM no debe crecer de forma continua.
5. Reiniciar la TV y confirmar que la protección vuelve sola.

## Refuerzo y optimización (tras la fase 5)

| Cambio | Antes | Ahora |
|---|---|---|
| Listas de uBlock Origin (solo dominios), opción desactivada por defecto | — | +240 dominios, +5 KB de RAM (sus reglas de ruta, cosméticas y scriptlets solo sirven dentro de un navegador) |
| Carga de listas | Texto completo de cada lista en memoria Java (~17 MB en UTF-16) y luego en Rust | Rust lee cada archivo línea a línea; Java nunca tiene una lista entera |
| Construcción del filtro (3 listas, 304 017 dominios, PC) | Pico 32,8 MB, retenido después 23,9 MB | Pico 16,9 MB, retenido 7,1 MB |
| Descarga de listas | Lista entera en memoria antes de guardarla | Línea a línea al disco, validando por el camino |
| Contadores de la pantalla | Consultados cada segundo aunque nadie mire | Solo mientras la pantalla está visible: sin despertar la CPU en segundo plano |
| Búfer por flujo UDP | 64 KiB (50 flujos QUIC: 3,2 MB) | 16 KiB (0,8 MB); los datagramas reales no pasan del MTU |

## Blindaje anti-bypass del DNS

Objetivo: fuera de los anuncios que sirve la propia app, ninguna app debe poder resolver un
dominio bloqueado ni conectarse a él.

| Vía de escape | Cierre | Probado en `e2e-linux.sh` |
|---|---|---|
| Resolvedor propio (cualquier IP, UDP 53) | Modo completo por defecto: toda consulta UDP 53 se contesta en el túnel | Sí (8.8.8.8 y 203.0.113.53) |
| DNS directo al router (está en la LAN, fuera del túnel) | Se enrutan al túnel solo las IP de los DNS de la red; el resto de la LAN sigue directa | No (es enrutado de Android) |
| DNS por TCP, DoT y DoQ (853) | RST / descarte hacia cualquier IP | Sí |
| DoH por nombre | Lista HaGeZi Encrypted DNS, por DNS y por SNI | Sí (SNI) |
| DoH por IP fija | Listas de IPs de DNS cifrado (unas 3400 IPv4 y 1400 IPv6): se corta todo lo que no sea DNS hacia ellas. Solo IPs públicas: nunca se bloquea una dirección local | Sí |
| TLS o QUIC en puertos no estándar | SNI inspeccionado en cualquier puerto (3 s en 80/443/8080/8443, 300 ms en el resto); QUIC detectado en cualquier puerto por su paquete Initial | Sí |
| QUIC ilegible (otra versión, cifrado propio sobre UDP 443) | Se descarta: la app vuelve a TCP | Sí |
| La protección se detiene (actualización, falta de memoria) | La app avisa si falta «Bloquear conexiones sin VPN» de Android; con él no sale nada sin filtrar | No (ajuste del sistema) |
| Encrypted Client Hello (oculta el nombre del servidor) | Las consultas HTTPS/SVCB (tipos 65 y 64), que llevan las claves ECH, reciben una respuesta vacía: sin claves, TLS y QUIC muestran el nombre real y el SNI se filtra. Los clientes vuelven a A/AAAA | Test unitario |
| DoH propio de Firefox | `use-application-dns.net` responde NXDOMAIN, la señal oficial de Mozilla para que no lo active | Test unitario |
| IP fija o resolvedor propio de una app permitida | **Apps vigiladas** (abajo): solo nombres legibles y permitidos o IPs dadas por nuestro DNS | Sí |
| Modo ligero | No es a prueba de bypass: solo se enruta el DNS. Queda como opción de bajo consumo | — |

**Límites que siguen existiendo** (ninguna herramienta sin descifrar el tráfico los cierra):
una app que lleve sus consultas dentro de su propio protocolo cifrado hacia sus servidores, o
que se conecte a una IP fija sin TLS ni nombre. Equivale a la app que sirve sus propios anuncios.
Para esas apps queda el último recurso: **cortarles internet por completo** (abajo).

## Apps permitidas, lo más limpias posible

Para una app que se quiere usar pero que hace lo que quiere, hay tres niveles, de menos a más:

1. **Por defecto, en todas:** DNS filtrado aunque usen su propio resolvedor, SNI/Host/QUIC
   inspeccionados en cualquier puerto, DNS cifrado cortado, sin ECH y CNAME desenmascarados.
2. **App vigilada** (Opciones › Apps vigiladas, Android 10+, modo completo): solo puede
   conectarse a un servidor cuyo nombre se lea (SNI, `Host`, QUIC Initial) y esté permitido, o
   a una dirección que haya dado nuestro DNS. Se cortan las IP fijas, su DNS por otro camino y
   cualquier protocolo sin nombre hacia una dirección desconocida. Una conexión a una IP
   desconocida no se abre hasta ver el nombre: el servidor no recibe nada.
   - Una dirección resuelta vale lo que dice su TTL (como mínimo 5 min y como máximo 6 h) más 10
     min. Se guardan como mucho 16 384 direcciones (~1 MB), y solo mientras hay alguna app
     vigilada. Las direcciones son comunes a todas las apps: Android resuelve con un servicio del
     sistema y no dice para quién.
   - Activarla reinicia la protección: Android vacía su caché DNS y las apps resuelven otra vez.
   - Rompe a propósito lo que conecta por IP sin pasar por el DNS (llamadas P2P/WebRTC, algunos
     juegos). Por eso se activa app por app.
3. **«A dónde se conecta» y bloquear lo que sobre:** de cada app vigilada se guardan los últimos
   50 destinos (permitidos y cortados). En Opciones se elige uno con el mando: si estaba permitido,
   se bloquea en todas las apps (su telemetría, por ejemplo) y queda en «Dominios bloqueados por
   ti»; si lo cortaban las listas y hace falta, se permite.
4. **App sin internet** (abajo), el último recurso.

Límite honesto: si la telemetría sale del mismo nombre que el contenido (como los anuncios de
YouTube desde `googlevideo.com`), nada que no descifre el tráfico puede separarlas.

## Apps sin internet

Si una app sirve sus propios anuncios o telemetría desde sus servidores, no hay forma de separar
eso de su contenido sin descifrar. Lo que sí se puede hacer es cortarle la red entera, aunque deje
de funcionar: en **Opciones › Apps sin internet** se marca la app.

- Android dice a la app de VPN qué app abrió cada conexión
  (`ConnectivityManager.getConnectionOwnerUid`, Android 10+). El núcleo pregunta el dueño de cada
  conexión TCP y de cada flujo UDP nuevos y, si es una app marcada, descarta la conexión antes de
  abrirla hacia el servidor: no le llega ni el SYN. También se quedan sin respuesta las consultas
  DNS que esa app mande a su propio resolvedor.
- Sin coste cuando no hay ninguna app marcada: el túnel no pregunta nada. Con alguna marcada,
  cuesta una llamada al sistema por conexión nueva, en un hilo aparte; las conexiones ya
  abiertas no se tocan.
- Si Android no sabe el dueño (conexión ya cerrada, error del sistema), se deja pasar: con un
  fallo así no debe quedarse sin red toda la TV.
- Necesita el modo completo (en el ligero el tráfico de la app no pasa por el túnel). Si la app
  también está excluida, el bloqueo manda: vuelve a pasar por el túnel. Los uid compartidos del
  sistema (menores que 10000) nunca se cortan.
- En `scripts/e2e-linux.sh` un segundo usuario Linux hace de app bloqueada (el dueño se busca en
  `/proc/net`, lo que hace el kernel para Android): TCP, HTTPS, UDP y su DNS propio cortados, y
  otra app conectando a la vez.

## Interfaz mínima

Una pantalla con un único botón grande (activar/desactivar), el estado y el número de bloqueos.
Al activarlo por primera vez la app pide a Android lo que necesita: el permiso de VPN y, una vez,
quedar fuera de la optimización de batería. Todo lo demás tiene valores por defecto válidos y está
en **Opciones**, que no hace falta abrir. En la pantalla principal solo aparecen los problemas que
impiden filtrar (error, DNS privado estricto). «Bloquear conexiones sin VPN» no se puede activar
desde una app (solo desde los ajustes de Android, ADB o una app de administración de empresa):
Opciones lo explica y abre ese ajuste.

## Validación medida (PC x86_64, Linux con TUN real)

Herramientas: `sudo scripts/e2e-linux.sh --bench` (latencia, cortes, eficiencia; compara cada
medida con la misma operación sin túnel) y `scripts/validate-lists.sh` (eficacia de las listas).

### Latencia añadida

| Operación | Con túnel (p50 / p99) | Sin túnel (p50 / p99) |
|---|---|---|
| DNS permitido (reenviado) | 0,09 / 0,81 ms | 0,06 / 0,24 ms |
| DNS bloqueado (respuesta local) | 0,05 / 0,12 ms | — |
| HTTP: conexión + primer byte | 0,58–0,69 / 2,0–2,3 ms | 0,55 / 6–10 ms |
| Saludo TLS con inspección de SNI | 2,1 / 4,2 ms | 21 / 36 ms (retrasos de ACK del kernel en el camino directo) |
| Protocolo en el que habla primero el servidor | 0,30 / 2,7 ms (antes 302 ms) | 0,78 / 3,4 ms |

### Cortes de conexión

| Prueba | Resultado |
|---|---|
| 500 conexiones abiertas a la vez | 500/500 responden |
| TCP y UDP inactivos 130 s y reutilizados | Siguen funcionando |
| Cambio de lista con una descarga de 200 MB en curso | 200 MB completos, sin corte |
| 250 conexiones cortas en ráfagas | RAM estable, todas liberadas |

### Eficiencia

| Medida | Antes | Ahora |
|---|---|---|
| Despertares del túnel en reposo | ~176 por segundo (espera fija de 5 ms de netstack-smoltcp) | 0 (parche en `native/vendor/netstack-smoltcp`) |
| CPU en reposo | 7–8 ticks / 20 s | 0 |
| Memoria por conexión TCP | 142 KB | 76 KB (búferes de 16 KiB en la pila y 8 KiB en el relay) |
| 500 conexiones | +71 MB | +38 MB |
| Un flujo con el túnel limitado al 15 % de un núcleo | 204 Mbit/s (32 KiB) | 184 Mbit/s (16 KiB): 7 veces lo que pide un 4K |
| CPU por GB transferido | ~6 s/GB en este PC | sin cambio |

### Eficacia de las listas por defecto

AdGuard DNS + HaGeZi Ultimate + native + DNS cifrado: unos 340 000 dominios y 3400 IPs, filtro de unos 7,6 MB.

| Conjunto | Resultado |
|---|---|
| Test de bloqueadores de d3ward (131 dominios de anuncios, analítica, rastreadores, fabricantes) | 131 bloqueados (100 %) |
| 50 dominios críticos de TV (YouTube, Netflix, Prime, Disney+, Twitch, Spotify, Plex, Pluto, Play, FCM, hora, conectividad) | 0 bloqueados |
| Top 1000 de Tranco | 119 bloqueados, casi todos publicidad, analítica y rastreadores. Ultimate prioriza bloquear: si algo deja de funcionar se permite en Opciones o se cambia a HaGeZi Pro |

### Lo que solo se puede medir en la onn

CPU por GB y memoria reales en su procesador, latencia con la red Wi-Fi real y la fluidez del 4K.
La pantalla de Opciones muestra RAM y CPU de la app para anotarlas.
