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
| HaGeZi Multi Pro | `https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt` | Sí |
| HaGeZi Encrypted DNS (servidores DoH/DoQ) | `https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/doh.txt` | Sí (fase 3) |
| OISD small | `https://small.oisd.nl/` | No (fase 5) |
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
