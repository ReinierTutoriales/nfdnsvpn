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
                     │
                     ▼
            Núcleo Rust (libnfdns.so)
   parser IP → clasificador → decisión del filtro
     UDP 53 (DNS)   TCP 443 (SNI)   QUIC / IP en lista
                     │
                     ▼
     sockets protegidos (VpnService.protect) ──► Internet
```

| Pieza | Lenguaje | Función |
|---|---|---|
| `ShieldVpnService` | Kotlin | Crea el TUN, lee y escribe paquetes, reenvía DNS permitido |
| `native/nfdns-core` | Rust | Parser IP/UDP/DNS, filtro de dominios, respuestas de bloqueo |
| `ListRepository` | Kotlin | Descarga las listas (gzip, ETag) y las guarda en disco |
| `MainActivity` | Kotlin | Interfaz para mando: encender, contador, últimos bloqueos |

## Modos

| Modo | Tráfico por la app | Cubre | Coste |
|---|---|---|---|
| Ligero | Solo DNS (y las IPs de resolvedores públicos conocidos) | Apps que usan DNS, y las que usan 8.8.8.8/1.1.1.1 | Casi cero |
| Completo | Todo | DNS + SNI + QUIC + IPs | Moderado, hay que medirlo en 4K |

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
