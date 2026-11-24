# Formato de sincronización (v2 y v3)

Este documento describe cómo guarda Mis Notas los datos en Nextcloud, para quien quiera escribir otro cliente o herramientas de exportación.

## Carpeta remota

Por defecto: `https://<servidor>/remote.php/dav/files/<usuario>/MisNotas/`. Todos los ficheros están en el mismo nivel.

| Fichero | Contenido |
|---------|-----------|
| `keyinfo.json` | Parámetros de derivación y verificador de la contraseña (sin cifrar) |
| `note_<uuid>.json` | Una nota (o su lápida) |
| `folder_<uuid>.json` | Una carpeta (o su lápida) |
| `att_<uuid>.bin` | Un adjunto binario cifrado (imagen WebP) |

## keyinfo.json

```json
{
  "format": "misnotas-keyinfo",
  "version": 1,
  "kdf": "PBKDF2WithHmacSHA256",
  "iterations": 600000,
  "salt": "<base64, 16 bytes>",
  "check": "<base64 AES-GCM de 'misnotas-key-check-v1' con AAD 'keyinfo'>"
}
```

Clave = `PBKDF2-HMAC-SHA256(contraseña, salt, iterations, 256 bits)`.

## Cifrado

`AES-256-GCM`; bloque = `IV (12 bytes) ‖ texto cifrado ‖ etiqueta (16 bytes)`, codificado en Base64 dentro de los JSON. El AAD es la cadena UTF-8 `<tipo>:<id>`.

## Nota

```json
{ "format": "misnotas", "version": 2, "type": "note", "id": "<uuid>", "payload": "<base64>" }
```

`payload` descifrado (AAD `note:<uuid>`):

```json
{
  "folderId": "<uuid> | null",
  "title": "Texto",
  "content": "Markdown",
  "isPinned": false,
  "color": "DEFAULT | YELLOW | BLUE | GREEN | ORANGE | RED | PURPLE | TEAL | INDIGO",
  "updatedAt": 1730000000000,
  "isTrashed": false
}
```

Las imágenes se referencian en el Markdown como `![texto](attachment://<uuid>)`.

## Carpeta

Igual que la nota con `"type": "folder"` y AAD `folder:<uuid>`. Payload:

```json
{ "parentId": "<uuid> | null", "name": "Trabajo", "color": "INDIGO", "updatedAt": 1730000000000 }
```

## Lápidas

Cuando una nota o carpeta se borra definitivamente, su fichero se sustituye por:

```json
{ "format": "misnotas", "version": 2, "type": "note", "id": "<uuid>", "deleted": true, "deletedAt": 1730000000000, "auth": "<base64 AES-GCM de 'deleted:<deletedAt>' con AAD 'tombstone:<type>:<uuid>'>" }
```

`auth` demuestra que la lápida la creó un dispositivo con la clave. Una lápida sin `auth` (versiones antiguas, o fabricada por el servidor) nunca borra nada de forma definitiva: una nota pasa a la papelera y una carpeta se conserva y se vuelve a subir.

Las lápidas no se eliminan, para que los dispositivos que estaban sin conexión también se enteren del borrado.

## Adjuntos

`att_<uuid>.bin` = bytes en bruto `IV ‖ texto cifrado ‖ etiqueta` (sin Base64), AAD `attachment:<uuid>`. Son inmutables.

## Formato v3 (opcional)

Una bóveda v2 puede actualizarse a v3 desde Ajustes → Sincronización → Cifrado. Las cuentas nuevas
siguen empezando en v2 para que los clientes que aún no conocen v3 puedan usarlas. Un cliente que
solo entiende v2 **debe detenerse** al ver `"version": 3` en `keyinfo.json` o en un fichero, sin
sobrescribir nada.

### keyinfo.json v3 (cifrado en sobre)

```json
{
  "format": "misnotas-keyinfo",
  "version": 3,
  "kdf": { "name": "argon2id", "version": 19, "memoryKiB": 65536, "iterations": 3, "parallelism": 4, "salt": "<base64, 16 bytes>" },
  "password": "<base64 AES-GCM(KEK, base64(VMK)), AAD 'vmk:password'>",
  "recovery": "<base64 AES-GCM(RK, base64(VMK)), AAD 'vmk:recovery'>",
  "recoverySalt": "<base64, 16 bytes>",
  "keyring": "<base64 AES-GCM(VMK, JSON del llavero), AAD 'keyring'>"
}
```

- `KEK = Argon2id(contraseña en NFC, salt, memoryKiB, iterations, parallelism)`, 32 bytes.
- `VMK`: clave maestra de la bóveda, 32 bytes aleatorios. El campo cifrado contiene la VMK **en Base64**.
- Clave de recuperación: 20 bytes aleatorios mostrados en Base32 (RFC 4648, sin relleno) en 8 grupos de
  4 caracteres separados por guiones. `RK = HKDF-SHA256(ikm = clave, salt = recoverySalt, info = "misnotas-recovery-v1")`.
  `recovery` y `recoverySalt` solo existen si se ha creado una clave de recuperación.
- Llavero (descifrado):

  ```json
  { "current": "k3fa92c", "keys": { "v2": "<base64 clave>", "k3fa92c": "<base64 clave>" } }
  ```

  `v2` es la clave PBKDF2 de la bóveda v2 original (así no hay que volver a cifrar nada al migrar).
  Rotar la clave añade otra aleatoria y la marca como `current`; las anteriores se conservan para leer
  ficheros que aún no se hayan reescrito.

Cambiar la contraseña solo cambia `kdf.salt` y `password`. Todos los cambios de `keyinfo.json` se
suben con `If-Match`.

### Notas, carpetas y lápidas v3

```json
{ "format": "misnotas", "version": 3, "type": "note", "id": "<uuid>", "kid": "k3fa92c", "payload": "<base64>" }
```

- `payload` se cifra con la clave `kid` del llavero y AAD `<type>:<id>`, igual que en v2.
- El JSON descifrado lleva además `"rev"` (número de versión del fichero, ver más abajo) y `"pad"`: una
  cadena de espacios para que su tamaño en UTF-8 sea múltiplo de 512 bytes. Hay que ignorarla.
- Las **lápidas** van cifradas igual: su payload es `{ "deleted": true, "deletedAt": <ms>, "rev": n, "pad": "…" }`.
  El servidor no puede distinguir una lápida de una nota.
- Los ficheros sin `kid` (v1 y v2) se descifran con la clave `v2` del llavero.

### Adjuntos v3

Mismo formato binario que en v2 (`IV ‖ texto cifrado ‖ etiqueta`, AAD `attachment:<uuid>`), cifrados con
la clave `current`. No indican su `kid`: se prueba la clave actual y después las anteriores.

### manifest.json y `rev` (protección contra vueltas atrás)

En v3 cada subida de una nota, carpeta o lápida lleva `rev` = último `rev` conocido de ese fichero + 1.
`manifest.json` guarda el `rev` más alto conocido de cada fichero y un número de secuencia:

```json
{ "format": "misnotas-manifest", "version": 1, "kid": "k3fa92c", "payload": "<base64 AES-GCM, AAD 'manifest'>" }
```

Payload descifrado: `{ "seq": 12, "revs": { "note_<uuid>.json": 4, … }, "pad": "…" }`.

- Al empezar cada ronda el cliente lo descarga y combina sus `revs` con los suyos (máximo de cada uno).
  Si su `seq` es menor que el más alto que ha visto, el servidor está sirviendo un manifiesto viejo.
- Un fichero v3 con `rev` menor que el conocido es una **vuelta atrás**: no se aplica, se vuelve a subir la
  versión local encima y se avisa al usuario. Los ficheros v2 que quedan de antes de actualizar tienen `rev` 0.
- Al terminar la ronda, si algo cambió, se sube con `seq + 1` e `If-Match`; si falla con `412`, se combina en
  la siguiente ronda.

No detecta que el servidor enseñe a cada dispositivo una historia distinta sin que lleguen a cruzarse
(ataque de bifurcación).

## Reglas del cliente

1. Antes de sincronizar, descarga `keyinfo.json` y verifica la clave. Si falta o no coincide, aborta.
2. Lista la carpeta con `PROPFIND Depth: 1` y compara cada `getetag` con el último ETag conocido.
3. Descarga solo los ficheros cuyo ETag cambió y fusiona:
   - Sin cambios locales → se acepta la versión remota, salvo que su `updatedAt` sea anterior al local (una vuelta atrás): entonces se conserva la local y se vuelve a subir, y si el texto difiere la remota queda como copia " (conflicto)".
   - Con cambios locales y contenido distinto → se fusionan línea a línea con la última versión común (diff3). Si los dos lados cambiaron las mismas líneas, gana la de `updatedAt` más reciente y la otra se guarda como nota nueva con el sufijo " (conflicto)".
   - Lápida verificada → se borra en local, salvo que haya cambios locales sin subir.
4. Sube con `If-Match: "<etag>"` (o `If-None-Match: *` si es nuevo). Si el servidor responde `412`, vuelve al paso 2.
5. La app nunca borra ficheros de notas o carpetas (deja lápidas). Si uno conocido desaparece del servidor, la nota pasa a la papelera y la carpeta se conserva, y ambas se vuelven a subir.

## Compatibilidad con v1

Los ficheros de la v1.0 no tienen el campo `format` y cifran por separado `title`, `content` (notas) y `name` (carpetas), sin AAD, con 65.536 iteraciones y un salt que solo existía en el dispositivo. La v2 los lee y los reescribe en el formato nuevo en la siguiente subida. Como sus metadatos no están autenticados, el `id` debe coincidir con el nombre del fichero y un fichero v1 nunca sustituye a una nota o carpeta que ya exista en el dispositivo: si el texto difiere, se guarda como copia " (conflicto)".
