# Cambios

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/); versiones según [SemVer](https://semver.org/lang/es/).

## [1.1.0] - 2026-11-24

### Añadido
- Compatibilidad con el **cifrado v3** de Mis Notas para Android 1.1: Argon2id, cifrado en sobre, llavero con varias claves (rotación), ficheros con relleno, lápidas cifradas y protección contra vueltas atrás (`rev` y `manifest.json`). Una bóveda actualizada en el móvil se abre aquí con la misma contraseña maestra. Si otro dispositivo la actualiza mientras esta app está abierta, se pide la contraseña una vez.
- Los **archivos adjuntos** (PDF, audio, documentos…) añadidos desde el móvil se descargan con su tipo, se abren con la aplicación del sistema al pulsar su enlace y se exportan con su extensión.

### Cambiado
- Un dispositivo con la bóveda en v3 se niega a sincronizar si el servidor le ofrece un `keyinfo.json` más antiguo.

## [1.0.1] - 2026-11-15

### Añadido
- Aviso de versiones nuevas: al arrancar (como mucho una vez al día) se consulta en GitHub la última versión publicada y, si hay una más reciente, la pantalla principal muestra un aviso con «Descargar» y «Omitir». En Ajustes → Acerca de se puede desactivar o comprobar en el momento.

### Cambiado
- La búsqueda de la pantalla principal es instantánea: con la primera letra se abre la lista de resultados, que se filtra mientras se escribe.
- En ventanas anchas (900 dp o más) la pantalla principal usa dos columnas: búsqueda y accesos rápidos a la izquierda, carpetas a la derecha.

## [1.0.0] - 2026-11-11

Primera versión de escritorio (Windows, macOS y Linux), a partir de [Mis Notas para Android](https://github.com/MisApps-labs/mis_notas) 1.0.0 con todas sus correcciones posteriores. Usa el mismo formato de sincronización (v2) y el mismo esquema de base de datos, así que se sincroniza con la app de Android a través del mismo Nextcloud.

### Añadido
- Instaladores `.dmg` (Apple Silicon e Intel), `.msi`/`.exe` y `.deb`/`.rpm`, con Java incluido.
- Barra de menús (Archivo → Nueva nota, Sincronizar ahora, Ajustes, Bloquear, Salir) y atajos de teclado: Ctrl/Cmd + N, R, `,`, L; Ctrl/Cmd + B, I y K en el editor; deshacer y rehacer; Esc para volver.
- Clic derecho para seleccionar notas y para cambiar el tamaño de una imagen (sustituye a la pulsación larga).
- "Guardar como Markdown…" para exportar una nota a un fichero `.md` (sustituye a "Compartir").
- La ventana recuerda su tamaño, posición y si estaba maximizada.
- Confianza en los certificados raíz del sistema, además de los de Java: funciona un Nextcloud con autoridad propia instalada en el sistema.

### Cambiado respecto a Android
- **Bloqueo de la app** con una contraseña propia (en lugar de huella, cara o PIN del móvil). Se pide al abrir la app y tras un minuto con la ventana en segundo plano.
- Credenciales y clave guardadas en un fichero cifrado cuya clave está en el llavero del sistema (Llavero de macOS, Administrador de credenciales de Windows, Secret Service en Linux), en lugar de Android Keystore.
- Sincronización periódica cada 30 minutos mientras la app está abierta (en lugar de WorkManager), y al volver a la ventana.
- La copia de seguridad previa a conectar una cuenta se guarda en la carpeta Descargas/MisNotas del usuario.
- Imágenes elegidas con el diálogo de ficheros del sistema; se siguen comprimiendo a WebP respetando la orientación EXIF.
- Fechas relativas ("Hace 5 min", "Ayer") con textos propios en los cinco idiomas.
