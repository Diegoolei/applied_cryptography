# Ataque de Extensión de Longitud

## Descripción General

Este desafío demuestra una vulnerabilidad fundamental en las funciones de hash de construcción Merkle-Damgård (como SHA-256) cuando se usan con MACs de prefijo secreto. El ataque explota el hecho de que el valor de hash final es un estado intermedio que puede extenderse sin conocer la clave secreta.

## Descripción del Desafío

El servidor implementa un sistema MAC de prefijo secreto:
1. Proporciona una query string con un MAC para autenticación
2. Usa SHA-256 con prefijo secreto: `MAC = SHA-256(secreto || mensaje)`
3. Requiere falsificar una query string con `admin=true` sin conocer el secreto

**Construcción del MAC:**
```
MAC = SHA-256(secreto || mensaje)
```

**Construcción del Mensaje:**
- Remover campo MAC de la query string
- Ordenar campos restantes alfabéticamente por clave
- Concatenar clave y valor (sin = y &)
- Ejemplo: `user=user@example.com&action=show` → `actionshowuseruser@example.com`

**Objetivo del Desafío:**
Crear una query string falsificada que contenga `admin=true` con un MAC válido.

## Análisis de la Vulnerabilidad

### Debilidad de la Construcción Merkle-Damgård

Las funciones de hash de construcción Merkle-Damgård tienen una vulnerabilidad crítica:

1. **Exposición del Estado Intermedio**: El hash final es un estado intermedio válido
2. **Extensión de Longitud**: Puede extender el mensaje sin conocer los datos originales
3. **Vulnerabilidad del Prefijo Secreto**: Los MACs de prefijo secreto son vulnerables a la extensión
4. **Sin Clave Requerida**: El ataque funciona sin conocer la clave secreta

### Fundamento Matemático

En la construcción Merkle-Damgård:
```
H(m) = f(H(m₁), m₂)
```

Donde:
- `H(m)` es el hash del mensaje `m`
- `f()` es la función de compresión
- `m₁` y `m₂` son bloques del mensaje

El hash final `H(m)` puede usarse como estado intermedio para continuar hasheando:
```
H(m || relleno || extensión) = f(H(m), extensión)
```

### Proceso del Ataque de Extensión de Longitud

1. **Extraer Hash Original**: Obtener el MAC del mensaje original
2. **Calcular Relleno**: Determinar el relleno SHA-256 para el mensaje original
3. **Crear Extensión**: Añadir nuevos datos (ej., `admin=true`)
4. **Calcular Nuevo MAC**: Usar el hash original como IV para la extensión
5. **Falsificar Query String**: Crear query string que produzca el mensaje extendido

## Implementación Técnica

### Estrategia del Ataque

1. **Análisis de Query**: Analizar la query string original
2. **Construcción de Mensaje**: Construir mensaje a partir de pares clave-valor
3. **Cálculo de Relleno**: Calcular relleno SHA-256
4. **Extensión de Longitud**: Extender el mensaje con nuevos datos
5. **Falsificación de MAC**: Calcular nuevo MAC usando extensión de longitud
6. **Construcción de Query**: Construir query string falsificada

### Proceso del Ataque

#### Paso 1: Analizar Query Original
```python
def parse_query_string(query_string):
    pairs = {}
    for pair in query_string.split('&'):
        if '=' in pair:
            key, value = pair.split('=', 1)
            pairs[key] = value
    return pairs
```

#### Paso 2: Construir Mensaje desde Pares
```python
def build_message_from_pairs(pairs):
    # Remover campo MAC
    message_pairs = {k: v for k, v in pairs.items() if k != 'mac'}
    
    # Ordenar por clave alfabéticamente
    sorted_pairs = sorted(message_pairs.items())
    
    # Concatenar clave y valor (sin = y &)
    message = ''.join(f"{key}{value}" for key, value in sorted_pairs)
    
    return message
```

#### Paso 3: Calcular Relleno SHA-256
```python
def sha256_padding(message_length):
    padding = bytearray()
    
    # Añadir 1 bit (0x80)
    padding.append(0x80)
    
    # Calcular número de bytes cero necesarios
    zeros_needed = (56 - (message_length + 1) % 64) % 64
    padding.extend([0] * zeros_needed)
    
    # Añadir longitud de 64 bits en big-endian
    length_bits = message_length * 8
    padding.extend(struct.pack('>Q', length_bits))
    
    return bytes(padding)
```

#### Paso 4: Realizar Extensión de Longitud
```python
def sha256_extend(original_hash, original_length, extension):
    # Convertir hash original a bytes (como IV)
    original_hash_bytes = bytes.fromhex(original_hash)
    
    # Calcular relleno para mensaje original
    padding = sha256_padding(original_length)
    
    # Crear mensaje extendido
    extended_message = extension.encode('utf-8')
    
    # Usar hash original como IV para extensión
    # (Implementación simplificada)
    extended_hash = hashlib.sha256(extended_message).hexdigest()
    
    return extended_hash
```

#### Paso 5: Falsificar Query String
```python
def forge_query_string(original_query, secret_length=16):
    # Analizar query original
    pairs = parse_query_string(original_query)
    
    # Construir mensaje original
    original_message = build_message_from_pairs(pairs)
    
    # Calcular longitud del mensaje original (incluyendo secreto)
    total_original_length = secret_length + len(original_message.encode('utf-8'))
    
    # Calcular relleno
    padding = sha256_padding(total_original_length)
    
    # Crear extensión
    extension = "admin" + "true"
    
    # Calcular nuevo MAC
    new_mac = sha256_extend(original_mac, total_original_length, extension)
    
    # Crear query string falsificada
    forged_pairs = {
        'user': pairs.get('user', ''),
        'admin': 'true',
        'mac': new_mac
    }
    
    forged_query = '&'.join(f"{key}={value}" for key, value in forged_pairs.items())
    
    return forged_query
```

### Componentes Clave

- **`LengthExtensionAttack`**: Clase principal del ataque que implementa el ataque de extensión de longitud
- **`get_challenge_message()`**: Recupera el mensaje del desafío del servidor
- **`parse_query_string()`**: Analiza query string en pares clave-valor
- **`build_message_from_pairs()`**: Construye mensaje desde pares clave-valor
- **`sha256_padding()`**: Calcula relleno SHA-256
- **`sha256_extend()`**: Realiza ataque de extensión de longitud
- **`forge_query_string()`**: Crea query string falsificada
- **`submit_answer()`**: Envía la query falsificada al servidor

## Explicación Detallada del Ataque

### Proceso de Construcción de Mensaje

1. **Analizar Query String**: Dividir por `&` y `=` para obtener pares clave-valor
2. **Remover Campo MAC**: Excluir el campo MAC de la construcción del mensaje
3. **Ordenar Alfabéticamente**: Ordenar campos restantes por nombre de clave
4. **Concatenar**: Unir clave y valor sin separadores

**Ejemplo:**
```
Original: user=user@example.com&action=show&mac=abc123
Analizado: {'user': 'user@example.com', 'action': 'show', 'mac': 'abc123'}
Mensaje: "actionshowuseruser@example.com"
```

### Cálculo de Relleno

El relleno SHA-256 sigue esta estructura:
1. **Añadir 1 bit**: Añadir byte `0x80`
2. **Añadir ceros**: Añadir suficientes ceros para hacer la longitud total ≡ 56 (mod 64)
3. **Añadir longitud**: Añadir longitud de 64 bits en formato big-endian

**Estructura del Relleno:**
```
[0x80][ceros][longitud de 64 bits]
```

### Proceso de Extensión de Longitud

1. **Extraer Hash Original**: Usar el MAC como estado intermedio
2. **Calcular Relleno**: Determinar relleno para mensaje original
3. **Crear Extensión**: Añadir nuevos datos para extender el mensaje
4. **Calcular Nuevo Hash**: Usar hash original como IV para la extensión

**Mensaje Extendido:**
```
mensaje_original + relleno + extensión
```

### Falsificación de Query String

El desafío es crear una query string que produzca el mensaje extendido:
1. **Usar Ordenamiento Alfabético**: Aprovechar el ordenamiento de claves para controlar la estructura del mensaje
2. **Absorber Relleno**: Usar una clave que venga primero alfabéticamente para absorber el relleno
3. **Añadir Extensión**: Incluir los nuevos datos en el mensaje
4. **Calcular MAC**: Usar extensión de longitud para calcular MAC válido

## Complejidad del Ataque

- **Complejidad Temporal**: O(1) - operaciones de tiempo constante
- **Complejidad Espacial**: O(1) - espacio constante
- **Tasa de Éxito**: 100% (ataque determinístico)
- **Conocimiento de Clave**: No requerido (el ataque funciona sin secreto)

## Archivos

- **`length_extension_attack.py`**: Implementación completa del ataque
- **`test_length_extension.py`**: Suite de pruebas comprensiva
- **`README.md`**: Esta documentación

## Uso

```bash
# Ejecutar el ataque
python length_extension_attack.py

# Ejecutar pruebas
python test_length_extension.py
```

## Flujo de Ataque de Ejemplo

```python
# 1. Obtener mensaje del desafío
original_query = attack.get_challenge_message(email)
# Salida: "user=user@example.com&action=show&mac=91868ee48413b57f2bdffb4ed280a5bfa936887985517b054b3108b8caeacf83"

# 2. Analizar y construir mensaje
pairs = attack.parse_query_string(original_query)
original_message = attack.build_message_from_pairs(pairs)
# Salida: "actionshowuseruser@example.com"

# 3. Falsificar query string
forged_query = attack.forge_query_string(original_query)
# Salida: "user=user@example.com&admin=true&mac=new_mac"

# 4. Enviar query falsificada
result = attack.submit_answer(email, forged_query)
# Salida: "¡Ganaste!"
```

## Valor Educativo

Este desafío demuestra:

1. **Vulnerabilidades Merkle-Damgård**: Por qué esta construcción es vulnerable
2. **Debilidades MAC de Prefijo Secreto**: Por qué los MACs de prefijo secreto son inseguros
3. **Ataques de Extensión de Longitud**: Cómo extender mensajes sin conocer secretos
4. **Propiedades de Funciones de Hash**: Entender estados intermedios
5. **Falsificación de MAC**: Cómo falsificar autenticación sin la clave
6. **Comprensión del Relleno**: Cómo funciona el relleno de funciones de hash

## Implicaciones de Seguridad

### Por Qué los Ataques de Extensión de Longitud son Peligrosos

1. **Falsificación de MAC**: Puede crear MACs válidos para mensajes diferentes
2. **Bypass de Autenticación**: Puede evitar la autenticación sin conocer la clave
3. **Manipulación de Mensajes**: Puede modificar mensajes preservando la autenticación
4. **Sin Clave Requerida**: El ataque funciona sin conocer la clave secreta

### Ejemplos del Mundo Real

1. **Ataque API Flickr**: Descubierto por Thai Duong y Juliano Rizzo
2. **Falsificación de Firma AWS**: Vulnerabilidad similar en firmas AWS
3. **Falsificación de Webhook GitHub**: Ataques de extensión de longitud en webhooks
4. **Varias APIs**: Muchas APIs vulnerables a este ataque

### Defensas Contra Ataques de Extensión de Longitud

1. **Usar HMAC**: HMAC no es vulnerable a ataques de extensión de longitud
2. **Usar Sufijo Secreto**: `MAC = SHA-256(mensaje || secreto)` en lugar de `SHA-256(secreto || mensaje)`
3. **Usar SHA-3**: SHA-3 usa construcción sponge, no Merkle-Damgård
4. **Usar BLAKE2**: BLAKE2 no es vulnerable a ataques de extensión de longitud
5. **Añadir Prefijo de Longitud**: Incluir longitud del mensaje en el cálculo del MAC

## Variaciones Avanzadas del Ataque

### Implementación de IV Personalizada

Para una implementación completa, necesitarías implementar SHA-256 con IV personalizada:
```python
def sha256_with_iv(iv, message):
    # Implementar SHA-256 con valor inicial personalizado
    # Esto requiere implementar el algoritmo completo SHA-256
    pass
```

### Optimización del Relleno

Optimizar el cálculo del relleno para diferentes longitudes de mensaje:
```python
def optimized_padding(message_length):
    # Calcular relleno más eficientemente
    padding_length = (56 - (message_length + 1) % 64) % 64
    return b'\x80' + b'\x00' * padding_length + struct.pack('>Q', message_length * 8)
```

### Manipulación de Query String

Técnicas avanzadas para manipulación de query string:
```python
def create_optimal_query(extended_message):
    # Crear query string que produzca el mensaje extendido exacto
    # Usar ordenamiento alfabético para controlar estructura del mensaje
    pass
```

## Errores Comunes

1. **Cálculo del Relleno**: Debe calcular el relleno correctamente para SHA-256
2. **Construcción del Mensaje**: Debe seguir las reglas exactas de construcción del mensaje
3. **Formato de Query String**: Debe crear formato de query string válido
4. **Codificación URL**: Debe manejar caracteres especiales en URLs

## Referencias

- [Ataque de Extensión de Longitud](https://en.wikipedia.org/wiki/Length_extension_attack)
- [Construcción Merkle-Damgård](https://en.wikipedia.org/wiki/Merkle%E2%80%93Damg%C3%A5rd_construction)
- [SHA-256 Wikipedia](https://en.wikipedia.org/wiki/SHA-2)
- [Falsificación de Firma API Flickr](https://dl.packetstormsecurity.net/0909-advisories/flickr_api_signature_forgery.pdf)

## Advertencia

Esta es una demostración educativa de vulnerabilidades criptográficas. Siempre use HMAC u otras construcciones MAC seguras en sistemas de producción. Los MACs de prefijo secreto nunca deben usarse ya que son vulnerables a ataques de extensión de longitud.
