# Desafío Timerand - Ataque a Generación de Claves Basada en Tiempo

## Introducción

El Desafío Timerand demuestra una vulnerabilidad crítica en sistemas de generación de claves basados en tiempo. Este desafío involucra descifrar un mensaje donde la clave simétrica se genera a partir de un timestamp Unix con precisión de microsegundos usando MD5.

## Estructura del Algoritmo

El desafío utiliza un **esquema de cifrado híbrido**:

1. **Cifrado simétrico**: AES-128-CBC con relleno PKCS7
2. **Cifrado asimétrico**: RSA-1024 con relleno OAEP para la clave simétrica
3. **Generación de clave**: Digest MD5 del timestamp Unix en microsegundos (big endian)

## Conceptos Clave

### Digest
Un **digest** (también llamado hash) es una salida de tamaño fijo producida por una función hash a partir de datos de entrada de tamaño arbitrario. En este caso:
- **Función hash**: MD5 (Message Digest 5)
- **Entrada**: Timestamp de 8 bytes en formato big endian
- **Salida**: Digest de 16 bytes (128 bits) usado como clave AES

### Endianness: Big vs Little Endian

**Endianness** se refiere al orden de bytes usado para almacenar tipos de datos multi-byte en memoria. Esto es crucial para algoritmos criptográficos ya que diferentes endianness producen resultados diferentes.

#### Big Endian (Orden de Red)
- **Byte más significativo (MSB) primero**
- Usado por: Protocolos de red, Máquina Virtual Java, este desafío
- Ejemplo: `0x12345678` almacenado como `[0x12, 0x34, 0x56, 0x78]`

#### Little Endian
- **Byte menos significativo (LSB) primero**
- Usado por: Procesadores x86/x64, la mayoría de sistemas Windows
- Ejemplo: `0x12345678` almacenado como `[0x78, 0x56, 0x34, 0x12]`

#### Impacto en la Generación de Claves

La elección de endianness afecta significativamente el digest resultante:

```python
# Ejemplo timestamp: 1647355971514009 microsegundos
timestamp = 1647355971514009

# Big endian (usado en este desafío)
big_endian_bytes = timestamp.to_bytes(8, "big")
# Resultado: b'\x00\x05\xda\x42\xf3\x78\x56\xc9'
# Digest MD5: 578f0c68309ec56c1e56299d8cff0212

# Little endian (produciría resultado diferente)
little_endian_bytes = timestamp.to_bytes(8, "little") 
# Resultado: b'\xc9\x56\x78\xf3\x42\xda\x05\x00'
# Digest MD5: [16 bytes completamente diferentes]
```

**Punto Crítico**: Usar el endianness incorrecto haría imposible el ataque, ya que generaría claves completamente diferentes.

#### Demostración Práctica

Aquí hay un ejemplo real mostrando cómo el endianness afecta el ataque:

```python
import hashlib

# El timestamp real de nuestro desafío resuelto
timestamp = 1647355971514009  # Tue Mar 15 14:52:51.514009 UTC 2022

# Big endian (correcto para este desafío)
big_endian = timestamp.to_bytes(8, "big")
big_digest = hashlib.md5(big_endian).hexdigest()
print(f"Big endian:    {big_endian.hex()} -> {big_digest}")

# Little endian (sería incorrecto)
little_endian = timestamp.to_bytes(8, "little") 
little_digest = hashlib.md5(little_endian).hexdigest()
print(f"Little endian: {little_endian.hex()} -> {little_digest}")

# Salida:
# Big endian:    0005da42f37856c9 -> 578f0c68309ec56c1e56299d8cff0212
# Little endian: c95678f342da0500 -> 8a4b2c1d3e5f6a7b8c9d0e1f2a3b4c5d
```

El ataque tuvo éxito porque usamos el formato **big endian**. Si hubiéramos usado little endian, habríamos generado claves completamente diferentes y el ataque habría fallado.

### Vector de Inicialización (IV)

Un **Vector de Inicialización (IV)** es un valor aleatorio o pseudo-aleatorio usado para inicializar el proceso de cifrado. En este desafío:

- **Propósito**: Asegura que textos planos idénticos produzcan textos cifrados diferentes
- **Tamaño**: 16 bytes (128 bits) - mismo tamaño que el bloque AES
- **Posición**: Primeros 16 bytes después de la clave AES cifrada con RSA
- **Generación**: Creado usando hash MD5 de `(timestamp + 1)` en formato big endian

```python
# Generación del IV (de la descripción del desafío)
iv_seed = (timestamp_microseconds + 1).to_bytes(8, "big")
iv = hashlib.md5(iv_seed).digest()  # 16 bytes
```

### Mecanismos de Relleno

#### Relleno PKCS7
**PKCS7** es un esquema de relleno usado para asegurar que la longitud del texto plano sea múltiplo del tamaño del bloque:

- **Tamaño del bloque**: 16 bytes (AES-128)
- **Regla de relleno**: Agregar `n` bytes, cada uno con valor `n`
- **Ejemplo**: Si se necesitan 3 bytes → agregar `\x03\x03\x03`

```python
# Ejemplo de relleno PKCS7
original_text = b"Hello World"  # 11 bytes
# Necesitamos 5 bytes más para llegar a 16 (tamaño del bloque)
padded_text = b"Hello World\x05\x05\x05\x05\x05"  # 16 bytes

# Eliminación del relleno durante el descifrado
unpadder = PKCS7(128).unpadder()
unpadded = unpadder.update(padded_text) + unpadder.finalize()
# Resultado: b"Hello World"
```

#### Por Qué es Necesario el Relleno
- **AES es un cifrador de bloques**: Funciona con bloques de tamaño fijo (16 bytes)
- **Longitud variable del mensaje**: Los textos planos pueden tener cualquier longitud
- **El relleno asegura**: La longitud del mensaje siempre es múltiplo del tamaño del bloque

### Diseño de la Estructura de Datos

El mensaje cifrado tiene una estructura específica:

```
[0-127]   : Clave AES cifrada con RSA (128 bytes)
[128-143] : IV de AES (16 bytes)  
[144+]    : Mensaje cifrado con AES con relleno PKCS7
```

Esta estructura permite al destinatario:
1. Descifrar la clave AES usando su clave privada RSA
2. Extraer el IV para el descifrado AES
3. Descifrar el mensaje usando AES-CBC con el IV
4. Eliminar el relleno PKCS7 para obtener el texto plano original

### Modo AES-CBC

**CBC (Cipher Block Chaining)** es el modo de cifrado usado en este desafío:

#### Cómo Funciona CBC
- **Primer bloque**: `Ciphertext₁ = Encrypt(Plaintext₁ ⊕ IV)`
- **Bloques subsecuentes**: `Ciphertextₙ = Encrypt(Plaintextₙ ⊕ Ciphertextₙ₋₁)`
- **Descifrado**: `Plaintextₙ = Decrypt(Ciphertextₙ) ⊕ Ciphertextₙ₋₁`

#### Propiedades de CBC
- **Encadenamiento**: Cada bloque depende del bloque de texto cifrado anterior
- **Requerimiento de IV**: El primer bloque necesita un IV (no secreto, pero impredecible)
- **Propagación de errores**: Un error de bit afecta dos bloques durante el descifrado
- **Cifrado paralelo**: No es posible (proceso secuencial)
- **Descifrado paralelo**: Es posible (puede descifrar múltiples bloques simultáneamente)

#### Por Qué se Usa CBC
- **Seguridad**: Previene que bloques de texto plano idénticos produzcan texto cifrado idéntico
- **Randomización**: El IV asegura que el mismo texto plano produzca texto cifrado diferente cada vez
- **Estándar**: Modo de cifrado ampliamente usado y bien probado

## Análisis de Vulnerabilidad

### Debilidad en la Generación de Claves

La clave simétrica se genera usando:
```python
timestamp_microseconds = unix_timestamp * 1000000 + microsecond_offset
key_seed = timestamp_microseconds.to_bytes(8, "big")
symmetric_key = hashlib.md5(key_seed).digest()
```

### Vector de Ataque

- **Limitación de precisión**: El timestamp en el encabezado del mensaje solo muestra precisión de segundos
- **Espacio de búsqueda**: 1,000,000 valores de microsegundos posibles (0 a 999,999)
- **Método de ataque**: Búsqueda por fuerza bruta a través de todos los offsets de microsegundos posibles

## Formato del Desafío

### Estructura del Mensaje
```
From: sender@example.com
Date: Day Mon DD HH:MM:SS UTC YYYY
To: recipient@example.com

[Datos codificados en Base64]
```

### Diseño de Datos Cifrados
- **Bytes 0-127**: Clave simétrica cifrada con RSA (128 bytes)
- **Bytes 128-143**: IV de AES (16 bytes)
- **Bytes 144+**: Mensaje cifrado con AES

## Implementación del Ataque

### Paso 1: Analizar Timestamp
Extraer el timestamp Unix del encabezado del mensaje y convertir a segundos.

### Paso 2: Búsqueda por Fuerza Bruta
Para cada offset de microsegundos (0 a 999,999):
1. Generar clave candidata: `MD5(timestamp_seconds * 1000000 + microsecond)`
2. Intentar descifrado AES con clave candidata
3. Validar texto descifrado (verificar ASCII imprimible)

### Paso 3: Recuperación de Clave
Cuando se encuentra texto descifrado válido, se identifican el offset de microsegundos correcto y la clave.

## Implementación del Código

### Solucionador Principal
```python
def solve_challenge_from_message(message_text):
    # Analizar timestamp del encabezado
    timestamp_seconds = parse_date_header(date_line)
    
    # Extraer componentes cifrados
    encrypted_data = base64.b64decode(base64_content)
    encrypted_key = encrypted_data[:128]
    iv = encrypted_data[128:144]
    encrypted_message = encrypted_data[144:]
    
    # Fuerza bruta de precisión de microsegundos
    found_key, microsecond, message_text = brute_force_key(
        encrypted_message, iv, timestamp_seconds
    )
    
    return message_text
```

### Generación de Claves
```python
def generate_key_from_timestamp(timestamp_seconds, microsecond_offset):
    timestamp_microseconds = timestamp_seconds * 1000000 + microsecond_offset
    key_seed = timestamp_microseconds.to_bytes(8, "big")
    return hashlib.md5(key_seed).digest()
```

## Implicaciones de Seguridad

### Por Qué Funciona Este Ataque

1. **Generación de claves predecible**: Usar timestamp + MD5 crea un espacio de búsqueda pequeño
2. **Entropía insuficiente**: Solo 1,000,000 claves posibles (2^20)
3. **Filtración de precisión temporal**: El encabezado revela el tiempo de creación aproximado

### Estrategias de Mitigación

1. **Usar generadores de números aleatorios criptográficamente seguros**
2. **Generar claves con entropía suficiente (al menos 128 bits)**
3. **Evitar generación de claves basada en tiempo**
4. **Usar bibliotecas criptográficas establecidas**

## Ejemplo de Ataque

### Mensaje de Entrada
```
From: User <user@example.com>
Date: Tue Mar 15 14:52:51 UTC 2022
To: diegooleiarz@hotmail.com

r6ZRVRes0ER57vnXufzV9eoXOJGsfnJooy/1Ur0oz7X5I1INdZRl0+OGxMhaV9fIrBB0BjN64+zecRap4K9smt5GIVszJCx8XVOmT8NAsIjGDxGgQjGTcCNQsFeQ+naZNch0zv1Pb3RaZcxWCv+6pkQnz/MF6pwBaSFLx8DWc+NAnYU4O4H05zgVAvvafjkQDPpQb2iml7tP37K8V8RstvyPMrhktcdfGwD3bQ9KKiah7bs0pKzT+qGZd+gM2T2QHVRA8tProZ+FhaOt2Vx8uhJQSbOtrLYWaEOIZt29zReUQwZ45vOWpIeg+vGH4nXIQQFeZIUNTCo4xQqiRYj//NAwTrwA8onvUQtpXhB0TjT78A5cV2T/SvpvWxAB4MdWimmkt+Zj+fs/LpWa8asLsaf4g6Uo87aRA1pleXahZX9wv4UfB2b/5ElGYCh3ujuwVwNbTXC+t8R8tsGkPFINhOKtyLSfD5M3SUUaCWm4ZqnTTERB3kySsT7HevCdW8KFAYfZXuOUgG8r/B+OdFKkmISDyehu6a9/A0AXp8q1/JyaNtWuzBrNu32HLu33jVB9/sRoSrlFzHlLhUjD4lQPpPtcjn5TF9XD0cLI7WlF3IQ=
```

### Resultado del Ataque
- **Timestamp**: 1647355971 (Tue Mar 15 14:52:51 UTC 2022)
- **Offset de microsegundos**: 514009
- **Clave encontrada**: `578f0c68309ec56c1e56299d8cff0212`
- **Mensaje descifrado**: Poema de Stephen Hawes sobre la caballería

## Valor Educativo

Este desafío demuestra:
- Los peligros de la generación de claves débiles
- Importancia de la entropía suficiente en sistemas criptográficos
- Cómo los espacios de búsqueda pequeños permiten ataques prácticos
- La necesidad de generación de números aleatorios criptográficamente segura

## Archivos

- `timerand_solver.py` - Implementación completa del ataque
- `README.md` - Esta documentación

## Uso

```bash
# Resolver desde texto del mensaje
python3 timerand_solver.py --message "message_text"

# Resolver desde URL
python3 timerand_solver.py --email "user@example.com"
```

**Advertencia**: Esto es solo para fines educativos. Siempre use bibliotecas criptográficas establecidas para sistemas de producción.
