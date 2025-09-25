# Algoritmo ADOdb Crypt - Explicación Paso a Paso

## Introducción

ADOdb Crypt es un algoritmo de cifrado que utiliza MD5 y operaciones XOR para cifrar texto. Este documento explica paso a paso cómo funciona el algoritmo con ejemplos detallados usando bits.

## Estructura del Algoritmo

El algoritmo ADOdb Crypt tiene **dos capas de cifrado**:

1. **Capa interna**: Genera una clave MD5 aleatoria y la intercala con el texto
2. **Capa externa**: Aplica XOR con una clave externa proporcionada por el usuario

## Constantes y Parámetros

- **Rango de números aleatorios**: 0 a 32,000
- **Longitud de clave MD5**: 32 caracteres hexadecimales
- **Codificación**: Base64 para el resultado final

## Fórmula del Algoritmo

```
Cifrado = Base64(KeyED(Intercalar(MD5(rand), Texto), ClaveExterna))
```

## Ejemplo Paso a Paso

Vamos a seguir el algoritmo con:
- **Texto original**: "HELLO"
- **Clave externa**: "0123456789abcdef0123456789abcdef"

### Paso 1: Generación de Clave Interna

```python
rand_num = random.randint(0, 32000)  # Ejemplo: 12345
encrypt_key = hashlib.md5(str(rand_num).encode()).hexdigest()
```

**Número aleatorio**: 12345
**MD5 de 12345**: `827ccb0eea8a706c4c34a16891f84e7b`

```
12345 en binario: 11000000111001
MD5 hash:        827ccb0eea8a706c4c34a16891f84e7b
En binario:      1000001001111100110011001011000011101110101010001010011100000110110001001100001101001010000101101000100111111000010011100111011
```

### Paso 2: Intercalación (Capa Interna)

```python
# Para cada byte del texto:
for b in txt.encode("utf-8"):
    tmp.append(encrypt_key_bytes[ctr])      # Byte de la clave MD5
    tmp.append(b ^ encrypt_key_bytes[ctr])  # Byte del texto XOR con clave MD5
    ctr += 1
```

**Texto original**: "HELLO"
**En bytes**: `[0x48, 0x45, 0x4C, 0x4C, 0x4F]`

#### 2.1: Intercalar con clave MD5

```
Clave MD5: 827ccb0eea8a706c4c34a16891f84e7b
En bytes:  [0x82, 0x7c, 0xcb, 0x0e, 0xea, 0x8a, 0x70, 0x6c, 0x4c, 0x34, 0xa1, 0x68, 0x91, 0xf8, 0x4e, 0x7b, ...]

Texto: HELLO
H (0x48) XOR 0x82 = 0xCA
E (0x45) XOR 0x7c = 0x39
L (0x4C) XOR 0xcb = 0x87
L (0x4C) XOR 0x0e = 0x42
O (0x4F) XOR 0xea = 0xA5

Resultado intercalado:
[0x82, 0xCA, 0x7c, 0x39, 0xcb, 0x87, 0x0e, 0x42, 0xea, 0xA5]
```

### Paso 3: Aplicar Clave Externa (Capa Externa)

```python
def keyED(txt: bytes, encrypt_key: str) -> bytes:
    encrypt_key = hashlib.md5(encrypt_key.encode()).hexdigest()
    # Aplicar XOR cíclico
    for b in txt:
        tmp.append(b ^ encrypt_key_bytes[ctr])
        ctr = (ctr + 1) % len(encrypt_key_bytes)
```

**Clave externa**: "0123456789abcdef0123456789abcdef"
**MD5 de la clave externa**: `a1b2c3d4e5f6789012345678901234ab`

#### 3.1: Aplicar XOR cíclico

```
Texto intercalado: [0x82, 0xCA, 0x7c, 0x39, 0xcb, 0x87, 0x0e, 0x42, 0xea, 0xA5]
Clave externa MD5: a1b2c3d4e5f6789012345678901234ab
En bytes:          [0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x78, 0x90, 0x12, 0x34, ...]

XOR cíclico:
0x82 XOR 0xa1 = 0x23
0xCA XOR 0xb2 = 0x78
0x7c XOR 0xc3 = 0xBF
0x39 XOR 0xd4 = 0xED
0xcb XOR 0xe5 = 0x2E
0x87 XOR 0xf6 = 0x71
0x0e XOR 0x78 = 0x76
0x42 XOR 0x90 = 0xD2
0xea XOR 0x12 = 0xF8
0xA5 XOR 0x34 = 0x91

Resultado final: [0x23, 0x78, 0xBF, 0xED, 0x2E, 0x71, 0x76, 0xD2, 0xF8, 0x91]
```

### Paso 4: Codificación Base64

```python
encrypted = base64.b64encode(encrypted).decode("utf-8")
```

**Resultado final**: `I3i/vk5xdvL4kQ==`

## Visualización del Proceso

```
Texto original: "HELLO"
    ↓
Generar rand(0,32000) → MD5 → Clave interna
    ↓
Intercalar: [clave_md5, texto_xor_clave, ...]
    ↓
Aplicar clave externa MD5 con XOR cíclico
    ↓
Codificar en Base64
    ↓
Resultado: "I3i/vk5xdvL4kQ=="
```

## Estructura de Datos

```
Capa 1 (Interna): [MD5_char, texto_xor_md5, MD5_char, texto_xor_md5, ...]
Capa 2 (Externa): XOR cíclico con clave externa MD5
Resultado: Base64 del resultado final
```

## La Vulnerabilidad

### ¿Por qué es vulnerable?

1. **Clave interna predecible**: Solo 32,001 valores posibles (0-32000)
2. **Estructura conocida**: Patrón intercalado de clave y texto
3. **Ataque de texto conocido**: Si conocemos parte del texto, podemos recuperar la clave
4. **XOR reversible**: Las operaciones XOR se pueden revertir

### Ejemplo de Ataque

Dado el texto cifrado y un fragmento conocido del texto original:

**Paso 1**: Eliminar la clave interna
```python
# XOR caracteres pares e impares para eliminar la clave MD5 interna
for i in range(0, len(decoded), 2):
    new_char = decoded[i] ^ decoded[i + 1]
    new_ciphertext.append(new_char)
```

**Paso 2**: Ataque Vigenère con texto conocido
```python
# Si conocemos "HELLO" está en el texto
known_text = "HELLO"
# Probar diferentes posiciones y recuperar la clave externa
```

**Paso 3**: Descifrar todo el mensaje
```python
# Una vez recuperada la clave, descifrar el resto
```

## Conversión de Datos

### MD5 a Bytes
```python
md5_hex = "827ccb0eea8a706c4c34a16891f84e7b"
md5_bytes = bytes.fromhex(md5_hex)
# Resultado: [0x82, 0x7c, 0xcb, 0x0e, 0xea, 0x8a, ...]
```

### XOR de Bytes
```python
byte1 = 0x48  # 'H'
byte2 = 0x82  # Primer byte de MD5
result = byte1 ^ byte2  # 0xCA
```

### Base64
```python
import base64
data = [0x23, 0x78, 0xBF, 0xED, 0x2E, 0x71, 0x76, 0xD2, 0xF8, 0x91]
encoded = base64.b64encode(bytes(data)).decode()
# Resultado: "I3i/vk5xdvL4kQ=="
```

## Resumen

El algoritmo ADOdb Crypt es:

1. **Determinístico**: Misma clave externa → mismo resultado
2. **Rápido**: Solo operaciones MD5, XOR y Base64
3. **Vulnerable**: Con texto conocido se puede romper
4. **No criptográfico**: No debe usarse para seguridad

**Recomendación**: Para aplicaciones criptográficas, usar algoritmos estándar como AES en lugar de ADOdb Crypt.

## Técnicas Avanzadas de Ataque

Aunque el ataque básico con texto conocido es efectivo, existen técnicas más sofisticadas:

### Análisis de Frecuencia
- **Patrones en MD5**: Los hashes MD5 tienen distribuciones conocidas
- **Análisis estadístico**: Identificar patrones en el texto cifrado

### Ataques de Fuerza Bruta Optimizados
- **Espacio de claves reducido**: Solo 32,001 claves internas posibles
- **Paralelización**: Probar múltiples claves simultáneamente
- **Filtrado temprano**: Descartar claves imposibles rápidamente

### Ataques de Texto Conocido Avanzados
- **Múltiples fragmentos**: Usar varios fragmentos conocidos
- **Análisis de contexto**: Aprovechar patrones del texto original
- **Recuperación parcial**: Recuperar la clave incluso con texto parcialmente conocido

### Investigación Académica
Estas técnicas demuestran que ADOdb Crypt es fundamentalmente inseguro debido a su diseño con claves internas predecibles y estructura intercalada conocida.
