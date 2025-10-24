# Ataque Oracle de Relleno

## Descripción General

Este desafío demuestra una vulnerabilidad fundamental en el cifrado AES usando modo CBC (Cipher Block Chaining) cuando el servidor revela información sobre la validez del relleno. El ataque explota el hecho de que el descifrado CBC revela si el relleno es válido o no, permitiendo a un atacante recuperar el texto plano byte por byte sin conocer la clave de cifrado.

## Descripción del Desafío

El servidor implementa el siguiente proceso:
1. Proporciona un mensaje cifrado usando AES-CBC con relleno PKCS7
2. El IV se envía como el primer bloque del texto cifrado
3. Ofrece un oracle de descifrado que revela la validez del relleno:
   - **200 OK**: Relleno válido y descifrado exitoso
   - **400 Bad Request**: Codificación base64 inválida
   - **400 Bad Request**: "Bad padding bytes" - relleno inválido o tamaño de bloque incorrecto

**Oracle del Servidor:**
```
POST /decrypt
- Relleno válido → 200 OK
- Relleno inválido → 400 "Bad padding bytes"
- Base64 inválido → 400 "not been encoded in base64"
```

El desafío es descifrar el mensaje secreto usando solo el oracle de relleno.

## Análisis de la Vulnerabilidad

### Debilidad del Modo CBC

El modo CBC tiene una vulnerabilidad crítica cuando se revela la validación del relleno:

1. **Filtración de Información de Relleno**: Las respuestas del servidor revelan la validez del relleno
2. **Recuperación Bloque por Bloque**: Cada bloque puede descifrarse independientemente
3. **Recuperación Byte por Byte**: Cada byte puede recuperarse mediante manipulación del relleno
4. **Sin Clave Requerida**: El ataque funciona sin conocer la clave de cifrado

### Proceso de Descifrado CBC

En modo CBC, el descifrado funciona de la siguiente manera:
```
P[i] = D(C[i]) XOR C[i-1]
```

Donde:
- `P[i]` es el bloque de texto plano
- `C[i]` es el bloque de texto cifrado
- `D()` es la función de descifrado
- `C[i-1]` es el bloque de texto cifrado anterior (o IV para el primer bloque)

### Principio del Ataque Oracle de Relleno

El ataque funciona manipulando el bloque anterior (`C[i-1]`) para controlar el relleno en el bloque actual (`P[i]`):

1. **Detección de Relleno Válido**: El servidor revela si el relleno es válido
2. **Recuperación de Bytes**: Usar la validez del relleno para recuperar bytes individuales
3. **Recuperación de Bloques**: Recuperar bloques completos byte por byte
4. **Recuperación de Mensajes**: Recuperar el mensaje completo

## Implementación Técnica

### Estrategia del Ataque

1. **Análisis del Texto Cifrado**: Entender la estructura (IV + bloques cifrados)
2. **Descifrado Bloque por Bloque**: Descifrar cada bloque independientemente
3. **Recuperación Byte por Byte**: Usar oracle de relleno para recuperar cada byte
4. **Manipulación del Relleno**: Controlar el relleno para revelar bytes del texto plano

### Proceso del Ataque

#### Paso 1: Analizar Estructura del Texto Cifrado
```python
ciphertext = get_challenge_ciphertext(email)
blocks = split_into_blocks(ciphertext)
iv = blocks[0]  # Primer bloque es IV
ciphertext_blocks = blocks[1:]  # El resto son datos cifrados
```

#### Paso 2: Descifrar Bloque Usando Oracle de Relleno
```python
def decrypt_block(target_block, previous_block):
    decrypted_block = bytearray(16)
    
    # Descifrar byte por byte, empezando desde el último byte
    for byte_pos in range(15, -1, -1):
        padding_length = 16 - byte_pos
        
        # Modificar bloque anterior para crear relleno válido
        modified_previous = bytearray(previous_block)
        
        # Establecer bytes de relleno
        for i in range(byte_pos + 1, 16):
            modified_previous[i] = decrypted_block[i] ^ padding_length
        
        # Probar todos los valores posibles para el byte actual
        for byte_value in range(256):
            modified_previous[byte_pos] = byte_value ^ padding_length
            
            if test_decryption(modified_previous + target_block) == "OK":
                decrypted_block[byte_pos] = byte_value
                break
    
    return bytes(decrypted_block)
```

#### Paso 3: Descifrar Mensaje Completo
```python
def decrypt_message(ciphertext):
    blocks = split_into_blocks(ciphertext)
    iv = blocks[0]
    ciphertext_blocks = blocks[1:]
    
    decrypted_blocks = []
    
    for i, block in enumerate(ciphertext_blocks):
        if i == 0:
            previous_block = iv
        else:
            previous_block = ciphertext_blocks[i-1]
        
        decrypted_block = decrypt_block(block, previous_block)
        decrypted_blocks.append(decrypted_block)
    
    # Combinar y eliminar relleno
    decrypted_data = b''.join(decrypted_blocks)
    return unpad(decrypted_data, 16).decode('utf-8')
```

### Componentes Clave

- **`PaddingOracleAttack`**: Clase principal del ataque que implementa el ataque oracle de relleno
- **`get_challenge_ciphertext()`**: Recupera el mensaje cifrado del desafío
- **`test_decryption()`**: Prueba el descifrado con el servidor (oracle de relleno)
- **`decrypt_block()`**: Descifra un solo bloque usando oracle de relleno
- **`decrypt_message()`**: Descifra el mensaje completo
- **`submit_answer()`**: Envía el mensaje descifrado al servidor

## Explicación Detallada del Ataque

### Proceso de Recuperación Byte por Byte

Para cada posición de byte en un bloque:

1. **Configurar Relleno Válido**: Modificar el bloque anterior para crear relleno válido
2. **Probar Todos los Valores de Byte**: Probar todos los 256 valores posibles para el byte actual
3. **Detectar Relleno Válido**: Usar respuesta del oracle para identificar el byte correcto
4. **Mover al Siguiente Byte**: Repetir para la siguiente posición de byte

### Fundamento Matemático

El ataque explota la relación:
```
P[i] = D(C[i]) XOR C[i-1]
```

Al modificar `C[i-1]`, podemos controlar `P[i]` para crear relleno válido:
```
P'[i] = D(C[i]) XOR C'[i-1]
```

Cuando `P'[i]` tiene relleno válido, conocemos la relación entre `C'[i-1]` y el texto plano original.

### Manipulación del Relleno

El ataque crea patrones de relleno específicos:
- **Relleno de 1 byte**: Último byte = 0x01
- **Relleno de 2 bytes**: Últimos dos bytes = 0x02
- **Relleno de 3 bytes**: Últimos tres bytes = 0x03
- Y así sucesivamente...

## Complejidad del Ataque

- **Complejidad Temporal**: O(n × 256) donde n es el número total de bytes
- **Complejidad Espacial**: O(1) - espacio constante
- **Solicitudes de Red**: n × 256 solicitudes al servidor (peor caso)
- **Tasa de Éxito**: 100% (ataque determinístico)

## Archivos

- **`padding_oracle_attack.py`**: Implementación completa del ataque
- **`test_padding_oracle.py`**: Suite de pruebas comprensiva
- **`README.md`**: Esta documentación

## Uso

```bash
# Ejecutar el ataque
python padding_oracle_attack.py

# Ejecutar pruebas
python test_padding_oracle.py
```

## Flujo de Ataque de Ejemplo

```python
# 1. Obtener texto cifrado del desafío
ciphertext = attack.get_challenge_ciphertext(email)

# 2. Analizar estructura
analysis = attack.analyze_ciphertext(ciphertext)
# Salida: "Ciphertext length: 64 bytes, Number of blocks: 4"

# 3. Descifrar bloque por bloque
for i, block in enumerate(ciphertext_blocks):
    decrypted_block = attack.decrypt_block(email, block, previous_block)
    print(f"Block {i+1} decrypted: {decrypted_block.hex()}")

# 4. Enviar mensaje descifrado
result = attack.submit_answer(email, decrypted_message)
# Salida: "¡Ganaste!"
```

## Valor Educativo

Este desafío demuestra:

1. **Vulnerabilidades Oracle de Relleno**: Por qué revelar la validez del relleno es peligroso
2. **Debilidades del Modo CBC**: Cómo el modo CBC puede ser explotado
3. **Filtración de Información**: Cómo pequeñas filtraciones de información pueden llevar a compromiso completo
4. **Canales Laterales Criptográficos**: Cómo las respuestas del servidor crean canales laterales
5. **Análisis de Cifrado por Bloques**: Entender procesos de descifrado a nivel de bloque
6. **Criptoanálisis Práctico**: Aplicación del mundo real de ataques teóricos

## Implicaciones de Seguridad

### Por Qué los Oracles de Relleno son Peligrosos

1. **Recuperación Completa de Mensajes**: Puede descifrar mensajes completos sin la clave
2. **Sin Clave Requerida**: Funciona sin conocer la clave de cifrado
3. **Ataque Determinístico**: Siempre tiene éxito dado suficiente acceso al oracle
4. **Información de Canal Lateral**: Las respuestas del servidor filtran información crítica

### Defensas Contra Ataques Oracle de Relleno

1. **Usar Cifrado Autenticado**: AES-GCM, ChaCha20-Poly1305
2. **Validación de Relleno de Tiempo Constante**: Siempre realizar descifrado completo
3. **Autenticación de Mensajes**: Añadir HMAC o usar modos autenticados
4. **Limitación de Velocidad**: Limitar el acceso al oracle para prevenir ataques exhaustivos
5. **Manejo de Errores**: Devolver mensajes de error consistentes independientemente del tipo de fallo

## Variaciones Avanzadas del Ataque

### Mensajes Multi-Bloque

Para mensajes con múltiples bloques:
- Cada bloque se descifra independientemente
- El bloque anterior se usa como "IV" para el bloque actual
- El ataque escala linealmente con la longitud del mensaje

### Optimizaciones

1. **Solicitudes Paralelas**: Enviar múltiples solicitudes simultáneamente
2. **Caché**: Almacenar en caché respuestas del oracle para evitar solicitudes duplicadas
3. **Terminación Temprana**: Detenerse cuando se encuentra el byte correcto
4. **Análisis Estadístico**: Usar análisis de frecuencia para caracteres comunes

## Errores Comunes

1. **Alineación de Bloques**: Debe entender los límites de bloques correctamente
2. **Validación de Relleno**: Debe manejar el relleno PKCS7 correctamente
3. **Orden de Bytes**: Debe descifrar bytes en el orden correcto (último al primero)
4. **Manejo de Errores**: Debe manejar errores de red y timeouts

## Referencias

- [Ataques Oracle de Relleno](https://en.wikipedia.org/wiki/Padding_oracle_attack)
- [Modo CBC Wikipedia](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CBC)
- [Relleno PKCS7](https://en.wikipedia.org/wiki/PKCS_7)
- [Canales Laterales Criptográficos](https://en.wikipedia.org/wiki/Side-channel_attack)

## Advertencia

Esta es una demostración educativa de vulnerabilidades criptográficas. Siempre use modos de cifrado autenticados en sistemas de producción. Nunca revele información de validez de relleno en respuestas del servidor, ya que esto crea una vulnerabilidad de seguridad crítica.
