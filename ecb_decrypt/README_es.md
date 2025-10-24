# Ataque de Descifrado ECB Byte por Byte

## Descripción General

Este desafío demuestra una vulnerabilidad fundamental en el cifrado AES usando modo ECB (Electronic Codebook). El ataque explota la naturaleza determinística del modo ECB para recuperar un mensaje secreto analizando respuestas cifradas a entradas controladas. Este es un ejemplo clásico de un **ataque oracle** donde el atacante usa el servicio de cifrado como una "caja negra" para aprender información sobre el secreto.

## Descripción del Desafío

El servidor implementa el siguiente proceso:
1. Recibe un mensaje elegido por el usuario (codificado en base64)
2. Lo concatena con un mensaje secreto: `mensaje_usuario || mensaje_secreto`
3. Cifra el resultado con AES-ECB y relleno PKCS7
4. Devuelve el resultado cifrado (codificado en base64)

**Proceso del Servidor:**
```
encode_base64(AES-ECB(decode_base64(mensaje_usuario) || mensaje_secreto))
```

El desafío es recuperar el mensaje secreto sin conocer la clave de cifrado.

## Análisis de la Vulnerabilidad

### Debilidad del Modo ECB

El modo ECB tiene una falla crítica: **los bloques de texto plano idénticos producen bloques de texto cifrado idénticos**. Este comportamiento determinístico permite a los atacantes:

1. **Predecir Salida de Cifrado**: La misma entrada siempre produce la misma salida
2. **Análisis Bloque por Bloque**: Analizar bloques individuales independientemente
3. **Ataques Oracle**: Usar el servicio de cifrado para aprender sobre datos desconocidos

### Estrategia del Ataque: Recuperación Byte por Byte

El ataque funciona explotando la alineación de bloques y el determinismo ECB:

1. **Descubrimiento de Longitud**: Determinar la longitud del mensaje secreto analizando cambios en la longitud del texto cifrado
2. **Alineación de Bloques**: Posicionar bytes desconocidos en límites de bloque
3. **Fuerza Bruta**: Probar todos los valores de byte posibles (0-255) para cada posición desconocida
4. **Coincidencia de Bloques**: Usar el determinismo ECB para identificar bytes correctos

## Implementación Técnica

### Proceso del Ataque

#### Paso 1: Determinar Longitud del Secreto
```python
# Enviar mensajes de longitud creciente
for length in range(0, 33):
    test_message = "A" * length
    encrypted_response = encrypt_message(email, test_message)
    
    # Analizar longitud del texto cifrado para determinar longitud del secreto
    ciphertext_length = len(base64.b64decode(encrypted_response))
```

#### Paso 2: Recuperación Byte por Byte
```python
for byte_position in range(secret_length):
    # Crear alineación: 15 bytes conocidos + 1 byte desconocido
    known_bytes = "A" * 15
    target_block_index = byte_position // 16
    
    # Obtener bloque de referencia con byte desconocido
    reference_message = known_bytes + "B" * padding
    reference_encrypted = encrypt_message(email, reference_message)
    reference_block = get_block(reference_encrypted, target_block_index)
    
    # Probar todos los valores de byte posibles
    for byte_value in range(256):
        test_message = known_bytes + chr(byte_value)
        test_encrypted = encrypt_message(email, test_message)
        test_block = get_block(test_encrypted, target_block_index)
        
        if test_block == reference_block:
            secret_byte = chr(byte_value)
            break
```

### Componentes Clave

- **`ECBDecryptAttack`**: Clase principal del ataque que implementa descifrado byte por byte
- **`encrypt_message()`**: Envía mensajes al servidor para cifrado
- **`determine_secret_length()`**: Descubre la longitud del mensaje secreto
- **`decrypt_byte_by_byte()`**: Recupera el mensaje secreto byte por byte
- **`submit_answer()`**: Envía el secreto recuperado al servidor

## Explicación Detallada del Ataque

### Estrategia de Alineación de Bloques

El ataque se basa en una alineación precisa de bloques:

1. **Bloque Objetivo**: El bloque que contiene el byte desconocido
2. **Bytes Conocidos**: 15 bytes que controlamos (relleno)
3. **Byte Desconocido**: El byte secreto que queremos recuperar
4. **Límite de Bloque**: Posicionar el byte desconocido al final de un bloque

### Por Qué Funciona

1. **Determinismo ECB**: Mismo bloque de texto plano → mismo bloque de texto cifrado
2. **Independencia de Bloques**: Cada bloque se cifra independientemente
3. **Entrada Controlada**: Podemos controlar 15 de 16 bytes en un bloque
4. **Búsqueda Exhaustiva**: Solo 256 valores posibles para el byte desconocido

### Fundamento Matemático

Para un bloque que contiene bytes `[b0, b1, ..., b14, b15]`:
- Controlamos `b0` a través de `b14` (15 bytes)
- Queremos encontrar `b15` (1 byte desconocido)
- Determinismo ECB: `AES([b0,b1,...,b14,b15]) = C` es único para cada `b15`

Al probar todos los 256 valores posibles para `b15`, encontramos el que produce el bloque de texto cifrado objetivo.

## Complejidad del Ataque

- **Complejidad Temporal**: O(n × 256) donde n es la longitud del secreto
- **Complejidad Espacial**: O(1) - espacio constante
- **Solicitudes de Red**: n × 256 solicitudes al servidor
- **Tasa de Éxito**: 100% (ataque determinístico)

## Archivos

- **`ecb_decrypt_attack.py`**: Implementación completa del ataque
- **`test_ecb_decrypt.py`**: Suite de pruebas comprensiva
- **`README.md`**: Esta documentación

## Uso

```bash
# Ejecutar el ataque
python ecb_decrypt_attack.py

# Ejecutar pruebas
python test_ecb_decrypt.py
```

## Flujo de Ataque de Ejemplo

```python
# 1. Determinar longitud del secreto
secret_length = attack.determine_secret_length(email)
# Salida: "Mensaje secreto tiene aproximadamente 25 bytes"

# 2. Descifrar byte por byte
for i in range(secret_length):
    # Probar todos los 256 valores de byte posibles
    for byte_val in range(256):
        if test_block == target_block:
            secret_byte = chr(byte_val)
            break
    decrypted_secret += secret_byte

# 3. Enviar respuesta
result = attack.submit_answer(email, decrypted_secret)
# Salida: "¡Ganaste!"
```

## Valor Educativo

Este desafío demuestra:

1. **Vulnerabilidades del Modo ECB**: Por qué ECB es fundamentalmente inseguro
2. **Ataques Oracle**: Usar servicios de cifrado como fuentes de información
3. **Análisis de Cifrado por Bloques**: Entender el comportamiento de cifrado a nivel de bloque
4. **Maleabilidad Criptográfica**: Cómo el cifrado determinístico permite ataques
5. **Ataques de Relleno**: Importancia del relleno adecuado en cifrado por bloques
6. **Información de Canal Lateral**: Cómo la longitud del texto cifrado revela la longitud del texto plano

## Implicaciones de Seguridad

### Por Qué el Modo ECB es Peligroso

1. **Filtración de Patrones**: Bloques idénticos crean patrones visibles
2. **Cifrado Determinístico**: La misma entrada siempre produce la misma salida
3. **Independencia de Bloques**: Los bloques pueden analizarse y manipularse por separado
4. **Vulnerabilidades Oracle**: Permite varios ataques basados en oracle

### Defensas Contra Este Ataque

1. **Usar Modos Seguros**: CBC, GCM, o ChaCha20-Poly1305
2. **IVs Aleatorios**: Asegurar diferentes salidas para las mismas entradas
3. **Autenticación**: Usar modos de cifrado autenticados
4. **Limitación de Velocidad**: Limitar el acceso oracle para prevenir ataques exhaustivos
5. **Validación de Entrada**: Validar y sanitizar todas las entradas

## Variaciones Avanzadas del Ataque

### Secretos Multi-Bloque

Para secretos más largos que 16 bytes, el ataque se extiende naturalmente:
- Cada bloque se recupera independientemente
- La alineación de bloques se mantiene a través de múltiples bloques
- La complejidad del ataque escala linealmente con la longitud del secreto

### Optimizaciones

1. **Solicitudes Paralelas**: Enviar múltiples solicitudes simultáneamente
2. **Caché**: Almacenar en caché resultados de cifrado para evitar solicitudes duplicadas
3. **Terminación Temprana**: Detenerse cuando se encuentra el byte correcto
4. **Análisis Estadístico**: Usar análisis de frecuencia para caracteres comunes

## Referencias

- [Modo ECB Wikipedia](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#ECB)
- [Ataques Oracle](https://en.wikipedia.org/wiki/Oracle_attack)
- [Ataques Oracle de Relleno](https://en.wikipedia.org/wiki/Padding_oracle_attack)
- [Maleabilidad Criptográfica](https://en.wikipedia.org/wiki/Malleability_(cryptography))

## Advertencia

Esta es una demostración educativa de vulnerabilidades criptográficas. Siempre use bibliotecas criptográficas establecidas y modos de operación seguros en sistemas de producción. El modo ECB nunca debe usarse para cifrar múltiples bloques de datos.
