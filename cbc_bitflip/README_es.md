# Ataque de Cambio de Bits en Modo CBC

## Descripción General

Este desafío demuestra una vulnerabilidad fundamental en el cifrado AES usando modo CBC (Cipher Block Chaining). El ataque explota la maleabilidad del modo CBC para modificar bloques de texto cifrado y afectar el descifrado de bloques posteriores de manera predecible. Este es un ejemplo clásico de un **ataque de cambio de bits** donde el atacante manipula el texto cifrado para lograr cambios deseados en el texto plano descifrado.

## Descripción del Desafío

El servidor implementa el siguiente proceso:
1. Recibe un email de usuario y datos adicionales (codificados en base64)
2. Crea un perfil: `user=<email>;data=<data>;role=user`
3. Cifra el perfil con AES-CBC y relleno PKCS7
4. Antepone un IV de 16 bytes al texto cifrado
5. Devuelve el resultado (IV + texto cifrado) codificado en base64

**Proceso del Servidor:**
```
IV || AES-CBC(perfil, clave, IV) -> base64_encode(IV || texto_cifrado)
```

El desafío es modificar el mensaje cifrado para que al descifrarse contenga `role=admin` en lugar de `role=user`.

## Análisis de la Vulnerabilidad

### Debilidad del Modo CBC

El modo CBC tiene una vulnerabilidad crítica: **modificar un bloque de texto cifrado afecta el descifrado del siguiente bloque de manera predecible**. Esta maleabilidad permite a los atacantes:

1. **Cambio de Bits**: Cambiar bits específicos en el texto cifrado para afectar bloques posteriores
2. **Manipulación de Bloques**: Modificar bloques de texto cifrado para lograr cambios deseados en el texto plano
3. **Cambios Predecibles**: Saber exactamente cómo las modificaciones afectarán el descifrado

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

### Principio del Ataque de Cambio de Bits

Si modificamos `C[i-1]` haciendo XOR con un valor `delta`:
```
C'[i-1] = C[i-1] XOR delta
```

Entonces el descifrado del bloque `i` se convierte en:
```
P'[i] = D(C[i]) XOR C'[i-1]
P'[i] = D(C[i]) XOR (C[i-1] XOR delta)
P'[i] = (D(C[i]) XOR C[i-1]) XOR delta
P'[i] = P[i] XOR delta
```

Esto significa que podemos controlar exactamente cómo cambia el siguiente bloque modificando el bloque actual.

## Implementación Técnica

### Estrategia del Ataque

1. **Análisis del Perfil**: Entender la estructura del perfil y el diseño de bloques
2. **Alineación de Bloques**: Controlar el campo de datos para alinear bloques correctamente
3. **Cálculo del Cambio de Bits**: Calcular la máscara XOR necesaria para los cambios deseados
4. **Modificación del Texto Cifrado**: Aplicar el cambio de bits al bloque apropiado
5. **Validación**: Asegurar que el texto cifrado modificado produzca resultados válidos

### Proceso del Ataque

#### Paso 1: Analizar Estructura del Perfil
```python
profile = "user=test@example.com;data=TestData;role=user"
# Dividir en bloques y analizar diseño
blocks = split_into_blocks(profile.encode('utf-8'))
```

#### Paso 2: Encontrar Bloque Objetivo
```python
# Encontrar qué bloque contiene 'role=user'
role_block_index = find_role_block(profile)
```

#### Paso 3: Calcular Cambio de Bits
```python
# Queremos cambiar 'role=user' a 'role=admin'
# Calcular máscara XOR para el cambio
original = b'role=user'
target = b'role=admin'
mask = bytes(a ^ b for a, b in zip(original, target))
```

#### Paso 4: Aplicar Cambio de Bits
```python
# Modificar el bloque anterior para afectar el bloque de rol
modified_blocks = ciphertext_blocks.copy()
modified_blocks[role_block_index - 1] = bytes(
    a ^ b for a, b in zip(modified_blocks[role_block_index - 1], mask)
)
```

### Componentes Clave

- **`CBCBitFlipAttack`**: Clase principal del ataque que implementa cambio de bits
- **`register_user()`**: Crea perfiles de usuario con datos controlados
- **`analyze_profile_structure()`**: Analiza el diseño del perfil y estructura de bloques
- **`find_role_block()`**: Localiza el bloque que contiene 'role=user'
- **`calculate_bit_flip()`**: Calcula la máscara XOR para cambios deseados
- **`submit_answer()`**: Envía el texto cifrado modificado al servidor

## Explicación Detallada del Ataque

### Estrategia de Alineación de Bloques

El ataque se basa en una alineación precisa de bloques:

1. **Bloque Objetivo**: El bloque que contiene 'role=user'
2. **Bloque Anterior**: El bloque que modificamos para afectar el objetivo
3. **Control de Datos**: Usar el campo de datos para controlar la alineación de bloques
4. **Posicionamiento de Bits**: Asegurar que los cambios ocurran en las posiciones correctas

### Por Qué Funciona

1. **Maleabilidad CBC**: Modificar `C[i-1]` afecta `P[i]` de manera predecible
2. **Propiedades XOR**: `(A XOR B) XOR B = A` permite control preciso
3. **Independencia de Bloques**: Cada bloque puede modificarse independientemente
4. **Entrada Controlada**: Podemos controlar el campo de datos para alinear bloques

### Fundamento Matemático

Para descifrado CBC: `P[i] = D(C[i]) XOR C[i-1]`

Si modificamos `C[i-1]` a `C'[i-1] = C[i-1] XOR delta`:
- `P'[i] = D(C[i]) XOR C'[i-1]`
- `P'[i] = D(C[i]) XOR (C[i-1] XOR delta)`
- `P'[i] = (D(C[i]) XOR C[i-1]) XOR delta`
- `P'[i] = P[i] XOR delta`

Esto nos da control preciso sobre cómo cambia el siguiente bloque.

## Complejidad del Ataque

- **Complejidad Temporal**: O(1) - tiempo constante para cálculo de cambio de bits
- **Complejidad Espacial**: O(n) donde n es la longitud del texto cifrado
- **Solicitudes de Red**: 2 solicitudes (registrar + enviar)
- **Tasa de Éxito**: Alta (ataque determinístico)

## Archivos

- **`cbc_bitflip_attack.py`**: Implementación completa del ataque
- **`test_cbc_bitflip.py`**: Suite de pruebas comprensiva
- **`README.md`**: Esta documentación

## Uso

```bash
# Ejecutar el ataque
python cbc_bitflip_attack.py

# Ejecutar pruebas
python test_cbc_bitflip.py
```

## Flujo de Ataque de Ejemplo

```python
# 1. Registrar usuario con datos controlados
encrypted_response = attack.register_user(challenge_email, user_email, "TestData")

# 2. Analizar estructura del perfil
analysis = attack.analyze_profile_structure(profile)

# 3. Encontrar bloque de rol
role_block_index = attack.find_role_block(profile)

# 4. Calcular cambio de bits
mask = calculate_bit_flip(original_block, target_block)

# 5. Aplicar modificación
modified_blocks[role_block_index - 1] = apply_bit_flip(modified_blocks[role_block_index - 1], mask)

# 6. Enviar texto cifrado modificado
result = attack.submit_answer(challenge_email, modified_ciphertext)
```

## Valor Educativo

Este desafío demuestra:

1. **Vulnerabilidades del Modo CBC**: Por qué CBC es maleable y vulnerable a cambios de bits
2. **Maleabilidad de Cifrado por Bloques**: Cómo las modificaciones del texto cifrado afectan el texto plano
3. **Propiedades XOR**: Fundamento matemático de los ataques de cambio de bits
4. **Alineación de Bloques**: Importancia de entender los límites de bloques
5. **Ataques de Relleno**: Cómo el relleno afecta el éxito del ataque
6. **Maleabilidad Criptográfica**: Por qué el cifrado determinístico es peligroso

## Implicaciones de Seguridad

### Por Qué el Modo CBC es Vulnerable

1. **Maleabilidad**: El texto cifrado puede modificarse para afectar el texto plano
2. **Cambios Predecibles**: Las modificaciones tienen efectos predecibles
3. **Dependencias de Bloques**: Cada bloque depende del anterior
4. **Sin Autenticación**: CBC no proporciona autenticación de mensajes

### Defensas Contra Ataques de Cambio de Bits

1. **Usar Cifrado Autenticado**: AES-GCM, ChaCha20-Poly1305
2. **Autenticación de Mensajes**: Añadir HMAC o usar modos autenticados
3. **Validación de Entrada**: Validar datos descifrados antes del procesamiento
4. **Comparación de Tiempo Constante**: Prevenir ataques de tiempo
5. **Relleno Seguro**: Usar esquemas de relleno seguros

## Variaciones Avanzadas del Ataque

### Modificaciones Multi-Bloque

Para cambios que abarcan múltiples bloques:
- Cada bloque puede modificarse independientemente
- Los cambios se propagan a través de la cadena CBC
- Las modificaciones complejas requieren planificación cuidadosa

### Ataques Oracle de Relleno

Combinados con vulnerabilidades oracle de relleno:
- Cambio de bits + oracle de relleno = descifrado completo
- Más poderoso que el cambio de bits independiente
- Requiere acceso oracle adicional

## Errores Comunes

1. **Alineación de Bloques**: Bloques desalineados causan resultados impredecibles
2. **Problemas de Relleno**: Relleno inválido causa fallos de descifrado
3. **Cambios de Longitud**: Cambiar 'user' a 'admin' cambia la longitud
4. **Codificación de Caracteres**: La codificación UTF-8 puede complicar cambios a nivel de byte

## Referencias

- [Modo CBC Wikipedia](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CBC)
- [Ataques de Cambio de Bits](https://en.wikipedia.org/wiki/Bit-flipping_attack)
- [Ataques Oracle de Relleno](https://en.wikipedia.org/wiki/Padding_oracle_attack)
- [Maleabilidad Criptográfica](https://en.wikipedia.org/wiki/Malleability_(cryptography))

## Advertencia

Esta es una demostración educativa de vulnerabilidades criptográficas. Siempre use modos de cifrado autenticados en sistemas de producción. El modo CBC debe usarse con autenticación adecuada (HMAC) o reemplazarse con modos de cifrado autenticados como AES-GCM.
