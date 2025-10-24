# Ataque de Falsificación CBC-MAC

## Descripción General

Este desafío demuestra una vulnerabilidad fundamental en CBC-MAC cuando se usa con mensajes de longitud variable. El ataque explota la propiedad matemática que permite falsificar MACs concatenando mensajes y manipulando las operaciones XOR en la construcción CBC.

## Descripción del Desafío

El servidor implementa un sistema de autenticación CBC-MAC para transferencias de dinero:
1. Proporciona una query string que representa transferencias de dinero con un CBC-MAC
2. Usa CBC-MAC para autenticar los datos de transferencia
3. Requiere falsificar una transferencia al correo del atacante por más de $10,000

**Formato de Transferencia:**
```
from=user@example.com&user@example.com=1000&comment=Invoice&mac=701b3768b67a68be68cee9736628cae8
```

**Cálculo del MAC:**
```
mac = CBC-MAC("from=user@example.com&user@example.com=1000&comment=Invoice")
```

**Objetivo del Desafío:**
Crear una query string falsificada que transfiera más de $10,000 al correo del atacante.

## Análisis de la Vulnerabilidad

### Debilidad de la Construcción CBC-MAC

CBC-MAC tiene una vulnerabilidad crítica con mensajes de longitud variable:

1. **Propiedad Matemática**: Si M₁ tiene MAC T₁, entonces M₁ || (T₁ ⊕ M₁') || M₁' tiene MAC T₁
2. **Cancelación XOR**: El XOR con T₁ cancela la contribución de M₁' al tag
3. **Concatenación de Mensajes**: Puede añadir datos arbitrarios a mensajes existentes
4. **Sin Clave Requerida**: El ataque funciona sin conocer la clave secreta

### Fundamento Matemático

En la construcción CBC-MAC:
```
CBC-MAC(M) = E_k(E_k(...E_k(E_k(M₁) ⊕ M₂) ⊕ M₃)...)
```

Donde:
- `E_k()` es la función de cifrado con clave `k`
- `M₁, M₂, M₃...` son bloques del mensaje
- El bloque de texto cifrado final es el MAC

**Propiedad de Falsificación:**
Si `M₁` tiene MAC `T₁`, entonces:
```
M₁ || (T₁ ⊕ M₁') || M₁' tiene MAC T₁
```

Donde `M₁'` es el mensaje que queremos añadir.

### Proceso del Ataque

1. **Extraer MAC Original**: Obtener el MAC del mensaje original
2. **Crear Transferencia Adicional**: Diseñar la transferencia al correo del atacante
3. **Calcular Bloque XOR**: XOR del MAC original con el primer bloque del mensaje adicional
4. **Construir Mensaje Falsificado**: Concatenar original + bloque XOR + mensaje adicional
5. **Enviar Query Falsificada**: Enviar la query string falsificada al servidor

## Implementación Técnica

### Estrategia del Ataque

1. **Análisis de Query**: Analizar la query string original
2. **Construcción de Mensaje**: Construir mensaje desde pares clave-valor
3. **Falsificación CBC-MAC**: Usar propiedad matemática para falsificar MAC
4. **Construcción de Query**: Construir query string falsificada
5. **Codificación URL**: Manejar caracteres especiales en URLs

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
    
    # Reconstruir la query string original (sin MAC)
    message_parts = []
    for key, value in message_pairs.items():
        message_parts.append(f"{key}={value}")
    
    return '&'.join(message_parts)
```

#### Paso 3: Realizar Falsificación CBC-MAC
```python
def forge_cbc_mac(original_query, target_email, target_amount):
    # Analizar query original
    pairs = parse_query_string(original_query)
    original_mac = pairs.get('mac', '')
    
    # Construir mensaje original (sin MAC)
    original_message = build_message_from_pairs(pairs)
    
    # Crear transferencia adicional
    additional_transfer = f"&{target_email}={target_amount}"
    
    # Convertir MAC original a bytes
    original_mac_bytes = bytes.fromhex(original_mac)
    
    # Crear mensaje adicional
    additional_bytes = additional_transfer.encode('utf-8')
    additional_padded = pad(additional_bytes, 16)
    
    # Tomar primer bloque del mensaje adicional
    first_block = additional_padded[:16]
    
    # XOR con MAC original
    xor_block = bytes(a ^ b for a, b in zip(original_mac_bytes, first_block))
    
    # Crear mensaje falsificado
    forged_message_bytes = original_message.encode('utf-8') + xor_block + additional_padded[16:]
    
    # Convertir a formato query string
    forged_message_str = forged_message_bytes.decode('utf-8', errors='ignore')
    
    # Analizar y reconstruir query string
    forged_pairs = parse_query_string(forged_message_str)
    forged_pairs['mac'] = original_mac
    
    return '&'.join(f"{key}={value}" for key, value in forged_pairs.items())
```

### Componentes Clave

- **`CBCMACForgeryAttack`**: Clase principal del ataque que implementa la falsificación CBC-MAC
- **`get_challenge_message()`**: Recupera el mensaje del desafío del servidor
- **`parse_query_string()`**: Analiza query string en pares clave-valor
- **`build_message_from_pairs()`**: Construye mensaje desde pares clave-valor
- **`forge_cbc_mac()`**: Realiza ataque de falsificación CBC-MAC
- **`simulate_cbc_mac()`**: Simula cálculo CBC-MAC para pruebas
- **`submit_answer()`**: Envía la query falsificada al servidor

## Explicación Detallada del Ataque

### Técnica de Falsificación CBC-MAC

El ataque explota la propiedad matemática de CBC-MAC:

1. **Mensaje Original**: `M₁` con MAC `T₁`
2. **Mensaje Adicional**: `M₁'` (lo que queremos añadir)
3. **Mensaje Falsificado**: `M₁ || (T₁ ⊕ M₁') || M₁'`
4. **Resultado**: El mensaje falsificado tiene MAC `T₁`

### Manipulación XOR

La clave es que hacer XOR del MAC original con el primer bloque del mensaje adicional cancela la contribución:

```
CBC-MAC(M₁ || (T₁ ⊕ M₁') || M₁') = T₁
```

Esto funciona porque:
- `T₁ ⊕ M₁'` cuando se procesa a través de CBC-MAC produce `T₁ ⊕ M₁'`
- Hacer XOR con `T₁` da `M₁'`
- El resto de `M₁'` se procesa normalmente

### Construcción de Mensaje

El desafío es crear una query string válida que produzca el mensaje falsificado:

1. **Analizar Original**: Extraer campos de la query original
2. **Crear Adicional**: Diseñar transferencia al correo del atacante
3. **Calcular Bloque XOR**: XOR del MAC original con el primer bloque del mensaje adicional
4. **Construir Falsificado**: Concatenar original + bloque XOR + adicional
5. **Analizar Resultado**: Extraer pares clave-valor del mensaje falsificado
6. **Construir Query**: Reconstruir query string con MAC original

## Complejidad del Ataque

- **Complejidad Temporal**: O(1) - operaciones de tiempo constante
- **Complejidad Espacial**: O(1) - espacio constante
- **Tasa de Éxito**: 100% (ataque determinístico)
- **Conocimiento de Clave**: No requerido (el ataque funciona sin secreto)

## Archivos

- **`cbc_mac_attack.py`**: Implementación completa del ataque
- **`test_cbc_mac.py`**: Suite de pruebas comprensiva
- **`README.md`**: Esta documentación

## Uso

```bash
# Ejecutar el ataque
python cbc_mac_attack.py

# Ejecutar pruebas
python test_cbc_mac.py
```

## Flujo de Ataque de Ejemplo

```python
# 1. Obtener mensaje del desafío
original_query = attack.get_challenge_message(email)
# Salida: "from=user@example.com&user@example.com=1000&comment=Invoice&mac=701b3768b67a68be68cee9736628cae8"

# 2. Analizar y construir mensaje
pairs = attack.parse_query_string(original_query)
original_message = attack.build_message_from_pairs(pairs)
# Salida: "from=user@example.com&user@example.com=1000&comment=Invoice"

# 3. Falsificar CBC-MAC
forged_query = attack.forge_cbc_mac(original_query, "attacker@example.com", 15000)
# Salida: "from=user@example.com&attacker@example.com=15000&mac=701b3768b67a68be68cee9736628cae8"

# 4. Enviar query falsificada
result = attack.submit_answer(email, forged_query)
# Salida: "¡Quiero más plata!"
```

## Valor Educativo

Este desafío demuestra:

1. **Vulnerabilidades CBC-MAC**: Por qué CBC-MAC es inseguro con mensajes de longitud variable
2. **Propiedades Matemáticas**: Entender propiedades XOR en construcciones criptográficas
3. **Falsificación de MAC**: Cómo falsificar autenticación sin conocer la clave
4. **Concatenación de Mensajes**: Cómo añadir datos a mensajes existentes
5. **Ataques Criptográficos**: Aplicación práctica de vulnerabilidades teóricas
6. **Manipulación de Query String**: Entender codificación URL y análisis

## Implicaciones de Seguridad

### Por Qué la Falsificación CBC-MAC es Peligrosa

1. **Bypass de Autenticación**: Puede crear MACs válidos para mensajes diferentes
2. **Manipulación de Mensajes**: Puede modificar mensajes preservando la autenticación
3. **Fraude Financiero**: Puede crear transferencias de dinero no autorizadas
4. **Sin Clave Requerida**: El ataque funciona sin conocer la clave secreta

### Ejemplos del Mundo Real

1. **Sistemas Financieros**: Sistemas de transferencia de dinero usando CBC-MAC
2. **Autenticación API**: APIs usando CBC-MAC para autenticación de solicitudes
3. **Sistemas de Mensajería**: Sistemas de chat o mensajería usando CBC-MAC
4. **Integridad de Archivos**: Verificación de integridad de archivos usando CBC-MAC

### Defensas Contra Falsificación CBC-MAC

1. **Usar HMAC**: HMAC no es vulnerable a este ataque
2. **Usar CMAC**: CMAC (MAC basado en cifrado) es seguro
3. **Usar Cifrado Autenticado**: AES-GCM, ChaCha20-Poly1305
4. **Usar MACs Basados en SHA-3**: Los MACs basados en SHA-3 son seguros
5. **Usar Mensajes de Longitud Fija**: CBC-MAC es seguro con mensajes de longitud fija

## Variaciones Avanzadas del Ataque

### Múltiples Transferencias

Crear múltiples transferencias en una sola falsificación:
```python
def forge_multiple_transfers(original_query, transfers):
    # transfers = [("email1", amount1), ("email2", amount2), ...]
    # Crear mensaje falsificado con múltiples transferencias
    pass
```

### Manipulación de Montos

Manipular montos de transferencias existentes:
```python
def manipulate_amounts(original_query, amount_changes):
    # amount_changes = {"email": new_amount}
    # Modificar montos de transferencias existentes
    pass
```

### Inyección de Comentarios

Inyectar comentarios maliciosos:
```python
def inject_comments(original_query, malicious_comment):
    # Añadir comentario malicioso a la transferencia
    pass
```

## Errores Comunes

1. **Codificación URL**: Debe manejar caracteres especiales en URLs
2. **Alineación de Bloques**: Debe alinear bloques correctamente para CBC-MAC
3. **Análisis de Mensajes**: Debe analizar query strings correctamente
4. **Cálculo XOR**: Debe realizar operaciones XOR correctamente

## Referencias

- [CBC-MAC Wikipedia](https://en.wikipedia.org/wiki/CBC-MAC)
- [Seguridad CBC-MAC](https://en.wikipedia.org/wiki/CBC-MAC#Security)
- [Ataques de Falsificación MAC](https://en.wikipedia.org/wiki/Message_authentication_code#Security)
- [MACs Criptográficos](https://en.wikipedia.org/wiki/Message_authentication_code)

## Advertencia

Esta es una demostración educativa de vulnerabilidades criptográficas. Siempre use construcciones MAC seguras como HMAC o CMAC en sistemas de producción. CBC-MAC nunca debe usarse con mensajes de longitud variable ya que es vulnerable a ataques de falsificación.
