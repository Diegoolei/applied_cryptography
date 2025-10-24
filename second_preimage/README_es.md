# Ataque de Segunda Preimagen

## Descripción General

Este desafío demuestra una vulnerabilidad fundamental en las funciones de hash truncadas al encontrar una segunda preimagen - un mensaje diferente que produce el mismo hash que el mensaje original. El ataque explota el hecho de que SHA-256 truncado (SHA-256-24) tiene seguridad significativamente reducida debido a su longitud de salida más corta.

## Descripción del Desafío

El servidor implementa el siguiente proceso:
1. Proporciona un hash objetivo (SHA-256-24) de la dirección de correo del usuario
2. Requiere encontrar un mensaje diferente que produzca el mismo hash
3. El desafío usa SHA-256-24, que toma los primeros 24 bits (3 bytes, 6 caracteres hexadecimales) de SHA-256

**Función de Hash:**
```
SHA-256-24(mensaje) = SHA-256(mensaje)[:6]
```

**Ejemplo:**
```
SHA-256("user@example.com") = b4c9a289323b21a01c3e940f150eb...
SHA-256-24("user@example.com") = b4c9a2
```

El desafío es encontrar una segunda preimagen que produzca el mismo hash que el correo original.

## Análisis de la Vulnerabilidad

### Debilidad de Hash Truncado

Las funciones de hash truncadas tienen seguridad significativamente reducida:

1. **Espacio de Salida Reducido**: Salida de 24 bits significa solo 2^24 = 16,777,216 hashes posibles
2. **Paradoja del Cumpleaños**: Las colisiones se vuelven probables con ~2^12 = 4,096 mensajes
3. **Fuerza Bruta Factible**: 2^24 operaciones son computacionalmente factibles
4. **Ataque de Segunda Preimagen**: Encontrar una segunda preimagen requiere ~2^24 operaciones

### Fundamento Matemático

Para una función de hash con salida de n bits:
- **Resistencia a Colisiones**: ~2^(n/2) operaciones (paradoja del cumpleaños)
- **Resistencia a Segunda Preimagen**: ~2^n operaciones (fuerza bruta)
- **Resistencia a Preimagen**: ~2^n operaciones (fuerza bruta)

Para SHA-256-24 (salida de 24 bits):
- **Resistencia a Colisiones**: ~2^12 = 4,096 operaciones
- **Resistencia a Segunda Preimagen**: ~2^24 = 16,777,216 operaciones

## Implementación Técnica

### Estrategia del Ataque

1. **Cálculo de Hash**: Implementar función SHA-256-24
2. **Búsqueda de Fuerza Bruta**: Probar diferentes sufijos para encontrar colisión
3. **Optimización**: Usar múltiples estrategias y threading
4. **Verificación**: Asegurar que el mensaje encontrado produce el hash objetivo

### Proceso del Ataque

#### Paso 1: Obtener Hash Objetivo
```python
def get_target_hash(email):
    url = f"{base_url}/cripto/second-preimage/{email}/challenge"
    response = requests.get(url)
    return response.text.strip()
```

#### Paso 2: Calcular SHA-256-24
```python
def calculate_hash(message):
    hash_obj = hashlib.sha256(message.encode('utf-8'))
    full_hash = hash_obj.hexdigest()
    truncated_hash = full_hash[:6]  # Primeros 6 caracteres hex = 24 bits
    return truncated_hash
```

#### Paso 3: Búsqueda de Fuerza Bruta
```python
def brute_force_search(target_hash, original_message, max_length=10):
    charset = string.printable.strip()
    
    for length in range(1, max_length + 1):
        for suffix in itertools.product(charset, repeat=length):
            candidate = original_message + ''.join(suffix)
            candidate_hash = calculate_hash(candidate)
            
            if candidate_hash == target_hash and candidate != original_message:
                return candidate
    
    return None
```

#### Paso 4: Estrategias de Búsqueda Optimizada
```python
def optimized_search(target_hash, original_message):
    # Estrategia 1: Sufijos comunes
    common_suffixes = ["1", "2", "3", "a", "b", "c", "!", "@", "#"]
    
    # Estrategia 2: Números incrementales
    for i in range(1, 10000):
        candidate = original_message + str(i)
        if calculate_hash(candidate) == target_hash:
            return candidate
    
    # Estrategia 3: Sufijos de apariencia aleatoria
    # ... (estrategias adicionales)
```

### Componentes Clave

- **`SecondPreimageAttack`**: Clase principal del ataque que implementa el ataque de segunda preimagen
- **`get_target_hash()`**: Recupera el hash objetivo del servidor
- **`calculate_hash()`**: Calcula el hash SHA-256-24 de un mensaje
- **`brute_force_search()`**: Realiza búsqueda de fuerza bruta para segunda preimagen
- **`optimized_search()`**: Usa múltiples estrategias para encontrar colisiones
- **`submit_answer()`**: Envía la segunda preimagen al servidor

## Explicación Detallada del Ataque

### Proceso de Fuerza Bruta

1. **Conjunto de Caracteres**: Usar caracteres ASCII imprimibles (94 caracteres)
2. **Generación de Sufijos**: Generar todos los sufijos posibles de longitud creciente
3. **Cálculo de Hash**: Calcular SHA-256-24 para cada candidato
4. **Detección de Colisión**: Verificar si el hash coincide con el objetivo
5. **Verificación**: Asegurar que el candidato es diferente del original

### Estrategias de Optimización

#### Estrategia 1: Sufijos Comunes
Probar patrones comunes primero:
- Caracteres únicos: "1", "2", "a", "b", "!"
- Caracteres dobles: "01", "aa", "!!"
- Caracteres triples: "001", "aaa", "!!!"

#### Estrategia 2: Números Incrementales
Probar sufijos numéricos:
- "1", "2", "3", ..., "1000", "1001", ...

#### Estrategia 3: Sufijos de Apariencia Aleatoria
Probar combinaciones de caracteres aleatorios:
- "abc", "def", "xyz", "!@#", "$%^", ...

#### Estrategia 4: Procesamiento Paralelo
Usar múltiples hilos para acelerar la búsqueda:
```python
with ThreadPoolExecutor(max_workers=4) as executor:
    futures = []
    for length in range(1, max_length + 1):
        future = executor.submit(search_length, target_hash, original_message, length)
        futures.append(future)
```

## Complejidad del Ataque

- **Complejidad Temporal**: O(2^24) en el peor caso, mucho mejor con optimizaciones
- **Complejidad Espacial**: O(1) - espacio constante
- **Operaciones Esperadas**: ~2^24 / 2 = 8,388,608 operaciones en promedio
- **Tasa de Éxito**: 100% (ataque determinístico)

## Archivos

- **`second_preimage_attack.py`**: Implementación completa del ataque
- **`test_second_preimage.py`**: Suite de pruebas comprensiva
- **`README.md`**: Esta documentación

## Uso

```bash
# Ejecutar el ataque
python second_preimage_attack.py

# Ejecutar pruebas
python test_second_preimage.py
```

## Flujo de Ataque de Ejemplo

```python
# 1. Obtener hash objetivo
target_hash = attack.get_target_hash(email)
# Salida: "b4c9a2"

# 2. Verificar mensaje original
original_hash = attack.calculate_hash(email)
# Salida: "b4c9a2"

# 3. Buscar segunda preimagen
second_preimage = attack.optimized_search(target_hash, email)
# Salida: "user@example.com123"

# 4. Verificar colisión
verification_hash = attack.calculate_hash(second_preimage)
# Salida: "b4c9a2"

# 5. Enviar respuesta
result = attack.submit_answer(email, second_preimage)
# Salida: "¡Ganaste!"
```

## Valor Educativo

Este desafío demuestra:

1. **Vulnerabilidades de Hash Truncado**: Por qué los hashes más cortos son más débiles
2. **Ataques de Segunda Preimagen**: Cómo encontrar mensajes diferentes con el mismo hash
3. **Paradoja del Cumpleaños**: Fundamento matemático de los ataques de colisión
4. **Factibilidad de Fuerza Bruta**: Cuándo los ataques computacionales se vuelven prácticos
5. **Seguridad de Funciones de Hash**: Importancia de las salidas de hash de longitud completa
6. **Estrategias de Optimización**: Cómo mejorar la eficiencia del ataque

## Implicaciones de Seguridad

### Por Qué los Hashes Truncados son Peligrosos

1. **Seguridad Reducida**: Hash de 24 bits proporciona solo 2^24 = 16M salidas posibles
2. **Ataques Prácticos**: La fuerza bruta se vuelve factible con hardware moderno
3. **Vulnerabilidad a Colisiones**: La paradoja del cumpleaños hace las colisiones probables
4. **Vulnerabilidad a Segunda Preimagen**: Diferentes mensajes pueden producir el mismo hash

### Ejemplos del Mundo Real

1. **Hashes de Commit Git**: Los hashes de commit cortos pueden ser vulnerables
2. **Tokens de Sesión**: Los tokens cortos pueden ser forzados por fuerza bruta
3. **Hashes de Contraseñas**: Los hashes de contraseñas truncados son débiles
4. **Checksums**: Los checksums cortos proporcionan protección de integridad limitada

### Defensas Contra Ataques de Segunda Preimagen

1. **Usar Hashes de Longitud Completa**: SHA-256 (256-bit) en lugar de versiones truncadas
2. **Usar Hashes Más Fuertes**: SHA-3, BLAKE2 para nuevas aplicaciones
3. **Salar Mensajes**: Añadir sal aleatoria para prevenir ataques precomputados
4. **Limitación de Velocidad**: Limitar intentos de cálculo de hash
5. **Hashes con Clave**: Usar HMAC con claves secretas

## Variaciones Avanzadas del Ataque

### Procesamiento Paralelo

Usar múltiples núcleos de CPU para acelerar la búsqueda:
```python
with ThreadPoolExecutor(max_workers=cpu_count()) as executor:
    # Distribuir trabajo entre núcleos
```

### Optimización de Memoria

Almacenar solo información necesaria para reducir el uso de memoria:
```python
# En lugar de almacenar todos los candidatos, solo verificar hashes
for candidate in generate_candidates():
    if calculate_hash(candidate) == target_hash:
        return candidate
```

### Análisis Estadístico

Usar análisis de frecuencia para priorizar candidatos probables:
```python
# Probar patrones comunes primero
common_patterns = ["123", "abc", "!@#", "000", "111"]
for pattern in common_patterns:
    candidate = original_message + pattern
    if calculate_hash(candidate) == target_hash:
        return candidate
```

## Errores Comunes

1. **Conjunto de Caracteres**: Debe usar conjunto de caracteres apropiado para la aplicación
2. **Límites de Longitud**: Debe respetar restricciones de longitud máxima de mensaje
3. **Problemas de Codificación**: Debe manejar la codificación UTF-8 correctamente
4. **Rendimiento**: Debe optimizar para la plataforma objetivo

## Referencias

- [Ataque de Segunda Preimagen](https://en.wikipedia.org/wiki/Preimage_attack)
- [Paradoja del Cumpleaños](https://en.wikipedia.org/wiki/Birthday_problem)
- [SHA-256 Wikipedia](https://en.wikipedia.org/wiki/SHA-2)
- [Seguridad de Funciones de Hash](https://en.wikipedia.org/wiki/Cryptographic_hash_function)

## Advertencia

Esta es una demostración educativa de vulnerabilidades criptográficas. Siempre use funciones de hash de longitud completa en sistemas de producción. Las funciones de hash truncadas solo deben usarse cuando las implicaciones de seguridad estén completamente entendidas y la seguridad reducida sea aceptable para el caso de uso específico.
