# Ataque de Colisión de Hash

## Descripción General

Este desafío demuestra una vulnerabilidad fundamental en las funciones de hash truncadas al encontrar colisiones de hash - dos mensajes diferentes que producen el mismo valor de hash. El ataque explota la paradoja del cumpleaños y la seguridad reducida de SHA-256 truncado (SHA-256-48) para encontrar colisiones de manera eficiente.

## Descripción del Desafío

El servidor implementa el siguiente proceso:
1. Requiere encontrar dos mensajes diferentes que produzcan el mismo hash SHA-256-48
2. Ambos mensajes deben contener la dirección de correo del usuario
3. El desafío usa SHA-256-48, que toma los primeros 48 bits (6 bytes, 12 caracteres hexadecimales) de SHA-256

**Función de Hash:**
```
SHA-256-48(mensaje) = SHA-256(mensaje)[:12]
```

**Ejemplo:**
```
SHA-256("user@example.com") = b4c9a289323b21a01c3e940f150eb...
SHA-256-48("user@example.com") = b4c9a289323b
```

El desafío es encontrar dos mensajes diferentes que ambos contengan el correo y produzcan el mismo hash.

## Análisis de la Vulnerabilidad

### Debilidad de Hash Truncado

Las funciones de hash truncadas tienen seguridad significativamente reducida:

1. **Espacio de Salida Reducido**: Salida de 48 bits significa solo 2^48 = 281,474,976,710,656 hashes posibles
2. **Paradoja del Cumpleaños**: Las colisiones se vuelven probables con ~2^24 = 16,777,216 mensajes
3. **Fuerza Bruta Factible**: 2^24 operaciones son computacionalmente factibles en hardware moderno
4. **Ataque de Colisión**: Encontrar colisiones requiere ~2^24 operaciones (ataque del cumpleaños)

### Fundamento Matemático

Para una función de hash con salida de n bits:
- **Resistencia a Colisiones**: ~2^(n/2) operaciones (paradoja del cumpleaños)
- **Resistencia a Segunda Preimagen**: ~2^n operaciones (fuerza bruta)
- **Resistencia a Preimagen**: ~2^n operaciones (fuerza bruta)

Para SHA-256-48 (salida de 48 bits):
- **Resistencia a Colisiones**: ~2^24 = 16,777,216 operaciones
- **Resistencia a Segunda Preimagen**: ~2^48 = 281,474,976,710,656 operaciones
- **Resistencia a Preimagen**: ~2^48 = 281,474,976,710,656 operaciones

### Paradoja del Cumpleaños

La paradoja del cumpleaños establece que en un grupo de 23 personas, hay un 50% de probabilidad de que dos personas compartan el mismo cumpleaños. Para funciones de hash:

- **Probabilidad de colisión**: P(colisión) ≈ 1 - e^(-k²/(2×2^n))
- **Colisiones esperadas**: Después de ~√(π/2 × 2^n) mensajes
- **Para hashes de 48 bits**: Colisión esperada después de ~2^24 mensajes

## Implementación Técnica

### Estrategia del Ataque

1. **Cálculo de Hash**: Implementar función SHA-256-48
2. **Detección de Colisiones**: Usar mapa de hash para detectar colisiones
3. **Múltiples Estrategias**: Búsqueda optimizada, ataque del cumpleaños, fuerza bruta
4. **Procesamiento Paralelo**: Usar múltiples hilos para rendimiento
5. **Verificación**: Asegurar que ambos mensajes contengan el correo y produzcan el mismo hash

### Proceso del Ataque

#### Paso 1: Calcular SHA-256-48
```python
def calculate_hash(message):
    hash_obj = hashlib.sha256(message.encode('utf-8'))
    full_hash = hash_obj.hexdigest()
    truncated_hash = full_hash[:12]  # Primeros 12 caracteres hex = 48 bits
    return truncated_hash
```

#### Paso 2: Búsqueda de Colisión Optimizada
```python
def find_collision_optimized(email):
    hash_map = defaultdict(list)
    
    # Estrategia 1: Sufijos comunes
    common_suffixes = ["1", "2", "3", "a", "b", "c", "!", "@", "#"]
    
    # Estrategia 2: Números incrementales
    for i in range(1, 10000):
        candidate = email + str(i)
        candidate_hash = calculate_hash(candidate)
        hash_map[candidate_hash].append(candidate)
        
        if len(hash_map[candidate_hash]) >= 2:
            return hash_map[candidate_hash][:2]
```

#### Paso 3: Ataque del Cumpleaños
```python
def find_collision_birthday_attack(email, max_attempts=1000000):
    hash_map = defaultdict(list)
    
    for attempt in range(max_attempts):
        # Generar sufijo aleatorio
        suffix = ''.join(random.choice(charset) for _ in range(random.randint(1, 8)))
        candidate = email + suffix
        candidate_hash = calculate_hash(candidate)
        hash_map[candidate_hash].append(candidate)
        
        if len(hash_map[candidate_hash]) >= 2:
            return hash_map[candidate_hash][:2]
```

#### Paso 4: Búsqueda de Fuerza Bruta
```python
def find_collision_brute_force(email, max_length=8):
    hash_map = defaultdict(list)
    
    for length in range(1, max_length + 1):
        for suffix in itertools.product(charset, repeat=length):
            candidate = email + ''.join(suffix)
            candidate_hash = calculate_hash(candidate)
            hash_map[candidate_hash].append(candidate)
            
            if len(hash_map[candidate_hash]) >= 2:
                return hash_map[candidate_hash][:2]
```

### Componentes Clave

- **`HashCollisionAttack`**: Clase principal del ataque que implementa la búsqueda de colisiones
- **`calculate_hash()`**: Calcula el hash SHA-256-48 de un mensaje
- **`find_collision_optimized()`**: Usa múltiples estrategias para encontrar colisiones
- **`find_collision_birthday_attack()`**: Ataque del cumpleaños con generación aleatoria
- **`find_collision_brute_force()`**: Búsqueda sistemática de fuerza bruta
- **`submit_collision()`**: Envía el par de colisión al servidor

## Explicación Detallada del Ataque

### Proceso de Detección de Colisiones

1. **Almacenamiento en Mapa de Hash**: Almacenar mensajes por sus valores de hash
2. **Detección de Colisiones**: Cuando el mapa de hash contiene 2+ mensajes para el mismo hash
3. **Validación de Mensajes**: Asegurar que ambos mensajes contengan el correo
4. **Verificación de Hash**: Verificar que ambos mensajes produzcan el mismo hash

### Estrategias de Optimización

#### Estrategia 1: Sufijos Comunes
Probar patrones comunes primero:
- Caracteres únicos: "1", "2", "a", "b", "!"
- Caracteres dobles: "01", "aa", "!!"
- Caracteres triples: "001", "aaa", "!!!"

#### Estrategia 2: Números Incrementales
Probar sufijos numéricos:
- "1", "2", "3", ..., "1000", "1001", ...

#### Estrategia 3: Generación Aleatoria
Usar combinaciones de caracteres aleatorios:
- Sufijos de longitud aleatoria con caracteres aleatorios
- Enfoque de ataque del cumpleaños

#### Estrategia 4: Procesamiento Paralelo
Usar múltiples hilos para acelerar la búsqueda:
```python
with ThreadPoolExecutor(max_workers=4) as executor:
    futures = []
    for length in range(1, max_length + 1):
        future = executor.submit(search_length, email, charset, length)
        futures.append(future)
```

## Complejidad del Ataque

- **Complejidad Temporal**: O(2^24) para búsqueda de colisiones (ataque del cumpleaños)
- **Complejidad Espacial**: O(2^24) para almacenamiento del mapa de hash
- **Operaciones Esperadas**: ~2^24 = 16,777,216 operaciones
- **Tasa de Éxito**: Alta probabilidad con intentos suficientes

## Archivos

- **`hash_collision_attack.py`**: Implementación completa del ataque
- **`test_hash_collision.py`**: Suite de pruebas comprensiva
- **`README.md`**: Esta documentación

## Uso

```bash
# Ejecutar el ataque
python hash_collision_attack.py

# Ejecutar pruebas
python test_hash_collision.py
```

## Flujo de Ataque de Ejemplo

```python
# 1. Inicializar ataque
attack = HashCollisionAttack()
email = "user@example.com"

# 2. Probar búsqueda optimizada primero
collision = attack.find_collision_optimized(email)
# Salida: ("user@example.com123", "user@example.com456")

# 3. Verificar colisión
hash1 = attack.calculate_hash(collision[0])
hash2 = attack.calculate_hash(collision[1])
# Salida: "b4c9a289323b" == "b4c9a289323b"

# 4. Enviar colisión
result = attack.submit_collision(email, collision[0], collision[1])
# Salida: "¡Ganaste!"
```

## Valor Educativo

Este desafío demuestra:

1. **Ataques de Colisión de Hash**: Cómo encontrar mensajes diferentes con el mismo hash
2. **Paradoja del Cumpleaños**: Fundamento matemático de los ataques de colisión
3. **Vulnerabilidades de Hash Truncado**: Por qué los hashes más cortos son más débiles
4. **Probabilidad de Colisión**: Entender la probabilidad de colisión
5. **Optimización de Ataques**: Múltiples estrategias para encontrar colisiones
6. **Procesamiento Paralelo**: Usar múltiples hilos para rendimiento

## Implicaciones de Seguridad

### Por Qué las Colisiones de Hash son Peligrosas

1. **Falsificación de Mensajes**: Puede crear mensajes falsos con el mismo hash
2. **Firmas Digitales**: Puede falsificar firmas para mensajes diferentes
3. **Ataques de Contraseñas**: Puede encontrar contraseñas diferentes con el mismo hash
4. **Violaciones de Integridad**: Puede modificar mensajes preservando el hash

### Ejemplos del Mundo Real

1. **Colisiones MD5**: MD5 es vulnerable a ataques de colisión
2. **Colisiones SHA-1**: SHA-1 ha sido roto para colisiones
3. **Ataques de Certificados**: Ataques de colisión en hashes de certificados
4. **Ataques de Blockchain**: Ataques de colisión en hashes de transacciones

### Defensas Contra Ataques de Colisión de Hash

1. **Usar Hashes Fuertes**: SHA-256, SHA-3, BLAKE2 para nuevas aplicaciones
2. **Evitar Hashes Truncados**: Usar salidas de hash de longitud completa
3. **Usar Hashes Salados**: Añadir sal aleatoria para prevenir ataques precomputados
4. **Usar Hashes con Clave**: Usar HMAC con claves secretas
5. **Actualizaciones Regulares**: Actualizar a funciones de hash más fuertes cuando se encuentran vulnerabilidades

## Variaciones Avanzadas del Ataque

### Procesamiento Paralelo

Usar múltiples núcleos de CPU para acelerar la búsqueda:
```python
with ThreadPoolExecutor(max_workers=cpu_count()) as executor:
    # Distribuir trabajo entre núcleos
```

### Optimización de Memoria

Usar estructuras de datos eficientes para reducir el uso de memoria:
```python
# Usar defaultdict para operaciones eficientes del mapa de hash
hash_map = defaultdict(list)
```

### Análisis Estadístico

Usar análisis de frecuencia para priorizar candidatos probables:
```python
# Probar patrones comunes primero
common_patterns = ["123", "abc", "!@#", "000", "111"]
for pattern in common_patterns:
    candidate = email + pattern
    # Verificar colisión
```

## Errores Comunes

1. **Conjunto de Caracteres**: Debe usar conjunto de caracteres apropiado para la aplicación
2. **Límites de Longitud**: Debe respetar restricciones de longitud máxima de mensaje
3. **Uso de Memoria**: Los mapas de hash pueden consumir memoria significativa
4. **Rendimiento**: Debe optimizar para la plataforma objetivo

## Referencias

- [Ataque de Colisión de Hash](https://en.wikipedia.org/wiki/Hash_collision)
- [Paradoja del Cumpleaños](https://en.wikipedia.org/wiki/Birthday_problem)
- [SHA-256 Wikipedia](https://en.wikipedia.org/wiki/SHA-2)
- [Seguridad de Funciones de Hash](https://en.wikipedia.org/wiki/Cryptographic_hash_function)

## Advertencia

Esta es una demostración educativa de vulnerabilidades criptográficas. Siempre use funciones de hash de longitud completa en sistemas de producción. Las funciones de hash truncadas solo deben usarse cuando las implicaciones de seguridad estén completamente entendidas y la seguridad reducida sea aceptable para el caso de uso específico.
