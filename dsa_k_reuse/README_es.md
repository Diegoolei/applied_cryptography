# Ataque de Reutilización de k en DSA

## Descripción General

Este desafío demuestra una vulnerabilidad crítica en DSA (Algoritmo de Firma Digital) cuando el mismo valor aleatorio k se reutiliza para múltiples firmas. El ataque explota esta debilidad para recuperar la clave privada sin conocer ninguno de los valores k individuales.

## Descripción del Desafío

El servidor implementa generación de firmas DSA con un generador de números aleatorios defectuoso:
1. Proporciona firmas DSA para mensajes elegidos por el usuario
2. Usa SHA-256 como función de hash
3. Tiene un generador de números aleatorios defectuoso que a menudo reutiliza valores k
4. Requiere recuperar la clave privada x

**Proceso de Firma DSA:**
```
1. Elegir k aleatorio
2. Calcular r = (g^k mod p) mod q
3. Calcular s = k^(-1) * (h + x*r) mod q
4. La firma es (r, s)
```

**Objetivo del Desafío:**
Recuperar la clave privada x explotando la reutilización de k en múltiples firmas.

## Análisis de la Vulnerabilidad

### Vulnerabilidad de Reutilización de k

DSA está completamente comprometido cuando se reutiliza el mismo valor k:

1. **Mismo Valor k**: Múltiples firmas usan el mismo k aleatorio
2. **Mismo Valor r**: Valores r idénticos indican reutilización de k
3. **Diferentes Valores s**: Diferentes mensajes producen diferentes valores s
4. **Explotación Matemática**: Se puede resolver para k y luego x

### Fundamento Matemático

**Ecuaciones de Firma DSA:**
Para dos mensajes m₁ y m₂ firmados con el mismo k:
```
r₁ = r₂ = (g^k mod p) mod q
s₁ = k^(-1) * (h₁ + x*r) mod q
s₂ = k^(-1) * (h₂ + x*r) mod q
```

**Recuperación de k:**
De las dos ecuaciones:
```
s₁ = k^(-1) * (h₁ + x*r) mod q
s₂ = k^(-1) * (h₂ + x*r) mod q
```

Restando:
```
s₁ - s₂ = k^(-1) * (h₁ - h₂) mod q
k = (h₁ - h₂) * (s₁ - s₂)^(-1) mod q
```

**Recuperación de Clave Privada:**
Una vez que k es conocido:
```
s = k^(-1) * (h + x*r) mod q
x = (s*k - h) * r^(-1) mod q
```

### Proceso del Ataque

1. **Recolectar Firmas**: Obtener múltiples firmas del servidor
2. **Encontrar Reutilización de k**: Buscar valores r idénticos
3. **Recuperar k**: Usar fórmula matemática para calcular k
4. **Recuperar Clave Privada**: Usar k para calcular clave privada x
5. **Enviar Respuesta**: Enviar clave privada recuperada al servidor

## Implementación Técnica

### Estrategia del Ataque

1. **Recolección de Datos**: Recolectar múltiples firmas del servidor
2. **Detección de Reutilización de k**: Encontrar firmas con valores r idénticos
3. **Recuperación Matemática**: Usar ecuaciones DSA para recuperar k y x
4. **Verificación**: Verificar valores recuperados
5. **Envío**: Enviar clave privada al servidor

### Proceso del Ataque

#### Paso 1: Recolectar Firmas
```python
def collect_signatures(self, email: str, messages: List[str], count: int = 10):
    signatures = []
    
    for i in range(count):
        message = messages[i] if i < len(messages) else f"message_{i}"
        signature = self.sign_message(email, message)
        signatures.append(signature)
    
    return signatures
```

#### Paso 2: Encontrar Reutilización de k
```python
def find_k_reuse(self, signatures: List[Dict[str, int]]):
    r_values = {}
    reuse_indices = []
    
    for i, sig in enumerate(signatures):
        r = sig['r']
        if r in r_values:
            reuse_indices.extend([r_values[r], i])
        else:
            r_values[r] = i
    
    return list(set(reuse_indices))
```

#### Paso 3: Recuperar k
```python
def recover_k(self, message1: bytes, message2: bytes, s1: int, s2: int, q: int):
    # Calcular hashes
    h1 = self.sha256_hash(message1)
    h2 = self.sha256_hash(message2)
    
    # Calcular k usando la fórmula:
    # k = (h1 - h2) * (s1 - s2)^(-1) mod q
    numerator = (h1 - h2) % q
    denominator = (s1 - s2) % q
    
    # Calcular inverso modular del denominador
    denominator_inv = self.modular_inverse(denominator, q)
    
    # Calcular k
    k = (numerator * denominator_inv) % q
    
    return k
```

#### Paso 4: Recuperar Clave Privada
```python
def recover_private_key(self, message: bytes, r: int, s: int, k: int, q: int):
    # Calcular hash
    h = self.sha256_hash(message)
    
    # Calcular clave privada usando la fórmula:
    # x = (s * k - h) * r^(-1) mod q
    numerator = (s * k - h) % q
    r_inv = self.modular_inverse(r, q)
    
    # Calcular clave privada
    x = (numerator * r_inv) % q
    
    return x
```

#### Paso 5: Inverso Modular
```python
def modular_inverse(self, a: int, m: int):
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y
    
    gcd, x, y = extended_gcd(a, m)
    if gcd != 1:
        raise ValueError(f"No existe inverso modular para {a} mod {m}")
    
    return x % m
```

### Componentes Clave

- **`DSAKReuseAttack`**: Clase principal del ataque que implementa el ataque de reutilización de k
- **`get_public_key()`**: Recupera clave pública DSA del servidor
- **`sign_message()`**: Firma un mensaje usando DSA
- **`find_k_reuse()`**: Encuentra firmas que reutilizan el mismo valor k
- **`recover_k()`**: Recupera k de dos firmas con mismo k
- **`recover_private_key()`**: Recupera clave privada x usando k
- **`modular_inverse()`**: Calcula inverso modular usando algoritmo de Euclides extendido
- **`submit_answer()`**: Envía la clave privada recuperada al servidor

## Explicación Detallada del Ataque

### Proceso de Firma DSA

La generación de firma DSA involucra:
1. **k Aleatorio**: Elegir un valor aleatorio k (debe ser único para cada firma)
2. **Calcular r**: r = (g^k mod p) mod q
3. **Calcular s**: s = k^(-1) * (h + x*r) mod q
4. **Firma**: El par (r, s)

### Detección de Reutilización de k

Cuando el mismo k se usa para múltiples firmas:
- **Mismo r**: Los valores r serán idénticos
- **Diferente s**: Los valores s serán diferentes debido a diferentes hashes de mensaje
- **Patrón**: Buscar valores r idénticos en la recolección de firmas

### Recuperación Matemática

**Fórmula de Recuperación de k:**
```
k = (h₁ - h₂) * (s₁ - s₂)^(-1) mod q
```

**Fórmula de Recuperación de Clave Privada:**
```
x = (s*k - h) * r^(-1) mod q
```

### Complejidad del Ataque

- **Complejidad Temporal**: O(n) donde n es el número de firmas
- **Complejidad Espacial**: O(n) para almacenar firmas
- **Tasa de Éxito**: 100% cuando se encuentra reutilización de k
- **Conocimiento de Clave**: No requerido (el ataque funciona sin conocer valores k)

## Archivos

- **`dsa_k_reuse_attack.py`**: Implementación completa del ataque
- **`test_dsa_k_reuse.py`**: Suite de pruebas comprensiva
- **`README.md`**: Esta documentación

## Uso

```bash
# Ejecutar el ataque
python dsa_k_reuse_attack.py

# Ejecutar pruebas
python test_dsa_k_reuse.py
```

## Flujo de Ataque de Ejemplo

```python
# 1. Obtener clave pública
public_key = attack.get_public_key(email)
# Salida: {"P": ..., "Q": ..., "G": ..., "Y": ...}

# 2. Recolectar firmas
signatures = attack.collect_signatures(email, messages, 20)
# Salida: Lista de firmas con valores r y s

# 3. Encontrar reutilización de k
reuse_indices = attack.find_k_reuse(signatures)
# Salida: [0, 5] (índices donde los valores r son idénticos)

# 4. Recuperar k
k = attack.recover_k(msg1, msg2, s1, s2, q)
# Salida: 123456789 (valor k recuperado)

# 5. Recuperar clave privada
private_key = attack.recover_private_key(msg1, r1, s1, k, q)
# Salida: 987654321 (clave privada x recuperada)

# 6. Enviar respuesta
result = attack.submit_answer(email, private_key)
# Salida: "¡Ganaste!"
```

## Valor Educativo

Este desafío demuestra:

1. **Vulnerabilidades DSA**: Por qué la reutilización de k es catastrófica para DSA
2. **Generación de Números Aleatorios**: Importancia de la aleatoriedad criptográficamente segura
3. **Criptoanálisis Matemático**: Usar teoría de números para romper firmas
4. **Análisis de Firmas**: Cómo detectar y explotar debilidades en firmas
5. **Recuperación de Clave Privada**: Cómo recuperar claves privadas de información pública
6. **Seguridad de Firmas Digitales**: Entender requisitos de implementación DSA

## Implicaciones de Seguridad

### Por Qué la Reutilización de k es Peligrosa

1. **Compromiso Completo**: Se puede recuperar la clave privada
2. **Falsificación de Firmas**: Se pueden falsificar firmas para cualquier mensaje
3. **Robo de Identidad**: Se puede suplantar al firmante
4. **Sin Detección**: El ataque es indetectable sin análisis de firmas

### Ejemplos del Mundo Real

1. **Sony PlayStation 3**: Usó el mismo k para todas las firmas
2. **Billeteras Bitcoin**: Algunas implementaciones tenían vulnerabilidades de reutilización de k
3. **Tarjetas Inteligentes**: Fallas en generadores de números aleatorios de hardware
4. **Sistemas Embebidos**: Entropía insuficiente en generación de números aleatorios

### Defensas Contra Ataques de Reutilización de k

1. **Aleatorio Criptográficamente Seguro**: Usar generadores de números aleatorios apropiados
2. **Unicidad de k**: Asegurar que cada k sea único e impredecible
3. **Fuentes de Entropía**: Usar múltiples fuentes de entropía para aleatoriedad
4. **Seguridad de Hardware**: Usar generadores de números aleatorios de hardware
5. **Análisis de Firmas**: Monitorear firmas para patrones de reutilización de k

## Variaciones Avanzadas del Ataque

### Múltiple Reutilización de k

Manejar casos con múltiples patrones de reutilización de k:
```python
def find_all_k_reuse(self, signatures):
    # Encontrar todos los patrones de reutilización de k
    # Manejar múltiples grupos de valores k reutilizados
    pass
```

### Análisis Estadístico

Usar métodos estadísticos para detectar reutilización de k:
```python
def statistical_k_detection(self, signatures):
    # Usar análisis estadístico para detectar reutilización de k
    # Incluso cuando los valores r no son idénticos
    pass
```

### Inyección de Fallas

Explotar inyección de fallas para causar reutilización de k:
```python
def fault_injection_attack(self, target_system):
    # Inyectar fallas para causar reutilización de k
    # Explotar vulnerabilidades de hardware
    pass
```

## Errores Comunes

1. **Firmas Insuficientes**: Puede necesitar muchas firmas para encontrar reutilización de k
2. **Aritmética Modular**: Debe manejar aritmética modular correctamente
3. **Cálculo de Hash**: Debe usar la misma función de hash que el servidor
4. **Codificación Base64**: Debe manejar codificación de mensajes correctamente

## Referencias

- [DSA Wikipedia](https://en.wikipedia.org/wiki/Digital_Signature_Algorithm)
- [Seguridad DSA](https://en.wikipedia.org/wiki/Digital_Signature_Algorithm#Security)
- [Ataque de Reutilización de k](https://en.wikipedia.org/wiki/Digital_Signature_Algorithm#k-reuse_attack)
- [Ataque Sony PlayStation 3](https://www.zdnet.com/article/sony-playstation-3-hacked-due-to-epic-cryptographic-fail/)

## Advertencia

Esta es una demostración educativa de vulnerabilidades criptográficas. Siempre use generadores de números aleatorios criptográficamente seguros para valores k de DSA en sistemas de producción. La reutilización de k compromete completamente la seguridad de DSA y nunca debe ocurrir en sistemas implementados correctamente.
