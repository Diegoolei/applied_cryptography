# Ataque RSA con Clave Pequeña

## Descripción General

Este desafío demuestra una vulnerabilidad crítica en RSA cuando se usan tamaños de clave pequeños (256 bits). El ataque explota el hecho de que los módulos pequeños pueden ser factorizados eficientemente, permitiendo la recuperación completa de la clave privada y el descifrado de cualquier texto cifrado.

## Descripción del Desafío

El servidor implementa cifrado RSA con un tamaño de clave pequeño:
1. Proporciona texto cifrado RSA cifrado con módulo de 256 bits
2. Usa relleno PKCS#1 v1.5
3. Usa exponente público estándar (e=65537)
4. Requiere recuperar el texto plano original

**Cifrado RSA:**
```
c = m^e mod n
```

**Objetivo del Desafío:**
Descifrar el texto cifrado factorizando el módulo pequeño y recuperando la clave privada.

## Análisis de la Vulnerabilidad

### Vulnerabilidad de Tamaño de Clave Pequeño

RSA con tamaños de clave pequeños es vulnerable a ataques de factorización:

1. **Módulo Pequeño**: El módulo de 256 bits puede ser factorizado eficientemente
2. **Factorización**: Una vez que n es factorizado, la clave privada puede ser calculada
3. **Compromiso Completo**: La clave privada permite el descifrado de cualquier texto cifrado
4. **PKCS#1 v1.5**: El relleno puede ser removido después del descifrado

### Fundamento Matemático

**Generación de Clave RSA:**
```
1. Elegir dos primos p, q
2. Calcular n = p * q
3. Calcular φ(n) = (p-1) * (q-1)
4. Elegir e tal que gcd(e, φ(n)) = 1
5. Calcular d tal que e * d ≡ 1 (mod φ(n))
```

**Ataque de Factorización:**
```
1. Factorizar n para encontrar p, q
2. Calcular φ(n) = (p-1) * (q-1)
3. Calcular d = e^(-1) mod φ(n)
4. Descifrar: m = c^d mod n
```

### Proceso del Ataque

1. **Extraer Módulo**: Obtener n de la clave pública
2. **Factorizar n**: Usar algoritmos de factorización para encontrar p, q
3. **Calcular Clave Privada**: Calcular d desde p, q, e
4. **Descifrar Texto Cifrado**: Usar clave privada para descifrar
5. **Remover Relleno**: Remover relleno PKCS#1 v1.5
6. **Enviar Respuesta**: Enviar texto plano descifrado al servidor

## Implementación Técnica

### Estrategia del Ataque

1. **Recolección de Datos**: Obtener texto cifrado y clave pública del servidor
2. **Factorización**: Usar múltiples algoritmos para factorizar n
3. **Recuperación de Clave**: Calcular clave privada desde factores
4. **Descifrado**: Descifrar texto cifrado usando clave privada
5. **Remoción de Relleno**: Remover relleno PKCS#1 v1.5
6. **Envío**: Enviar texto plano al servidor

### Proceso del Ataque

#### Paso 1: Analizar Datos del Desafío
```python
def parse_challenge_data(self, data: dict):
    # Decodificar texto cifrado base64
    ciphertext_b64 = data['ciphertext']
    ciphertext_bytes = base64.b64decode(ciphertext_b64)
    
    # Extraer componentes de clave pública
    public_key = data['publicKey']
    n = public_key['n']
    e = public_key['e']
    
    return ciphertext_bytes, n, e
```

#### Paso 2: Factorizar Módulo
```python
def factorize(self, n: int):
    # Probar diferentes métodos de factorización
    
    # 1. División por prueba para factores pequeños
    factor = self.trial_division(n)
    if factor:
        return factor, n // factor
    
    # 2. Algoritmo rho de Pollard
    factor = self.pollard_rho(n)
    if factor:
        return factor, n // factor
    
    # 3. Factorización de Fermat
    factors = self.fermat_factorization(n)
    if factors:
        return factors
    
    # 4. Fuerza bruta para números muy pequeños
    for i in range(3, int(math.sqrt(n)) + 1, 2):
        if n % i == 0:
            return i, n // i
    
    raise ValueError(f"No se pudo factorizar n = {n}")
```

#### Paso 3: División por Prueba
```python
def trial_division(self, n: int, limit: int = 1000000):
    # Probar primos pequeños
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]
    
    for p in small_primes:
        if n % p == 0:
            return p
    
    # Probar números impares hasta el límite
    for i in range(3, min(int(math.sqrt(n)) + 1, limit), 2):
        if n % i == 0:
            return i
    
    return None
```

#### Paso 4: Algoritmo Rho de Pollard
```python
def pollard_rho(self, n: int):
    if n % 2 == 0:
        return 2
    
    def f(x):
        return (x * x + 1) % n
    
    x = 2
    y = 2
    d = 1
    
    while d == 1:
        x = f(x)
        y = f(f(y))
        d = math.gcd(abs(x - y), n)
    
    if d == n:
        return None
    return d
```

#### Paso 5: Factorización de Fermat
```python
def fermat_factorization(self, n: int):
    a = int(math.ceil(math.sqrt(n)))
    b2 = a * a - n
    
    while b2 < 0 or int(math.sqrt(b2)) ** 2 != b2:
        a += 1
        b2 = a * a - n
        
        if a > n:
            return None
    
    b = int(math.sqrt(b2))
    p = a - b
    q = a + b
    
    if p * q == n and p > 1 and q > 1:
        return p, q
    
    return None
```

#### Paso 6: Calcular Clave Privada
```python
def calculate_private_key(self, p: int, q: int, e: int):
    # Calcular función totiente de Euler
    phi = (p - 1) * (q - 1)
    
    # Calcular clave privada d usando algoritmo de Euclides extendido
    d = self.modular_inverse(e, phi)
    
    return d
```

#### Paso 7: Descifrar y Remover Relleno
```python
def decrypt_rsa(self, ciphertext: bytes, n: int, d: int):
    # Convertir texto cifrado a entero
    c = bytes_to_long(ciphertext)
    
    # Descifrar: m = c^d mod n
    m = pow(c, d, n)
    
    # Convertir de vuelta a bytes
    plaintext_bytes = long_to_bytes(m)
    
    return plaintext_bytes

def remove_pkcs1_padding(self, padded_data: bytes):
    if len(padded_data) < 3:
        raise ValueError("Relleno PKCS#1 v1.5 inválido")
    
    if padded_data[0] != 0x00:
        raise ValueError("Relleno PKCS#1 v1.5 inválido")
    
    if padded_data[1] != 0x02:
        raise ValueError("Relleno PKCS#1 v1.5 inválido")
    
    # Encontrar byte separador (0x00)
    separator_index = None
    for i in range(2, len(padded_data)):
        if padded_data[i] == 0x00:
            separator_index = i
            break
    
    if separator_index is None:
        raise ValueError("Relleno PKCS#1 v1.5 inválido")
    
    # Extraer datos reales
    actual_data = padded_data[separator_index + 1:]
    
    return actual_data
```

### Componentes Clave

- **`RSASmallKeyAttack`**: Clase principal del ataque que implementa el ataque de clave pequeña
- **`get_challenge_data()`**: Recupera datos del desafío del servidor
- **`parse_challenge_data()`**: Analiza respuesta JSON para extraer texto cifrado y clave pública
- **`factorize()`**: Orquesta múltiples métodos de factorización
- **`trial_division()`**: Implementa factorización por división de prueba
- **`pollard_rho()`**: Implementa algoritmo rho de Pollard
- **`fermat_factorization()`**: Implementa método de factorización de Fermat
- **`calculate_private_key()`**: Calcula clave privada desde factores primos
- **`decrypt_rsa()`**: Descifra texto cifrado usando clave privada
- **`remove_pkcs1_padding()`**: Remueve relleno PKCS#1 v1.5
- **`submit_answer()`**: Envía el texto plano descifrado al servidor

## Explicación Detallada del Ataque

### Métodos de Factorización

**División por Prueba:**
- Probar primos pequeños y números impares hasta √n
- Eficiente para factores pequeños
- Complejidad temporal: O(√n)

**Algoritmo Rho de Pollard:**
- Usa algoritmo de detección de ciclos de Floyd
- Encuentra factores detectando ciclos en una secuencia
- Complejidad temporal: O(√p) donde p es el factor más pequeño

**Factorización de Fermat:**
- Explota la diferencia de cuadrados
- Efectivo cuando los factores están cerca de √n
- Complejidad temporal: O(√n)

### Relleno PKCS#1 v1.5

**Estructura del Relleno:**
```
00 || 02 || PS || 00 || D
```

Donde:
- `00`: Primer byte (siempre 0x00)
- `02`: Segundo byte (siempre 0x02)
- `PS`: Cadena de relleno (bytes aleatorios no cero)
- `00`: Byte separador
- `D`: Datos reales

**Proceso de Remoción:**
1. Verificar primeros dos bytes (0x00, 0x02)
2. Encontrar byte separador (0x00)
3. Extraer datos después del separador

### Complejidad del Ataque

- **Complejidad Temporal**: O(√n) para factorización
- **Complejidad Espacial**: O(1) para la mayoría de métodos
- **Tasa de Éxito**: 100% para módulos pequeños
- **Conocimiento de Clave**: No requerido (el ataque funciona solo con clave pública)

## Archivos

- **`rsa_small_attack.py`**: Implementación completa del ataque
- **`test_rsa_small.py`**: Suite de pruebas comprensiva
- **`README.md`**: Esta documentación

## Uso

```bash
# Ejecutar el ataque
python rsa_small_attack.py

# Ejecutar pruebas
python test_rsa_small.py
```

## Flujo de Ataque de Ejemplo

```python
# 1. Obtener datos del desafío
data = attack.get_challenge_data(email)
# Salida: {"ciphertext": "...", "publicKey": {"n": ..., "e": 65537}}

# 2. Analizar datos
ciphertext_bytes, n, e = attack.parse_challenge_data(data)
# Salida: bytes de texto cifrado, módulo n, exponente e

# 3. Factorizar módulo
p, q = attack.factorize(n)
# Salida: factores primos p y q

# 4. Calcular clave privada
d = attack.calculate_private_key(p, q, e)
# Salida: clave privada d

# 5. Descifrar texto cifrado
padded_plaintext = attack.decrypt_rsa(ciphertext_bytes, n, d)
# Salida: bytes de texto plano con relleno

# 6. Remover relleno
plaintext = attack.remove_pkcs1_padding(padded_plaintext)
# Salida: "Hello, World!"

# 7. Enviar respuesta
result = attack.submit_answer(email, plaintext)
# Salida: "¡Ganaste!"
```

## Valor Educativo

Este desafío demuestra:

1. **Vulnerabilidades RSA**: Por qué los tamaños de clave pequeños son peligrosos
2. **Algoritmos de Factorización**: Múltiples métodos para factorización de enteros
3. **Relleno PKCS#1 v1.5**: Entender y remover relleno
4. **Recuperación de Clave Privada**: Cómo recuperar claves privadas de información pública
5. **Criptoanálisis Matemático**: Usar teoría de números para romper criptografía
6. **Importancia del Tamaño de Clave**: Por qué son necesarios tamaños de clave más grandes

## Implicaciones de Seguridad

### Por Qué las Claves Pequeñas son Peligrosas

1. **Factibilidad de Factorización**: Los módulos pequeños pueden ser factorizados eficientemente
2. **Compromiso Completo**: La clave privada puede ser recuperada
3. **Capacidad de Descifrado**: Puede descifrar cualquier texto cifrado
4. **Falsificación de Firmas**: Puede falsificar firmas si se usa para firmar

### Ejemplos del Mundo Real

1. **Implementaciones RSA Tempranas**: Usaron tamaños de clave pequeños para rendimiento
2. **Sistemas Embebidos**: El poder computacional limitado llevó a claves pequeñas
3. **Sistemas Legacy**: Sistemas antiguos que no han sido actualizados
4. **Ejemplos Educativos**: Demostraciones usando claves pequeñas

### Defensas Contra Ataques de Clave Pequeña

1. **Usar Tamaños de Clave Grandes**: Usar al menos claves de 2048 bits (3072 bits recomendado)
2. **Actualizaciones Regulares de Clave**: Rotar claves regularmente
3. **Validación de Tamaño de Clave**: Validar tamaños mínimos de clave
4. **Estándares de Seguridad**: Seguir estándares de la industria para tamaños de clave
5. **Rendimiento vs Seguridad**: Equilibrar rendimiento con requisitos de seguridad

## Variaciones Avanzadas del Ataque

### Factorización Paralela

Usar múltiples procesos para factorización más rápida:
```python
def parallel_factorization(self, n: int):
    # Usar múltiples procesos para factorizar
    # Distribuir trabajo a través de núcleos de CPU
    pass
```

### Métodos de Factorización Avanzados

Implementar algoritmos más sofisticados:
```python
def advanced_factorization(self, n: int):
    # Implementar ECM, QS, o NFS
    # Para números más grandes
    pass
```

### Integración de Herramientas Automatizadas

Integrar con herramientas de factorización existentes:
```python
def external_factorization(self, n: int):
    # Usar herramientas como msieve, GMP-ECM, o CADO-NFS
    # Para factorización de calidad de producción
    pass
```

## Errores Comunes

1. **Métodos de Factorización Insuficientes**: Puede necesitar múltiples algoritmos
2. **Validación de Relleno**: Debe manejar relleno PKCS#1 v1.5 correctamente
3. **Desbordamiento de Entero**: Debe manejar enteros grandes correctamente
4. **Manejo de Errores**: Debe manejar fallas de factorización graciosamente

## Referencias

- [Criptosistema RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
- [Factorización de Enteros](https://en.wikipedia.org/wiki/Integer_factorization)
- [Algoritmo Rho de Pollard](https://en.wikipedia.org/wiki/Pollard%27s_rho_algorithm)
- [Método de Factorización de Fermat](https://en.wikipedia.org/wiki/Fermat%27s_factorization_method)
- [PKCS#1 v1.5](https://tools.ietf.org/html/rfc2313)

## Advertencia

Esta es una demostración educativa de vulnerabilidades criptográficas. Siempre use tamaños de clave grandes (al menos 2048 bits) para RSA en sistemas de producción. Los tamaños de clave pequeños hacen que RSA sea completamente inseguro y nunca deben usarse en aplicaciones del mundo real.
