# Ataque de Broadcast sobre RSA

## Descripción General

Este desafío demuestra una vulnerabilidad fundamental en RSA cuando el mismo mensaje se cifra con múltiples claves públicas usando exponente pequeño (e=3). El ataque explota el Teorema Chino del Resto para recuperar el texto plano sin conocer ninguna clave privada.

## Descripción del Desafío

El servidor implementa cifrado RSA con exponente pequeño:
1. Proporciona múltiples textos cifrados del mismo mensaje cifrado con diferentes claves públicas
2. Usa RSA con exponente e=3 (exponente pequeño)
3. Usa RSA de libro de texto (sin relleno)
4. Requiere recuperar el texto plano original

**Cifrado RSA:**
```
c = m^e mod n
```

**Objetivo del Desafío:**
Recuperar el mensaje de texto plano a partir de múltiples textos cifrados cifrados con diferentes claves públicas.

## Análisis de la Vulnerabilidad

### Vulnerabilidad de Exponente Pequeño

RSA con exponente pequeño (e=3) es vulnerable a ataques de broadcast:

1. **Mismo Mensaje**: Múltiples cifrados del mismo mensaje
2. **Exponente Pequeño**: El exponente e=3 hace el ataque factible
3. **Sin Relleno**: RSA de libro de texto sin relleno
4. **Teorema Chino del Resto**: Herramienta matemática para el ataque

### Fundamento Matemático

**Teorema Chino del Resto:**
Si tenemos un sistema de congruencias:
```
x ≡ a₁ (mod n₁)
x ≡ a₂ (mod n₂)
x ≡ a₃ (mod n₃)
```

Donde n₁, n₂, n₃ son coprimos dos a dos, entonces existe una solución única x módulo n₁n₂n₃.

**Aplicación a RSA:**
Si el mismo mensaje m se cifra con tres claves públicas diferentes (n₁,3), (n₂,3), (n₃,3):
```
c₁ ≡ m³ (mod n₁)
c₂ ≡ m³ (mod n₂)
c₃ ≡ m³ (mod n₃)
```

Podemos usar CRT para encontrar m³, luego tomar la raíz cúbica para obtener m.

### Proceso del Ataque

1. **Recolectar Textos Cifrados**: Obtener múltiples textos cifrados del mismo mensaje
2. **Extraer Módulos**: Extraer los módulos RSA de las claves públicas
3. **Aplicar CRT**: Usar el Teorema Chino del Resto para encontrar m³
4. **Calcular Raíz Cúbica**: Tomar raíz cúbica para recuperar m
5. **Convertir a Texto**: Convertir entero de vuelta a texto plano

## Implementación Técnica

### Estrategia del Ataque

1. **Recolección de Datos**: Recolectar múltiples textos cifrados del servidor
2. **Análisis**: Analizar respuestas JSON para extraer textos cifrados y módulos
3. **Teorema Chino del Resto**: Resolver sistema de congruencias
4. **Raíz Cúbica**: Calcular raíz cúbica entera
5. **Recuperación de Texto**: Convertir entero recuperado a texto plano

### Proceso del Ataque

#### Paso 1: Recolectar Textos Cifrados
```python
def collect_ciphertexts(self, email: str, count: int = 3):
    ciphertexts = []
    moduli = []
    
    for i in range(count):
        data = self.get_challenge_data(email)
        ciphertext_bytes, n, e = self.parse_challenge_data(data)
        
        ciphertexts.append(ciphertext_bytes)
        moduli.append(n)
    
    return ciphertexts, moduli
```

#### Paso 2: Analizar Datos del Desafío
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

#### Paso 3: Teorema Chino del Resto
```python
def chinese_remainder_theorem(self, remainders: List[int], moduli: List[int]):
    # Calcular producto de todos los módulos
    N = 1
    for modulus in moduli:
        N *= modulus
    
    # Calcular solución usando fórmula CRT
    result = 0
    for i in range(len(remainders)):
        # Calcular Ni = N / ni
        Ni = N // moduli[i]
        
        # Calcular Mi = Ni^(-1) mod ni
        Mi = self.modular_inverse(Ni, moduli[i])
        
        # Añadir al resultado
        result += remainders[i] * Ni * Mi
    
    return result % N
```

#### Paso 4: Inverso Modular
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

#### Paso 5: Cálculo de Raíz Cúbica
```python
def cube_root(self, n: int):
    # Usar método de Newton para raíz cúbica
    x = n
    for _ in range(100):  # Iteraciones de precisión
        x = (2 * x + n // (x * x)) // 3
    
    return x
```

#### Paso 6: Realizar Ataque de Broadcast
```python
def perform_broadcast_attack(self, ciphertexts: List[bytes], moduli: List[int]):
    # Convertir textos cifrados a enteros
    ciphertext_ints = []
    for ciphertext in ciphertexts:
        ciphertext_int = bytes_to_long(ciphertext)
        ciphertext_ints.append(ciphertext_int)
    
    # Aplicar Teorema Chino del Resto
    m_cubed = self.chinese_remainder_theorem(ciphertext_ints, moduli)
    
    # Calcular raíz cúbica para obtener m
    m = self.cube_root(m_cubed)
    
    # Convertir de vuelta a bytes y luego a string
    plaintext_bytes = long_to_bytes(m)
    plaintext = plaintext_bytes.decode('utf-8')
    
    return plaintext
```

### Componentes Clave

- **`RSABroadcastAttack`**: Clase principal del ataque que implementa el ataque de broadcast
- **`get_challenge_data()`**: Recupera datos del desafío del servidor
- **`parse_challenge_data()`**: Analiza respuesta JSON para extraer texto cifrado y clave pública
- **`chinese_remainder_theorem()`**: Implementa CRT para resolver sistema de congruencias
- **`modular_inverse()`**: Calcula inverso modular usando algoritmo de Euclides extendido
- **`cube_root()`**: Calcula raíz cúbica entera usando método de Newton
- **`perform_broadcast_attack()`**: Orquesta el ataque completo
- **`submit_answer()`**: Envía el texto plano recuperado al servidor

## Explicación Detallada del Ataque

### Teorema Chino del Resto

El Teorema Chino del Resto establece que si tenemos un sistema de congruencias:
```
x ≡ a₁ (mod n₁)
x ≡ a₂ (mod n₂)
x ≡ a₃ (mod n₃)
```

Donde n₁, n₂, n₃ son coprimos dos a dos, entonces existe una solución única x módulo n₁n₂n₃.

**Fórmula de Solución:**
```
x = Σ(aᵢ × Nᵢ × Mᵢ) mod N
```

Donde:
- N = n₁ × n₂ × n₃
- Nᵢ = N / nᵢ
- Mᵢ = Nᵢ^(-1) mod nᵢ

### Ataque de Broadcast RSA

Cuando el mismo mensaje m se cifra con tres claves públicas diferentes (n₁,3), (n₂,3), (n₃,3):
```
c₁ ≡ m³ (mod n₁)
c₂ ≡ m³ (mod n₂)
c₃ ≡ m³ (mod n₃)
```

Podemos usar CRT para encontrar m³, luego tomar la raíz cúbica para obtener m.

**Por Qué Funciona:**
1. **Exponente Pequeño**: e=3 hace m³ manejable
2. **Sin Relleno**: RSA de libro de texto sin relleno
3. **Mismo Mensaje**: Múltiples cifrados del mismo mensaje
4. **Coprimos Dos a Dos**: Los módulos RSA son típicamente coprimos dos a dos

### Cálculo de Raíz Cúbica

Como necesitamos encontrar m a partir de m³, necesitamos calcular la raíz cúbica:
```
m = ∛(m³)
```

Para enteros grandes, usamos el método de Newton:
```
x_{n+1} = (2x_n + m³/x_n²) / 3
```

## Complejidad del Ataque

- **Complejidad Temporal**: O(k³) donde k es el número de textos cifrados
- **Complejidad Espacial**: O(k) para almacenar textos cifrados y módulos
- **Tasa de Éxito**: 100% (ataque determinístico)
- **Conocimiento de Clave**: No requerido (el ataque funciona sin claves privadas)

## Archivos

- **`rsa_broadcast_attack.py`**: Implementación completa del ataque
- **`test_rsa_broadcast.py`**: Suite de pruebas comprensiva
- **`README.md`**: Esta documentación

## Uso

```bash
# Ejecutar el ataque
python rsa_broadcast_attack.py

# Ejecutar pruebas
python test_rsa_broadcast.py
```

## Flujo de Ataque de Ejemplo

```python
# 1. Recolectar textos cifrados
ciphertexts, moduli = attack.collect_ciphertexts(email, 3)
# Salida: 3 textos cifrados y 3 módulos

# 2. Realizar ataque de broadcast
plaintext = attack.perform_broadcast_attack(ciphertexts, moduli)
# Salida: "Professional wrestling: ballet for the common man."

# 3. Enviar respuesta
result = attack.submit_answer(email, plaintext)
# Salida: "¡Ganaste!"
```

## Valor Educativo

Este desafío demuestra:

1. **Vulnerabilidades RSA**: Por qué los exponentes pequeños son peligrosos
2. **Teorema Chino del Resto**: Herramienta matemática para resolver congruencias
3. **Ataques de Broadcast**: Cómo explotar múltiples cifrados
4. **Debilidades RSA de Libro de Texto**: Por qué el relleno es esencial
5. **Criptoanálisis Matemático**: Usar teoría de números para romper criptografía
6. **Aritmética Entera**: Trabajar con enteros grandes en Python

## Implicaciones de Seguridad

### Por Qué los Ataques de Broadcast son Peligrosos

1. **Sin Clave Privada Requerida**: El ataque funciona sin conocer ninguna clave privada
2. **Determinístico**: Siempre tiene éxito con suficientes textos cifrados
3. **Eficiente**: Complejidad temporal polinomial
4. **Práctico**: Se puede implementar fácilmente

### Ejemplos del Mundo Real

1. **RSA de Exponente Pequeño**: Sistemas usando e=3 para eficiencia
2. **RSA de Libro de Texto**: Sistemas sin relleno adecuado
3. **Sistemas de Broadcast**: Sistemas que cifran el mismo mensaje múltiples veces
4. **Sistemas Legacy**: Sistemas antiguos que no han sido actualizados

### Defensas Contra Ataques de Broadcast

1. **Usar Exponentes Más Grandes**: Usar e=65537 en lugar de e=3
2. **Usar Relleno Adecuado**: Usar relleno OAEP o PKCS#1 v1.5
3. **Usar Relleno Aleatorio**: Añadir datos aleatorios a cada cifrado
4. **Usar Mensajes Diferentes**: Nunca cifrar el mismo mensaje múltiples veces
5. **Usar Cifrado Híbrido**: Usar RSA solo para intercambio de claves

## Variaciones Avanzadas del Ataque

### Múltiples Textos Cifrados

El ataque se puede extender para usar más de 3 textos cifrados:
```python
def extended_broadcast_attack(self, ciphertexts: List[bytes], moduli: List[int]):
    # Usar más textos cifrados para mejor precisión
    # Especialmente útil para raíces cúbicas no perfectas
    pass
```

### Diferentes Exponentes

El ataque se puede adaptar para diferentes exponentes pequeños:
```python
def generalized_broadcast_attack(self, ciphertexts: List[bytes], moduli: List[int], exponent: int):
    # Generalizar para cualquier exponente pequeño
    # Usar raíz n-ésima en lugar de raíz cúbica
    pass
```

### Manejo de Errores

Manejo robusto de errores para escenarios del mundo real:
```python
def robust_broadcast_attack(self, ciphertexts: List[bytes], moduli: List[int]):
    # Manejar raíces no perfectas
    # Manejar errores de decodificación
    # Manejar textos cifrados inválidos
    pass
```

## Errores Comunes

1. **Raíces Cúbicas No Perfectas**: Puede necesitar manejar cubos no perfectos
2. **Errores de Decodificación**: Puede necesitar manejar secuencias UTF-8 inválidas
3. **Validación de Módulos**: Asegurar que los módulos sean coprimos dos a dos
4. **Problemas de Precisión**: Puede necesitar mayor precisión para el cálculo de raíz cúbica

## Referencias

- [Ataque de Broadcast RSA](https://en.wikipedia.org/wiki/Coppersmith%27s_attack#H%C3%A5stad%27s_broadcast_attack)
- [Teorema Chino del Resto](https://en.wikipedia.org/wiki/Chinese_remainder_theorem)
- [Criptosistema RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
- [Ataque de Exponente Pequeño](https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Small_private_exponent)

## Advertencia

Esta es una demostración educativa de vulnerabilidades criptográficas. Siempre use relleno adecuado (OAEP o PKCS#1 v1.5) y exponentes más grandes (e=65537) en sistemas RSA de producción. RSA de libro de texto nunca debe usarse ya que es vulnerable a múltiples ataques incluyendo ataques de broadcast.
