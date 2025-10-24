# Ataque de Falsificación ECB

## Descripción General

Este desafío demuestra la vulnerabilidad del cifrado AES en modo ECB (Electronic Codebook) debido a su maleabilidad. El ataque explota el hecho de que el modo ECB cifra cada bloque independientemente, permitiendo a los atacantes intercambiar, duplicar o reorganizar bloques para falsificar mensajes.

## Descripción del Desafío

El servidor permite a los usuarios registrarse con una dirección de correo electrónico y devuelve un perfil en el formato:
```
user=<email>&id=<id>&role=user
```

El desafío es falsificar un mensaje cifrado que, al descifrarse, contenga `role=admin` en lugar de `role=user`.

## Análisis de la Vulnerabilidad

### Debilidad del Modo ECB

El modo ECB tiene una falla fundamental: **los bloques de texto plano idénticos producen bloques de texto cifrado idénticos**. Esto lo hace vulnerable a:

1. **Reconocimiento de Patrones**: Los patrones repetidos en el texto plano son visibles en el texto cifrado
2. **Manipulación de Bloques**: Los bloques pueden ser intercambiados, duplicados o reorganizados
3. **Falsificación de Mensajes**: Se pueden construir nuevos mensajes combinando bloques de diferentes mensajes cifrados

### Estrategia del Ataque

1. **Encontrar Bloque Admin**: Crear un email que genere un bloque conteniendo `role=admin`
2. **Obtener Perfil Objetivo**: Obtener el perfil cifrado del usuario objetivo
3. **Sustitución de Bloques**: Reemplazar el último bloque del perfil objetivo con el bloque admin
4. **Enviar Mensaje Falsificado**: Enviar el mensaje cifrado modificado al servidor

## Implementación

### Componentes Clave

- **`ECBForgeAttack`**: Clase principal del ataque que implementa la falsificación
- **`get_profile()`**: Recupera perfiles de usuario del servidor
- **`find_admin_block_email()`**: Descubre emails que generan bloques admin
- **`forge_message()`**: Construye el mensaje cifrado falsificado
- **`submit_answer()`**: Envía el mensaje falsificado al servidor

### Proceso del Ataque

```python
# 1. Encontrar email que genere bloque admin
admin_email, admin_block_index = attack.find_admin_block_email(challenge_email)

# 2. Obtener perfil objetivo (cifrado)
target_encrypted = attack.get_profile(challenge_email, target_email, encrypted=True)

# 3. Obtener perfil admin (cifrado)
admin_encrypted = attack.get_profile(challenge_email, admin_email, encrypted=True)

# 4. Dividir en bloques
target_blocks = split_into_blocks(base64.b64decode(target_encrypted))
admin_blocks = split_into_blocks(base64.b64decode(admin_encrypted))

# 5. Falsificar mensaje reemplazando último bloque
forged_blocks = target_blocks[:-1] + [admin_blocks[admin_block_index]]

# 6. Reconstruir y enviar
forged_message = base64.b64encode(b''.join(forged_blocks))
result = attack.submit_answer(challenge_email, forged_message)
```

## Detalles Técnicos

### Tamaño de Bloque y Alineación

- **Tamaño de Bloque AES**: 128 bits (16 bytes)
- **Relleno**: Se aplica relleno PKCS7
- **Alineación**: La longitud del email debe elegirse cuidadosamente para alinear `role=admin` en los límites de bloque

### Cálculo de Longitud de Email

Para crear un bloque que contenga `role=admin`, necesitamos calcular la longitud del email que posicione esta cadena al inicio de un bloque:

```
user=<email>&id=<id>&role=admin
```

La longitud del email determina dónde aparece `role=admin` en la estructura de bloques.

### Relleno PKCS7

El servidor usa relleno PKCS7:
- Añade 1-16 bytes para hacer que la longitud del mensaje sea múltiplo de 16
- Cada byte de relleno contiene la longitud del relleno
- Debe ser válido cuando el mensaje se descifra

## Archivos

- **`ecb_forge_attack.py`**: Implementación completa del ataque
- **`test_ecb_forge.py`**: Casos de prueba y validación
- **`README.md`**: Esta documentación

## Uso

```bash
# Ejecutar el ataque
python ecb_forge_attack.py

# Ejecutar pruebas
python test_ecb_forge.py
```

## Valor Educativo

Este desafío demuestra:

1. **Por qué el modo ECB es inseguro**: La independencia de bloques permite manipulación
2. **Vulnerabilidades de cifrado por bloques**: Cómo los bloques idénticos crean problemas de seguridad
3. **Ataques de relleno**: Importancia de la validación adecuada del relleno
4. **Maleabilidad criptográfica**: Cómo el cifrado puede modificarse sin descifrado
5. **Criptoanálisis práctico**: Aplicación del mundo real de vulnerabilidades teóricas

## Implicaciones de Seguridad

- **Nunca usar modo ECB** para cifrar múltiples bloques de datos
- **Usar cifrado autenticado** (AES-GCM, ChaCha20-Poly1305)
- **Implementar validación adecuada del relleno**
- **Usar IVs aleatorios** para modo CBC
- **Considerar autenticación de mensajes** para todas las comunicaciones cifradas

## Referencias

- [Modo ECB Wikipedia](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#ECB)
- [Ataques Oracle de Relleno](https://en.wikipedia.org/wiki/Padding_oracle_attack)
- [Maleabilidad Criptográfica](https://en.wikipedia.org/wiki/Malleability_(cryptography))

## Advertencia

Esta es una demostración educativa. Siempre use bibliotecas criptográficas establecidas y modos de operación seguros en sistemas de producción.
