# Rate Limiting por Fingerprint

## Descripción

El nuevo tipo de rate limiting `per_fingerprint` permite aplicar límites de velocidad basados en el fingerprint único del dispositivo/navegador del usuario. Esto proporciona una identificación más granular y robusta que los métodos tradicionales como IP o User-Agent.

## Características

- **Identificación única**: Combina UserID, Token, IP y UserAgent en un identificador único
- **Protección contra evasión**: Más difícil de evadir que los límites por IP
- **Granularidad**: Permite límites más específicos por dispositivo/navegador
- **Integración**: Funciona con el middleware de fingerprinting existente

## Configuración

```json
{
  "name": "rate_limiter",
  "enabled": true,
  "stage": "pre_request",
  "priority": 1,
  "settings": {
    "limits": {
      "per_fingerprint": {
        "limit": 10,
        "window": "1m"
      },
      "per_ip": {
        "limit": 50,
        "window": "1m"
      },
      "per_user": {
        "limit": 100,
        "window": "1m"
      },
      "global": {
        "limit": 1000,
        "window": "1m"
      }
    },
    "actions": {
      "type": "reject",
      "retry_after": "60"
    }
  }
}
```

## Orden de Verificación

Los límites se verifican en el siguiente orden (de más específico a más general):

1. **per_fingerprint**: Límite por fingerprint único
2. **per_ip**: Límite por dirección IP
3. **per_user**: Límite por usuario autenticado
4. **global**: Límite global

## Requisitos

- El middleware de fingerprinting debe estar activo
- El fingerprint se genera automáticamente para cada request
- Compatible con todos los tipos de rate limiting existentes

## Casos de Uso

### Protección contra abuso
```json
{
  "per_fingerprint": {
    "limit": 5,
    "window": "1m"
  }
}
```

### Límites graduales
```json
{
  "per_fingerprint": {
    "limit": 10,
    "window": "1m"
  },
  "per_ip": {
    "limit": 50,
    "window": "1m"
  },
  "global": {
    "limit": 1000,
    "window": "1m"
  }
}
```

### Usuarios anónimos
Para usuarios no autenticados, `per_fingerprint` proporciona una alternativa más robusta que `per_user`:

```json
{
  "per_fingerprint": {
    "limit": 20,
    "window": "1h"
  },
  "per_user": {
    "limit": 100,
    "window": "1h"
  }
}
```

## Headers de Respuesta

El plugin añade headers informativos a las respuestas:

```
X-RateLimit-per_fingerprint-Limit: 10
X-RateLimit-per_fingerprint-Remaining: 7
X-RateLimit-per_fingerprint-Reset: 1640995200
```

## Consideraciones

- **Dependencia**: Requiere que el middleware de fingerprinting esté configurado
- **Performance**: Los fingerprints son strings base64, pero el impacto es mínimo
- **Fallback**: Si no hay fingerprint disponible, se usa "unknown" como clave
- **Compatibilidad**: Funciona junto con todos los otros tipos de rate limiting
