# Contribuir a Centinela

¡Gracias por tu interés! Centinela es un proyecto de aprendizaje abierto a mejoras.

## Cómo contribuir

1. Hacé un fork y creá una rama (`git checkout -b mejora/mi-feature`).
2. Asegurate de que los tests pasen: `python -m unittest discover -s tests`.
3. Si agregás una capacidad, sumá su test correspondiente.
4. Abrí un Pull Request describiendo el cambio.

## Agregar un chequeo nuevo (sin tocar código)

La forma más fácil de sumar detección es con el **motor de plantillas**: creá un archivo
`templates/mi-chequeo.json`. Ejemplo:

```json
{
  "id": "mi-chequeo",
  "info": { "name": "Descripción", "severity": "medium", "category": "disclosure",
            "remediation": "Cómo arreglarlo." },
  "requests": [{
    "method": "GET", "path": "/ruta-sensible",
    "matchers_condition": "and",
    "matchers": [
      { "type": "status", "status": [200] },
      { "type": "word", "part": "body", "words": ["firma-distintiva"] }
    ]
  }]
}
```

## Principios del proyecto

- **Cero dependencias externas** — todo con la librería estándar de Python.
- **Detección no destructiva** — solo se detecta y valida, nunca se daña el objetivo.
- **Uso ético** — mantené el gate de autorización.
- **Código testeable** — el núcleo (`core/`) es lógica pura; las interfaces son finas.
