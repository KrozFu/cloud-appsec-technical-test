# Diagramas como código

Los diagramas de arquitectura del Reto 1 se generan desde [`architecture.py`](./architecture.py) con la librería [`diagrams`](https://diagrams.mingrammer.com/), que empaqueta los iconos oficiales de AWS Architecture Icons.

El diagrama es código versionado, no una imagen suelta: se revisa en un *pull request* como cualquier otro cambio, y no puede quedar desincronizado sin que se vea en el diff.

## Regenerar

```bash
uv run architecture.py
```

`uv` resuelve la dependencia a partir de los metadatos inline (PEP 723) del propio script, sin entorno virtual que gestionar a mano.

### Prerrequisito

El binario de Graphviz, que `diagrams` usa como motor de dibujo:

```bash
sudo pacman -S graphviz      # Arch / CachyOS
sudo apt install graphviz    # Debian / Ubuntu
brew install graphviz        # macOS
```

## Salida

Se escribe en [`out/`](./out) y se commitea, para que los documentos rendericen en GitHub y en Obsidian sin que nadie tenga que ejecutar nada:

| Fichero | Dónde se usa |
| --- | --- |
| `architecture.png` / `.svg` | [`../README.md`](../README.md) §2.1 — flujo de datos y zonas de confianza |
| `cross-cutting.png` / `.svg` | [`../README.md`](../README.md) §2.2 — CI/CD, cifrado y detección |

Las etiquetas numeradas ①-⑥ de las aristas se corresponden una a una con los límites de confianza del DFD de [`../threat-model.md`](../threat-model.md), para poder leer ambos documentos cruzados.

## Por qué el DFD del threat model sigue en Mermaid

Un DFD de límites de confianza es convencionalmente abstracto: lo que comunica son las fronteras y la dirección de los flujos, no qué servicio gestionado concreto implementa cada caja. Además, al ser Mermaid renderiza inline en GitHub y en Obsidian, y se edita en el propio markdown sin regenerar nada.

Los iconos de AWS aportan donde importa —el diagrama de arquitectura, que es el entregable— y no donde estorban.

## Iconos

Los iconos son los [AWS Architecture Icons](https://aws.amazon.com/architecture/icons/) oficiales, distribuidos dentro del paquete `diagrams` (licencia MIT) y sujetos a los términos de uso de AWS.
