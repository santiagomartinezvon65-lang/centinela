# Centinela — tareas comunes (sin dependencias)
.PHONY: test serve gui help scan pentest clean

test:        ## Corre la suite de tests
	python -m unittest discover -s tests -v

serve:       ## Levanta el dashboard web
	python cli.py serve

gui:         ## Abre la app de escritorio
	python cli.py gui

help:        ## Lista todos los comandos del CLI
	python cli.py --help

# Uso: make scan URL=https://misitio.com
scan:
	python cli.py scan $(URL) --authorized

pentest:
	python cli.py pentest $(URL) --authorized

clean:       ## Borra caches de Python
	python -c "import shutil,pathlib; [shutil.rmtree(p) for p in pathlib.Path('.').rglob('__pycache__')]"
