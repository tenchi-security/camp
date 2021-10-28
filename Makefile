update:
	camp/camp.py

venv: clean-venv
	virtualenv --python=python3 venv

clean-venv:
	rm -rf venv

install: venv
	venv/bin/python3 -m pip install -r requirements.txt
