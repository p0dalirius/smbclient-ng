.PHONY : all clean build upload

all: install clean

clean:
	@rm -rf `find ./ -type d -name "*__pycache__"`
	@rm -rf ./build/ ./dist/ ./smbclientng.egg-info/ ./.venv/

docs:
	@python3 -m pip install pdoc
	@echo "[$(shell date)] Generating docs ..."
	@PDOC_ALLOW_EXEC=1 python3 -m pdoc -d markdown -o ./documentation/ ./smbclientng/
	@echo "[$(shell date)] Done!"

install: build
	poetry install

build:
	poetry build

dist: clean build
	poetry build

upload: dist
	poetry publish --build
