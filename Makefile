
## 2.3 `Makefile`
```make
.PHONY: install run test fmt

install:
	python -m venv .venv && . .venv/bin/activate && pip install -e .

run:
	. .venv/bin/activate && sentry --help

test:
	. .venv/bin/activate && python -m pytest -q

fmt:
	@echo "Usa tu formateador preferido (opcional)."

