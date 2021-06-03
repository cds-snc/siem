default: 
	python3 lambda_function.py

fmt:
	black . $(ARGS)

install:
	pip3 install --user -r requirements.txt

lint:
	pylint lambda_function.py

test:
	python -m pytest -s -vv tests

.PHONY: \
	fmt \
	install	\
	lint \
	test