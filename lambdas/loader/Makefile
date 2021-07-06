default: 
	python3 lambda_function.py

fmt:
	black . $(ARGS)

install:
	pip3 install --user -r requirements.txt

lint:
	# pylint index.py
	echo "Skipping lint"

test:
	python -m pytest -s -vv tests

.PHONY: \
	fmt \
	install	\
	lint \
	test