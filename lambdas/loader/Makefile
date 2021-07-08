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
	coverage run -m pytest -s -vv tests &&\
	coverage report -m

.PHONY: \
	fmt \
	install	\
	lint \
	test