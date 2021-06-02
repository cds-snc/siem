.PHONY: fmt siem

fmt:
	terraform fmt -recursive aws

siem:
	cd terragrunt/siem &&\
	terragrunt run-all apply
