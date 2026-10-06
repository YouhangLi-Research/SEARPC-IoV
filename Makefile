.PHONY: paper-check paper-results adjudication fsm-sensitivity brs-authorization doctor check vehicle-inputs role domain source-baselines vehicle-smoke vehicle content-risk message-evidence safety-coverage canonical shared7 audit-budget figures system-smoke system-full all all-full

doctor:
	python run.py doctor

check:
	python run.py check

vehicle-inputs:
	python run.py vehicle-inputs

role:
	python run.py role

domain:
	python run.py domain

source-baselines:
	python run.py source-baselines

vehicle-smoke:
	python run.py vehicle-smoke

vehicle:
	python run.py vehicle

content-risk:
	python run.py content-risk

message-evidence:
	python run.py message-evidence

safety-coverage:
	python run.py safety-coverage

canonical:
	python run.py canonical

shared7:
	python run.py shared7

audit-budget:
	python run.py audit-budget

figures:
	python run.py figures

system-smoke:
	python run.py system-smoke

system-full:
	python run.py system-full

all:
	python run.py all

all-full:
	python run.py all-full

paper-check:
	python run.py paper-check

paper-results:
	python run.py paper-results

adjudication:
	python run.py adjudication

fsm-sensitivity:
	python run.py fsm-sensitivity

brs-authorization:
	python run.py brs-authorization

