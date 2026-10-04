# SecureMailScope - common tasks
PY := python3

all: console report

verify:                       ## re-check every claim in the README against the captures
	$(PY) verify.py

bench:                        ## regenerate the corpus and the benchmark
	$(PY) -m mailscope.engine

report:                       ## rebuild report/report.html + report.json + report.pdf
	$(PY) -m mailscope.report

console:                      ## rebuild the console (one self-contained file, ten pages)
	$(PY) -m mailscope.console

ledger:                       ## re-verify the published evidence chain
	$(PY) -m mailscope.ledger --ledger results/ledger.json

live:                         ## grade real public MTAs -> data/live/ + results/live_validation.json
	$(PY) -m mailscope.live

analyze:                      ## grade your own capture: make analyze PCAP=your.pcap
	$(PY) -m mailscope.analyze $(PCAP)

clean:
	find . -name '__pycache__' -type d -exec rm -rf {} +
