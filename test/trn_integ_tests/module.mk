
.PHONY: run_integ_test
run_integ_test:
	sudo python3 -W ignore -m unittest test.trn_integ_tests.${TEST}

clean::
	rm -rf test/trn_perf_tests/__pycache__
	rm -rf test/trn_perf_tests/*.pyc
