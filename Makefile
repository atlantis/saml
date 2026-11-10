CRYSTAL_FLAGS := -Duse_pcre2 -Dwithout_mt

.PHONY: spec check

spec:
	mkdir -p bin
	crystal build $(CRYSTAL_FLAGS) spec/*_test.cr -o bin/spec
	./bin/spec

check:
	crystal tool format --check src spec
