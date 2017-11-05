EXES= test1 test2 test3 test4 test5 test6
all: $(EXES)

test%: test%.c
	gcc -g -O2 -std=gnu99 $^ -o $@

check: $(EXES)
	./test1
	./test2
	./test3
	./test4
	./test5
	./test6

clean: 
	rm -f $(EXES)
