all: build

build: my_av

my_av: my_av.c url_check.c traffic_check.c file_manager.c
	gcc -g $^ -o my_av -lm -DVARIATION

my_av_var: my_av.c
	gcc -o my_av my_av.c -lm

run:
	./my_av

pack:
	zip -9 -FSr 312CA_BaldovinRazvan_AV.zip *.c *.h my_av.py Makefile README

valorant:
	valgrind --leak-check=full --track-origins=yes -s --show-leak-kinds=all ./my_av

debug:
	gdb my_av

clean:
	rm -f my_av
