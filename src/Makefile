#
all: clean e v c k

e:
	gcc -O0 -g3 elfenstein.c -o elfenstein -lcapstone

v:
	gcc -O0 -g3 -no-pie virus.c -o virus

c:
	gcc -O0 -g3 test_capstone.c -o cs_disas -lcapstone 

k:
	gcc -O0 -g3 test_keystone.c parse.c -o ks_assem -lkeystone 

#
clean:
	rm -Rf *~ elfenstein virus encode cs_disas ks_assem
