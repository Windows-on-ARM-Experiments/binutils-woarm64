#source: ifunc-25-x86.s
#ld: -shared
#readelf: -r --wide
#target: x86_64-*-* i?86-*-*

Relocation section '.rel(a|).dyn' at offset 0x[0-9a-f]+ contains 1 entry:
 +Offset +Info +Type +Sym.* Value +Symbol's Name.*
[0-9a-f]+[ ]+[0-9a-f]+[ ]+R_(386|X86_64)_(32|64) +foo\(\) +foo( \+ 0|)

Relocation section '.rel(a|).plt' at offset 0x[0-9a-f]+ contains 1 entry:
 +Offset +Info +Type +Sym.* Value +Symbol's Name.*
[0-9a-f]+[ ]+[0-9a-f]+[ ]+R_(386|X86_64)_JUMP_SLOT +foo\(\) +foo( \+ [0-9a-f]+|)
