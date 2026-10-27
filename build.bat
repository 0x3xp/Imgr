@echo off

if not exist bin mkdir bin

cl /nologo /W3 /Fe:bin\main.exe /Fo:bin\ src\main.c src\loader.c src\reloc.c src\iat.c src\protect.c src\entry.c src\exceptions.c src\tls.c

echo Build finished