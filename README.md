<div align=center>
   <h1>Sweetdream</h1>
   <i><p>A Recursive UDRL that uses smelly_vx's Feverdream technique.</p></i>
</div>

## About:

Nothing special. Just a fully recursive portable executable (PE) loader written in C. 

The idea for this project popped up in my head while solving random Codewars 
problems with recursion as practice for my upcoming exam. At that time I began to wonder:

> How nice would resolving imports & performing relocations look if I implemented it recursively? 

And here we are.

## Features:
- It's Recursive!
- API Hashing
- DLL Unhooking
- AMSI & ETW Patch
<!-- - No CRT <- In Progress -->
<!-- - Anti-Debugging using smelly_vx's `feverdream` technique (code runs only once machine is locked)-->

## Tasks Left:

- [ ] [Execute only when PC is locked](https://vx-api.gitbook.io/vx-api/my-projects/fever-dream-code-executing-when-the-windows-machine-is-locked)
- [ ] Convert to Shellcode (place functions in correct sections, replace calls to CreateFile, call from ASM, add linker script ...)

<!--
Add screenshots here once its fully done and working :)
-->
