<div align=center>
   <h1>$$\text{\LARGE Sweetdream}$$</h1>
   <i><p>$$\text{Weird Reflective Loader}$$</p></i>
</div>

## $$\text{About:}$$

Nothing special. Just a fully recursive portable executable (PE) loader written in C. 

The idea for this project popped up in my head while solving random Codewars 
problems with recursion as practice for my upcoming exam. At that time I began to wonder:

> How nice would resolving imports & performing relocations look if I implemented it recursively? 

And here we are.

## $$\text{Features:}$$
- It's Recursive!
- API Hashing
- `ntdll.dll` Unhooking
- AMSI & ETW Patch
- No CRT <- In Progress
<!-- - Anti-Debugging using smelly_vx's `feverdream` technique (code runs only once machine is locked)-->

## $$\text{Tasks Left:}$$

- [ ] [Execute only when PC is locked](https://vx-api.gitbook.io/vx-api/my-projects/fever-dream-code-executing-when-the-windows-machine-is-locked)
- [ ] Convert to Shellcode (place functions in correct sections, replace calls to CreateFile, call from ASM, add linker script ...)

Later...
- [ ] Test against Elastic????)
