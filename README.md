<div align=center>
   <h1>Sweetdream</h1>
   <i><p>A Recursive UDRL Leveraging smelly_vx's Feverdream Technique.</p></i>
</div>

## About:

Sweetdream is a fully recursive, portable executable (PE) loader written in C.
The concept emerged while practicing recursion through Codewars problems in preparation for an upcoming exam. This sparked a simple question:

> Wouldn’t it be interesting if import resolution and relocation handling were implemented recursively?

And here we are.

> [!NOTE]
> This project is a proof of concept and not production-ready.
> Currently, the loader remains in memory while the machine is unlocked, as it only activates once the machine is locked.
> A better approach would involve encrypting the thread routine during unlocked sessions and decrypting it when the machine locks. (may be added in the future)

## Features:
- It's Recursive!
- API Hashing
- DLL Unhooking
- AMSI & ETW Patch
- Anti-Debugging using smelly_vx's `feverdream` technique (PE is mapped while the machine is locked)

<!--
Add screenshots here once its fully done and working :)
-->
