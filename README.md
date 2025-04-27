<div align=center>
   <h1>Sweetdream</h1>
   <i><p>A Recursive UDRL Leveraging smelly_vx's "Fever Dream" Trick.</p></i>
</div>

## About:

Sweetdream is a fully recursive, portable executable (PE) loader written in C.
The concept emerged while practicing recursion through Codewars problems in preparation for an upcoming exam. This sparked a simple question:

> Wouldn’t it be interesting if import resolution and relocation handling were implemented recursively?

And here we are.

> [!NOTE]
> **TL;DR: This is stupid, don't use it. :pray: :sob: :100:** 
>
> This project is a proof of concept and not production-ready.
> Currently, the loader remains in memory while the machine is unlocked, as it only activates once the machine is locked.
> A better approach would involve encrypting the thread routine during unlocked sessions and decrypting it when the machine locks. (may be added in the future)

## Features:
- It's Recursive!
- API Hashing
- DLL Unhooking
- AMSI & ETW Patch
- Anti-Debugging using smelly_vx's ["Fever Dream"](https://vx-api.gitbook.io/vx-api/my-projects/fever-dream-code-executing-when-the-windows-machine-is-locked) trick.

## Thanks:

Here I would just like to thank [Nox](https://github.com/CaptainNox) and [cyb3rjerry](https://x.com/cyb3rjerry) for dealing with my stupid questions while developing this pretty useless loader. :)

##
<div align=center>
   <p>It ain't much but it's honest work. :P</p>
</div>
