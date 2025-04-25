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

>[!NOTE]
> This is obviously not production ready. Also since the loader only runs once the computer is locked the loader just sits there in memory- A better approach would be to encrypt the thread routine/function while the computer is unlocked and then decrypt it once its locked but that is a task for another time (I am getting lazy :P).

## Features:
- It's Recursive!
- API Hashing
- DLL Unhooking
- AMSI & ETW Patch
<!-- - No CRT <- In Progress -->
<!-- - Anti-Debugging using smelly_vx's `feverdream` technique (code runs only once machine is locked)-->

<!--
Add screenshots here once its fully done and working :)
-->
