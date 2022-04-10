# SharpInjector is a C# shellcode injector that utilizes functions exported from ntdll.dll to avoid userland hooking. #
This was a project for my ECE 264 class, and satisfies all rubric requirements. **I am aware that utilizng PInvoke forfeits the ability to dynamically invoke the ntdll functions, however, since this was a school project it was important to restrict myself to default .NET functionality.**

Currently two method of shellcode injection are implemented, default injection, (NtWriteProcessMemory & NtCreateThreadEx), and section mapping, (NtCreateSection & NtMapViewOfSection). In the future more process injection techniques will be implemented, as well as other functionality. 

Resources I used in creating SharpInjector were [Ired.team](https://www.ired.team/offensive-security/code-injection-process-injection), [PInvoke](https://www.pinvoke.net/), [RastaMouse](https://offensivedefence.co.uk/posts/dinvoke-syscalls/)
