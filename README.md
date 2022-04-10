# SharpInjector is a C# shellcode injector that utilizes functions exported from ntdll.dll to avoid userland hooking. #
This was a project for my ECE 264 class, and satisfies all rubric requirements. **I am aware that utilizng PInvoke forfeits the ability to dynamically invoke the ntdll functions, however, since this was a school project it was important to restrict myself to default .NET functionality.**

Currently two method of shellcode injection are implemented, default injection, (NtWriteProcessMemory & NtCreateThreadEx), and section mapping, (NtCreateSection & NtMapViewOfSection). In the future more process injection techniques will be implemented, as well as other functionality. 

Resources I used in creating SharpInjector were [Ired.team](https://www.ired.team/offensive-security/code-injection-process-injection), [PInvoke](https://www.pinvoke.net/), [RastaMouse](https://offensivedefence.co.uk/posts/dinvoke-syscalls/)


# MessageBox #

Shellcode<img width="874" alt="messagebox" src="https://user-images.githubusercontent.com/77711496/162606844-8f2bc78d-0148-417f-94ee-62e4ebcadc27.png">

# Reverse Shell #

<img width="692" alt="reverse_shell" src="https://user-images.githubusercontent.com/77711496/162606989-d82b2138-573f-4d15-b0de-62371f970467.png">

# InMemory View of Reverse Shell Shellcode #

<img width="734" alt="shellcode_in_mem" src="https://user-images.githubusercontent.com/77711496/162607013-ddb1df61-0d72-4cef-8c97-5dbce98d9e74.png">
