using System;
using System.Linq;

namespace PIF.Misc {
    internal class Output {
        internal static void PrintBanner() {
            Console.WriteLine(@"
    .______       __            _______
    |   _  \     |  |          |   ____|
    |  |_)  |    |  |          |  |__
    |   ___/     |  |          |   __|
    |  |         |  |          |  |
    | _|rocess   |__|njection  |__|ramework
");
        }

        internal static void PrintHelp() {
            Console.WriteLine(@"
 PIF (Process Injection Framework) is a tool that facilitates injecting & executing
 arbitrary code in remote processes through various process injection techniques.

 Arguments:
    /[m]ethod  | Desired process injection technique to use.
    /[t]arget  | Target process or executable to inject into.
    /[p]ayload | Payload to be injected.

 You may also view this message by passing '/help' (or '/h') or specify another
 argument to learn more about it. For instance, to show details about supported
 process injection techniques, call PIF with '/help=method' (or '/h=m').

 Usage:
    .\PIF.exe /m=<METHOD> /t=<TARGET> /p=<PAYLOAD>
");
        }

        internal static void PrintMethodInfo() {
            int cSCPadding = Methods.validShellcodeMethods.Max(m => m.Length) + 6;
            int cDLLPadding = Methods.validDLLMethods.Max(m => m.Length) + 5;
            int cPEPadding = Methods.validPEMethods.Max(m => m.Length) + 5;

            string outMessage = "\n Injection methods supported by PIF are dependent on the supplied payload type.\n\n";
            outMessage += " |  Shellcode".PadRight(cSCPadding) + "|  DLL".PadRight(cDLLPadding) + "|  PE".PadRight(cPEPadding) + "|\n";
            outMessage += " |".PadRight(cSCPadding, '_') + "|".PadRight(cDLLPadding, '_') + "|".PadRight(cPEPadding, '_') + "|\n";

            for (int i = 0; i < Math.Max(Methods.validShellcodeMethods.Length, Math.Max(Methods.validDLLMethods.Length, Methods.validPEMethods.Length)); i++
            ) {
                outMessage += $" |  {(i < Methods.validShellcodeMethods.Length ? Methods.validShellcodeMethods[i] : "").PadRight(cSCPadding - 4)}" +
                    $"|  {(i < Methods.validDLLMethods.Length ? Methods.validDLLMethods[i] : "").PadRight(cDLLPadding - 3)}" +
                    $"|  {(i < Methods.validPEMethods.Length ? Methods.validPEMethods[i] : "").PadRight(cPEPadding - 3)}|\n";
            }
            outMessage += " |".PadRight(cSCPadding, '_') + "|".PadRight(cDLLPadding, '_') + "|".PadRight(cPEPadding, '_') + "|\n";
            Console.WriteLine(outMessage);
        }

        internal static void PrintTargetInfo() {
            Console.WriteLine(@"
 The target may be the full path to an executable, process name, or process ID. If
 a full path is supplied, PIF will create a new process. Otherwise, it will locate
 an existing process that matches the given name or ID.

 When a process name is provided, the first process will always be selected as the
 target regardless of how many processes are a match.

 Examples:
    Full Path     =>  /target=C:\Windows\System32\svchost.exe
    Process Name  =>  /target=svchost
    Process ID    =>  /target=616
");
        }

        internal static void PrintPayloadInfo() {
            Console.WriteLine(@"
 PIF supports shellcode, DLLs, or PE files as a payload and determines the payload
 type based on the file extension. DLL files should have the 'dll' extension while
 EXE files should have the 'exe' extension. Shellcode payloads can be either 'txt'
 or 'bin' files.

 Examples:
    Shellcode  =>  /payload=C:\Some\Shellcode.txt
    Shellcode  =>  /payload=C:\Some\Shellcode.bin
    DLL        =>  /payload=C:\Your\Custom.dll
    PE         =>  /payload=C:\Your\Custom.exe
");
        }

        internal static void Write(string msg) {
            Console.WriteLine($" [+] {msg}");
        }

        internal static void WriteErr(string err = "Failed") {
            Console.WriteLine($" [*] {err}");
        }
    }
}
