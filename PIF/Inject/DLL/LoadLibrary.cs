using PIF.Misc;
using System;
using System.Text;

namespace PIF.Inject.DLL {
    internal class LoadLibrary {
        public static void Invoke(Init pif) {
            Output.Write("Opening a handle to the target process");
            IntPtr hProcess = Helpers.GetProcessHandle(pif);
            if (hProcess == IntPtr.Zero) {
                PIFException.Throw("Failed to open handle.");
            }

            Output.Write("Allocating new buffer and writing payload into the target process");
            byte[] bPayload = Encoding.ASCII.GetBytes(pif.pifPayload);
            if (!Helpers.AllocAndWriteMemory(hProcess, bPayload, out IntPtr hBuffer)) {
                PIFException.Throw($"Failed to {(hBuffer == IntPtr.Zero ? "allocate memory in" : "write to")} target process.");
            }

            Output.Write("Calling 'LoadLibrary()' in remote process");
            IntPtr loadLib = PInvoke.GetProcAddress(PInvoke.GetModuleHandle("kernel32.dll"), "LoadLibraryA");
            if (PInvoke.CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLib, hBuffer, 0, IntPtr.Zero) == IntPtr.Zero) {
                PIFException.Throw("Failed to call 'LoadLibrary()'.");
            }
        }
    }
}
