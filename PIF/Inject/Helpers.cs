using PIF.Misc;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace PIF.Inject {
    internal class Helpers {
        internal static IntPtr GetProcessHandle(Init pif) {
            IntPtr processHandle = IntPtr.Zero;
            if (pif.targetType == "Executable") {
                processHandle = NewProcess(pif, out PInvoke.PROCESS_INFORMATION pInfo) ? pInfo.hProcess : IntPtr.Zero;
            } else {
                processHandle = PInvoke.OpenProcess(0x001FFFFF, false, int.Parse(pif.pifTarget));
            }
            return processHandle;
        }

        internal static bool AllocAndWriteMemory(IntPtr hProcess, byte[] bPayload, out IntPtr hBuffer) {
            hBuffer = PInvoke.VirtualAllocEx(hProcess, IntPtr.Zero, (uint)bPayload.Length, 0x00001000, 0x40);
            if (hBuffer == IntPtr.Zero) {
                return false;
            }
            return PInvoke.WriteProcessMemory(hProcess, hBuffer, bPayload, (uint)bPayload.Length, out _);
        }

        internal static List<IntPtr> GetProcessThreads(int pid) {
            List<IntPtr> hThreads = new List<IntPtr>();
            PInvoke.THREADENTRY32 tEntry = new PInvoke.THREADENTRY32();
            tEntry.dwSize = (uint)Marshal.SizeOf(tEntry);

            IntPtr snapshot = PInvoke.CreateToolhelp32Snapshot(0x00000004, (uint)pid);
            if (snapshot == IntPtr.Zero) {
                return null;
            }

            try {
                if (PInvoke.Thread32First(snapshot, ref tEntry)) {
                    do {
                        if (tEntry.th32OwnerProcessID == pid) {
                            hThreads.Add(PInvoke.OpenThread(PInvoke.ThreadAccess.THREAD_ALL_ACCESS, false, tEntry.th32ThreadID));
                        }
                    } while (PInvoke.Thread32Next(snapshot, ref tEntry));
                }
            } finally {
                PInvoke.CloseHandle(snapshot);
            }

            return hThreads;
        }

        internal static bool NewProcess(Init pif, out PInvoke.PROCESS_INFORMATION pInfo, bool createSuspended = false) {
            pInfo = new PInvoke.PROCESS_INFORMATION();
            PInvoke.STARTUPINFOEX sInfo = new PInvoke.STARTUPINFOEX();
            sInfo.StartupInfo.cb = (uint)Marshal.SizeOf(sInfo);

            PInvoke.SECURITY_ATTRIBUTES pSec = new PInvoke.SECURITY_ATTRIBUTES();
            PInvoke.SECURITY_ATTRIBUTES tSec = new PInvoke.SECURITY_ATTRIBUTES();
            pSec.nLength = Marshal.SizeOf(pSec);
            tSec.nLength = Marshal.SizeOf(tSec);

            uint dwCreationFlags = createSuspended ? 0x00000004u : 0u;

            return PInvoke.CreateProcess(pif.pifTarget, null, ref pSec, ref tSec, false, dwCreationFlags, IntPtr.Zero, null, ref sInfo, out pInfo);
        }

        internal static bool GetProcessPEB(IntPtr hProcess, out PInvoke.PROCESS_BASIC_INFORMATION pbi) {
            pbi = new PInvoke.PROCESS_BASIC_INFORMATION();
            return PInvoke.NtQueryInformationProcess(hProcess, PInvoke.PROCESSINFOCLASS.ProcessBasicInformation, out pbi, Marshal.SizeOf(pbi), out _) == 0;
        }

        internal static void GetPEHeaders(IntPtr buffer, out PInvoke.PE_HEADERS peHeaders) {
            peHeaders = new PInvoke.PE_HEADERS();
            peHeaders.dosHeader = (PInvoke.IMAGE_DOS_HEADER)Marshal.PtrToStructure(buffer, typeof(PInvoke.IMAGE_DOS_HEADER));
            peHeaders.ntHeaders = (PInvoke.IMAGE_NT_HEADERS64)Marshal.PtrToStructure(IntPtr.Add(buffer, peHeaders.dosHeader.e_lfanew), typeof(PInvoke.IMAGE_NT_HEADERS64));
        }

        internal static List<PInvoke.IMAGE_SECTION_HEADER> GetPESections(IntPtr plBuffer, PInvoke.PE_HEADERS peHeaders) {
            int sizeOfImageSectionHeader = Marshal.SizeOf(typeof(PInvoke.IMAGE_SECTION_HEADER));

            IntPtr plNTHeadersAddr = IntPtr.Add(plBuffer, peHeaders.dosHeader.e_lfanew);
            IntPtr sectionStartPtr = IntPtr.Add(plNTHeadersAddr, Marshal.SizeOf(peHeaders.ntHeaders));

            List<PInvoke.IMAGE_SECTION_HEADER> peSections = new List<PInvoke.IMAGE_SECTION_HEADER>();
            for (int pSection = 0; pSection < peHeaders.ntHeaders.FileHeader.NumberOfSections; pSection++) {
                IntPtr sectionPtr = IntPtr.Add(sectionStartPtr, (sizeOfImageSectionHeader * pSection));
                peSections.Add((PInvoke.IMAGE_SECTION_HEADER)Marshal.PtrToStructure(sectionPtr, typeof(PInvoke.IMAGE_SECTION_HEADER)));
            }
            return peSections;
        }

        internal static bool WritePESection(IntPtr hProcess, IntPtr plBuffer, PInvoke.PE_HEADERS peHeaders, PInvoke.IMAGE_SECTION_HEADER peSection) {
            byte[] sectionData = new byte[peSection.SizeOfRawData];
            Marshal.Copy(IntPtr.Add(plBuffer, (int)peSection.PointerToRawData), sectionData, 0, sectionData.Length);

            IntPtr writeAddr = (IntPtr)(peHeaders.ntHeaders.OptionalHeader.ImageBase + peSection.VirtualAddress);

            return PInvoke.WriteProcessMemory(hProcess, writeAddr, sectionData, (uint)sectionData.Length, out _);
        }
    }
}
