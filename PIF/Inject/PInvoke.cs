using System;
using System.Runtime.InteropServices;

namespace PIF.Inject {
    internal class PInvoke {
        internal const int SIZE_OF_80387_REGISTERS = 80;
        internal const int CONTEXT_i386 = 0x00010000;
        internal const int CONTEXT_CONTROL = (CONTEXT_i386 | 0x00000001);
        internal const int CONTEXT_INTEGER = (CONTEXT_i386 | 0x00000002);
        internal const int CONTEXT_SEGMENTS = (CONTEXT_i386 | 0x00000004);
        internal const int CONTEXT_FLOATING_POINT = (CONTEXT_i386 | 0x00000008);
        internal const int CONTEXT_DEBUG_REGISTERS = (CONTEXT_i386 | 0x00000010);
        internal const int CONTEXT_EXTENDED_REGISTERS = (CONTEXT_i386 | 0x00000020);
        internal const int CONTEXT_FULL = (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS);
        internal const int CONTEXT_ALL = (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | CONTEXT_EXTENDED_REGISTERS);

        [Flags]
        internal enum DataSectionFlags : uint {
            TypeReg = 0x00000000,
            TypeDsect = 0x00000001,
            TypeNoLoad = 0x00000002,
            TypeGroup = 0x00000004,
            TypeNoPadded = 0x00000008,
            TypeCopy = 0x00000010,
            ContentCode = 0x00000020,
            ContentInitializedData = 0x00000040,
            ContentUninitializedData = 0x00000080,
            LinkOther = 0x00000100,
            LinkInfo = 0x00000200,
            TypeOver = 0x00000400,
            LinkRemove = 0x00000800,
            LinkComDat = 0x00001000,
            NoDeferSpecExceptions = 0x00004000,
            RelativeGP = 0x00008000,
            MemPurgeable = 0x00020000,
            Memory16Bit = 0x00020000,
            MemoryLocked = 0x00040000,
            MemoryPreload = 0x00080000,
            Align1Bytes = 0x00100000,
            Align2Bytes = 0x00200000,
            Align4Bytes = 0x00300000,
            Align8Bytes = 0x00400000,
            Align16Bytes = 0x00500000,
            Align32Bytes = 0x00600000,
            Align64Bytes = 0x00700000,
            Align128Bytes = 0x00800000,
            Align256Bytes = 0x00900000,
            Align512Bytes = 0x00A00000,
            Align1024Bytes = 0x00B00000,
            Align2048Bytes = 0x00C00000,
            Align4096Bytes = 0x00D00000,
            Align8192Bytes = 0x00E00000,
            LinkExtendedRelocationOverflow = 0x01000000,
            MemoryDiscardable = 0x02000000,
            MemoryNotCached = 0x04000000,
            MemoryNotPaged = 0x08000000,
            MemoryShared = 0x10000000,
            MemoryExecute = 0x20000000,
            MemoryRead = 0x40000000,
            MemoryWrite = 0x80000000
        }

        [Flags]
        internal enum ProcessAccessFlags : uint {
            PROCESS_TERMINATE = 0x00000001,
            PROCESS_CREATE_THREAD = 0x00000002,
            PROCESS_SET_SESSIONID = 0x00000004,
            PROCESS_VM_OPERATION = 0x00000008,
            PROCESS_VM_READ = 0x00000010,
            PROCESS_VM_WRITE = 0x00000020,
            PROCESS_DUP_HANDLE = 0x00000040,
            PROCESS_CREATE_PROCESS = 0x00000080,
            PROCESS_SET_QUOTA = 0x00000100,
            PROCESS_SET_INFORMATION = 0x00000200,
            PROCESS_QUERY_INFORMATION = 0x00000400,
            PROCESS_SUSPEND_RESUME = 0x00000800,
            PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000,
            PROCESS_SET_LIMITED_INFORMATION = 0x00002000,
            SYNCHRONIZE = 0x00100000,
            PROCESS_ALL_ACCESS = 0x000F0000 | SYNCHRONIZE | 0xFFFF
        }

        [Flags]
        internal enum ThreadAccess : int {
            DELETE = 0x00010000,
            READ_CONTROL = 0x00020000,
            SYNCHRONIZE = 0x00100000,
            WRITE_DAC = 0x00040000,
            WRITE_OWNER = 0x00080000,
            THREAD_DIRECT_IMPERSONATION = 0x0200,
            THREAD_GET_CONTEXT = 0x0008,
            THREAD_IMPERSONATE = 0x0100,
            THREAD_QUERY_INFORMATION = 0x0040,
            THREAD_QUERY_LIMITED_INFORMATION = 0x0800,
            THREAD_SET_CONTEXT = 0x0010,
            THREAD_SET_INFORMATION = 0x0020,
            THREAD_SET_LIMITED_INFORMATION = 0x0400,
            THREAD_SET_THREAD_TOKEN = 0x0080,
            THREAD_SUSPEND_RESUME = 0x0002,
            THREAD_TERMINATE = 0x0001,
            THREAD_ALL_ACCESS = 0x000F0000 | SYNCHRONIZE | 0xFFFF
        }

        internal enum PROCESSINFOCLASS {
            ProcessBasicInformation = 0x00,
            ProcessDebugPort = 0x07,
            ProcessExceptionPort = 0x08,
            ProcessAccessToken = 0x09,
            ProcessWow64Information = 0x1A,
            ProcessImageFileName = 0x1B,
            ProcessDebugObjectHandle = 0x1E,
            ProcessDebugFlags = 0x1F,
            ProcessExecuteFlags = 0x22,
            ProcessInstrumentationCallback = 0x28,
            MaxProcessInfoClass = 0x64
        }

        internal enum SubSystemType : ushort {
            IMAGE_SUBSYSTEM_UNKNOWN = 0,
            IMAGE_SUBSYSTEM_NATIVE = 1,
            IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
            IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
            IMAGE_SUBSYSTEM_POSIX_CUI = 7,
            IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
            IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
            IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
            IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
            IMAGE_SUBSYSTEM_EFI_ROM = 13,
            IMAGE_SUBSYSTEM_XBOX = 14
        }

        internal enum DllCharacteristicsType : ushort {
            RES_0 = 0x0001,
            RES_1 = 0x0002,
            RES_2 = 0x0004,
            RES_3 = 0x0008,
            IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 0x0040,
            IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY = 0x0080,
            IMAGE_DLL_CHARACTERISTICS_NX_COMPAT = 0x0100,
            IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200,
            IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400,
            IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800,
            RES_4 = 0x1000,
            IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
            IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
        }

        internal enum MagicType : ushort {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
            IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
        }

        [StructLayout(LayoutKind.Explicit, Pack = 16)]
        internal struct CONTEXT {
            [FieldOffset(0x000)]
            public ulong P1Home;
            [FieldOffset(0x008)]
            public ulong P2Home;
            [FieldOffset(0x010)]
            public ulong P3Home;
            [FieldOffset(0x018)]
            public ulong P4Home;
            [FieldOffset(0x020)]
            public ulong P5Home;
            [FieldOffset(0x028)]
            public ulong P6Home;
            [FieldOffset(0x030)]
            public int ContextFlags;
            [FieldOffset(0x034)]
            public int MxCsr;
            [FieldOffset(0x038)]
            public ushort SegCs;
            [FieldOffset(0x03a)]
            public ushort SegDs;
            [FieldOffset(0x03c)]
            public ushort SegEs;
            [FieldOffset(0x03e)]
            public ushort SegFs;
            [FieldOffset(0x040)]
            public ushort SegGs;
            [FieldOffset(0x042)]
            public ushort SegSs;
            [FieldOffset(0x044)]
            public int EFlags;

            [FieldOffset(0x048)]
            public ulong Dr0;
            [FieldOffset(0x050)]
            public ulong Dr1;
            [FieldOffset(0x058)]
            public ulong Dr2;
            [FieldOffset(0x060)]
            public ulong Dr3;
            [FieldOffset(0x068)]
            public ulong Dr6;
            [FieldOffset(0x070)]
            public ulong Dr7;
            [FieldOffset(0x078)]
            public ulong Rax;
            [FieldOffset(0x080)]
            public ulong Rcx;
            [FieldOffset(0x088)]
            public ulong Rdx;
            [FieldOffset(0x090)]
            public ulong Rbx;
            [FieldOffset(0x098)]
            public ulong Rsp;
            [FieldOffset(0x0a0)]
            public ulong Rbp;
            [FieldOffset(0x0a8)]
            public ulong Rsi;
            [FieldOffset(0x0b0)]
            public ulong Rdi;

            [FieldOffset(0x0b8)]
            public ulong R8;
            [FieldOffset(0x0c0)]
            public ulong R9;
            [FieldOffset(0x0c8)]
            public ulong R10;
            [FieldOffset(0x0d0)]
            public ulong R11;
            [FieldOffset(0x0d8)]
            public ulong R12;
            [FieldOffset(0x0e0)]
            public ulong R13;
            [FieldOffset(0x0e8)]
            public ulong R14;
            [FieldOffset(0x0f0)]
            public ulong R15;
            [FieldOffset(0x0f8)]
            public ulong Rip;

            [FieldOffset(0x100)]
            public XMM_SAVE_AREA32 FltSave;

            [FieldOffset(0x300)]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
            public M128A[] VectorRegister;
            [FieldOffset(0x4a0)]
            public ulong VectorControl;
            [FieldOffset(0x4a8)]
            public ulong DebugControl;
            [FieldOffset(0x4b0)]
            public ulong LastBranchToRip;
            [FieldOffset(0x4b8)]
            public ulong LastBranchFromRip;
            [FieldOffset(0x4c0)]
            public ulong LastExceptionToRip;
            [FieldOffset(0x4c8)]
            public ulong LastExceptionFromRip;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct FLOATING_SAVE_AREA {
            public int ControlWord;
            public int StatusWord;
            public int TagWord;
            public int ErrorOffset;
            public int ErrorSelector;
            public int DataOffset;
            public int DataSelector;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = SIZE_OF_80387_REGISTERS)]
            public byte[] RegisterArea;
            public int Spare0;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct IMAGE_DATA_DIRECTORY {
            public UInt32 VirtualAddress;
            public UInt32 Size;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct IMAGE_DOS_HEADER {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public char[] e_magic;
            public UInt16 e_cblp;
            public UInt16 e_cp;
            public UInt16 e_crlc;
            public UInt16 e_cparhdr;
            public UInt16 e_minalloc;
            public UInt16 e_maxalloc;
            public UInt16 e_ss;
            public UInt16 e_sp;
            public UInt16 e_csum;
            public UInt16 e_ip;
            public UInt16 e_cs;
            public UInt16 e_lfarlc;
            public UInt16 e_ovno;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public UInt16[] e_res1;
            public UInt16 e_oemid;
            public UInt16 e_oeminfo;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public UInt16[] e_res2;
            public Int32 e_lfanew;

            private string _e_magic {
                get { return new string(e_magic); }
            }

            public bool isValid {
                get { return _e_magic == "MZ"; }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct IMAGE_FILE_HEADER {
            public UInt16 Machine;
            public UInt16 NumberOfSections;
            public UInt32 TimeDateStamp;
            public UInt32 PointerToSymbolTable;
            public UInt32 NumberOfSymbols;
            public UInt16 SizeOfOptionalHeader;
            public UInt16 Characteristics;
        }

        [StructLayout(LayoutKind.Explicit)]
        internal struct IMAGE_NT_HEADERS64 {
            [FieldOffset(0)]
            public UInt32 Signature;

            [FieldOffset(4)]
            public IMAGE_FILE_HEADER FileHeader;

            [FieldOffset(24)]
            public IMAGE_OPTIONAL_HEADER64 OptionalHeader;

            private string _Signature {
                get { return Signature.ToString(); }
            }

            public bool isValid {
                get { return _Signature == "PE\0\0" && OptionalHeader.Magic == MagicType.IMAGE_NT_OPTIONAL_HDR64_MAGIC; }
            }
        }

        [StructLayout(LayoutKind.Explicit)]
        internal struct IMAGE_OPTIONAL_HEADER64 {
            [FieldOffset(0)]
            public MagicType Magic;
            [FieldOffset(2)]
            public byte MajorLinkerVersion;
            [FieldOffset(3)]
            public byte MinorLinkerVersion;
            [FieldOffset(4)]
            public uint SizeOfCode;
            [FieldOffset(8)]
            public uint SizeOfInitializedData;
            [FieldOffset(12)]
            public uint SizeOfUninitializedData;
            [FieldOffset(16)]
            public uint AddressOfEntryPoint;
            [FieldOffset(20)]
            public uint BaseOfCode;
            [FieldOffset(24)]
            public ulong ImageBase;
            [FieldOffset(32)]
            public uint SectionAlignment;
            [FieldOffset(36)]
            public uint FileAlignment;
            [FieldOffset(40)]
            public ushort MajorOperatingSystemVersion;
            [FieldOffset(42)]
            public ushort MinorOperatingSystemVersion;
            [FieldOffset(44)]
            public ushort MajorImageVersion;
            [FieldOffset(46)]
            public ushort MinorImageVersion;
            [FieldOffset(48)]
            public ushort MajorSubsystemVersion;
            [FieldOffset(50)]
            public ushort MinorSubsystemVersion;
            [FieldOffset(52)]
            public uint Win32VersionValue;
            [FieldOffset(56)]
            public uint SizeOfImage;
            [FieldOffset(60)]
            public uint SizeOfHeaders;
            [FieldOffset(64)]
            public uint CheckSum;
            [FieldOffset(68)]
            public SubSystemType Subsystem;
            [FieldOffset(70)]
            public DllCharacteristicsType DllCharacteristics;
            [FieldOffset(72)]
            public ulong SizeOfStackReserve;
            [FieldOffset(80)]
            public ulong SizeOfStackCommit;
            [FieldOffset(88)]
            public ulong SizeOfHeapReserve;
            [FieldOffset(96)]
            public ulong SizeOfHeapCommit;
            [FieldOffset(104)]
            public uint LoaderFlags;
            [FieldOffset(108)]
            public uint NumberOfRvaAndSizes;
            [FieldOffset(112)]
            public IMAGE_DATA_DIRECTORY ExportTable;
            [FieldOffset(120)]
            public IMAGE_DATA_DIRECTORY ImportTable;
            [FieldOffset(128)]
            public IMAGE_DATA_DIRECTORY ResourceTable;
            [FieldOffset(136)]
            public IMAGE_DATA_DIRECTORY ExceptionTable;
            [FieldOffset(144)]
            public IMAGE_DATA_DIRECTORY CertificateTable;
            [FieldOffset(152)]
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;
            [FieldOffset(160)]
            public IMAGE_DATA_DIRECTORY Debug;
            [FieldOffset(168)]
            public IMAGE_DATA_DIRECTORY Architecture;
            [FieldOffset(176)]
            public IMAGE_DATA_DIRECTORY GlobalPtr;
            [FieldOffset(184)]
            public IMAGE_DATA_DIRECTORY TLSTable;
            [FieldOffset(192)]
            public IMAGE_DATA_DIRECTORY LoadConfigTable;
            [FieldOffset(200)]
            public IMAGE_DATA_DIRECTORY BoundImport;
            [FieldOffset(208)]
            public IMAGE_DATA_DIRECTORY IAT;
            [FieldOffset(216)]
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
            [FieldOffset(224)]
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
            [FieldOffset(232)]
            public IMAGE_DATA_DIRECTORY Reserved;
        }

        [StructLayout(LayoutKind.Explicit)]
        internal struct IMAGE_SECTION_HEADER {
            [FieldOffset(0)]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public char[] Name;
            [FieldOffset(8)]
            public UInt32 VirtualSize;
            [FieldOffset(12)]
            public UInt32 VirtualAddress;
            [FieldOffset(16)]
            public UInt32 SizeOfRawData;
            [FieldOffset(20)]
            public UInt32 PointerToRawData;
            [FieldOffset(24)]
            public UInt32 PointerToRelocations;
            [FieldOffset(28)]
            public UInt32 PointerToLinenumbers;
            [FieldOffset(32)]
            public UInt16 NumberOfRelocations;
            [FieldOffset(34)]
            public UInt16 NumberOfLinenumbers;
            [FieldOffset(36)]
            public DataSectionFlags Characteristics;
            public string Section {
                get {
                    return new string(Name);
                }
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        internal struct M128A {
            public M128A(ulong _low, long _high) {
                low = _low;
                high = _high;
            }
            public ulong low;
            public long high;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PE_HEADERS {
            public IMAGE_DOS_HEADER dosHeader;
            public IMAGE_NT_HEADERS64 ntHeaders;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct PROCESS_BASIC_INFORMATION {
            public IntPtr ExitStatus;
            public IntPtr PebBaseAddress;
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public UIntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct SECURITY_ATTRIBUTES {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct STARTUPINFO {
            public uint cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttributes;
            public uint dwFlags;
            public ushort wShowWindow;
            public ushort cbReserved;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdErr;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct STARTUPINFOEX {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct THREADENTRY32 {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ThreadID;
            public uint th32OwnerProcessID;
            public int tpBasePri;
            public int tpDeltaPri;
            public uint dwFlags;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        internal struct XMM_SAVE_AREA32 {
            public ushort ControlWord;
            public ushort StatusWord;
            public char TagWord;
            public char Reserved1;
            public ushort ErrorOpcode;
            public uint ErrorOffset;
            public ushort ErrorSelector;
            public ushort Reserved2;
            public uint DataOffset;
            public ushort DataSelector;
            public ushort Reserved3;
            public uint MxCsr;
            public uint MxCsrMask;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public M128A[] FloatRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public M128A[] XmmRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
            public char[] Reserved4;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        internal static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll")]
        internal static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        internal static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        internal static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern int GetProcessId(IntPtr processHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

        [DllImport("NTDLL.DLL", SetLastError = true)]
        internal static extern int NtQueryInformationProcess(IntPtr hProcess, PROCESSINFOCLASS pic, out PROCESS_BASIC_INFORMATION pbi, int cb, out int pSize);

        [DllImport("kernel32.dll")]
        internal static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern uint QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern int SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll")]
        internal static extern bool Thread32First(IntPtr hSnapshot, ref THREADENTRY32 lpte);

        [DllImport("kernel32.dll")]
        internal static extern bool Thread32Next(IntPtr hSnapshot, ref THREADENTRY32 lpte);

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("ntdll.dll")]
        internal static extern int ZwUnmapViewOfSection(IntPtr ProcessHandle, IntPtr BaseAddress);
    }
}
