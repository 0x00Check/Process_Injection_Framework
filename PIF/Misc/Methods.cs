namespace PIF.Misc {
    internal class Methods {
        internal static string[] validShellcodeMethods = {
            "CreateRemoteThread",
            "EarlyBirdAPC",
            "QueueUserAPC",
            "ThreadHijacking"
        };

        internal static string[] validDLLMethods = {
            "LoadLibrary"
        };

        internal static string[] validPEMethods = {
            "ProcessHollowing"
        };
    }
}
