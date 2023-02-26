using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace PIF.Misc {
    internal class Init {
        internal bool validArgs = false;
        internal string pifMethod;
        internal string pifTarget;
        internal string pifPayload;

        internal string targetType;
        internal string payloadType;
        internal byte[] payloadBytes;

        public Init(Dictionary<string, string> dArgs) {
            dArgs = FormatArguments(dArgs);

            if (dArgs.Count != 3 || dArgs.ContainsKey("/h")) {
                ShowHelp(dArgs);
                return;
            }

            if (!ValidateAndSetPayload(dArgs["/p"])) { return; }
            if (!ValidateAndSetTarget(dArgs["/t"])) { return; }
            if (!ValidateAndSetMethod(dArgs["/m"])) { return; }
            validArgs = true;
        }

        private Dictionary<string, string> FormatArguments(Dictionary<string, string> dArgs) {
            string[][] argumentMappings = new string[][] {
                new string[] { "/method",  "/m" },
                new string[] { "/target",  "/t" },
                new string[] { "/payload", "/p" },
                new string[] { "/help",    "/h" }
            };
            Dictionary<string, string> filteredArgs = dArgs
                .Where(k => argumentMappings.SelectMany(mapping => mapping).Contains(k.Key.ToLower()))
                .ToDictionary(k => argumentMappings.First(mapping => mapping.Contains(k.Key.ToLower()))[1], k => k.Value);
            return filteredArgs;
        }

        private void ShowHelp(Dictionary<string, string> dArgs) {
            try {
                switch (dArgs["/h"]) {
                    case "m":
                    case "method":
                        Output.PrintMethodInfo();
                        break;
                    case "t":
                    case "target":
                        Output.PrintTargetInfo();
                        break;
                    case "p":
                    case "payload":
                        Output.PrintPayloadInfo();
                        break;
                    default:
                        Output.PrintHelp();
                        break;
                }
            } catch {
                Output.PrintHelp();
            }
        }

        private bool ValidateAndSetMethod(string method) {
            bool methodSupported;
            switch (payloadType) {
                case "SC":
                    methodSupported = Methods.validShellcodeMethods.Contains(method, StringComparer.OrdinalIgnoreCase);
                    if (methodSupported) {
                        method = Methods.validShellcodeMethods[Array.FindIndex(Methods.validShellcodeMethods, x => string.Equals(x, method, StringComparison.OrdinalIgnoreCase))];
                    }
                    break;
                case "DLL":
                    methodSupported = Methods.validDLLMethods.Contains(method, StringComparer.OrdinalIgnoreCase);
                    if (methodSupported) {
                        method = Methods.validDLLMethods[Array.FindIndex(Methods.validDLLMethods, x => string.Equals(x, method, StringComparison.OrdinalIgnoreCase))];
                    }
                    break;
                case "PE":
                    methodSupported = Methods.validPEMethods.Contains(method, StringComparer.OrdinalIgnoreCase);
                    if (methodSupported) {
                        method = Methods.validPEMethods[Array.FindIndex(Methods.validPEMethods, x => string.Equals(x, method, StringComparison.OrdinalIgnoreCase))];
                    }
                    break;
                default:
                    methodSupported = false;
                    break;
            }
            if (!methodSupported) {
                Output.WriteErr($"Invalid Method : '{method}' does not exist for the '{payloadType}' payload type.");
                method = "";
            }
            pifMethod = method;
            return string.IsNullOrEmpty(method) ? false : true;
        }

        private bool ValidateAndSetTarget(string target) {
            if (Path.IsPathRooted(target)) {
                targetType = "Executable";
                if (!File.Exists(target) || Path.GetExtension(target).ToLower() != ".exe") {
                    Output.WriteErr($"Invalid Target : '{target}' does not exist or is not '*.exe' type.");
                    target = "";
                }
            } else {
                targetType = "Process";
                Process targetProc;
                try {
                    targetProc = int.TryParse(target, out int PID) ? Process.GetProcessById(PID) : Process.GetProcessesByName(target)[0];
                } catch {
                    targetProc = null;
                }
                if (targetProc != null) {
                    target = targetProc.Id.ToString();
                } else {
                    Output.WriteErr($"Invalid Target : Failed to locate process matching '{target}'.");
                    target = "";
                }
                target = targetProc != null ? targetProc.Id.ToString() : "";
            }
            pifTarget = target;
            return string.IsNullOrEmpty(target) ? false : true;
        }

        private bool ValidateAndSetPayload(string payload) {
            if (File.Exists(payload)) {
                switch (Path.GetExtension(payload).ToLower()) {
                    case ".txt":
                        payloadType = "SC";
                        Payloader.ReadContents(payload, out payloadBytes);
                        break;
                    case ".bin":
                        payloadType = "SC";
                        Payloader.ReadFile(payload, out payloadBytes);
                        break;
                    case ".dll":
                        payloadType = "DLL";
                        Payloader.ReadFile(payload, out payloadBytes);
                        break;
                    case ".exe":
                        payloadType = "PE";
                        Payloader.ReadFile(payload, out payloadBytes);
                        break;
                    default:
                        Output.WriteErr($"Invalid Payload : Unexpected file type for '{payload}'.");
                        payload = "";
                        break;
                }
            } else {
                Output.WriteErr($"Invalid Payload : File '{payload}' does not exist.");
                payload = "";
            }
            pifPayload = payload;
            return string.IsNullOrEmpty(payload) ? false : true;
        }
    }
}