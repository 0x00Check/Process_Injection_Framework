using PIF.Misc;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace PIF {
    public class PIFStandardExec {
        public static void Main(string[] args) {
            Dictionary<string, string> dArgs = new Dictionary<string, string>();
            try {
                dArgs = args
                    .Select(arg => arg.Split(new char[] { '=' }, 2))
                    .ToDictionary(split => split[0], split => split.Length > 1 ? split[1] : "");
            } catch (Exception ex) {
                Output.WriteErr($"Invalid Arguments: {ex.Message}.");
            }
            PIF.Start(dArgs);
        }
    }

    [System.ComponentModel.RunInstaller(true)]
    internal class PIFProxyExec : System.Configuration.Install.Installer {
        public override void Uninstall(IDictionary savedState) {
            Dictionary<string, string> dArgs = new Dictionary<string, string>();
            try {
                dArgs = this.Context.Parameters
                    .Cast<DictionaryEntry>()
                    .ToDictionary(arg => $"/{arg.Key.ToString()}", arg => arg.Value.ToString());
            } catch (Exception ex) {
                Output.WriteErr($"Invalid Arguments: {ex.Message}.");
            }
            PIF.Start(dArgs);
        }
    }
    internal class PIF {
        internal static void Start(Dictionary<string, string> dArgs) {
            Output.PrintBanner();

            Init pifArgs = new Init(dArgs);
            if (!pifArgs.validArgs) {
                return;
            }

            DynamicInvoker(pifArgs);
        }
        internal static void DynamicInvoker(Init pifArgs) {
            string pifFQN = $"PIF.Inject.{pifArgs.payloadType}.{pifArgs.pifMethod}";

            Type pifType;
            try {
                pifType = Type.GetType(pifFQN, true, true);
            } catch {
                Output.WriteErr($"Failed to locate '{pifFQN}'. Is it implemented?");
                return;
            }

            Output.Write($"Invoking '{pifFQN}'");
            try {
                MethodInfo pifMethod = pifType.GetMethod("Invoke");
                pifMethod.Invoke(null, new object[] { pifArgs });
            } catch (Exception ex) {
                string errPF = ex.InnerException is PIFException ? "Error" : "Invocation Error";
                Output.WriteErr($"{errPF}: {ex.InnerException.Message}");
            }

            Console.WriteLine("\t--- FINISHED ---\n");
        }
    }
}
