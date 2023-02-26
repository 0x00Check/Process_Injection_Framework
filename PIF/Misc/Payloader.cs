using System;
using System.IO;

namespace PIF.Misc {
    internal class Payloader {
        // *slaps knee* (directing your attention away from below)
        internal static void ReadContents(string payload, out byte[] bytes) {
            string fileContents = File.ReadAllText(payload)
                .Replace(" ", "")
                .Replace("\r", "")
                .Replace("\n", "")
                .Replace("'", "")
                .Replace("\"", "")
                .Replace(",", "")
                .Replace("0x", "")
                .Replace("\\x", "")
                .Trim();

            bytes = new byte[fileContents.Length / 2];
            for (int i = 0; i < bytes.Length; i++) {
                bytes[i] = Convert.ToByte(fileContents.Substring(i * 2, 2), 16);
            }
        }

        internal static void ReadFile(string payload, out byte[] bytes) {
            bytes = File.ReadAllBytes(payload);
        }
    }
}
