using System;

namespace PIF.Misc {
    internal class PIFException : Exception {
        internal PIFException(string message) : base(message) { }

        internal static void Throw(string message) {
            throw new PIFException(message);
        }
    }
}