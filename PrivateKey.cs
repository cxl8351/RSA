///Author: Christopher Lee
using System.Collections.Generic;

namespace Messenger {
    /// <summary>
    /// PrivateKey object representation
    /// </summary>
    internal class PrivateKey {
        public List<string> emails { get; set; }
        public string key { get; set; }
    }
}