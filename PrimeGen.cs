///Author: Christopher Lee
using System;
using System.Diagnostics;
using System.Numerics;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace Messenger {
    
    
    class PrimeGen {
        /// <summary>
        /// Generates a random number of size "bitsGiven", "countGiven" times.
        /// </summary>
        /// <param name="bitsGiven">The size of the number.</param>
        /// <param name="countGiven">How many times it is to be generated.</param>
        internal BigInteger ParallelPrimeGen(int bitsGiven, int countGiven) {
            var po = new ParallelOptions();
            var src = new CancellationTokenSource();
            po.CancellationToken = src.Token;
            po.MaxDegreeOfParallelism = Environment.ProcessorCount;
            BigInteger value = 0;
            
            var timesCounted = 0;
            try {
                Parallel.For(0, Int32.MaxValue, po, (i, state) => {
                    var byteArr = new byte[bitsGiven / 8];
                    var rngCsp = new RNGCryptoServiceProvider();
                    rngCsp.GetBytes(byteArr);
                    BigInteger num = new BigInteger(byteArr);

                    if (num.IsProbablyPrime()) {
                        value = num;
                        Interlocked.Increment(ref timesCounted);
                    }
                    
                    if (timesCounted >= countGiven) {
                        src.Cancel();
                    }
                });
            }
            catch { }

            return value;
        }
        
    }
    
    /// <summary>
    /// Extension static class to hold isProbablyPrime()
    /// </summary>
    internal static class PrimeChecker {
        /// <summary>
        /// Checks to see if a number is (probably) prime.
        /// </summary>
        /// <param name="value"></param>
        /// <param name="witnesses"></param>
        /// <returns>true if is probably prime, false if not probably prime</returns>
        internal static Boolean IsProbablyPrime(this BigInteger value, int witnesses = 10) {
            if (value <= 1) return false;
            if (witnesses <= 0) witnesses = 10;
            BigInteger d = value - 1;
            int s = 0;
            while (d % 2 == 0) {
                d /= 2;
                s += 1;
            }

            Byte[] bytes = new Byte[value.ToByteArray().LongLength];
            BigInteger a;
            for (int i = 0; i < witnesses; i++) {
                do {
                    var Gen = new Random();
                    Gen.NextBytes(bytes);
                    a = new BigInteger(bytes);
                } while (a < 2 || a >= value - 2);
                BigInteger x = BigInteger.ModPow(a, d, value);
                if (x == 1 || x == value - 1) continue;
                for (int r = 1; r < s; r++) {
                    x = BigInteger.ModPow(x, 2, value);
                    if (x == 1) return false;
                    if (x == value - 1) break;
                }
                if (x != value - 1) return false;
            }
            return true;
        }
    }
}