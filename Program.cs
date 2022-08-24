/// Author: Christopher Lee
/// A program utilizing the RSA cyrptosystem to send crypted messages to others
/// in a isolated area. Highlights of this program involves client-to-server
/// communication, while separating responsibilities, bitwise management, and
/// of course, cryptography.
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Numerics;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using Newtonsoft.Json;
using Formatting = Newtonsoft.Json.Formatting;

namespace Messenger {
    class Program {
        
        /// <summary>
        /// Main method
        /// </summary>
        /// <param name="args"></param>
        /// <returns></returns>
        static int Main(string[] args) {
            Program myProgram = new Program();
            switch (args[0]) {
                case "keyGen":
                    if (args.Length != 2) {
                        Console.WriteLine("Usage: dotnet run <option> <arguments>");
                        return 1;
                    }
                    //keySize is in bits
                    var keysize = Int32.Parse(args[1]);
                    myProgram.keyGen(keysize);
                    break;
                case "sendKey":
                    if (args.Length != 2) {
                        Console.WriteLine("Usage: dotnet run <option> <arguments>");
                        return 1;
                    }
                    myProgram.sendKey(args[1]);
                    break;
                case "getKey":
                    if (args.Length != 2) {
                        Console.WriteLine("Usage: dotnet run <option> <arguments>");
                        return 1;
                    }
                    myProgram.getKey(args[1]);
                    break;
                case "sendMsg":
                    if (args.Length != 3) {
                        Console.WriteLine("Usage: dotnet run <option> <arguments>");
                        return 1;
                    }
                    myProgram.sendMsg(args[1],args[2]);
                    break;
                case "getMsg":
                    if (args.Length != 2) {
                        Console.WriteLine("Usage: dotnet run <option> <arguments>");
                        return 1;
                    }
                    myProgram.getMsg(args[1]);
                    break;
                default:
                    Console.WriteLine("Usage: dotnet run <option> <arguments>");
                    break;
            }
            return 0;
        }

        /// <summary>
        /// this will generate a keypair (public and private keys) and store
        /// them locally on the disk (in files called public.key and private.key respectively),
        /// as base64 encoded keys.
        /// </summary>
        /// <param name="keysize">the size of the key, in bits</param>
        private void keyGen(int keysize) {
            PrimeGen primeGen = new PrimeGen();
            int Psize = keysize / 2;
            var P = primeGen.ParallelPrimeGen(Psize, 1);
            // Generate Q
            var Qsize = keysize - Psize;
            var Q = primeGen.ParallelPrimeGen(Qsize, 1);
            //Generate R
            var R = (P - 1) * (Q - 1);
            // Generate N
            BigInteger N = P * Q;
            // E must be between 3 and R, and have a GCD of 1 with R.
            BigInteger E = 151;
            // Keep randomly generating E until we get a prime number.
            // while (!E.IsProbablyPrime()) {
            //    E = rand.Next(3, (int)R);
            //}
            // Generate D
            BigInteger D = ModInverse.modInverse(E, R);
            
            var NbyteArray = N.ToByteArray();
            var EbyteArray = E.ToByteArray();
            var DbyteArray = D.ToByteArray();
            var publickeyArr = new byte[8 + NbyteArray.Length + EbyteArray.Length];
            var privatekeyArr = new byte[8 + NbyteArray.Length + DbyteArray.Length];
            var eLength = BitConverter.GetBytes(EbyteArray.Length);
            var nLength = BitConverter.GetBytes(NbyteArray.Length);
            var dLength = BitConverter.GetBytes(DbyteArray.Length);
            //var eLength = EbyteArray.Length;
            //var nLength = NbyteArray.Length;
            //var dLength = DbyteArray.Length;

            if (BitConverter.IsLittleEndian) {
                Array.Reverse(eLength);
                Array.Reverse(nLength);
                Array.Reverse(dLength);
            }

            // Counter needed for array indexing
            int idx = 0;
            // Copies the length of E into publickey
            Array.Copy(eLength, 0, publickeyArr, 0, eLength.Length);
            idx += 4;
            
            // Copies the contents of E into publickey
            Array.Copy(EbyteArray, 0, publickeyArr, idx, EbyteArray.Length);
            idx += EbyteArray.Length;
            
            // Copies the length of N into publickey
            Array.Copy(nLength, 0, publickeyArr, idx, nLength.Length);
            idx += 4;
            
            // Copies the contents of N into publickey
            Array.Copy( NbyteArray, 0, publickeyArr, idx, NbyteArray.Length);
            
            idx = 0;
            Array.Copy(dLength, 0, privatekeyArr, 0, dLength.Length);
            idx += 4;
            
            Array.Copy(DbyteArray, 0, privatekeyArr, idx,
                DbyteArray.Length);
            idx += DbyteArray.Length;
            
            Array.Copy(nLength, 0, privatekeyArr, idx, nLength.Length);
            idx += 4;
            
            Array.Copy(NbyteArray, 0, privatekeyArr, idx, NbyteArray.Length);

            var publicKeyString = Convert.ToBase64String(publickeyArr);
            var privateKeyString = Convert.ToBase64String(privatekeyArr);

            var publickeyObj = new Key() {
                email = "", 
                key = publicKeyString
            };

            var privatekeyObj = new PrivateKey() {
                emails = new List<string>(), 
                key = privateKeyString
            };

            //Console.WriteLine("D = {0}", D);
            //Console.WriteLine("N = {0}", N);

            var publickey =
                JsonConvert.SerializeObject(publickeyObj, Formatting.Indented);
            var privatekey =
                JsonConvert.SerializeObject(privatekeyObj, Formatting.Indented);
            
            File.WriteAllText("public.key", publickey);
            File.WriteAllText("private.key", privatekey);
            Console.WriteLine("Key generated");
        }

        /// <summary>
        /// this option sends the public key and to the server. The server will
        /// then register this email address as a valid receiver of messages. The private key will
        /// remain locally. If the server already has a key for this user, it will be overwritten.
        /// SendKey should also update the local system to register the email address as valid
        /// (one for which messages can be decoded).
        /// </summary>
        /// <param name="email">The email that belongs to the key</param>
        private void sendKey(String email) {
            // Since both keys are objects, we have to deserialize in
            // order to get anything valuable.
            var privatekey =
                JsonConvert.DeserializeObject<PrivateKey>(
                    File.ReadAllText("private.key"));
            var publickey =
                JsonConvert.DeserializeObject<Key>(
                    File.ReadAllText("public.key"));
            
            // Set the owner of this publickey
            publickey.email = email;

            // Serialize the publickey so we can send it to the server
            string publickeyObj =
                JsonConvert.SerializeObject(publickey, Formatting.Indented);
            HttpClient client = new HttpClient();
            var response = client.PutAsync(
                "http://kayrun.cs.rit.edu:5000/Key/"
                + email, new StringContent(publickeyObj, Encoding.UTF8,
                    "application/json")).Result;
            var c = response.IsSuccessStatusCode; // Get response

            // Does the privatekey already know about this email?
            if( !privatekey.emails.Contains(email) ) {
                // The privatekey should know which emails it has 
                privatekey.emails.Add(email);
            }

            var privatekeyObj =
                JsonConvert.SerializeObject(privatekey, Formatting.Indented);
            File.WriteAllText("private.key", privatekeyObj);

            // User feedback; end of algorithm
            Console.WriteLine("Key saved");
        }

        /// <summary>
        /// email - this will retrieve a base64 encoded public key for a particular user
        /// (not usually yourself). You will need this key to encode messages for a particular
        /// user. Stored as <email>.key
        /// </summary>
        /// <param name="email">The email to associate the gained key with.</param>
        private void getKey(String email) {
            // gets publickey from server
            HttpClient client = new HttpClient();
            var response = client
                .GetAsync("http://kayrun.cs.rit.edu:5000/Key/" + email).Result;
            var c = response.IsSuccessStatusCode;
            // Get the key from the server
            var content = response.Content.ReadAsStringAsync().Result;
            // deserialize the key so that we get something meaningful
            var serverKey = JsonConvert.DeserializeObject<Key>(content);
            // Serialize it into our local system
            var localKey = JsonConvert.SerializeObject(serverKey, Formatting.Indented);
            File.WriteAllText(email + ".key", localKey);

            // User feedback; end of algorithm.
            Console.WriteLine("Got key.");
        }

        /// <summary>
        /// email plaintext - this will base64 encode a message for a user in the to
        /// field. If you do not have a public key for that particular user,
        /// an error occurs.
        /// </summary>
        /// <param name="email">The email to send the message to.</param>
        /// <param name="plaintext">The message to be sent.</param>
        private int sendMsg(String email, string plaintext) {

            if (!File.Exists(email + ".key")) {
                Console.WriteLine("Key does not exist for {0}", email);
                return 1;
            }
            
            // 1) Read JSON object
            var emailKey =
                JsonConvert.DeserializeObject<Key>(
                    File.ReadAllText(email + ".key"));

            if (emailKey.key == null) {
                Console.WriteLine("Key does not exist for {0}", email);
                return 1;
            }

            // 2) Extract Base64 encoded key
            var byteKey = Convert.FromBase64String(emailKey.key);
            
            // 3) Get the first four bits and copy it into a temp array
            var tempFourBytes = new byte[4];
            Array.Copy(byteKey, 0, tempFourBytes, 0, 4);

            // 4) Check Endianess
            if (BitConverter.IsLittleEndian) {
                Array.Reverse(tempFourBytes);
            }

            // 5) Convert those bytes to an Int named e
            var e = BitConverter.ToInt32(tempFourBytes, 0);

            // 6) Skip the first 4 bytes, read 'e' number of bytes as E.
            var tempE = new byte[e];
            Array.Copy(byteKey, 4, tempE, 0, e);

            // 7) Convert E to a BigInteger
            BigInteger E = new BigInteger(tempE);

            // 8) Skip 4+e bytes, read 4 bytes sa n, check endianess
            tempFourBytes = new byte[] {0, 0, 0, 0};
            var nLength = 4 + e;
            Array.Copy(byteKey, nLength, tempFourBytes, 0, 4);

            // 8.5) Check Endianess
            if (BitConverter.IsLittleEndian) {
                Array.Reverse(tempFourBytes);
            }
            
            // 9) Convert n to an Int
            var n = BitConverter.ToInt32(tempFourBytes, 0);
            
            // 10) Skip 4 + e + 4 bytes, read 'n' bytes into N
            nLength += 4;
            var tempN = new byte[n];
            Array.Copy(byteKey, nLength, tempN, 0, tempN.Length);
            
            BigInteger N = new BigInteger(tempN);

            //Console.WriteLine("E = {0}", E);
            //Console.WriteLine("N = {0}", N);

            var myText = Encoding.UTF8.GetBytes(plaintext);
            var myTextBig = new BigInteger(myText);
            var cypherText = BigInteger.ModPow(myTextBig, E, N);

            var content = new Content() {
                email = email,
                content = Convert.ToBase64String(cypherText.ToByteArray())
            };
            var contentJson =
                JsonConvert.SerializeObject(content, Formatting.Indented);

            HttpClient client = new HttpClient();
            var response = client
                .PutAsync("http://kayrun.cs.rit.edu:5000/Message/" + email,
                    new StringContent(contentJson, Encoding.UTF8,
                        "application/json")).Result;
            var c = response.IsSuccessStatusCode;

            Console.WriteLine("Message written");
            return 0;
        }

        /// <summary>
        /// this will retrieve the base64 encoded message for a particular user,
        /// while it is possible to download messages for any user, you will only be able to decode
        /// messages for which you have the private key.
        /// </summary>
        /// <param name="email">The email to get the message from.</param>
        /// <returns>1 on exit code, 0 otherwise</returns>
        private int getMsg(string email) {
            HttpClient client = new HttpClient();
            var response = client
                .GetAsync("http://kayrun.cs.rit.edu:5000/Message/" + email)
                .Result;
            response.EnsureSuccessStatusCode();

            var json = response.Content.ReadAsStringAsync().Result;

            var content = JsonConvert.DeserializeObject<Content>(json);

            var privatekey =
                JsonConvert.DeserializeObject<PrivateKey>(
                    File.ReadAllText("private.key"));

            if (!privatekey.emails.Contains(email)) {
                Console.WriteLine("Cannot decode message because {0} does not exist.", email);
                return 1;
            }

            // 2) Extract Base64 encoded key
            var byteKey = Convert.FromBase64String(privatekey.key);
            
            // 3) Get the first four bits and copy it into a temp array
            var tempFourBytes = new byte[4];
            Array.Copy(byteKey, 0, tempFourBytes, 0, 4);

            // 4) Check Endianess
            if (BitConverter.IsLittleEndian) {
                Array.Reverse(tempFourBytes);
            }

            // 5) Convert those bytes to an Int named d
            var d = BitConverter.ToInt32(tempFourBytes, 0);

            // 6) Skip the first 4 bytes, read 'e' number of bytes as E.
            var tempD = new byte[d];
            Array.Copy(byteKey, 4, tempD, 0, tempD.Length);
            if (!BitConverter.IsLittleEndian) {
                Array.Reverse(tempD);
            }
            // 7) Convert E to a BigInteger
            BigInteger D = new BigInteger(tempD);

            // 8) Skip 4+e bytes, read 4 bytes sa n, check endianess
            var nLength = 4 + d;
            tempFourBytes = new byte[] {0, 0, 0, 0};
            Array.Copy(byteKey, nLength, tempFourBytes, 0, 4);

            if (BitConverter.IsLittleEndian) {
                Array.Reverse(tempFourBytes);
            }
            
            // 9) Convert n to an Int
            var n = BitConverter.ToInt32(tempFourBytes, 0);
            
            // 10) Skip 4 + e + 4 bytes, read 'n' bytes into N
            var tempN = new byte[n];
            nLength += 4;
            Array.Copy(byteKey, nLength, tempN, 0, tempN.Length);

            BigInteger N = new BigInteger(tempN);
            
            //Console.WriteLine("D = {0}", D);
            //Console.WriteLine("N = {0}", N);
            
            var myContent = Convert.FromBase64String(content.content);
            var cypherText = new BigInteger(myContent);
            var plaintext = BigInteger.ModPow(cypherText, D, N);
            var textBytes = plaintext.ToByteArray();

            if (!BitConverter.IsLittleEndian) {
               Array.Reverse(textBytes);
            }

            Console.WriteLine(Encoding.UTF8.GetString(textBytes));

            return 0;
        }
        
    }

    /// <summary>
    /// Class holder for modInverse
    /// </summary>
    static class ModInverse {
        /// <summary>
        /// Takes the modInverse of a BigInteger
        /// </summary>
        /// <param name="a"></param>
        /// <param name="n"></param>
        /// <returns></returns>
        public static BigInteger modInverse(BigInteger a, BigInteger n) {
            BigInteger i = n, v = 0, d = 1;
            while (a>0) {
                BigInteger t = i/a, x = a;
                a = i % x;
                i = x;
                x = d;
                d = v - t*x;
                v = x;
            }
            v %= n;
            if (v<0) v = (v+n)%n;
            return v;
        }
    }
    
    
}

