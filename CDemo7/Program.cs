/*

 */

using System;
using System.Diagnostics;
using System.Linq;
using System.Text;
using OmniBean.PowerCrypt4;

namespace CDemo7
{
    internal class Program
    {
        public static void Main(string[] args)
        {
            const int rsaKeySize = 728; //Smaller key sizes are easier to generate while testing
            var prsa = new PowerRSA(rsaKeySize, PowerRSA.PHashAlgorithm.SHA256);
            const string p = "this is n";
            var c = prsa.EncryptStringWithPublicKey(p);
            Console.WriteLine(c);
            var d = prsa.DecryptStringWithPrivateKey(c);
            Console.WriteLine(d);
            var x = prsa.PublicKey;
            Console.WriteLine("RSAProvider Data: " + prsa.PrivateKey);
            Console.WriteLine("Exporting Private key to PKCS format:");
            var priPemKey = RSAExtensions.ConvertPrivateKeyToPKCS(prsa);
            Console.WriteLine(priPemKey);
            Console.Write("PKCS Signing...");
            const string signData = "Hello, World!";
            var signature = RSAExtensions.SignWithPKCSPrivateKey(signData, prsa);
            Console.WriteLine(signature);
            Console.Write("Verifying...");
            var verification = RSAExtensions.VerifyWithPKCSPublicKey(signData, signature, prsa);
            Console.WriteLine(verification);

            prsa.Dispose();

            var pub = new PowerRSA(x, rsaKeySize, PowerRSA.PHashAlgorithm.SHA256);
            var e = pub.EncryptStringWithPublicKey(p);
            var d2 = prsa.DecryptStringWithPrivateKey(e);
            Console.WriteLine(d2);
            pub.Dispose();
            Console.WriteLine(e);
            const string k = "1234";
            var a1 = PowerAES.Encrypt(p, k);
            Console.WriteLine(a1);
            var d1 = PowerAES.Decrypt(a1, k);
            Console.WriteLine(d1);
            Console.WriteLine(PowerAES.SHA512Hash(p));

            Console.WriteLine("Testing encryption directly on bytes...");
            byte[] salt = AESProvider.GenerateRandomBytes(24);
            byte[] key = AESProvider.DeriveKeyFromPassphrase("monkey", salt);
            var iv = AESProvider.GenerateRandomBytes(16); //256-bit IV
            byte[] plaintextBytes = Encoding.UTF8.GetBytes("Hi I am a monkey");
            byte[] encryptedBytes = AESProvider.EncryptBytes(plaintextBytes, key, iv);
            byte[] decryptedBytes = AESProvider.DecryptBytes(iv, salt, encryptedBytes, key);
            Debug.Assert(decryptedBytes.SequenceEqual(plaintextBytes));
            Console.WriteLine("Hash Test");
            var hash = HashUtils.SHA512(k);
            Console.WriteLine(hash);
            Console.WriteLine("Demo completed");
            Console.ReadKey();
        }
    }
}