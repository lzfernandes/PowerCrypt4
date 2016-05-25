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

            Console.WriteLine("Testing AES encryption on strings...");
            var plaintextString = "Hi i like pie";
            var password = "monkeys like cupcakes! this is a random passphrase!";
            var encryptedString = PowerAES.Encrypt(plaintextString, password);
            var decryptedString = PowerAES.Decrypt(encryptedString, password);
            Debug.Assert(decryptedString == plaintextString);

            Console.WriteLine("Testing AES encryption directly on bytes...");
            var aesProvider = new AESProvider();
            var salt = aesProvider.GenerateRandomBytes(24);
            var key = aesProvider.DeriveKeyFromPassphrase("monkey", salt);
            var iv = aesProvider.GenerateRandomBytes(16); //128-bit IV
            var plaintextBytes = Encoding.UTF8.GetBytes("Hi I am a monkey");
            var encryptedBytes = aesProvider.EncryptBytes(plaintextBytes, key, iv);
            var decryptedBytes = aesProvider.DecryptBytes(iv, salt, encryptedBytes, key);
            Debug.Assert(decryptedBytes.SequenceEqual(plaintextBytes));
            Console.WriteLine("Hash Test");
            var hash = HashUtils.SHA512(k);
            Console.WriteLine(hash);
            Console.WriteLine("Demo completed");
            Console.ReadKey();
        }
    }
}
