/*

 */

using System;
using OmniBean.PowerCrypt4;

namespace CDemo7
{
    internal class Program
    {
        public static void Main(string[] args)
        {
			int rsaKeySize = 728;
            PowerRSA prsa = new PowerRSA(rsaKeySize, PowerRSA.PHashAlgorithm.SHA256);
            string p = "this is n";
            string c = prsa.EncryptStringWithPublicKey(p);
            Console.WriteLine(c);
            string d = prsa.DecryptStringWithPrivateKey(c);
            Console.WriteLine(d);
            string x = prsa.PublicKey;
			Console.WriteLine("RSAProvider Data: "+prsa.PrivateKey);
			Console.WriteLine("Exporting Private key to PKCS format:");
			string priPemKey = RSAExtensions.ConvertPrivateKeyToPKCS(prsa);
			Console.WriteLine(priPemKey);
			Console.Write("PKCS Signing...");
			string signData = "Hello, World!";
			string signature = RSAExtensions.SignWithPKCSPrivateKey(signData, prsa);
			Console.WriteLine(signature);
			Console.Write("Verifying...");
			bool verification = RSAExtensions.VerifyWithPKCSPublicKey(signData, signature, prsa);
			Console.WriteLine(verification);
			
            prsa.Dispose();
            
            PowerRSA pub = new PowerRSA(x, rsaKeySize, PowerRSA.PHashAlgorithm.SHA256);
            string e = pub.EncryptStringWithPublicKey(p);
            string d2 = prsa.DecryptStringWithPrivateKey(e);
            Console.WriteLine(d2);
            pub.Dispose();
            Console.WriteLine(e);
            string k = "1234";
            string a1 = PowerAES.Encrypt(p, k);
            Console.WriteLine(a1);
            string d1 = PowerAES.Decrypt(a1, k);
            Console.WriteLine(d1);
            Console.WriteLine(PowerAES.SHA512Hash(p));
            Console.ReadKey();
            /*
			Console.WriteLine("PowerCrypt4");
			int keyLength = 1024;
			RSACryptoServiceProvider csp = new RSACryptoServiceProvider(keyLength);
            string rsaKeyInfo = csp.ToXmlString(true).Replace("><", ">\r\n<");
			RSAProvider rsa = new RSAProvider(rsaKeyInfo, keyLength);
			string plaintext = "encryptme";
			byte[] CTX = rsa.Encrypt(Encoding.UTF8.GetBytes(plaintext), true, true);
			string CipherText = Convert.ToBase64String(CTX);
			Console.WriteLine(CipherText);
			byte[] PTX = rsa.Decrypt(CTX, false, true);
			string DecryptedString = Encoding.UTF8.GetString(PTX);
			Console.WriteLine(DecryptedString);
			Console.ReadKey(true);
			*/
            Console.WriteLine("Hash Test");
            string hash = HashUtils.SHA512(k);
            Console.WriteLine(hash);
        }
    }
}