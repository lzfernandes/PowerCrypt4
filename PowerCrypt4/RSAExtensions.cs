﻿using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace OmniBean.PowerCrypt4
{
    /// <summary>
    ///     Extensions for PowerRSA
    /// </summary>
    public static class RSAExtensions
    {
        /// <summary>
        ///     Generates a PKCS private key from the PowerRSA object
        /// </summary>
        /// <param name="prsa"></param>
        /// <returns></returns>
        public static string ConvertPrivateKeyToPKCS(PowerRSA prsa)
        {
            var rsa = RSA.Create();
            rsa.FromXmlString(prsa.PrivateKey);
            var bcKeyPair = DotNetUtilities.GetRsaKeyPair(rsa);
            var pkcs8Gen = new Pkcs8Generator(bcKeyPair.Private);
            var pemObj = pkcs8Gen.Generate();
            string outputPem;
            using (var sw = new StringWriter())
            {
                var pkcs8Out = sw;
                var pemWriter = new PemWriter(pkcs8Out);
                pemWriter.WriteObject(pemObj);
                pkcs8Out.Close();
                outputPem = sw.ToString();
            }
            return outputPem;
        }

        public static string SignWithPKCSPrivateKey(string plaintext, PowerRSA prsa)
        {
            var signer = SignerUtilities.GetSigner("SHA256withRSA");
            var rsa = RSA.Create();
            rsa.FromXmlString(prsa.PrivateKey);
            var bcKeyPair = DotNetUtilities.GetRsaKeyPair(rsa);
            signer.Init(true, bcKeyPair.Private);
            var byteplaintext = Encoding.UTF8.GetBytes(plaintext);
            signer.BlockUpdate(byteplaintext, 0, byteplaintext.Length);
            var signature = signer.GenerateSignature();
            /* Base 64 encode the sig so its 8-bit clean */
            var signedString = Convert.ToBase64String(signature);
            return signedString;
        }

        public static bool VerifyWithPKCSPublicKey(string message, string expectedSignature, PowerRSA prsa)
        {
            var rsa = RSA.Create();
            rsa.FromXmlString(prsa.PublicKey);
            /* Make the key */
            var key = DotNetUtilities.GetRsaPublicKey(rsa);
            /* Init alg */
            var signer = SignerUtilities.GetSigner("SHA256withRSA");
            /* Populate key */
            signer.Init(false, key);
            /* Get the signature into bytes */
            var expectedSig = Convert.FromBase64String(expectedSignature);
            /* Get the bytes to be signed from the string */
            var msgBytes = Encoding.UTF8.GetBytes(message);
            /* Calculate the signature and see if it matches */
            signer.BlockUpdate(msgBytes, 0, msgBytes.Length);
            return signer.VerifySignature(expectedSig);
        }
    }
}