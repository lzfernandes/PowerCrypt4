using System;
using System.IO;
using System.Text;
using OmniBean.PowerCrypt4.Utilities;
using System.Security.Cryptography;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.OpenSsl;

namespace OmniBean.PowerCrypt4
{
    /// <summary>
    /// Extensions for PowerRSA
    /// </summary>
    public static class RSAExtensions
    {
    	/// <summary>
    	/// Generates a PKCS private key from the PowerRSA object
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
	            pemWriter.WriteObject (pemObj);
	            pkcs8Out.Close();
				outputPem = sw.ToString();
            }
			return outputPem;
        }
    }
}