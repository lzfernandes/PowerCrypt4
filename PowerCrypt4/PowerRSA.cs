using System;
using System.Security.Cryptography;
using System.Text;

namespace OmniBean.PowerCrypt4
{
    public class PowerRSA
    {
        public enum PHashAlgorithm
        {
            SHA1 = 0,
            SHA256 = 1,
            SHA512 = 2
        }

        private int KeySize;
        private RSAProvider rsaProvider;

        /// <summary>
        ///     Initializes the RSA Provider from an RSACryptoServiceProvider instance
        /// </summary>
        /// <param name="cryptoServiceProviderInstance">The RSACryptoServiceProvider instance.</param>
        /// \
        /// <returns>PowerRSA object initialized with al RSACryptoServiceProvider instance.</returns>
        public PowerRSA(RSACryptoServiceProvider cryptoServiceProviderInstance)
        {
            CryptoServiceProvider = cryptoServiceProviderInstance;
            rsaProvider.RSAProviderHashAlgorithm = RSAProviderParameters.RSAProviderHashAlgorithm.SHA256;
        }

        /// <summary>
        ///     Initializes the RSA Provider with either only a public key or a public/private key pair.
        /// </summary>
        /// <param name="rsaKeyInfo">The XML string to initialize the RSA Provider with.</param>
        /// <param name="keySize">The length of the key.</param>
        /// <returns>PowerRSA object initialized with XML string.</returns>
        public PowerRSA(string rsaKeyInfo, int keySize)
        {
            KeySize = keySize;
            var keyLength = keySize;
            CryptoServiceProvider = new RSACryptoServiceProvider(keyLength);
            CryptoServiceProvider.FromXmlString(rsaKeyInfo);
            rsaProvider = new RSAProvider(rsaKeyInfo, keyLength);
            rsaProvider.RSAProviderHashAlgorithm = RSAProviderParameters.RSAProviderHashAlgorithm.SHA256;
        }

        /// <summary>
        ///     Initializes the RSA Provider with either only a public key or a public/private key pair.
        /// </summary>
        /// <param name="rsaKeyInfo">The XML string to initialize the RSA Provider with.</param>
        /// <param name="keySize">The length of the key.</param>
        /// <param name="hashAlgorithm">The hash algorithm to use.</param>
        /// <returns>PowerRSA object initialized with XML string.</returns>
        public PowerRSA(string rsaKeyInfo, int keySize, PHashAlgorithm hashAlgorithm)
        {
            KeySize = keySize;
            var keyLength = keySize;
            CryptoServiceProvider = new RSACryptoServiceProvider(keyLength);
            CryptoServiceProvider.FromXmlString(rsaKeyInfo);
            rsaProvider = new RSAProvider(rsaKeyInfo, keyLength);
            switch ((int) hashAlgorithm)
            {
                case 0:
                    rsaProvider.RSAProviderHashAlgorithm = RSAProviderParameters.RSAProviderHashAlgorithm.SHA1;
                    break;

                case 1:
                    rsaProvider.RSAProviderHashAlgorithm = RSAProviderParameters.RSAProviderHashAlgorithm.SHA256;
                    break;

                case 2:
                    rsaProvider.RSAProviderHashAlgorithm = RSAProviderParameters.RSAProviderHashAlgorithm.SHA512;
                    break;
            }
        }

        /// <summary>
        ///     Initializes the RSA Provider.
        /// </summary>
        /// <param name="keySize">The length of the key.</param>
        /// <returns>PowerRSA object.</returns>
        public PowerRSA(int keySize)
        {
            var ha = PHashAlgorithm.SHA256;
            InitRSA(keySize, ha);
        }

        /// <summary>
        ///     Initializes the RSA Provider.
        /// </summary>
        /// <param name="keySize">The length of the key.</param>
        /// <param name="hashAlgorithm">The hash algorithm to use.</param>
        /// <returns>PowerRSA object.</returns>
        public PowerRSA(int keySize, PHashAlgorithm hashAlgorithm)
        {
            InitRSA(keySize, hashAlgorithm);
        }

        public RSACryptoServiceProvider CryptoServiceProvider { get; private set; }

        public string PublicKey
        {
            get { return CryptoServiceProvider.ToXmlString(false); }
        }

        public string PrivateKey
        {
            get { return CryptoServiceProvider.ToXmlString(true); }
        }

        /// <summary>
        ///     Disposes the cryptographic service provider and keeps it from persisting in the CSP Container.
        /// </summary>
        public void Dispose()
        {
            CryptoServiceProvider.PersistKeyInCsp = false;
        }

        private void InitRSA(int keySize, PHashAlgorithm hashAlgorithm)
        {
            KeySize = keySize;
            var keyLength = keySize;
            CryptoServiceProvider = new RSACryptoServiceProvider(keyLength);
            var rsaKeyInfo = CryptoServiceProvider.ToXmlString(true); //.Replace("><", ">\r\n<");
            rsaProvider = new RSAProvider(rsaKeyInfo, keyLength);
            switch ((int) hashAlgorithm)
            {
                case 0:
                    rsaProvider.RSAProviderHashAlgorithm = RSAProviderParameters.RSAProviderHashAlgorithm.SHA1;
                    break;

                case 1:
                    rsaProvider.RSAProviderHashAlgorithm = RSAProviderParameters.RSAProviderHashAlgorithm.SHA256;
                    break;

                case 2:
                    rsaProvider.RSAProviderHashAlgorithm = RSAProviderParameters.RSAProviderHashAlgorithm.SHA512;
                    break;
            }
        }

        public string EncryptStringWithPublicKey(string plainText)
        {
            var CTX = rsaProvider.Encrypt(Encoding.UTF8.GetBytes(plainText), false, true);
            var CipherText = Convert.ToBase64String(CTX);
            return CipherText;
        }

        public string EncryptStringWithPrivateKey(string plainText)
        {
            var CTX = rsaProvider.Encrypt(Encoding.UTF8.GetBytes(plainText), true, true);
            var CipherText = Convert.ToBase64String(CTX);
            return CipherText;
        }

        public string DecryptStringWithPrivateKey(string cipherText)
        {
            var CTX = Convert.FromBase64String(cipherText);
            var PTX = rsaProvider.Decrypt(CTX, true, true);
            var DecryptedString = Encoding.UTF8.GetString(PTX);
            return DecryptedString;
        }

        public string DecryptStringWithPublicKey(string cipherText)
        {
            var CTX = Convert.FromBase64String(cipherText);
            var PTX = rsaProvider.Decrypt(CTX, false, true);
            var DecryptedString = Encoding.UTF8.GetString(PTX);
            return DecryptedString;
        }
    }
}