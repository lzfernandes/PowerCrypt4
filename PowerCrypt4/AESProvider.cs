using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace OmniBean.PowerCrypt4
{
    /// <summary>
    /// An internal AES class. Use the PowerAES class for more high-level operations
    /// </summary>
    public class AESProvider
    {
        #region Public Fields

        public int IterationCount { get; } = 2000;
        public int KeyLengthBits { get; } = 256;
        public int SaltLength { get; } = 24;

        #endregion Public Fields

        #region Private Fields

        //Salt length in bytes
        //Passkey iterations
        private readonly RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();

        #endregion Private Fields

        #region Public Methods

        public static string HexString(byte[] bytes)
        {
            var sBuilder = new StringBuilder();
            foreach (var t in bytes)
            {
                sBuilder.Append(t.ToString("x2"));
            }
            return sBuilder.ToString();
        }

        public string CalculateMD5Hash(string input)
        {
            try
            {
                var md5 = MD5.Create();
                var inputBytes = Encoding.UTF8.GetBytes(input);
                var hash = md5.ComputeHash(inputBytes);
                return HexString(hash);
            }
            catch (Exception ex)
            {
                throw new CryptographicException("Operation Failed.", ex);
            }
        }

        public string CalculateMD5HashFile(string fileName)
        {
            try
            {
                var md5 = MD5.Create();
                var inputBytes = File.ReadAllBytes(fileName);
                var hash = md5.ComputeHash(inputBytes);
                return HexString(hash);
            }
            catch (Exception ex)
            {
                throw new CryptographicException("Operation Failed.", ex);
            }
        }

        public string CalculateSHA512Hash(string input)
        {
            try
            {
                var sha512 = SHA512.Create();
                var inputBytes = Encoding.UTF8.GetBytes(input);
                var hash = sha512.ComputeHash(inputBytes);
                return HexString(hash);
            }
            catch (Exception ex)
            {
                throw new CryptographicException("Operation Failed.", ex);
            }
        }

        public string CalculateSHA512HashFile(string fileName)
        {
            try
            {
                var sha512 = SHA512.Create();
                var inputBytes = File.ReadAllBytes(fileName);
                var hash = sha512.ComputeHash(inputBytes);
                return HexString(hash);
            }
            catch (Exception ex)
            {
                throw new CryptographicException("Operation Failed.", ex);
            }
        }

        public byte[] DecryptBytes(byte[] iv, byte[] salt, byte[] ciphertextBytes, byte[] key)
        {
            // Decrypt
            var plaintext = DoCryptoOperation(ciphertextBytes, key, iv, false);
            return plaintext;
        }

        public string DecryptString(string ciphertext, string passphrase)
        {
            try
            {
                var inputs = ciphertext.Split(":".ToCharArray(), 3);
                var iv = Convert.FromBase64String(inputs[0]); // Extract the IV
                var salt = Convert.FromBase64String(inputs[1]); // Extract the salt
                var ciphertextBytes = Convert.FromBase64String(inputs[2]); // Extract the ciphertext
                // Derive the password from the supplied passphrase and extracted salt
                var key = DeriveKeyFromPassphrase(passphrase, salt);

                var plaintext = DecryptBytes(iv, salt, ciphertextBytes, key);

                // Return the decrypted string
                return Encoding.UTF8.GetString(plaintext);
            }
            catch (Exception ex)
            {
                throw new CryptographicException("Key did not match the ciphertext.", ex);
            }
        }

        public byte[] EncryptBytes(byte[] plaintext, byte[] key, byte[] iv)
        {
            // Encrypt
            var ciphertext = DoCryptoOperation(plaintext, key, iv, true);
            return ciphertext;
        }

        public string EncryptString(string plaintext, string passphrase)
        {
            try
            {
                var salt = GenerateRandomBytes(SaltLength); // Random salt
                var iv = GenerateRandomBytes(16); // AES always uses a 128-bit block size
                var key = DeriveKeyFromPassphrase(passphrase, salt); // Derive the password from the passphrase

                var ciphertext = EncryptBytes(Encoding.UTF8.GetBytes(plaintext), key, iv);

                // Return the formatted string
                return
                    $"{Convert.ToBase64String(iv)}:{Convert.ToBase64String(salt)}:{Convert.ToBase64String(ciphertext)}";
            }
            catch (Exception ex)
            {
                throw new CryptographicException("Cryptographic error while Encrypting.", ex);
            }
        }

        public byte[] GenerateRandomBytes(int lengthBytes)
        {
            var bytes = new byte[lengthBytes];
            rng.GetBytes(bytes);
            return bytes;
        }

        #endregion Public Methods

        #region Private Methods

        public byte[] DeriveKeyFromPassphrase(string passphrase, byte[] salt)
        {
            var keyDerivationFunction = new Rfc2898DeriveBytes(passphrase, salt, IterationCount); //PBKDF2
            return keyDerivationFunction.GetBytes(KeyLengthBits / 8);
        }

        private byte[] DoCryptoOperation(byte[] inputData, byte[] key, byte[] iv, bool encrypt)
        {
            byte[] output;

            using (var aes = new AesCryptoServiceProvider())
            using (var ms = new MemoryStream())
            {
                aes.Mode = CipherMode.CBC; //Explicitly set mode

                var cryptoTransform = encrypt ? aes.CreateEncryptor(key, iv) : aes.CreateDecryptor(key, iv);

                try
                {
                    using (var cs = new CryptoStream(ms, cryptoTransform, CryptoStreamMode.Write))
                    {
                        cs.Write(inputData, 0, inputData.Length);
                    }
                    output = ms.ToArray();
                }
                catch
                {
                    output = new byte[0];
                }
            }

            return output;
        }

        #endregion Private Methods
    }
}