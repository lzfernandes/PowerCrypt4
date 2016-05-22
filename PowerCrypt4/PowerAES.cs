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

        public static int IterationCount = 2000;
        public static int KeyLengthBits = 256; //AES Key Length in bits
        public static int SaltLength = 24; //Salt for PBKDF2

        #endregion Public Fields

        #region Private Fields

        //Salt length in bytes
        //Passkey iterations
        private static readonly RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();

        #endregion Private Fields

        #region Public Methods

        public static string CalculateMD5Hash(string input)
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

        public static string CalculateMD5HashFile(string fileName)
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

        public static string CalculateSHA512Hash(string input)
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

        public static string CalculateSHA512HashFile(string fileName)
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

        public static byte[] DecryptBytes(byte[] iv, byte[] salt, byte[] ciphertextBytes, byte[] key)
        {
            // Decrypt
            var plaintext = DoCryptoOperation(ciphertextBytes, key, iv, false);
            return plaintext;
        }

        public static string DecryptString(string ciphertext, string passphrase)
        {
            try
            {
                var inputs = ciphertext.Split(":".ToCharArray(), 3);
                var iv = Convert.FromBase64String(inputs[0]); // Extract the IV
                var salt = Convert.FromBase64String(inputs[1]); // Extract the salt
                var ciphertextBytes = Convert.FromBase64String(inputs[2]); // Extract the ciphertext
                                                                           // Derive the key from the supplied passphrase and extracted salt
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

        public static byte[] EncryptBytes(byte[] plaintext, byte[] key, byte[] iv)
        {
            // Encrypt
            var ciphertext = DoCryptoOperation(plaintext, key, iv, true);
            return ciphertext;
        }

        public static string EncryptString(string plaintext, string passphrase)
        {
            try
            {
                var salt = GenerateRandomBytes(SaltLength); // Random salt
                var iv = GenerateRandomBytes(16); // AES always uses a 128-bit block size
                var key = DeriveKeyFromPassphrase(passphrase, salt); // Derive the key from the passphrase

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

        public static byte[] GenerateRandomBytes(int lengthBytes)
        {
            var bytes = new byte[lengthBytes];
            rng.GetBytes(bytes);
            return bytes;
        }

        public static string HexString(byte[] bytes)
        {
            var sBuilder = new StringBuilder();
            foreach (var t in bytes)
            {
                sBuilder.Append(t.ToString("x2"));
            }
            return sBuilder.ToString();
        }

        #endregion Public Methods

        #region Private Methods

        public static byte[] DeriveKeyFromPassphrase(string passphrase, byte[] salt)
        {
            var keyDerivationFunction = new Rfc2898DeriveBytes(passphrase, salt, IterationCount); //PBKDF2
            return keyDerivationFunction.GetBytes(KeyLengthBits / 8);
        }

        private static byte[] DoCryptoOperation(byte[] inputData, byte[] key, byte[] iv, bool encrypt)
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

    /// <summary>
    ///     A class providing AES encryption and some hash utilities
    /// </summary>
    public class PowerAES
    {
        #region Public Methods

        /// <summary>
        ///     Decrypt an AES encrypted cipher (previously encrypted) using a password key.
        /// </summary>
        /// <param name="cipher">The encrypted text (cipher).</param>
        /// <param name="password">The password key for the encryption.</param>
        /// <returns>The original unencrypted text or "" if password and cipher don't match.</returns>
        public static string Decrypt(string cipher, string password)
        {
            return AESProvider.DecryptString(cipher, password);
        }

        /// <summary>
        ///     Encrypt some text using AES encryption and a password key.
        /// </summary>
        /// <param name="plaintext">The text to encrypt.</param>
        /// <param name="key">The password key for the encryption.</param>
        /// <returns>The encrypted text (cipher).</returns>
        public static string Encrypt(string plaintext, string key)
        {
            return AESProvider.EncryptString(plaintext, key);
        }

        public static string GenerateRandomString(int length)
        {
            return AESProvider.HexString(AESProvider.GenerateRandomBytes(length));
        }

        /// <summary>
        ///     Create an MD5 hash of a text input (http://wikipedia.org/wiki/MD5).
        ///     This 32 character hash is recommended where a general or shorter hash is required (password or data integrity).
        /// </summary>
        /// <param name="text">A text or password to create a hash.</param>
        /// <returns>The 32 character hex MD5 Hash.</returns>
        public static string MD5Hash(string text)
        {
            return AESProvider.CalculateMD5Hash(text);
        }

        /// <summary>
        ///     Create an MD5 hash of a file.
        ///     This 32 character hash is for file data integrity checks (e.g. a file contents is unchanged).
        /// </summary>
        /// <param name="fileName">The full path to a file to get the hash.</param>
        /// <returns>The 32 character hex MD5 Hash.</returns>
        public static string MD5HashFile(string fileName)
        {
            if (!File.Exists(fileName))
            {
                //Utilities.OnFileError(Utilities.GetCurrentMethod(), fileName);
                throw new CryptographicException("File does not exist.");
            }
            return AESProvider.CalculateMD5HashFile(fileName);
        }

        /// <summary>
        ///     Create a SHA2-512 hash of a text input.
        ///     This 128 character hash is recommended for the most secure password encryption.
        /// </summary>
        /// <param name="password">A text to create a hash (often a password).</param>
        /// <returns>The 128 character hex SHA512 Hash.</returns>
        public static string SHA512Hash(string password)
        {
            return AESProvider.CalculateSHA512Hash(password);
        }

        /// <summary>
        ///     Create an SHA512 hash of a file.
        /// </summary>
        /// <param name="fileName">The full path to a file to get the hash.</param>
        /// <returns>The SHA512 Hash.</returns>
        public static string SHA512HashFile(string fileName)
        {
            if (!File.Exists(fileName))
            {
                //Utilities.OnFileError(Utilities.GetCurrentMethod(), fileName);
                throw new CryptographicException("File does not exist.");
            }
            return AESProvider.CalculateSHA512HashFile(fileName);
        }

        #endregion Public Methods
    }
}