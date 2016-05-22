using System.IO;
using System.Security.Cryptography;

namespace OmniBean.PowerCrypt4
{
    /// <summary>
    ///     A class providing AES encryption and some hash utilities
    /// </summary>
    public static class PowerAES
    {
        #region Public Fields

        public static readonly AESProvider AESCryptoProvider;

        #endregion Public Fields

        #region Public Constructors

        static PowerAES()
        {
            AESCryptoProvider = new AESProvider();
        }

        #endregion Public Constructors

        #region Public Methods

        /// <summary>
        ///     Decrypt an AES encrypted ciphertext (previously encrypted with the Encrypt method) using a password.
        /// </summary>
        /// <param name="ciphertext">The encrypted text (ciphertext).</param>
        /// <param name="password">The password for the encryption.</param>
        /// <returns>The original unencrypted text or "" if password and ciphertext don't match.</returns>
        public static string Decrypt(string ciphertext, string password)
        {
            return AESCryptoProvider.DecryptString(ciphertext, password);
        }

        /// <summary>
        ///     Encrypt some text using AES encryption and a password.
        /// </summary>
        /// <param name="plaintext">The text to encrypt.</param>
        /// <param name="password">The password for the encryption.</param>
        /// <returns>The encrypted text (ciphertext).</returns>
        public static string Encrypt(string plaintext, string password)
        {
            return AESCryptoProvider.EncryptString(plaintext, password);
        }

        public static string GenerateRandomString(int length)
        {
            return AESProvider.HexString(AESCryptoProvider.GenerateRandomBytes(length));
        }

        /// <summary>
        ///     Create an MD5 hash of a text input (http://wikipedia.org/wiki/MD5).
        ///     This 32 character hash is recommended where a general or shorter hash is required (password or data integrity).
        /// </summary>
        /// <param name="text">A text or password to create a hash.</param>
        /// <returns>The 32 character hex MD5 Hash.</returns>
        public static string MD5Hash(string text)
        {
            return AESCryptoProvider.CalculateMD5Hash(text);
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
            return AESCryptoProvider.CalculateMD5HashFile(fileName);
        }

        /// <summary>
        ///     Create a SHA2-512 hash of a text input.
        ///     This 128 character hash is recommended for the most secure password encryption.
        /// </summary>
        /// <param name="password">A text to create a hash (often a password).</param>
        /// <returns>The 128 character hex SHA512 Hash.</returns>
        public static string SHA512Hash(string password)
        {
            return AESCryptoProvider.CalculateSHA512Hash(password);
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
            return AESCryptoProvider.CalculateSHA512HashFile(fileName);
        }

        #endregion Public Methods
    }
}