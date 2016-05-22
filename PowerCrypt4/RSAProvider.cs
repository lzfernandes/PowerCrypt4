using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;

namespace OmniBean.PowerCrypt4
{
    /// <summary>
    ///     The main RSAProvider Class
    /// </summary>
    public class RSAProvider : IDisposable
    {
        private readonly RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
        private readonly RSAProviderParameters rsaParams;

        /// <summary>
        ///     Initialize the RSA class.
        /// </summary>
        /// <param name="rsaParams">Preallocated RSAProviderParameters containing the required keys.</param>
        public RSAProvider(RSAProviderParameters rsaParams)
        {
            this.rsaParams = rsaParams;
            UseCRTForPublicDecryption = true;
        }

        /// <summary>
        ///     Initialize the RSA class from a XML KeyInfo string.
        /// </summary>
        /// <param name="keyInfo">XML Containing Key Information</param>
        /// <param name="ModulusSize">Length of RSA Modulus in bits.</param>
        public RSAProvider(string keyInfo, int ModulusSize)
        {
            rsaParams = RSAProviderUtils.GetRSAProviderParameters(keyInfo, ModulusSize);
            UseCRTForPublicDecryption = true;
        }

        /// <summary>
        ///     Hash Algorithm to be used for OAEP encoding.
        /// </summary>
        public RSAProviderParameters.RSAProviderHashAlgorithm RSAProviderHashAlgorithm
        {
            set { rsaParams.HashAlgorithm = value; }
        }

        /// <summary>
        ///     If True, and if the parameters are available, uses CRT for private key decryption. (Much Faster)
        /// </summary>
        public bool UseCRTForPublicDecryption { get; set; }

        /// <summary>
        ///     Releases all the resources.
        /// </summary>
        public void Dispose()
        {
            rsaParams.Dispose();
        }

        #region PRIVATE FUNCTIONS

        /// <summary>
        ///     Low level RSA Process function for use with private key.
        ///     Should never be used; Because without padding RSA is vulnerable to attacks.  Use with caution.
        /// </summary>
        /// <param name="PlainText">Data to encrypt. Length must be less than Modulus size in octets.</param>
        /// <param name="usePrivate">True to use Private key, else Public.</param>
        /// <returns>Encrypted Data</returns>
        public byte[] RSAProcess(byte[] PlainText, bool usePrivate)
        {
            if (usePrivate && !rsaParams.Has_PRIVATE_Info)
            {
                throw new CryptographicException("RSA Process: Incomplete Private Key Info");
            }

            if ((usePrivate == false) && !rsaParams.Has_PUBLIC_Info)
            {
                throw new CryptographicException("RSA Process: Incomplete Public Key Info");
            }

            BigInteger _E;
            if (usePrivate)
                _E = rsaParams.D;
            else
                _E = rsaParams.E;

            var PT = RSAProviderUtils.OS2IP(PlainText, false);
            var M = BigInteger.ModPow(PT, _E, rsaParams.N);

            if (M.Sign == -1)
                return RSAProviderUtils.I2OSP(M + rsaParams.N, rsaParams.OctetsInModulus, false);
            return RSAProviderUtils.I2OSP(M, rsaParams.OctetsInModulus, false);
        }

        /// <summary>
        ///     Low level RSA Decryption function for use with private key. Uses CRT and is Much faster.
        ///     Should never be used; Because without padding RSA is vulnerable to attacks. Use with caution.
        /// </summary>
        /// <param name="Data">Data to encrypt. Length must be less than Modulus size in octets.</param>
        /// <returns>Encrypted Data</returns>
        public byte[] RSADecryptPrivateCRT(byte[] Data)
        {
            if (rsaParams.Has_PRIVATE_Info && rsaParams.HasCRTInfo)
            {
                var C = RSAProviderUtils.OS2IP(Data, false);

                var M1 = BigInteger.ModPow(C, rsaParams.DP, rsaParams.P);
                var M2 = BigInteger.ModPow(C, rsaParams.DQ, rsaParams.Q);
                var H = (M1 - M2)*rsaParams.InverseQ%rsaParams.P;
                var M = M2 + rsaParams.Q*H;

                if (M.Sign == -1)
                    return RSAProviderUtils.I2OSP(M + rsaParams.N, rsaParams.OctetsInModulus, false);
                return RSAProviderUtils.I2OSP(M, rsaParams.OctetsInModulus, false);
            }
            throw new CryptographicException("RSA Decrypt CRT: Incomplete Key Info");
        }

        private byte[] RSAProcessEncodePKCS(byte[] Message, bool usePrivate)
        {
            if (Message.Length > rsaParams.OctetsInModulus - 11)
            {
                throw new ArgumentException("Message too long.");
            }
            // RFC3447 : Page 24. [RSAES-PKCS1-V1_5-ENCRYPT ((n, e), M)]
            // EM = 0x00 || 0x02 || PS || 0x00 || Msg

            var PCKSv15_Msg = new List<byte>();

            PCKSv15_Msg.Add(0x00);
            PCKSv15_Msg.Add(0x02);

            var PaddingLength = rsaParams.OctetsInModulus - Message.Length - 3;

            var PS = new byte[PaddingLength];
            rng.GetNonZeroBytes(PS);

            PCKSv15_Msg.AddRange(PS);
            PCKSv15_Msg.Add(0x00);

            PCKSv15_Msg.AddRange(Message);

            return RSAProcess(PCKSv15_Msg.ToArray(), usePrivate);
        }

        /// <summary>
        ///     Mask Generation Function
        /// </summary>
        /// <param name="Z">Initial pseudorandom Seed.</param>
        /// <param name="l">Length of output required.</param>
        /// <returns></returns>
        private byte[] MGF(byte[] Z, int l)
        {
            if (l > Math.Pow(2, 32))
            {
                throw new ArgumentException("Mask too long.");
            }
            var result = new List<byte>();
            for (var i = 0; i <= l/rsaParams.hLen; i++)
            {
                var data = new List<byte>();
                data.AddRange(Z);
                data.AddRange(RSAProviderUtils.I2OSP(i, 4, false));
                result.AddRange(rsaParams.ComputeHash(data.ToArray()));
            }

            if (l <= result.Count)
            {
                return result.GetRange(0, l).ToArray();
            }
            throw new ArgumentException("Invalid Mask Length.");
        }

        private byte[] RSAProcessEncodeOAEP(byte[] M, byte[] P, bool usePrivate)
        {
            //                           +----------+---------+-------+
            //                      DB = |  lHash   |    PS   |   M   |
            //                           +----------+---------+-------+
            //                                          |
            //                +----------+              V
            //                |   seed   |--> MGF ---> XOR
            //                +----------+              |
            //                      |                   |
            //             +--+     V                   |
            //             |00|    XOR <----- MGF <-----|
            //             +--+     |                   |
            //               |      |                   |
            //               V      V                   V
            //             +--+----------+----------------------------+
            //       EM =  |00|maskedSeed|          maskedDB          |
            //             +--+----------+----------------------------+

            var mLen = M.Length;
            if (mLen > rsaParams.OctetsInModulus - 2*rsaParams.hLen - 2)
            {
                throw new ArgumentException("Message too long.");
            }
            var PS = new byte[rsaParams.OctetsInModulus - mLen - 2*rsaParams.hLen - 2];
            //4. pHash = Hash(P),
            var pHash = rsaParams.ComputeHash(P);

            //5. DB = pHash||PS||01||M.
            var _DB = new List<byte>();
            _DB.AddRange(pHash);
            _DB.AddRange(PS);
            _DB.Add(0x01);
            _DB.AddRange(M);
            var DB = _DB.ToArray();

            //6. Generate a random octet string seed of length hLen.
            var seed = new byte[rsaParams.hLen];
            rng.GetBytes(seed);

            //7. dbMask = MGF(seed, k - hLen -1).
            var dbMask = MGF(seed, rsaParams.OctetsInModulus - rsaParams.hLen - 1);

            //8. maskedDB = DB XOR dbMask
            var maskedDB = RSAProviderUtils.XOR(DB, dbMask);

            //9. seedMask = MGF(maskedDB, hLen)
            var seedMask = MGF(maskedDB, rsaParams.hLen);

            //10. maskedSeed = seed XOR seedMask.
            var maskedSeed = RSAProviderUtils.XOR(seed, seedMask);

            //11. EM = 0x00 || maskedSeed || maskedDB.
            var result = new List<byte>();
            result.Add(0x00);
            result.AddRange(maskedSeed);
            result.AddRange(maskedDB);

            return RSAProcess(result.ToArray(), usePrivate);
        }

        private byte[] Decrypt(byte[] Message, byte[] Parameters, bool usePrivate, bool fOAEP)
        {
            var EM = new byte[0];
            try
            {
                if (usePrivate && UseCRTForPublicDecryption && rsaParams.HasCRTInfo)
                {
                    EM = RSADecryptPrivateCRT(Message);
                }
                else
                {
                    EM = RSAProcess(Message, usePrivate);
                }
            }
            catch (CryptographicException ex)
            {
                throw new CryptographicException("Exception while Decryption: " + ex.Message);
            }
            catch
            {
                throw new Exception("Exception while Decryption: ");
            }

            try
            {
                if (fOAEP) //DECODE OAEP
                {
                    if ((EM.Length == rsaParams.OctetsInModulus) && (EM.Length > 2*rsaParams.hLen + 1))
                    {
                        byte[] maskedSeed;
                        byte[] maskedDB;
                        var pHash = rsaParams.ComputeHash(Parameters);
                        if (EM[0] == 0) // RFC3447 Format : http://tools.ietf.org/html/rfc3447
                        {
                            maskedSeed = EM.ToList().GetRange(1, rsaParams.hLen).ToArray();
                            maskedDB =
                                EM.ToList().GetRange(1 + rsaParams.hLen, EM.Length - rsaParams.hLen - 1).ToArray();
                            var seedMask = MGF(maskedDB, rsaParams.hLen);
                            var seed = RSAProviderUtils.XOR(maskedSeed, seedMask);
                            var dbMask = MGF(seed, rsaParams.OctetsInModulus - rsaParams.hLen - 1);
                            var DB = RSAProviderUtils.XOR(maskedDB, dbMask);

                            if (DB.Length >= rsaParams.hLen + 1)
                            {
                                var _pHash = DB.ToList().GetRange(0, rsaParams.hLen).ToArray();
                                var PS_M = DB.ToList().GetRange(rsaParams.hLen, DB.Length - rsaParams.hLen);
                                var pos = PS_M.IndexOf(0x01);
                                if (pos >= 0 && (pos < PS_M.Count))
                                {
                                    var _01_M = PS_M.GetRange(pos, PS_M.Count - pos);
                                    byte[] M;
                                    if (_01_M.Count > 1)
                                    {
                                        M = _01_M.GetRange(1, _01_M.Count - 1).ToArray();
                                    }
                                    else
                                    {
                                        M = new byte[0];
                                    }
                                    var success = true;
                                    for (var i = 0; i < rsaParams.hLen; i++)
                                    {
                                        if (_pHash[i] != pHash[i])
                                        {
                                            success = false;
                                            break;
                                        }
                                    }

                                    if (success)
                                    {
                                        return M;
                                    }
                                    M = new byte[rsaParams.OctetsInModulus]; //Hash Match Failure.
                                    throw new CryptographicException("OAEP Decode Error");
                                }
                                // #3: Invalid Encoded Message Length.
                                throw new CryptographicException("OAEP Decode Error");
                            }
                            // #2: Invalid Encoded Message Length.
                            throw new CryptographicException("OAEP Decode Error");
                        }
                        //OAEP : THIS STADNARD IS NOT IMPLEMENTED
                        throw new CryptographicException("OAEP Decode Error");
                    }
                    // #1: Invalid Encoded Message Length.
                    throw new CryptographicException("OAEP Decode Error");
                }
                if (EM.Length >= 11)
                {
                    if ((EM[0] == 0x00) && (EM[1] == 0x02))
                    {
                        var startIndex = 2;
                        var PS = new List<byte>();
                        for (var i = startIndex; i < EM.Length; i++)
                        {
                            if (EM[i] != 0)
                            {
                                PS.Add(EM[i]);
                            }
                            else
                            {
                                break;
                            }
                        }

                        if (PS.Count >= 8)
                        {
                            var DecodedDataIndex = startIndex + PS.Count + 1;
                            if (DecodedDataIndex < EM.Length - 1)
                            {
                                var DATA = new List<byte>();
                                for (var i = DecodedDataIndex; i < EM.Length; i++)
                                {
                                    DATA.Add(EM[i]);
                                }
                                return DATA.ToArray();
                            }
                            return new byte[0];
                            //throw new CryptographicException("PKCS v1.5 Decode Error #4: No Data");
                        }
                        // #3: Invalid Key / Invalid Random Data Length
                        throw new CryptographicException("PKCS v1.5 Decode Error");
                    }
                    // #2: Invalid Key / Invalid Identifiers
                    throw new CryptographicException("PKCS v1.5 Decode Error");
                }
                // #1: Invalid Key / PKCS Encoding
                throw new CryptographicException("PKCS v1.5 Decode Error");
            }
            catch (CryptographicException ex)
            {
                throw new CryptographicException("Exception while decoding: " + ex.Message);
            }
            catch
            {
                throw new CryptographicException("Exception while decoding");
            }
        }

        #endregion PRIVATE FUNCTIONS

        #region PUBLIC FUNCTIONS

        /// <summary>
        ///     Encrypts the given message with RSA, performs OAEP Encoding.
        /// </summary>
        /// <param name="Message">
        ///     Message to Encrypt. Maximum message length is (ModulusLengthInOctets - 2 * HashLengthInOctets -
        ///     2)
        /// </param>
        /// <param name="OAEP_Params">Optional OAEP parameters. Normally Empty. But, must match the parameters while decryption.</param>
        /// <param name="usePrivate">True to use Private key for encryption. False to use Public key.</param>
        /// <returns>Encrypted message.</returns>
        public byte[] Encrypt(byte[] Message, byte[] OAEP_Params, bool usePrivate)
        {
            return RSAProcessEncodeOAEP(Message, OAEP_Params, usePrivate);
        }

        /// <summary>
        ///     Encrypts the given message with RSA.
        /// </summary>
        /// <param name="Message">
        ///     Message to Encrypt. Maximum message length is For OAEP [ModulusLengthInOctets - (2 *
        ///     HashLengthInOctets) - 2] and for PKCS [ModulusLengthInOctets - 11]
        /// </param>
        /// <param name="usePrivate">True to use Private key for encryption. False to use Public key.</param>
        /// <param name="fOAEP">True to use OAEP encoding (Recommended), False to use PKCS v1.5 Padding.</param>
        /// <returns>Encrypted message.</returns>
        public byte[] Encrypt(byte[] Message, bool usePrivate, bool fOAEP)
        {
            if (fOAEP)
            {
                return RSAProcessEncodeOAEP(Message, new byte[0], usePrivate);
            }
            return RSAProcessEncodePKCS(Message, usePrivate);
        }

        /// <summary>
        ///     Encrypts the given message using RSA Public Key.
        /// </summary>
        /// <param name="Message">
        ///     Message to Encrypt. Maximum message length is For OAEP [ModulusLengthInOctets - (2 *
        ///     HashLengthInOctets) - 2] and for PKCS [ModulusLengthInOctets - 11]
        /// </param>
        /// <param name="fOAEP">True to use OAEP encoding (Recommended), False to use PKCS v1.5 Padding.</param>
        /// <returns>Encrypted message.</returns>
        public byte[] Encrypt(byte[] Message, bool fOAEP)
        {
            if (fOAEP)
            {
                return RSAProcessEncodeOAEP(Message, new byte[0], false);
            }
            return RSAProcessEncodePKCS(Message, false);
        }

        /// <summary>
        ///     Decrypts the given RSA encrypted message.
        /// </summary>
        /// <param name="Message">The encrypted message.</param>
        /// <param name="usePrivate">True to use Private key for decryption. False to use Public key.</param>
        /// <param name="fOAEP">True to use OAEP.</param>
        /// <returns>Encrypted byte array.</returns>
        public byte[] Decrypt(byte[] Message, bool usePrivate, bool fOAEP)
        {
            return Decrypt(Message, new byte[0], usePrivate, fOAEP);
        }

        /// <summary>
        ///     Decrypts the given RSA encrypted message.
        /// </summary>
        /// <param name="Message">The encrypted message.</param>
        /// <param name="OAEP_Params">Parameters to the OAEP algorithm (Must match the parameter while Encryption).</param>
        /// <param name="usePrivate">True to use Private key for decryption. False to use Public key.</param>
        /// <returns>Encrypted byte array.</returns>
        public byte[] Decrypt(byte[] Message, byte[] OAEP_Params, bool usePrivate)
        {
            return Decrypt(Message, OAEP_Params, usePrivate, true);
        }

        /// <summary>
        ///     Decrypts the given RSA encrypted message using Private key.
        /// </summary>
        /// <param name="Message">The encrypted message.</param>
        /// <param name="fOAEP">True to use OAEP.</param>
        /// <returns>Encrypted byte array.</returns>
        public byte[] Decrypt(byte[] Message, bool fOAEP)
        {
            return Decrypt(Message, new byte[0], true, fOAEP);
        }

        #endregion PUBLIC FUNCTIONS
    }
}