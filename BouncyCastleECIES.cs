using System;
using System.Text;
using System.Diagnostics;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Math;

namespace SomeNamespace
{
    // AES-GCM (Advanced Encryption Standard in Galois/Counter Mode)
    // Classes Storage, PassMan and AddressBook not provided, but their usage is obvious. 
    // AddressBook is used for other's public keys. 
    // PassMan is a just a local private key encryption utility.
    // Refer to method EncryptDecryptTest() for how to use this class, also key-to-string and string-to-key methods are handy.
    // 'myself' and 'them' uniquely identify people, I use email addresses
    // Thanks to Claude.ai for helping write this code!
    internal class BouncyCastleECIES
    {
        static readonly SecureRandom _random = new SecureRandom();
        static readonly string Curve = "secp256r1";

        // return my public key (create public and private keys if they don't yet exist)
        internal static string VerifyMyKey(string myself)
        {
            string storedkey = $"{myself}.public";
            string pubkey = Storage.GetStringValue(storedkey);
            if (!string.IsNullOrEmpty(pubkey))
                return pubkey;

	    // no keys - create and return
            AsymmetricCipherKeyPair keyPair = GenerateKeyPair();
            pubkey = PublicKeyToString((ECPublicKeyParameters)keyPair.Public);
            Storage.SetValue(storedkey, pubkey);

            string myPrivateKey = PrivateKeyToString((ECPrivateKeyParameters)keyPair.Private);
            storedkey = $"{myself}.private";
            Storage.SetValue(storedkey, PassMan.Encode(myPrivateKey));

            return pubkey;
        }

	// before sending encrypted data we need to know if public keys have been exchanged
        internal static void SetTheyHaveOurKey(string myself, string them, bool value)
        {
            string storedkey = $"{myself}->{them}";
            Storage.SetValue(storedkey, value);
        }

        internal static bool TheyHaveOurKey(string myself, string them)
        {
            var storedkey = $"{myself}->{them}";
            return Storage.GetBoolValue(storedkey);
        }

	// this is just a test/demonstration method
        internal static void EncryptDecryptTest()
        {
            AsymmetricCipherKeyPair aliceKeyPair = GenerateKeyPair();
            AsymmetricCipherKeyPair bobKeyPair = GenerateKeyPair();

            string alicePublicKeyString = PublicKeyToString((ECPublicKeyParameters)aliceKeyPair.Public);
            string bobPublicKeyString = PublicKeyToString((ECPublicKeyParameters)bobKeyPair.Public);

            Debug.WriteLine($"Alice's public key: {alicePublicKeyString}");
            Debug.WriteLine($"Bob's public key: {bobPublicKeyString}");

            ECPublicKeyParameters aliceReceivedBobPublicKey = StringToPublicKey(bobPublicKeyString);
            ECPublicKeyParameters bobReceivedAlicePublicKey = StringToPublicKey(alicePublicKeyString);

            string message = "Secret message is here...";
            Debug.WriteLine($"Original: {message}");

            byte[] encrypted = EncryptECIES(Encoding.UTF8.GetBytes(message), aliceReceivedBobPublicKey, (ECPrivateKeyParameters)aliceKeyPair.Private);
            byte[] decrypted = DecryptECIES(encrypted, bobReceivedAlicePublicKey, (ECPrivateKeyParameters)bobKeyPair.Private);

            Debug.WriteLine($"Decrypted: {Encoding.UTF8.GetString(decrypted)}");
        }

        internal static string Encrypt(string myPrivateKey, string theirPublicKey, string content)
        {
            ECPublicKeyParameters recipientPublicKey = StringToPublicKey(theirPublicKey);
            ECPrivateKeyParameters senderPrivateKey = StringToPrivateKey(myPrivateKey);

            byte[] encrypted = EncryptECIES(Encoding.UTF8.GetBytes(content), recipientPublicKey, senderPrivateKey);
            return Convert.ToBase64String(encrypted);
        }

        internal static string Decrypt(string myself, string them, string encryptedContent)
        {
            try
            {
                object theirPublicKey = new AddressBook().GetTheirKey(them);
                if (them == null || string.IsNullOrEmpty(theirPublicKey as string))
                {
                    Logger.Instance.Error("Failed to find key for " + them);
                    return string.Empty;
                }
                ECPublicKeyParameters senderPublicKey = StringToPublicKey(theirPublicKey as string);

                string myPrivateKey = PassMan.Decode(Storage.GetStringValue($"{myself}.private"));
                ECPrivateKeyParameters recipientPrivateKey = StringToPrivateKey(myPrivateKey);

                byte[] encryptedBytes = Convert.FromBase64String(encryptedContent);
                byte[] decrypted = DecryptECIES(encryptedBytes, senderPublicKey, recipientPrivateKey);

                return Encoding.UTF8.GetString(decrypted);
            }
            catch (Exception ex)
            {
                Logger.Instance.Error($"Failed to decrypt message from {them} error {ex.Message}");
                return string.Empty;
            }
        }

        private static ECPublicKeyParameters StringToPublicKey(string publicKeyString)
        {
            byte[] publicKeyBytes = Convert.FromBase64String(publicKeyString);
            var curve = ECNamedCurveTable.GetByName(Curve);
            var domainParams = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);
            var q = curve.Curve.DecodePoint(publicKeyBytes);
            return new ECPublicKeyParameters(q, domainParams);
        }

        private static ECPrivateKeyParameters StringToPrivateKey(string privateKeyString)
        {
            byte[] privateKeyBytes = Convert.FromBase64String(privateKeyString);
            var curve = ECNamedCurveTable.GetByName(Curve);
            var domainParams = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);
            return new ECPrivateKeyParameters(new BigInteger(1, privateKeyBytes), domainParams);
        }

        private static AsymmetricCipherKeyPair GenerateKeyPair()
        {
            X9ECParameters curve = ECNamedCurveTable.GetByName(Curve);
            ECDomainParameters domainParams = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());

            ECKeyPairGenerator keyGen = new ECKeyPairGenerator();
            keyGen.Init(new ECKeyGenerationParameters(domainParams, _random));

            return keyGen.GenerateKeyPair();
        }

        private static byte[] HKDF(byte[] inputKeyingMaterial, byte[] salt, byte[] info, int length)
        {
            HMac hmac = new HMac(new Sha256Digest());
            if (salt == null)
            {
                salt = new byte[hmac.GetMacSize()];
                _random.NextBytes(salt);
            }

            hmac.Init(new KeyParameter(salt));
            hmac.BlockUpdate(inputKeyingMaterial, 0, inputKeyingMaterial.Length);
            byte[] prk = new byte[hmac.GetMacSize()];
            hmac.DoFinal(prk, 0);

            byte[] result = new byte[length];
            byte[] previousBlock = new byte[0];
            int bytesGenerated = 0;
            int blockIndex = 1;

            while (bytesGenerated < length)
            {
                hmac.Init(new KeyParameter(prk));
                hmac.BlockUpdate(previousBlock, 0, previousBlock.Length);
                hmac.BlockUpdate(info, 0, info.Length);
                hmac.Update((byte)blockIndex);
                previousBlock = new byte[hmac.GetMacSize()];
                hmac.DoFinal(previousBlock, 0);

                int bytesToCopy = Math.Min(previousBlock.Length, length - bytesGenerated);
                Array.Copy(previousBlock, 0, result, bytesGenerated, bytesToCopy);
                bytesGenerated += bytesToCopy;
                blockIndex++;
            }

            return result;
        }

        private static byte[] EncryptECIES(byte[] plainText, ECPublicKeyParameters recipientPublicKey, ECPrivateKeyParameters senderPrivateKey)
        {
            // Perform ECDH key agreement
            var agreement = new ECDHBasicAgreement();
            agreement.Init(senderPrivateKey);
            BigInteger sharedSecret = agreement.CalculateAgreement(recipientPublicKey);

            // Derive key using HKDF
            byte[] salt = new byte[32];
            _random.NextBytes(salt);
            byte[] info = Encoding.UTF8.GetBytes("ECIES");
            byte[] key = HKDF(sharedSecret.ToByteArrayUnsigned(), salt, info, 32);

            byte[] iv = new byte[12];
            _random.NextBytes(iv);

            // Encrypt using AES-GCM
            var cipher = new GcmBlockCipher(new AesEngine());
            var keyParam = new KeyParameter(key);
            var parameters = new AeadParameters(keyParam, 128, iv, null);
            cipher.Init(true, parameters);

            byte[] output = new byte[cipher.GetOutputSize(plainText.Length)];
            int length = cipher.ProcessBytes(plainText, 0, plainText.Length, output, 0);
            length += cipher.DoFinal(output, length);

            // Combine salt, IV, and cipher text
            byte[] result = new byte[salt.Length + iv.Length + length];
            Array.Copy(salt, 0, result, 0, salt.Length);
            Array.Copy(iv, 0, result, salt.Length, iv.Length);
            Array.Copy(output, 0, result, salt.Length + iv.Length, length);

            return result;
        }

        private static byte[] DecryptECIES(byte[] cipherText, ECPublicKeyParameters senderPublicKey, ECPrivateKeyParameters recipientPrivateKey)
        {
            byte[] salt = new byte[32];
            Array.Copy(cipherText, 0, salt, 0, salt.Length);

            byte[] iv = new byte[12];
            Array.Copy(cipherText, salt.Length, iv, 0, iv.Length);

            // Extract actual cipher text
            byte[] actualCipherText = new byte[cipherText.Length - salt.Length - iv.Length];
            Array.Copy(cipherText, salt.Length + iv.Length, actualCipherText, 0, actualCipherText.Length);

            // Perform ECDH key agreement
            var agreement = new ECDHBasicAgreement();
            agreement.Init(recipientPrivateKey);
            BigInteger sharedSecret = agreement.CalculateAgreement(senderPublicKey);

            // Derive key using HKDF
            byte[] info = Encoding.UTF8.GetBytes("ECIES");
            byte[] key = HKDF(sharedSecret.ToByteArrayUnsigned(), salt, info, 32);

            // Decrypt using AES-GCM
            var cipher = new GcmBlockCipher(new AesEngine());
            var keyParam = new KeyParameter(key);
            var parameters = new AeadParameters(keyParam, 128, iv, null);
            cipher.Init(false, parameters);

            byte[] output = new byte[cipher.GetOutputSize(actualCipherText.Length)];
            int length = cipher.ProcessBytes(actualCipherText, 0, actualCipherText.Length, output, 0);
            length += cipher.DoFinal(output, length);

            byte[] result = new byte[length];
            Array.Copy(output, 0, result, 0, length);

            return result;
        }

        private static string PublicKeyToString(ECPublicKeyParameters publicKey)
        {
            return Convert.ToBase64String(publicKey.Q.GetEncoded());
        }

        private static string PrivateKeyToString(ECPrivateKeyParameters privateKey)
        {
            return Convert.ToBase64String(privateKey.D.ToByteArrayUnsigned());
        }
    }
}
