using System.Security.Cryptography;
using System.Text;

namespace Application_Security_Practical_Assignment.Services
{
    public class AesCreditCardCrypto : ICreditCardCrypto
    {
        private readonly byte[] _aesKey;
        private readonly byte[] _hmacKey;

        public AesCreditCardCrypto(IConfiguration config)
        {
            // Expect a long string; we derive two keys from it
            var keyMaterial = config["Security:CreditCardEncryptionKey"] ?? "";
            if (keyMaterial.Length < 32)
                throw new InvalidOperationException("CreditCardEncryptionKey must be at least 32 characters.");

            using var sha = SHA256.Create();
            var full = sha.ComputeHash(Encoding.UTF8.GetBytes(keyMaterial));
            // Split into 16/16 or derive separate; here we derive AES(16) + HMAC(16) from two hashes
            _aesKey = full; // 32 bytes for AES-256

            using var sha2 = SHA256.Create();
            _hmacKey = sha2.ComputeHash(Encoding.UTF8.GetBytes(keyMaterial + "|hmac"));
        }

        public string EncryptToBase64(string plaintext)
        {
            if (plaintext == null) plaintext = "";

            using var aes = Aes.Create();
            aes.Key = _aesKey;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.GenerateIV();

            byte[] plainBytes = Encoding.UTF8.GetBytes(plaintext);
            byte[] cipherBytes;
            using (var enc = aes.CreateEncryptor())
            {
                cipherBytes = enc.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
            }

            // payload = IV + CIPHERTEXT
            var payload = new byte[aes.IV.Length + cipherBytes.Length];
            Buffer.BlockCopy(aes.IV, 0, payload, 0, aes.IV.Length);
            Buffer.BlockCopy(cipherBytes, 0, payload, aes.IV.Length, cipherBytes.Length);

            // tag = HMAC(payload)
            byte[] tag;
            using (var h = new HMACSHA256(_hmacKey))
            {
                tag = h.ComputeHash(payload);
            }

            // final = payload + tag
            var final = new byte[payload.Length + tag.Length];
            Buffer.BlockCopy(payload, 0, final, 0, payload.Length);
            Buffer.BlockCopy(tag, 0, final, payload.Length, tag.Length);

            return Convert.ToBase64String(final);
        }

        public string DecryptFromBase64(string base64Ciphertext)
        {
            var final = Convert.FromBase64String(base64Ciphertext);

            // Split: payload + tag(32 bytes)
            if (final.Length < 16 + 32) throw new CryptographicException("Ciphertext too short.");
            int tagLen = 32;
            int payloadLen = final.Length - tagLen;

            var payload = new byte[payloadLen];
            var tag = new byte[tagLen];
            Buffer.BlockCopy(final, 0, payload, 0, payloadLen);
            Buffer.BlockCopy(final, payloadLen, tag, 0, tagLen);

            // Verify HMAC
            byte[] expected;
            using (var h = new HMACSHA256(_hmacKey))
            {
                expected = h.ComputeHash(payload);
            }
            if (!CryptographicOperations.FixedTimeEquals(tag, expected))
                throw new CryptographicException("Invalid HMAC.");

            // Create AES instance
            using var aes = Aes.Create();

            // Use AES-256 key derived from configuration
            aes.Key = _aesKey;

            // Use CBC mode with PKCS7 padding
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            // Determine IV length dynamically from AES block size (recommended practice)
            // AES block size is 128 bits = 16 bytes
            int ivLen = aes.BlockSize / 8;

            // payload = IV + ciphertext
            // Ensure payload is long enough to contain at least the IV
            if (payloadLen < ivLen)
                throw new CryptographicException("Invalid payload length.");

            // Extract IV from the beginning of payload
            var iv = new byte[ivLen];
            Buffer.BlockCopy(payload, 0, iv, 0, ivLen);

            // Extract ciphertext (remaining bytes after IV)
            var cipherBytes = new byte[payloadLen - ivLen];
            Buffer.BlockCopy(payload, ivLen, cipherBytes, 0, cipherBytes.Length);

            // Assign extracted IV to AES instance
            aes.IV = iv;

            // Decrypt ciphertext using AES-CBC
            using var dec = aes.CreateDecryptor();
            var plain = dec.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);

            // Return decrypted plaintext as UTF-8 string
            return Encoding.UTF8.GetString(plain);


        }
    }
}
