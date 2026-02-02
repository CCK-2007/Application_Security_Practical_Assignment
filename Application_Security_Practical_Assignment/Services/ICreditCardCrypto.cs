namespace Application_Security_Practical_Assignment.Services
{
    public interface ICreditCardCrypto
    {
        string EncryptToBase64(string plaintext);
        string DecryptFromBase64(string base64Ciphertext);
    }
}
