// Copyright (C) 2020 Elmir Kurakin
// OpenSSL CBC

#include <cassert>
#include <string>
#include <iostream>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>


constexpr size_t kSizeOfUnsignedCharBits = sizeof(unsigned char) * 8;
constexpr size_t kBlockSize = 128 / kSizeOfUnsignedCharBits;


// generate random String with length lambda with openssl
std::string generateRandomString(size_t lambda)
{
    unsigned char *key = new unsigned char[lambda];
    const int generateResult = RAND_bytes(key, lambda);

    if (generateResult != 1)
    {
        std::cerr << "Generate key error: RAND_bytes function returned code " << generateResult << std::endl;
    }

    const std::string retVal = std::string(key, key + lambda / sizeof(unsigned char));
    delete[] key;

    return retVal;
}


//generate tag for message with key
std::string generateTag(const std::string &message, const std::string &key)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    std::string retVal;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, reinterpret_cast<const unsigned char*>(key.data()), NULL) == 1)
    {
        assert(EVP_CIPHER_CTX_block_size(ctx) == kBlockSize);

        int fullLength = 0;
        int len;
        unsigned char messageToEncrypt[kBlockSize];
        unsigned char tmpBuffer[kBlockSize];

        for (size_t i = 0; i < kBlockSize; i++)
        {
            messageToEncrypt[i] = 0;
        }

        while (fullLength < message.size())
        {
            for (size_t i = 0; i < kBlockSize; i++)
            {
                messageToEncrypt[i] ^= message.data()[i + fullLength];
            }

            EVP_EncryptUpdate(ctx, tmpBuffer, &len, messageToEncrypt, kBlockSize);
            EVP_EncryptFinal_ex(ctx, tmpBuffer, &len);
            fullLength += kBlockSize;

            for (size_t i = 0; i < kBlockSize; i++)
            {
                messageToEncrypt[i] = tmpBuffer[i];
            }
        }

        retVal = std::string(messageToEncrypt, messageToEncrypt + kBlockSize);
    }
    else
    {
        std::cerr << "Error init encryption\n";
    }

    EVP_CIPHER_CTX_free(ctx);

    return retVal;
}


//generate fake message from original
std::string generateFakeMessage(const std::string &originalMessage)
{
    const std::string randBytes = generateRandomString(originalMessage.size());

    return randBytes + originalMessage;
}


//generate tag for message and compare with original tag
void checkTag(const std::string &message, const std::string &key, const std::string &originalTag)
{
    const std::string newTag = generateTag(message, key);

    if (newTag == originalTag)
    {
        std::cout << "Accept for message: " << message.data() << std::endl;
    }
}


int main()
{
    const std::string key = generateRandomString(kBlockSize);

    const std::string originalMessage = "IvanIvanov123456"; //length == kBlockSize
    const std::string originalTag = generateTag(originalMessage, key);

    const std::string randomGeneratedMessage = generateRandomString(originalMessage.size()); //try generate random message with same length and check tag
    checkTag(randomGeneratedMessage, key, originalTag);

    const std::string generatedString = generateFakeMessage(originalMessage); //generate message from original
    checkTag(generatedString, key, originalTag);

    return 0;
}
