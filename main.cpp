#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <cstring>
#include <iostream>
#include <fstream>
#include <vector>
#include <unistd.h>  // для getopt()

#define AES_KEY_LENGTH 32  // для AES-256
#define AES_BLOCK_SIZE 16  // размер блока AES

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

// Функция для генерации ключа из пароля с использованием PBKDF2
void generateKeyFromPassword(const std::string &password, unsigned char *key) {
    const unsigned char *salt = (unsigned char *)"12345678"; // Соль для PBKDF2
    if (PKCS5_PBKDF2_HMAC_SHA1(password.c_str(), password.size(), salt, 8, 10000, AES_KEY_LENGTH, key) != 1) {
        handleErrors();
    }
}

// Чтение файла
std::vector<unsigned char> readFile(const std::string &filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Cannot open file: " << filename << std::endl;
        exit(1);
    }
    return std::vector<unsigned char>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

// Запись файла
void writeFile(const std::string &filename, const std::vector<unsigned char> &data) {
    std::ofstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Cannot open file: " << filename << std::endl;
        exit(1);
    }
    file.write((char*)data.data(), data.size());
}

// Шифрование данных с записью IV в начало файла
std::vector<unsigned char> encryptDataWithIV(const std::vector<unsigned char> &plaintext, unsigned char *key, unsigned char *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv)) {
        handleErrors();
    }

    std::vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
    int len;
    int ciphertext_len = 0;

    if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size())) {
        handleErrors();
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len)) {
        handleErrors();
    }
    ciphertext_len += len;

    ciphertext.resize(ciphertext_len);

    EVP_CIPHER_CTX_free(ctx);

    // Добавляем IV в начало шифрованных данных
    std::vector<unsigned char> result(AES_BLOCK_SIZE + ciphertext.size());
    std::copy(iv, iv + AES_BLOCK_SIZE, result.begin());
    std::copy(ciphertext.begin(), ciphertext.end(), result.begin() + AES_BLOCK_SIZE);

    return result;
}

// Дешифрование данных с использованием IV из начала файла
std::vector<unsigned char> decryptDataWithIV(const std::vector<unsigned char> &ciphertext, unsigned char *key) {
    unsigned char iv[AES_BLOCK_SIZE];
    std::copy(ciphertext.begin(), ciphertext.begin() + AES_BLOCK_SIZE, iv);
    
    std::cout << "Extracted IV: ";
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        std::cout << std::hex << (int)iv[i] << " ";
    }
    std::cout << std::dec << std::endl;  // Возврат к десятичному

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv)) {
        handleErrors();
    }

    std::vector<unsigned char> plaintext(ciphertext.size() - AES_BLOCK_SIZE);
    int len;
    int plaintext_len = 0;

    if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data() + AES_BLOCK_SIZE, ciphertext.size() - AES_BLOCK_SIZE)) {
        handleErrors();
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len)) {
        handleErrors();
    }
    plaintext_len += len;

    plaintext.resize(plaintext_len);

    EVP_CIPHER_CTX_free(ctx);

    return plaintext;
}

// Вывод использования программы
void printUsage(const char *program) {
    std::cout << "Usage: " << program << " [-e | -d] -i <inputfile> -o <outputfile> -p <password>" << std::endl;
}

int main(int argc, char *argv[]) {
    int opt;
    std::string inputFile, outputFile, password;
    bool encrypt = false, decrypt = false;

    // Разбор аргументов командной строки
    while ((opt = getopt(argc, argv, "edi:o:p:")) != -1) {
        switch (opt) {
            case 'e':
                encrypt = true;
                break;
            case 'd':
                decrypt = true;
                break;
            case 'i':
                inputFile = optarg;
                break;
            case 'o':
                outputFile = optarg;
                break;
            case 'p':
                password = optarg;
                break;
            default:
                printUsage(argv[0]);
                return 1;
        }
    }

    if ((encrypt && decrypt) || (!encrypt && !decrypt) || inputFile.empty() || outputFile.empty() || password.empty()) {
        printUsage(argv[0]);
        return 1;
    }

    unsigned char key[AES_KEY_LENGTH];
    unsigned char iv[AES_BLOCK_SIZE];

    // Генерация ключа из пароля
    generateKeyFromPassword(password, key);

    // Чтение данных из файла
    std::vector<unsigned char> fileData = readFile(inputFile);

    std::vector<unsigned char> resultData;

    if (encrypt) {
        // Генерация случайного IV
        if (!RAND_bytes(iv, AES_BLOCK_SIZE)) {
            handleErrors();
        }

        std::cout << "Generated IV: ";
        for (int i = 0; i < AES_BLOCK_SIZE; i++) {
            std::cout << std::hex << (int)iv[i] << " ";
        }
        std::cout << std::dec << std::endl;  // Возврат к десятичному

        // Шифрование данных с записью IV
        resultData = encryptDataWithIV(fileData, key, iv);
    } else if (decrypt) {
        // Дешифрование данных с использованием IV из файла
        resultData = decryptDataWithIV(fileData, key);
    }

    // Запись результата в файл
    writeFile(outputFile, resultData);

    std::cout << "Operation " << (encrypt ? "encryption" : "decryption") << " completed successfully!" << std::endl;

    return 0;
}
