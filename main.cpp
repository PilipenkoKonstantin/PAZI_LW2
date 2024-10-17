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

/**
 * @brief Обрабатывает ошибки OpenSSL и завершает программу.
 * 
 * Выводит сообщения об ошибках, используя библиотеку OpenSSL, и завершает выполнение программы.
 */
void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}
/**
 * @brief Генерация ключа из пароля с использованием PBKDF2.
 * 
 * @param[in] password Пароль, из которого будет генерироваться ключ.
 * @param[out] key Массив байтов для сохранения сгенерированного ключа.
 * 
 * Функция использует алгоритм PBKDF2 с хэш-функцией SHA-1 для генерации ключа длиной AES_KEY_LENGTH байт.
 */
void generateKeyFromPassword(const std::string &password, unsigned char *key) {
    const unsigned char *salt = (unsigned char *)"12345678"; // Соль для PBKDF2
    if (PKCS5_PBKDF2_HMAC_SHA1(password.c_str(), password.size(), salt, 8, 10000, AES_KEY_LENGTH, key) != 1) {
        handleErrors();
    }
}
/**
 * @brief Чтение содержимого файла в вектор байтов.
 * 
 * @param[in] filename Имя файла для чтения.
 * @return std::vector<unsigned char> Вектор байтов, содержащий данные файла.
 * 
 * Функция открывает файл в бинарном режиме и считывает его содержимое в вектор байтов.
 */
std::vector<unsigned char> readFile(const std::string &filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Cannot open file: " << filename << std::endl;
        exit(1);
    }
    return std::vector<unsigned char>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}
/**
 * @brief Запись данных в файл.
 * 
 * @param[in] filename Имя файла для записи.
 * @param[in] data Вектор байтов, содержащий данные для записи.
 * 
 * Функция открывает файл в бинарном режиме и записывает данные из вектора байтов в файл.
 */
void writeFile(const std::string &filename, const std::vector<unsigned char> &data) {
    std::ofstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Cannot open file: " << filename << std::endl;
        exit(1);
    }
    file.write((char*)data.data(), data.size());
}
/**
 * @brief Шифрование данных с использованием AES-256 CBC и записью IV в начало файла.
 * 
 * @param[in] plaintext Вектор байтов, содержащий исходные данные (plaintext).
 * @param[in] key Массив байтов, содержащий ключ для шифрования.
 * @param[in] iv Массив байтов, содержащий вектор инициализации (IV).
 * @return std::vector<unsigned char> Вектор байтов, содержащий зашифрованные данные с добавленным в начало IV.
 * 
 * Функция шифрует данные с использованием AES-256 в режиме CBC, добавляет IV в начало зашифрованного текста
 * и возвращает результат.
 */
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
/**
 * @brief Расшифрование данных с использованием AES-256 CBC и извлечением IV из начала файла.
 * 
 * @param[in] ciphertext Вектор байтов, содержащий зашифрованные данные с IV в начале.
 * @param[in] key Массив байтов, содержащий ключ для расшифрования.
 * @return std::vector<unsigned char> Вектор байтов, содержащий расшифрованные данные (plaintext).
 * 
 * Функция извлекает IV из первых AES_BLOCK_SIZE байт зашифрованного текста, а затем использует его для 
 * расшифрования оставшейся части данных.
 */
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
/**
 * @brief Выводит сообщение об использовании программы.
 * 
 * @param[in] program Имя программы (argv[0]).
 * 
 * Функция выводит инструкции по использованию программы, включая доступные опции.
 */
void printUsage(const char *program) {
    std::cout << "Usage: " << program << " [-e | -d] -i <inputfile> -o <outputfile> -p <password>" << std::endl;
}
/**
 * @brief Точка входа в программу.
 * 
 * Основная функция программы, которая обрабатывает аргументы командной строки,
 * генерирует ключ на основе пароля, читает данные из файла, выполняет шифрование
 * или расшифрование и сохраняет результат в файл.
 * 
 * @param argc Количество аргументов командной строки.
 * @param argv Массив аргументов командной строки.
 * @return int Возвращает 0 при успешном выполнении программы, иначе 1.
 */
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
        // Расшифрование данных с использованием IV из файла
        resultData = decryptDataWithIV(fileData, key);
    }

    // Запись результата в файл
    writeFile(outputFile, resultData);

    std::cout << "Operation " << (encrypt ? "encryption" : "decryption") << " completed successfully!" << std::endl;

    return 0;
}
