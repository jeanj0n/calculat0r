#include "seal/seal.h"
#include <iostream>
#include <cstdint>
using namespace std;
using namespace seal;

inline std::string uint64_to_hex_string(std::uint64_t value)
{
     return seal::util::uint_to_hex_string(&value, std::size_t(1));
}

int main()
{
     EncryptionParameters parms(scheme_type::bfv);

     size_t poly_modulus_degree = 4096;
     parms.set_poly_modulus_degree(poly_modulus_degree);

     parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

     parms.set_plain_modulus(1024);

     SEALContext context(parms);

     cout << "Parameter validation (success): " << context.parameter_error_message() << endl;

     cout << endl;
     cout << "~~~~~~ A naive way to calculate addition/multiplication of two numbers ~~~~~~" << endl;

     KeyGenerator keygen(context);
     SecretKey secret_key = keygen.secret_key();
     PublicKey public_key;
     keygen.create_public_key(public_key);

     Encryptor encryptor(context, public_key);

     Evaluator evaluator(context);

     Decryptor decryptor(context, secret_key);

     uint64_t x, y;
     cout << "Enter first number: ";
     cin >> x;
     cout << "Enter second number: ";
     cin >> y;

     Plaintext x_plain(uint64_to_hex_string(x));
     Plaintext y_plain(uint64_to_hex_string(y));

     cout << "Express x = " + to_string(x) + " as a plaintext polynomial 0x" + x_plain.to_string() + "." << endl;
     cout << "Express y = " + to_string(y) + " as a plaintext polynomial 0x" + y_plain.to_string() + "." << endl;

     Ciphertext x_encrypted;
     cout << "Encrypt x_plain to x_encrypted." << endl;
     encryptor.encrypt(x_plain, x_encrypted);

     cout << "    + size of freshly encrypted x: " << x_encrypted.size() << endl;

     cout << "    + noise budget in freshly encrypted x: " << decryptor.invariant_noise_budget(x_encrypted) << " bits"
          << endl;

     Plaintext x_decrypted;
     cout << "    + decryption of x_encrypted: ";
     decryptor.decrypt(x_encrypted, x_decrypted);
     cout << "0x" << x_decrypted.to_string() << " ...... Correct." << endl;

     Ciphertext y_encrypted;
     cout << "Encrypt y_plain to y_encrypted." << endl;
     encryptor.encrypt(y_plain, y_encrypted);

     cout << "    + size of freshly encrypted y: " << y_encrypted.size() << endl;

     cout << "    + noise budget in freshly encrypted y: " << decryptor.invariant_noise_budget(y_encrypted) << " bits"
          << endl;

     Plaintext y_decrypted;
     cout << "    + decryption of y_encrypted: ";
     decryptor.decrypt(y_encrypted, y_decrypted);
     cout << "0x" << y_decrypted.to_string() << " ...... Correct." << endl;

     cout << "Enter 1 for addition or 2 for multiplication :" << endl;
     int choice;
     cin >> choice;

     if (choice == 1)
     {
          cout << "Computing sum of x and y" << endl;
          Ciphertext sum;
          evaluator.add(x_encrypted, y_encrypted, sum);

          cout << "    + size of sum: " << sum.size() << endl;
          cout << "    + noise budget in sum: " << decryptor.invariant_noise_budget(sum) << " bits"
               << endl;

          Plaintext decrypted_result;
          cout << "    + decryption of sum: ";
          decryptor.decrypt(sum, decrypted_result);
          cout << "0x" << decrypted_result.to_string() << " ...... Correct." << endl;
     }

     else if (choice == 2)
     {
          cout << "Computing product of x and y" << endl;
          Ciphertext product;
          evaluator.multiply(x_encrypted, y_encrypted, product);

          cout << "    + size of product: " << product.size() << endl;
          cout << "    + noise budget in product: " << decryptor.invariant_noise_budget(product) << " bits"
               << endl;

          Plaintext decrypted_result;
          cout << "    + decryption of product: ";
          decryptor.decrypt(product, decrypted_result);
          cout << "0x" << decrypted_result.to_string() << " ...... Correct." << endl;
     }

     return 0;
}