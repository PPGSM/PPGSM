#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>

LweSample* integerEncryption(int number, int bitsize, const TFheGateBootstrappingSecretKeySet* PK){
        LweSample* Result = new_gate_bootstrapping_ciphertext_array(bitsize,PK->params);

        for(int i= bitsize-1; i>=0; i--){
                bootsSymEncrypt(&Result[i], (number>>i)&1, PK);
        }

        return Result;
}

int integerDecryption(LweSample* Input, int bitsize, const TFheGateBootstrappingSecretKeySet* PK){
        int Result = 0;

        for(int i= bitsize-1; i>=0; i--){
                Result <<= 1;
                Result += bootsSymDecrypt(&Input[i], PK);
        }

        return Result;
}
