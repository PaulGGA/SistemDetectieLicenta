#include <stdio.h>
#include <math.h>


#ifdef _WIN32
    #define EXPORT __declspec(dllexport)
#else
    #define EXPORT
#endif

EXPORT double calcEntropie(const unsigned char *data, size_t size){
    if(size ==0)
        return 0.0;

    int frecv[256] = {0};
    double entropie = 0.0;

    for(size_t i = 0 ; i < size ;i++)
        frecv[data[i]]++;
    

    for(int i = 0 ; i < 256; i++)
        if(frecv[i] != 0)
            entropie -= (double)frecv[i]/size * log2((double)frecv[i]/size);
    

    return entropie;




}