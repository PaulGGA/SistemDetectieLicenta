from cffi import FFI

# crearea modulului de calcul al entropiei optimizate
builder = FFI()
builder.cdef("double calcEntropie(const unsigned char *data, size_t size);")
builder.set_source("entropyCalcC",
                   """
double calcEntropie(const unsigned char *data, size_t size){
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
                    """,
                    libraries =[])



if __name__ == "__main__":
    builder.compile(verbose=True)
