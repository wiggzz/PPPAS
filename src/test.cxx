#include <config.h>
#include <cryptopp/osrng.h>
#include <iostream>
#include <stdexcept>
#include <chrono>
#include <ctime>
#include "core.h"

using namespace pbpdp;

class random_file : public file
{
public:
	random_file(unsigned int size,pairing_t pairing)
	{
		_size = size;
		_data = new unsigned char[_size];
		
		CryptoPP::AutoSeededRandomPool rng;
		
		rng.GenerateBlock(_data,_size);
		
		_chunk_size = pairing_length_in_bytes_Zr(pairing);
		_buf = new unsigned char[_chunk_size];
	}
	
	~random_file()
	{
		delete[] _buf;
	}
	
	void get_chunk(mpz_t e,unsigned int i) // gets the next chunk into element e
	{
		mpz_import(e,_chunk_size,1,sizeof(unsigned char),0,0,get_chunk(i));
	}
	
	void get_chunk(element_t e, unsigned int i)
	{
		element_from_bytes(e,get_chunk(i));
	}
	
	unsigned int get_chunk_count() // gets the total number of chunks in the file
	{
		unsigned int count = _size/_chunk_size;
		if (_size%_chunk_size > 0)
		{
			count++;
		}
		return count;
	}
	
private:
	unsigned int get_chunk_start(unsigned int i)
	{
		return i*_chunk_size;
	}
	
	unsigned int get_chunk_end(unsigned int i)
	{	
		return (i+1)*_chunk_size;
	}
	
	unsigned char *get_chunk(unsigned int i)
	{
		if (get_chunk_end(i)<_size)
		{
			return _data+get_chunk_start(i);
		}
		else
		{
			memset(_buf,0,_chunk_size);
			memcpy(_buf,_data+get_chunk_start(i),_size-get_chunk_start(i));
			return _buf;
		}
	}

	unsigned int _size;
	unsigned char *_data;
	unsigned int _chunk_size;
	unsigned char *_buf;
};

int main()
{
	// simple test program that should test the process.
	try {
	scheme_parameters scheme;
	public_parameters p;
	secret_parameters s;
	const unsigned int size = 32000;
	
	std::cout << "Generating key..." << std::endl;
	
	std::chrono::time_point<std::chrono::system_clock> start, end;
	
	key_gen(scheme,s,p);
	
	random_file f(size,scheme.get_pairing());
	
	verification_metadata vmd;
	
	start = std::chrono::system_clock::now();
	sig_gen(vmd,s,p,scheme,f);
	end = std::chrono::system_clock::now();
	
	std::chrono::duration<double> elapsed = end - start;
	
	std::cout << "sig_gen (bytes/s): " << size / elapsed.count() << std::endl;
	
	if (check_sig(vmd,p,scheme))
	{
		std::cout << "Signature verified." << std::endl;
	}
	else
	{
		std::cout << "Signature failed." << std::endl;
	}
	
	challenge chal;
	
	
	start = std::chrono::system_clock::now();
	gen_challenge(chal,scheme,f.get_chunk_count()*0.8,f.get_chunk_count());
	end = std::chrono::system_clock::now();
	
	elapsed = end - start;
	
	std::cout << "gen_challenge (bytes/s): " << size / elapsed.count() << std::endl;
	
	response_proof rp;
	
	
	start = std::chrono::system_clock::now();
	gen_proof(rp,chal,vmd,p,scheme,f);
	end = std::chrono::system_clock::now();
	
	elapsed = end - start;
	
	std::cout << "gen_proof (bytes/s): " << size / elapsed.count() << std::endl;
	
	start  = std::chrono::system_clock::now();
	if (verify_proof(rp,chal,vmd,p,scheme))
	{
		std::cout << "Proof verified." << std::endl;
	}
	else
	{
		std::cout << "Proof invalid." << std::endl;
	}
	end = std::chrono::system_clock::now();
	
	elapsed = end - start;
	
	std::cout << "verify_proof (bytes/s): " << size / elapsed.count() << std::endl;
	
	} catch (const std::exception &e)
	{
		std::cout << "Unhandled std::exception: " << e.what() << std::endl;
	} catch (...)
	{
		std::cout << "Unhandled exception." << std::endl;
	}
	return 0;
}