#include <config.h>
#include "core.h"
#include <osrng.h>
#include <iostream>

using pbpdp;

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
	}

	void get_chunk(element_t e,unsigned int i) // gets the next chunk into element e
	{
		// going to get byte i*_chunk_size through (i+1)*_chunk_size
		// if we're on the last chunk we may need to pad
		unsigned char *data;
		if (get_chunk_end(i) > _size)
		{
			unsigned char *data = new unsigned char[_chunk_size];
			memcpy(data,_data+get_chunk_start(i),_size-get_chunk_start(i));
		}
		else
		{
			unsigned char *data = _data+get_chunk_start(i);
		}
		int read = element_from_bytes(e,data);
		if (read != _chunk_size)
		{	
			throw std::exception("Logic error: element did not read all bytes from buffer.");
		}
	}
	
	unsigned int get_chunk_start(unsigned int i)
	{
		return i*_chunk_size;
	}
	
	unsigned int get_chunk_end(unsigned int i)
	{	
		return (i+1)*_chunk_size;
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
	unsigned int _size;
	unsigned char *_data;
	unsigned int _chunk_size;
};

int main()
{
	// simple test program that should test the process.
	
	scheme_parameters scheme;
	public_parameters p;
	secret_parameters s;
	
	key_gen(scheme,p,s);

	random_file f(32000,scheme.get_pairing());
	
	verification_metadata vmd;
	
	sig_gen(vmd,s,p,scheme,f);
	
	if (check_sig(vmd,p,scheme))
	{
		std::cout << "Signature verified." << std::endl;
	}
	else
	{
		std::cout << "Signature failed." << std::endl;
	}
	
	challenge chal;
	
	gen_challenge(chal,p,scheme,f.get_chunk_count()*0.8,f.get_chunk_count());
	
	response_proof rp;
	
	gen_proof(rp,chal,vmd,p,scheme);
	
	if (verify_proof(rp,chal,p,scheme))
	{
		std::cout << "Proof verified." << std::endl;
	}
	else
	{
		std::cout << "Proof invalid." << std::endl;
	}

	
	return 0;
}