#include <config.h>
#include <cryptopp/osrng.h>
#include <iostream>
#include <stdexcept>
#include <chrono>
#include <ctime>
#include <string>
#include "core.h"

using namespace pbpdp;

class random_file : public file
{
public:
	random_file(unsigned int size,pairing_t pairing)
	{
		init(size);

		_chunk_size = pairing_length_in_bytes_Zr(pairing);

		allocate_chunk_buf();
	}

	random_file(unsigned int size,unsigned int chunk_size)
	{
		init(size);

		_chunk_size = chunk_size;

		allocate_chunk_buf();
	}

	~random_file()
	{
		delete[] _buf;
	}

	void init(unsigned int size)
	{
		_size = size;
		_data = new unsigned char[_size];

		CryptoPP::AutoSeededRandomPool rng;

		rng.GenerateBlock(_data,_size);
	}

	void allocate_chunk_buf()
	{
		_buf = new unsigned char[_chunk_size];
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

int main(int argc,char *argv[])
{
	// simple test program that should test the process.
	try {

	// usage: [-ssize] [-bblock_size] [-pparam_file]

	unsigned int size = 10000;
	unsigned int blk_size = 4000;
	char *param_file_name = 0;
	char *params = 0;

	for (int i=1;i<argc;i++)
	{
		if (argv[i][0] == '-')
		{
			switch (argv[i][1])
			{
			case 's':
				size = atoi(&argv[i][2]);
				std::cout << "Using file size of " << size << std::endl;
				break;
			case 'b':
				blk_size = atoi(&argv[i][2]);
				std::cout << "Using block size of " << blk_size << std::endl;
				break;
			case 'p':
				param_file_name = &argv[i][2];
				std::cout << "Using parameter file " << param_file_name << std::endl;

				break;
			}
		}
	}

	if (param_file_name)
	{
		std::cout << "Opening " << param_file_name << std::endl;
		FILE * f = fopen(param_file_name,"rb");
		if (f != NULL)
		{
			fseek(f,0,SEEK_END);
			int sz = ftell(f);
			rewind(f);

			params = new char[sz+1];

			int read = fread(params,1,sz,f);

			if (read != sz)
			{
				throw new std::runtime_error("Failed to read parameter file.");
			}
			fclose(f);

			params[sz] = 0;

			std::cout << "Using parameters: " << std::endl << params << std::endl;
		}
		else
		{
			throw new std::runtime_error("Unable to open parameter file.");
		}
	}

	scheme_parameters scheme;
	public_parameters p;
	secret_parameters s;

	std::cout << "Generating key..." << std::endl;

	std::chrono::time_point<std::chrono::system_clock> start, end;

	key_gen(scheme,s,p,params);

	random_file f(size,blk_size);

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
		throw std::runtime_error("Invalid proof");
	}
	end = std::chrono::system_clock::now();

	elapsed = end - start;

	std::cout << "verify_proof (bytes/s): " << size / elapsed.count() << std::endl;

	} catch (const std::exception &e)
	{
		std::cout << "Unhandled std::exception: " << e.what() << std::endl;
		return 1;
	} catch (...)
	{
		std::cout << "Unhandled exception." << std::endl;
		return 1;
	}
	return 0;
}