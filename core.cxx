#include "core.h"

using pbpdp;

void scheme_parameters::init(const char *param)
{
	pairing_init_set_str(_pairing,param);
	element_init_G2(_g,_pairing);
	element_random(_g);
	_sig_length = pairing_length_in_bytes_x_only_G1(_pairing);
}

void secret_parameters::init(const scheme_parameters &scheme)
{
	// for BLS signature
	element_init_Zr(_ssk,scheme.get_pairing());
	element_random(_ssk);
	// for PDP scheme
	element_init_Zr(_x,scheme.get_pairing());
	element_random(_x);
}

void public_parameters::init(const scheme_parameters &scheme,const secret_parameters &sp)
{
	// for BLS signature
	element_init_G2(_spk,scheme.get_pairing());
	element_pow_zn(_spk,scheme.get_g(),sp.get_ssk());
	// for PDP scheme
	element_init_G1(_u,scheme.get_pairing());
	element_random(_u);
	element_init_G2(_v,scheme.get_pairing());
	element_pow_zn(_v,scheme.get_g(),sp.get_x());
	
	element_init_GT(_euv,scheme.get_pairing());
	element_pairing(_euv,_u,_v);
}

void verification_metadata::generate_authenticators(const secret_parameters &s, const public_parameters &p, const scheme_parameters &scheme, file &f)
{
	unsigned int count = file.get_chunk_count();
	allocate_authenticators(count);
	for (int i=0;i<count;i++)
	{
		_authenticators[i]
	}
}

void verification_metadata::allocate_authenticators(unsigned int count)
{
	clear_authenticators();
	_authenticators = new element_ptr[count];
	_count = count;
}
void verification_metadata::clear_authenticators()
{
	if (_count > 0)
	{
		delete[] _authenticators;
		_count = 0;
	}
}

void key_gen(scheme_parameters &scheme, secret_parameters &s, public_parameters &p,const char *param)
{
	scheme.init(param);
	s.init(scheme);
	p.init(scheme,s);
}

verification_metadata& sig_gen(const secret_parameters &s, const public_parameters &p, file &f)
{
	
}

challenge& gen_challenge(const public_parameters &p, unsigned int chunk_count)
{
}

response_proof& gen_proof(const challenge &c, const verification_metadata &vm, const public_parameters &p)
{
}

bool verify_proof(const response_proof &r, const challenge &c, const public_parameters &p)
{
}

void hash_data_to_element(element_t e,unsigned char *data,unsigned int len)
{
	element_from_hash(e,data,len);
}

void hash_element_to_element(element_t out, element_t in)
{
	static unsigned char *buffer;
	static unsigned int cap = 0;
	unsigned int req_len = element_length_in_bytes(in);
	if (req_len > cap)
	{
		cap = req_len;
		buffer = new char[cap];
	}
	
	element_to_bytes(buffer,in);
	element_from_hash(out,buffer,req_len);
}