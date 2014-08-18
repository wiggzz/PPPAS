#include <cryptopp/sha.h>

#include "core.h"

#include <iostream>

namespace pbpdp
{

void scheme_parameters::init()
{	
	bool use_a1_params = false;
	
	if (use_a1_params)
	{
		std::cout << "Generating A1 parameters." << std::endl;
		// first generate two large 512 bit primes
		mpz_t r0,r1;
		mpz_t p,q,n;
		
		mpz_init(r0);
		mpz_init(r1);
		mpz_init(p);
		mpz_init(q);
		mpz_init(n);
		mpz_init(_L);
		
		pbc_mpz_randomb(r0,513);
		pbc_mpz_randomb(r1,512);
		
		mpz_nextprime(p,r0);
		mpz_nextprime(q,r1);
		
		mpz_mul(n,p,q);
		
		// _L = _N - (p + q - 1);
		mpz_add(_L,p,q);
		mpz_sub_ui(_L,_L,1);
		mpz_sub(_L,n,_L);
		_L_available = true;
		
		pbc_param_init_a1_gen(_params,n);
	}
	else
	{
		_L_available = false;
		pbc_param_init_a_gen(_params,160,512);
	}
	
	std::cout << "Finished generating parameters." << std::endl;
	
	pairing_init_pbc_param(_pairing,_params);
	
	element_init_G2(_g,_pairing);
	element_random(_g);
	_name_length = pairing_length_in_bytes_Zr(_pairing);
	_sig_length = pairing_length_in_bytes_x_only_G1(_pairing);
	_initialized = true;
}

void scheme_parameters::cleanup()
{
	element_clear(_g);
	pairing_clear(_pairing);
	_initialized = false;
}

void secret_parameters::init(scheme_parameters &scheme)
{
	std::cout << "Initializing secret_parameters..." << std::endl;
	// for BLS signature
	element_init_Zr(_ssk,scheme.get_pairing());
	element_random(_ssk);
	// for PDP scheme
	element_init_Zr(_x,scheme.get_pairing());
	element_random(_x);
	_initialized = true;
}

void secret_parameters::cleanup()
{
	element_clear(_ssk);
	element_clear(_x);
	_initialized = false;
}

void public_parameters::init(scheme_parameters &scheme,secret_parameters &sp)
{
	std::cout << "Initializing public_parameters..." << std::endl;
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
	_initialized = true;
}

void public_parameters::cleanup()
{
	element_clear(_spk);
	element_clear(_u);
	element_clear(_v);
	element_clear(_euv);
	_initialized = false;
}

void verification_metadata::init(secret_parameters &s, public_parameters &p, scheme_parameters &scheme, file &f)
{
	std::cout << "Initializing verification_metadata..." << std::endl;
	unsigned int count = f.get_chunk_count();
	allocate_authenticators(count,scheme);
	element_t t0;
	element_t t1;
	element_t z0;
	mpz_t z1;
	mpz_t xmodl_mpz;
	element_t xmodl;
	
	element_init_G1(t0,scheme.get_pairing());
	element_init_G1(t1,scheme.get_pairing());
	element_init_Zr(z0,scheme.get_pairing());
	mpz_init(z1);
	mpz_init(xmodl_mpz);
	element_init_Zr(xmodl,scheme.get_pairing());
	
	bool eulers_theorem_opt = false;
	
	element_set(xmodl,s.get_x());
	
	if (scheme.get_L_available())
	{
		std::cout << "Using euler's theorem to improve performance." << std::endl;
		eulers_theorem_opt = true;
		element_to_mpz(xmodl_mpz,xmodl);
		mpz_mod(xmodl_mpz,xmodl_mpz,scheme.get_L());
		element_set_mpz(xmodl,xmodl_mpz);
	}
	
	mpz_clear(xmodl_mpz);	
	
	element_t name;
	element_init_Zr(name,scheme.get_pairing());
	element_random(name);
	
	_name_len = scheme.get_name_len();
	_name = new unsigned char[_name_len];
	element_to_bytes(_name,name);
	
	element_clear(name);
	
	element_pp_t pp;
	element_pp_init(pp,p.get_u());
	
	std::cout << "Calculating authenticators..." << std::endl;
	// calculate each sigma_i = (H(W_i)*u^m_i)^x
	for (int i=0;i<count;i++)
	{
		get_HWi(t0,i);
		
		if (eulers_theorem_opt)
		{
			f.get_chunk(z1,i);
			mpz_mod(z1,z1,scheme.get_L());
			element_set_mpz(z0,z1);
		}
		else
		{
			f.get_chunk(z0,i);
		}
		
		element_pp_pow_zn(t1,z0,pp);
		
		element_mul(t0,t0,t1);
		element_pow_zn(&_authenticators[i],t0,xmodl);
	}
	std::cout << "Authenticators calculated." << std::endl;
	element_pp_clear(pp);
	
	// generate name signature
	element_t name_sig;
	element_init_G1(name_sig,scheme.get_pairing());
	
	// signature is H(name)^ssk
	get_Hname(t0);
	
	element_pow_zn(name_sig,t0,s.get_ssk());
	
	_name_sig_len = scheme.get_sig_len();
	_name_sig = new unsigned char[_name_sig_len];
	element_to_bytes_x_only(_name_sig,name_sig);
	
	element_clear(name_sig);
	
	element_clear(z0);
	mpz_clear(z1);
	element_clear(t1);
	element_clear(t0);
	element_clear(xmodl);
	
	_initialized = true;
	std::cout << "Verification metatdata initialized..." << std::endl;
}

void verification_metadata::cleanup()
{
	delete[] _name;
	delete[] _name_sig;
	_initialized = false;
}

void verification_metadata::allocate_authenticators(unsigned int count, scheme_parameters &scheme)
{
	std::cout << "Allocating " << count << " authenticators..." << std::endl;
	clear_authenticators();
	_authenticators = new element_s[count];
	std::cout << "Finished allocating space... now initializing." << std::endl;
	for (int i=0;i<count;i++)
	{
		element_init_G1(&_authenticators[i],scheme.get_pairing());
	}
	_count = count;
	std::cout << "Authenticators allocated..." << std::endl;
}

void verification_metadata::clear_authenticators()
{
	if (_count > 0)
	{
		for (int i=0;i<_count;i++)
		{
			element_clear(&_authenticators[i]);
		}
		delete[] _authenticators;
		_count = 0;
	}
}

bool verification_metadata::check_sig(public_parameters &p, scheme_parameters &scheme)
{
	std::cout << "Checking signature..." << std::endl;
	// now we know sig = H(name)^ssk and spk = g^ssk  we need to verify that e(sig,g) = e(H(name),spk)
	
	element_t Hname;
	element_t name_sig;
	element_init_G1(Hname,scheme.get_pairing());
	element_init_G1(name_sig,scheme.get_pairing());
	
	get_Hname(Hname);
	element_from_bytes_x_only(name_sig,_name_sig);
	
	element_t p0,p1;
	
	element_init_GT(p0,scheme.get_pairing());
	element_init_GT(p1,scheme.get_pairing());
	
	element_pairing(p0,name_sig,scheme.get_g());
	element_pairing(p1,Hname,p.get_spk());
	
	// now we must compare the pairings, although since we only got the x coordinate,
	// each one could be the inverse of the true value.
	// so either p0 == p1 or 1/p0 == p1 (p0*p1 == 1)
	bool sig_valid = false;
	
	if (!element_cmp(p0,p1))
	{
		std::cout << "Sig valid on first attempt." << std::endl;
		sig_valid = true;
	}
	else
	{
		std::cout << "Sig not valid on first attempt." << std::endl;
		element_mul(p0,p0,p1);
		if (element_is1(p0))
		{
			std::cout << "Sig valid on second attempt." << std::endl;
			sig_valid = true;
		}
		else
		{
			std::cout << "Sig not valid." << std::endl;
		}
	}
	
	element_clear(p1);
	element_clear(p0);
	
	element_clear(name_sig);
	element_clear(Hname);
	
	return sig_valid;
}

unsigned int verification_metadata::get_W_size() const
{
	return _name_len + sizeof(unsigned int);
}

void verification_metadata::get_Wi(unsigned char *W, unsigned int i) const
{
	memcpy(W,_name,_name_len);
	memcpy(W+_name_len,(unsigned char*)&i,sizeof(unsigned int));
}

void verification_metadata::get_HWi(element_t e,unsigned int i) const
{
	static unsigned char *W = 0;
	static unsigned int W_cap = 0;
	
	if (W_cap < get_W_size())
	{
		if (W)
		{
			delete[] W;
		}
		W_cap = get_W_size();
		W = new unsigned char[get_W_size()];
	}
	
	get_Wi(W,i);
	
	hash_data_to_element(e,W,get_W_size());
}

void verification_metadata::get_Hname(element_t e) const
{
	hash_data_to_element(e,_name,_name_len);
}

void challenge::init(scheme_parameters &scheme, unsigned int c, unsigned int chunk_count)
{
	std::cout << "Initializing challenge..." << std::endl;
	if (c > 0)
	{
		_pairs = new pair[c];
		_count = c;
		
		mpz_t mpz_s;
		mpz_t mpz_lim;
		
		mpz_init(mpz_s);
		
		mpz_init_set_ui(mpz_lim,chunk_count);
		
		
		std::cout << "Generating " << _count << " challenge pairs." << std::endl;
		for (int i=0;i<_count;i++)
		{
			// select a random element
			pbc_mpz_random(mpz_s,mpz_lim);
			
			_pairs[i]._s = mpz_get_ui(mpz_s);
			
			//std::cout << "Challenge " << i << " checks block " << _pairs[i]._s << std::endl;
			
			// select a random challenge value
			element_init_Zr(_pairs[i]._v,scheme.get_pairing());
			element_random(_pairs[i]._v);
		}
		
		mpz_clear(mpz_lim);
		mpz_clear(mpz_s);
		
		_initialized = true;
	}
	std::cout << "Challenge initialized." << std::endl;
}

void challenge::cleanup()
{
	if (_initialized)
	{
		for (int i=0;i<_count;i++)
		{
			element_clear(_pairs[i]._v);
		}
		delete[] _pairs;
		_count = 0;
	}
}

void response_proof::init(challenge &c, verification_metadata &vm, public_parameters &p, scheme_parameters &scheme, file &f)
{
	std::cout << "Initialiing response proof." << std::endl;
	element_t r;
	element_t chunk;
	element_t mu_prime;
	element_t gamma;
	element_t t0;
	mpz_t t1;
	
	element_init_Zr(r,scheme.get_pairing());
	
	element_random(r);
	
	element_init_GT(_R,scheme.get_pairing());
	
	element_pairing(_R,p.get_u(),p.get_v());
	
	// now R = e(u,v)^r, where r is random
	element_pow_zn(_R,_R,r);
	
	element_init_Zr(chunk,scheme.get_pairing());
	element_init_Zr(mu_prime,scheme.get_pairing());
	element_init_G1(_sigma,scheme.get_pairing());
	element_init_G1(t0,scheme.get_pairing());
	
	element_set0(mu_prime);
	element_set1(_sigma);
	
	// calculate the linear combination of sampled blocks from the challenge
	// mu' = sum(v_i*mu_i)
	// also
	// sigma = prod(sigma_i^v_i)
	for (int i=0;i<c.get_count();i++)
	{
		challenge::pair pair = c.get_pair(i);
		f.get_chunk(chunk,pair._s);
		
		element_mul(chunk,pair._v,chunk);
		element_add(mu_prime,mu_prime,chunk);
		
		element_pow_zn(t0,vm.get_authenticator(pair._s),pair._v);
		element_mul(_sigma,_sigma,t0);
	}
	
	element_init_Zr(gamma,scheme.get_pairing());
	
	element_init_Zr(_mu,scheme.get_pairing());
	
	hash_element_to_element(gamma,_R);
	
	// mu = r + gamma * mu'
	element_mul(_mu,gamma,mu_prime);
	
	element_add(_mu,r,_mu);
	
	element_clear(gamma);
	element_clear(t0);
	element_clear(mu_prime);
	element_clear(chunk);
	element_clear(r);
	
	_initialized = true;
	std::cout << "Response proof initialized." << std::endl;

	//element_printf("mu: %B\n",_mu);
	//element_printf("sigma: %B\n",_sigma);
	//element_printf("R: %B\n",_R);
}

void response_proof::cleanup()
{
	if (_initialized)
	{
		element_clear(_R);
		element_clear(_sigma);
		element_clear(_mu);
	}
}

void key_gen(scheme_parameters &scheme, secret_parameters &s, public_parameters &p)
{
	scheme.init();
	s.init(scheme);
	p.init(scheme,s);
}

void sig_gen(verification_metadata &vmd, secret_parameters &s, public_parameters &p, scheme_parameters &scheme, file &f)
{
	vmd.init(s,p,scheme,f);
}

bool check_sig(verification_metadata &vmd, public_parameters &p, scheme_parameters &scheme)
{
	vmd.check_sig(p,scheme);
}

void gen_challenge(challenge &chal, scheme_parameters &scheme, unsigned int c, unsigned int chunk_count)
{
	// generates a challenge for c chunks of the file which has chunk count chunk_count
	chal.init(scheme,c,chunk_count);
}

void gen_proof(response_proof& rp, challenge &c, verification_metadata &vm, public_parameters &p, scheme_parameters &scheme, file &f)
{
	rp.init(c,vm,p,scheme,f);
}

bool verify_proof(response_proof &r, challenge &c, verification_metadata &vm, public_parameters &p, scheme_parameters &scheme)
{
	std::cout << "Verifying proof." << std::endl;
	element_t gamma;
	element_t lhs;
	element_t rhs;
	element_t t0;
	element_t t1;
	
	element_init_Zr(gamma,scheme.get_pairing());
	
	hash_element_to_element(gamma,r.get_R());
	
	element_init_G1(t0,scheme.get_pairing());
	element_init_GT(lhs,scheme.get_pairing());
	element_init_GT(rhs,scheme.get_pairing());
	
	element_pow_zn(t0,r.get_sigma(),gamma);
	element_pairing(lhs,t0,scheme.get_g());
	element_mul(lhs,r.get_R(),lhs);
	
	element_init_G1(t1,scheme.get_pairing());
	
	element_set1(t1);
	
	for (int i=0;i<c.get_count();i++)
	{
		challenge::pair pair = c.get_pair(i);
		vm.get_HWi(t0,pair._s);
		element_pow_zn(t0,t0,pair._v);
		
		element_mul(t1,t1,t0);
	}
	
	element_pow_zn(t1,t1,gamma);
	
	element_pow_zn(t0,p.get_u(),r.get_mu());
	
	element_mul(t0,t1,t0);
	
	element_pairing(rhs,t0,p.get_v());
	
	element_printf("LHS: %B\n",lhs);
	element_printf("RHS: %B\n",rhs);
	
	// check that they are equal.  for now all of the elements should have been 
	// fully stored so they should always be equal.  in the future i may have to 
	// serialize one coordinate of some elements for transport, which will mean
	// that they may be inverses of each other
	bool result = !element_cmp(lhs,rhs);
	
	// cleanup
	element_clear(t1);
	element_clear(rhs);
	element_clear(lhs);
	element_clear(t0);
	element_clear(gamma);
	
	std::cout << "Finished verifying proof." << std::endl;
	
	return result;
}

void hash_data_to_element(element_t e,unsigned char *data,unsigned int len)
{
	static CryptoPP::SHA256 sha256;
	static unsigned char *hash = 0;
	static unsigned int hash_cap = 0;

	if (hash_cap < sha256.DigestSize())
	{
		if (hash)
		{
			delete[] hash;
		}
		hash_cap = sha256.DigestSize();
		hash = new unsigned char[sha256.DigestSize()];
	}
	
	sha256.CalculateDigest(hash,data,len);
	
	element_from_hash(e,hash,sha256.DigestSize());
}

void hash_element_to_element(element_t out, element_t in)
{
	static unsigned char *buffer = 0;
	static unsigned int cap = 0;
	unsigned int req_len = element_length_in_bytes(in);
	if (req_len > cap)
	{
		if (buffer)
		{
			delete[] buffer;
		}
		cap = req_len;
		buffer = new unsigned char[cap];
	}
	
	element_to_bytes(buffer,in);
	
	hash_data_to_element(out,buffer,req_len);
}

};
