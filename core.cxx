#include "core.h"
#include <sha.h>

using pbpdp;

void scheme_parameters::init(const char *param)
{
	pairing_init_set_str(_pairing,param);
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

void secret_parameters::init(const scheme_parameters &scheme)
{
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
	initialized = true;
}

void public_parameters::cleanup()
{
	element_clear(_spk);
	element_clear(_u);
	element_clear(_v);
	element_clear(_euv);
	_initialized = false;
}

void verification_metadata::init(const secret_parameters &s, const public_parameters &p, const scheme_parameters &scheme, file &f)
{
	unsigned int count = file.get_chunk_count();
	allocate_authenticators(count,scheme);
	element_t t0;
	element_t t1;
	element_t z0;
	element_init_G1(t0);
	element_init_G1(t1);
	element_init_Zr(z0);
	
	element_t name;
	element_init_Zr(name,scheme.get_pairing());
	element_random(name);
	
	_name_len = scheme.get_name_len();
	_name = new char[_name_len];
	element_to_bytes_x_only(_name,name);
	
	element_clear(name);
	
	element_pp_t pp;
	element_pp_init(pp,p.get_u());
	
	// calculate each sigma_i = (H(W_i)*u^m_i)^x
	for (int i=0;i<count;i++)
	{
		get_HW(t0,i);
		
		file.get_chunk(z0,i);
		element_pp_pow_zn(t1,z0,pp);
		
		element_mul(t0,t0,t1);
		element_pow_zn(_authenticators[i],t0,s.get_x());
	}
	
	element_pp_clear(pp);
	
	// generate name signature
	element_t name_sig;
	element_init_G1(name_sig,scheme.get_pairing());
	
	// signature is name^ssk
	element_from_hash(t0,_name,_name_len);
	element_pow_zn(name_sig,t0,s.get_ssk());
	
	_name_sig_len = scheme.get_sig_len();
	_name_sig = new char[_name_sig_len];
	element_to_bytes_x_only(_name_sig,name_sig);
	
	element_clear(name_sig);
	
	element_clear(z0);
	element_clear(t1);
	element_clear(t0);
	
	_initialized = true;
}

void verification_metadata::cleanup()
{
	delete[] _name;
	delete[] _name_sig;
	_initialized = false;
}

void verification_metadata::allocate_authenticators(unsigned int count,const scheme_parameters &scheme)
{
	clear_authenticators();
	_authenticators = new element_t[count];
	for (int i=0;i<count;i++)
	{
		element_init_G1(_authenticators[i],scheme.get_pairing());
	}
	_count = count;
}

void verification_metadata::clear_authenticators()
{
	if (_count > 0)
	{
		for (int i=0;i<count;i++)
		{
			element_clear(_authenticators[i]);
		}
		delete[] _authenticators;
		_count = 0;
	}
}

void verification_metadata::check_sig(const public_parameters &p,const scheme_parameters &scheme) const
{
	// now we know sig = name^ssk and spk = g^ssk  we need to verify that e(sig,g) = e(name,spk)
	
	element_t name;
	element_t name_sig;
	element_init_G1(name,scheme.get_pairing());
	element_init_G1(name_sig,scheme.get_pairing());
	
	element_from_x_bytes_only(name,_name);
	element_from_x_bytes_only(name_sig,_name_sig);
	
	element_t p0,p1;
	
	element_init_GT(p0,scheme.get_pairing());
	element_init_GT(p1,scheme.get_pairing());
	
	element_pairing(p0,name_sig,scheme.get_g());
	element_pairing(p1,name,scheme.get_spk());
	
	// now we must compare the pairings, although since we only got the x coordinate,
	// each one could be the inverse of the true value.
	// so either p0 == p1 or 1/p0 == p1 (p0*p1 == 1)
	bool sig_valid = false;
	
	if (!element_cmp(p0,p1))
	{
		sig_valid = true;
	}
	else
	{
		element_mul(p0,p0,p1);
		if (!element_is1(p0))
		{
			sig_valid = true;
		}
	}
	
	element_clear(p1);
	element_clear(p0);
	
	element_clear(name_sig);
	element_clear(name);
	
	return sig_valid;
}

void verification_metadata::get_W_size() const
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
	static SHA256 sha256;
	static unsigned char *W = 0;
	static unsigned int W_cap = 0;
	static unsigned char *HW = 0;
	static unsigned int HW_cap = 0;
	
	if (W_cap < get_W_size())
	{
		if (W)
		{
			delete[] W;
		}
		W_cap = get_W_size();
		W = new char[get_W_size()];
	}
	if (HW < sha256.DigestSize())
	{
		if (HW)
		{
			delete[] HW;
		}
		HW_cap = sha256.DigestSize();
		HW = new char[sha256.DigestSize()];
	}
	
	get_W(W,i);
	sha256.CalculateDigest(HW,W,get_W_size());
	
	element_from_hash(e,HW,sha256.DigestSize());
}

void challenge::init(const scheme_parameters &scheme, unsigned int c, unsigned int chunk_count)
{
	if (c > 0)
	{
		_pairs = new pair[c];
		_count = c;
		
		mpz_t mpz_s;
		mpz_t mpz_lim;
		
		mpz_init(mpz_s);
		
		mpz_init_set_ui(mpz_lim,chunk_count);
			
		for (int i=0;i<_count;i++)
		{
			// select a random element
			pbc_mpz_random(mpz_s,mpz_lim);
			
			_pairs[i]._s = mpz_get_ui(mpz_s);
		
			// select a random challenge value
			element_init(_pairs[i]._v,scheme.get_pairing());
			element_random(_pairs[i]._v);
		}
		
		mpz_clear(mpz_lim);
		mpz_clear(mpz_s);
		
		_initialized = true;
	}
}

void challenge:cleanup()
{
	if (_initialized)
	{
		delete[] _pairs;
		_count = 0;
	}
}

void response_proof::init(const challenge &c, const verification_metadata &vm, const public_parameters &p,const scheme_parameters &scheme, file &f)
{
	element_t r;
	element_t chunk;
	element_t mu_prime;
	element_t gamma;
	element_t t0;
	
	element_init_Zr(r,scheme.get_pairing());
	
	element_random(r);
	
	element_init_GT(_R,scheme.get_pairing());
	
	element_pairing(_R,p.get_u(),p.get_v());
	
	// now R = e(u,v)^r, where r is random
	element_pow_Zn(_R,_R,r);
	
	element_init_Zn(chunk);
	element_init_Zn(mu_prime);
	element_init_G1(_sigma);
	element_init_G1(t0);
	
	element_set0(mu_prime);
	element_set1(_sigma);
	
	// calculate the linear combination of sampled blocks from the challenge
	// mu' = sum(v_i*mu_i)
	for (int i=0;i<c.get_count();i++)
	{
		challenge::pair pair = c.get_pair(i);
		file.get_chunk(chunk,pair._s);
		
		element_mul(chunk,pair._v,chunk);
		element_add(mu_prime,mu_prime,chunk);
		
		element_pow_zn(t0,vm.get_authenticator(i),pair._v);
		element_mul(_sigma,_sigma,t0);
	}
	
	element_init_Zr(gamma,scheme.get_pairing());
	
	element_init_Zr(_mu,scheme.get_pairing());
	
	hash_element_to_element(gamma,R);
	
	// mu = r + gamma * mu'
	element_mul(gamma,gamma,mu_prime);
	element_add(_mu,r,gamma);
	
	element_clear(gamma);
	element_clear(t0);
	element_clear(mu_prime);
	element_clear(chunk);
	element_clear(r);
	
	_initialized = true;
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

void key_gen(scheme_parameters &scheme, secret_parameters &s, public_parameters &p,const char *param)
{
	scheme.init(param);
	s.init(scheme);
	p.init(scheme,s);
}

void sig_gen(verification_metadata &vmd,const secret_parameters &s, const public_parameters &p, file &f)
{
	vmd.init(s,p,scheme,f);
}

bool check_sig(const verification_metdata &vmd, const public_parameters &p, const scheme_parameters &scheme)
{
	vmd.check_sig(p,scheme);
}

void gen_challenge(challenge &chal, const scheme_parameters &scheme, unsigned int c, unsigned int chunk_count)
{
	// generates a challenge for c chunks of the file which has chunk count chunk_count
	chal.init(scheme,c,chunk_count);
}

void gen_proof(response_proof& rp, const challenge &c, const verification_metadata &vm, const public_parameters &p,const scheme_parameters &scheme, file &f)
{
	rp.init(c,vm,p,scheme,file);
}

bool verify_proof(const response_proof &r, const challenge &c, const verification_metadata &vm, const public_parameters &p,const scheme_parameters &scheme)
{
	element_t gamma;
	element_t lhs;
	element_t rhs;
	element_t t0;
	element_t t1;
	
	element_init_Zr(gamma,scheme.get_pairing());
	
	hash_element_to_elemen(gamma,r.get_R());
	
	element_init_G1(t0);
	element_init_GT(lhs);
	element_init_GT(rhs);
	
	element_pow_zn(t0,r.get_sigma(),gamma);
	element_pairing(lhs,t0,scheme.get_g());
	element_mul(lhs,R,lhs);
	
	element_init_G1(t1);
	
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
	
	// check that they are equal.  for now all of the elements should have been 
	// fully stored so they should always be equal.  in the future i may have to 
	// serialize one coordinate of some elements for transport, which will mean
	// that they may be inverses of each other
	return !element_cmp(lhs,rhs);
}

void hash_data_to_element(element_t e,unsigned char *data,unsigned int len)
{
	element_from_hash(e,data,len);
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
		buffer = new char[cap];
	}
	
	element_to_bytes(buffer,in);
	element_from_hash(out,buffer,req_len);
}