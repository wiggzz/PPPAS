#include <pbc.h>
#include <vector>
#include "bls.h"

namespace pbpdp
{
	const char params[373];
	
	class scheme_parameters
	{
	public:
		scheme_parameters(const char *param) { init(param); }
		void init(const char *param);
	
		pairing_t get_pairing() { return _pairing; }
		element_t get_g() { return _g; }
		
	private:
		pairing_t 			_pairing;
		element_t			_g;
		unsigned int		_sig_length;
	};
	
	class secret_parameters
	{
	public:
		secret_parameters(const scheme_parameters &scheme) { init(scheme); }
		void init(const scheme_parameters &scheme);
		
		element_t get_ssk() { return _ssk; }
		element_t get_x() { return _x; }
		
	private:
		element_t			_ssk;
		element_t 			_x;
	};

	class public_parameters
	{
	public:
		public_parameters(const scheme_parameters &scheme,const secret_parameters &sp) { init(sp); }
		void init(const secret_parameters &sp);
		
		element_t get_spk() { return _spk; }
		element_t get_u() { return _u; }
		element_t get_v() { return _v; }
		element_t get_pair() { return _euv; }
		
	private:
		element_t			_spk;
		element_t			_u;
		element_t			_v;
		element_t			_euv;
	};

	class verification_metadata
	{
	public:
		void generate_authenticators(const secret_parameters &s, const public_parameters &p, const scheme_parameters &scheme, file &f);
		void allocate_authenticators(unsigned int count);
		void clear_authenticators();
		
	private:
		element_t* 			_authenticators;
		unsigned int 		_count;
		element_t 			_name;
		unsigned char *		_name_sig;
	};

	typedef struct 
	{
		unsigned int		_i;
		element_t			_v;
	} challenge_pair;
	
	class challenge
	{
	public:
	
	private:
		challenge_pair *	_pairs;
		unsigned int 		_count;
	};

	class response_proof
	{
	public:
		
	private:
		element_t			_mu;
		element_t			_sigma;
		element_t			_R;
	};
	
	class file
	{
	public:
		virtual void get_chunk(element_t e,unsigned int i) = 0; // gets the next chunk into element e
		virtual unsigned int get_chunk_count() = 0; // gets the total number of chunks in the file
	};
	
	void key_gen(const scheme_parameters &scheme,secret_parameters &s, public_parameters &p);
	void sig_gen(verification_metadata &vmd, const secret_parameters &s, const public_parameters &p, const scheme_parameters &scheme, file &f);
	void gen_challenge(challenge &chal,const public_parameters &p, const scheme_parameters &scheme, unsigned int chunk_count);
	void gen_proof(response_proof &rp, const challenge &c, const verification_metadata &vm, const public_parameters &p, const scheme_parameters &scheme);
	bool verify_proof(const response_proof &r, const challenge &c, const public_parameters &p);
	
	void hash_data_to_element(element_t e,unsigned char *data,unsigned int len);
	void hash_element_to_element(element_t out, element_t in);
};