#include <pbc.h>
#include <vector>
#include "bls.h"

namespace pbpdp
{
	const char params[373];
	
	class serializable
	{
	public:
		void serialize(unsigned char *data,unsigned int size) const = 0;
		void deserialize(unsigned char *data,unsigned int size) = 0;
		unsigned int get_serialized_size() const = 0;
	};
	
	class scheme_parameters : public serializable
	{
	public:
		void init(const char *param);
		void init(unsigned char *data,unsigned int sz); // initializes from serialized form
		void cleanup();
	
		pairing_t get_pairing() const { return _pairing; }
		element_t get_g() const { return _g; }
		unsigned int get_name_len() const { return _name_length; }
		unsigned int get_sig_len() const { return _sig_length; }
		
		void serialize(unsigned char *data,unsigned int size) const;
		void deserialize(unsigned char *data,unsigned int size);
		unsigned int get_serialized_size() const;
		
	private:
		bool				_initialized;
		pairing_t 			_pairing;
		element_t			_g;					// G2
		unsigned int 		_name_length;
		unsigned int		_sig_length;
	};
	
	class secret_parameters : public serializable
	{
	public:
		void init(const scheme_parameters &scheme);
		void cleanup();
		
		element_t get_ssk() const { return _ssk; }
		element_t get_x() const { return _x; }
		
		void serialize(unsigned char *data,unsigned int size) const;
		void deserialize(unsigned char *data,unsigned int size);
		unsigned int get_serialized_size() const;
		
	private:
		bool				_initialized;
		element_t			_ssk;				// Zp
		element_t 			_x;					// Zp
	};

	class public_parameters
	{
	public:
		void init(const scheme_parameters &scheme, const secret_parameters &sp);
		void cleanup();
		
		element_t get_spk() const { return _spk; }
		element_t get_u() const { return _u; }
		element_t get_v() const { return _v; }
		element_t get_pair() const { return _euv; }
		
		void serialize(unsigned char *data,unsigned int size) const;
		void deserialize(unsigned char *data,unsigned int size);
		unsigned int get_serialized_size() const;
		
	private:
		bool 				_initialized;
		element_t			_spk;			// G2
		element_t			_u;				// G1
		element_t			_v;				// G2
		element_t			_euv;			// GT
	};

	class verification_metadata : public serializable
	{
	public:
		void init(const secret_parameters &s, const public_parameters &p, const scheme_parameters &scheme, file &f);
		void cleanup();
		
		void allocate_authenticators(unsigned int count);
		void clear_authenticators();
		
		bool check_sig(const public_parameters &p,const scheme_parameters &scheme) const;
		
		element_t get_authenticator(unsigned int i);
		
		void verification_metadata::get_W_size() const;
		void get_Wi(unsigned char *W, unsigned int sz, unsigned int i) const;
		void get_HWi(element_t e,unsigned int i) const;
		
		void serialize(unsigned char *data,unsigned int size) const;
		void deserialize(unsigned char *data,unsigned int size);
		unsigned int get_serialized_size() const;
		
	private:
		bool				_initialized;
		element_t* 			_authenticators;
		unsigned int 		_count;
		unsigned char *		_name;
		unsigned int		_name_len;
		unsigned char *		_name_sig;
		unsigned int		_name_sig_len;
	};
	
	class challenge : public serializable
	{
	public:
		typedef struct 
		{
			unsigned int		_s;
			element_t			_v;
		} pair;
	
		void init(const scheme_parameters &scheme,unsigned int c, unsigned int chunk_count);
		void cleanup();
		
		unsigned int get_count() const { return _count; }
		pair get_pair(unsigned int i) const { return _pairs[i]; }
		
		void serialize(unsigned char *data,unsigned int size) const;
		void deserialize(unsigned char *data,unsigned int size);
		unsigned int get_serialized_size() const;
		
	private:
		bool				_initialized;
		challenge_pair *	_pairs;
		unsigned int 		_count;
	};

	class response_proof : public serializable
	{
	public:
		void init(const challenge &c, const verification_metadata &vm, const public_parameters &p,const scheme_parameters &scheme, file &f);
		void cleanup();
		
		element_t get_mu() const { return _mu; }
		element_t get_sigma() const { return _sigma; }
		element_t get_R() const { return _R; }
		
		void serialize(unsigned char *data,unsigned int size) const;
		void deserialize(unsigned char *data,unsigned int size);
		unsigned int get_serialized_size() const;
		
	private:
		bool				_initialized;
		element_t			_mu;				// Zp
		element_t			_sigma;				// G1
		element_t			_R;					// GT
	};
	
	class file
	{
	public:
		virtual void get_chunk(element_t e,unsigned int i) = 0; // gets the next chunk into element e
		virtual unsigned int get_chunk_count() = 0; // gets the total number of chunks in the file
	};
	
	void key_gen(const scheme_parameters &scheme,secret_parameters &s, public_parameters &p);
	void sig_gen(verification_metadata &vmd, const secret_parameters &s, const public_parameters &p, const scheme_parameters &scheme, file &f);
	bool check_sig(const verification_metadata &vmd, const public_parameters &p, const scheme_parameters &scheme);
	void gen_challenge(challenge &chal,const public_parameters &p, const scheme_parameters &scheme, unsigned int c, unsigned int chunk_count);
	void gen_proof(response_proof &rp, const challenge &c, const verification_metadata &vm, const public_parameters &p, const scheme_parameters &scheme);
	bool verify_proof(const response_proof &r, const challenge &c, const public_parameters &p, const scheme_parameters &scheme);
	
	void hash_data_to_element(element_t e,unsigned char *data,unsigned int len);
	void hash_element_to_element(element_t out, element_t in);
};