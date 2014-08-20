#include <pbc/pbc.h>
#include <vector>

// this is an implementation of 
//
// C. Wang, S. Chow, Q. Wang, K. Ren, W. Lou "Privacy-Preserving Public Auditing for Secure Cloud Storage"

namespace pbpdp
{	
	class file
	{
	// file chunks should be smaller than N for the scheme to work.  otherwise the server can store m_i as m_i mod N.  
	public:
		virtual void get_chunk(element_t e,unsigned int i) = 0; // gets the next chunk into element e
		virtual void get_chunk(mpz_t e,unsigned int i) = 0; // gets the next chunk into mpz integer e
		virtual unsigned int get_chunk_count() = 0; // gets the total number of chunks in the file
	};
	
	
	class serializable
	{
	public:
		virtual void serialize(unsigned char *data,unsigned int size) const = 0;
		virtual void deserialize(unsigned char *data,unsigned int size) = 0;
		virtual unsigned int get_serialized_size() const = 0;
	};
	
	class scheme_parameters //: public serializable
	{
	public:
		scheme_parameters() : _initialized(false) {}
		void init(char *params = 0);
		//void init(unsigned char *data,unsigned int sz); // initializes from serialized form
		void cleanup();
	
		pairing_s* get_pairing() { return _pairing; }
		element_s* get_g() { return _g; }
		unsigned int get_name_len() const { return _name_length; }
		unsigned int get_sig_len() const { return _sig_length; }
		
		bool get_L_available() const { return _L_available; }
		__mpz_struct* get_L() { return _L; }
		
		//void serialize(unsigned char *data,unsigned int size) const;
		//void deserialize(unsigned char *data,unsigned int size);
		//unsigned int get_serialized_size() const;
		
	private:
		bool				_initialized;
		pairing_t 			_pairing;
		element_t			_g;					// G2
		mpz_t				_L;					// eulers totient
		bool				_L_available;
		unsigned int 		_name_length;
		unsigned int		_sig_length;
		pbc_param_t			_params;
	};
	
	class element_hash
	{
	public:
		element_hash() : _initialized(false) {}
		void init(scheme_parameters &scheme);
		void cleanup();
	
		void hash_data_to_element(element_t e,unsigned char *data,unsigned int len) const;
		void hash_element_to_element(element_t out, element_t in) const;
		void hash_data_to_mpz(mpz_t e,unsigned char *data,unsigned int len) const;
		void hash_mpz_to_mpz(mpz_t out,mpz_t in) const;
		
	private:
		bool						_initialized;
		mutable CryptoPP::SHA256 	_sha256;
		mutable unsigned char*		_hash_buf;
		unsigned int 				_hash_sz;
		mutable unsigned char*		_element_buf;
	};
	
	class secret_parameters //: public serializable
	{
	public:
		secret_parameters() : _initialized(false) {}
		void init(scheme_parameters &scheme);
		void cleanup();
		
		element_s* get_ssk() { return _ssk; }
		element_s* get_x() { return _x; }
		
		//void serialize(unsigned char *data,unsigned int size) const;
		//void deserialize(unsigned char *data,unsigned int size);
		//unsigned int get_serialized_size() const;
		
	private:
		bool				_initialized;
		element_t			_ssk;				// Zp
		element_t 			_x;					// Zp
	};

	class public_parameters // : public serializable
	{
	public:
		public_parameters() : _initialized(false) {}
		void init(scheme_parameters &scheme, secret_parameters &sp);
		void cleanup();
		
		element_s* get_spk() { return _spk; }
		element_s* get_u() { return _u; }
		element_s* get_v() { return _v; }
		element_s* get_pair() { return _euv; }
		
		//void serialize(unsigned char *data,unsigned int size) const;
		//void deserialize(unsigned char *data,unsigned int size);
		//unsigned int get_serialized_size() const;
		
	private:
		bool 				_initialized;
		element_t			_spk;			// G2
		element_t			_u;				// G1
		element_t			_v;				// G2
		element_t			_euv;			// GT
	};

	class verification_metadata //: public serializable
	{
	public:
		verification_metadata() : _initialized(false), _count(0) {}
		void init(secret_parameters &s, public_parameters &p, scheme_parameters &scheme, file &f);
		void cleanup();
		
		void allocate_authenticators(unsigned int count, scheme_parameters &scheme);
		void clear_authenticators();
		
		bool check_sig(public_parameters &p, scheme_parameters &scheme);
		
		element_s* get_authenticator(unsigned int i) { return &_authenticators[i]; }
		
		unsigned int get_W_size() const;
		void append_index_to_W(unsigned int i) const;
		void get_HWi(element_t e,unsigned int i) const;
		void get_HWi(mpz_t e,unsigned int i) const;
		void get_Hname(element_t e) const;  // returns the hash of the name (for signing)
		void get_Hname(mpz_t e) const;
		
		//void serialize(unsigned char *data,unsigned int size) const;
		//void deserialize(unsigned char *data,unsigned int size);
		//unsigned int get_serialized_size() const;
		
	private:
		bool				_initialized;
		element_s*			_authenticators;
		unsigned int 		_count;
		unsigned char *		_name;
		unsigned int		_name_len;
		unsigned char *		_name_sig;
		unsigned int		_name_sig_len;
		mutable unsigned char* 		_W_buffer;
		element_hash		_hasher;
	};
	
	class challenge //: public serializable
	{
	public:
		typedef struct 
		{
			unsigned int		_s;
			element_t			_v;
		} pair;
	
		challenge() : _initialized(false) {}
		void init(scheme_parameters &scheme, unsigned int c, unsigned int chunk_count);
		void cleanup();
		
		unsigned int get_count() const { return _count; }
		pair get_pair(unsigned int i) const { return _pairs[i]; }
		
		//void serialize(unsigned char *data,unsigned int size) const;
		//void deserialize(unsigned char *data,unsigned int size);
		//unsigned int get_serialized_size() const;
		
	private:
		bool				_initialized;
		pair *				_pairs;
		unsigned int 		_count;
	};

	class response_proof //: public serializable
	{
	public:
		response_proof() : _initialized(false) {}
		void init(challenge &c, verification_metadata &vm, public_parameters &p, scheme_parameters &scheme, file &f);
		void cleanup();
		
		//element_s* get_mu() { return _mu; }
		__mpz_struct* get_mu() { return _mu; }
		element_s* get_sigma() { return _sigma; }
		element_s* get_R() { return _R; }
		
		//void serialize(unsigned char *data,unsigned int size) const;
		//void deserialize(unsigned char *data,unsigned int size);
		//unsigned int get_serialized_size() const;
		
	private:
		bool				_initialized;
		//element_t			_mu;				// Zp
		mpz_t				_mu;
		element_t			_sigma;				// G1
		element_t			_R;					// GT
	};
	
	void key_gen(scheme_parameters &scheme, secret_parameters &s, public_parameters &p,char *params = 0);
	void sig_gen(verification_metadata &vmd, secret_parameters &s, public_parameters &p, scheme_parameters &scheme, file &f);
	bool check_sig(verification_metadata &vmd, public_parameters &p, scheme_parameters &scheme);
	void gen_challenge(challenge &chal, scheme_parameters &scheme, unsigned int c, unsigned int chunk_count);
	void gen_proof(response_proof &rp, challenge &c, verification_metadata &vm, public_parameters &p, scheme_parameters &scheme, file &f);
	bool verify_proof(response_proof &r, challenge &c, verification_metadata &vm, public_parameters &p, scheme_parameters &scheme);
};