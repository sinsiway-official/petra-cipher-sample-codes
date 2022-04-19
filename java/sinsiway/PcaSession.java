package sinsiway;
import java.util.*;


public class PcaSession extends Object {
	private static native int INIT(byte[] conf_file_path, byte[] credentials_password);
	private static native int OPN(int db_sid, byte[] instance_id, byte[] db_name, byte[] client_ip, byte[] db_user, byte[] os_user, byte[] client_program, int protocol, byte[] user_id, byte[] client_mac); // open user session
	private static native void CLS(int db_sid); // close API session
	private static native void CCS(int db_sid, byte[] char_set_bytes); // set session charater set
	private static native byte[] ENC(int db_sid, int enc_col_id, byte[] src); // encrypt
	private static native byte[] ENC_NM(int db_sid, byte[] enc_col_name, byte[] src); // encrypt
	private static native byte[] ENC(int db_sid, int enc_col_id, byte[] src, int sql_type); // encrypt
	private static native byte[] ENC_NM(int db_sid, byte[] enc_col_name, byte[] src, int sql_type); // encrypt
	private static native byte[] ENC_NM_SETKEY(int db_sid, byte[] enc_col_name, byte[] src, byte[] set_key); // encrypt set_key for IBK bank
	private static native byte[] ENC_NM_SETKEYIV(int db_sid, byte[] enc_col_name, byte[] src, int sql_type, byte[] set_key, byte[] set_iv); // encrypt set_key , set_iv
	private static native byte[] DEC(int db_sid, int enc_col_id, byte[] src); // decrypt
	private static native byte[] DEC_NM(int db_sid, byte[] enc_col_name, byte[] src); // decrypt
	private static native byte[] DEC_NM_SETKEY(int db_sid, byte[] enc_col_name, byte[] src, byte[] set_key); // decrypt set_key for IBK bank
	private static native byte[] DEC_NM_SETKEYIV(int db_sid, byte[] enc_col_name, byte[] src, int sql_type, byte[] set_key, byte[] set_iv); // decrypt set_key , set_iv
	private static native byte[] DEC(int db_sid, int enc_col_id, byte[] src, int sql_type); // decrypt
	private static native byte[] DEC_NM(int db_sid, byte[] enc_col_name, byte[] src, int sql_type); // decrypt
	private static native byte[] OPHUEK(int db_sid, int enc_col_id, byte[] src,int src_enc_flag); // get indexing hash
	private static native byte[] OPHUEK_NM(int db_sid, byte[] enc_col_name, byte[] src,int src_enc_flag); // get indexing hash
	private static native byte[] ENC_CPN(int db_sid, int enc_col_id, byte[] src); // encrypt coupon
	private static native byte[] ENC_CPN_NM(int db_sid, byte[] enc_col_name, byte[] src); // encrypt coupon
	private static native byte[] DEC_CPN(int db_sid, int enc_col_id, byte[] src); // decrypt coupon
	private static native byte[] DEC_CPN_NM(int db_sid, byte[] enc_col_name, byte[] src); // decrypt coupon
	private static native int SSHT(int db_sid, byte[] sql_hash, int sql_type); // set sql byte array hash 
	private static native int LCR(int db_sid, byte[] sql_hash, int sql_type); // log current request with byte array hash
	private static native int LCR(int db_sid, byte[] api_program, int sql_type, byte[] api_userid); // log current request with byte array hash
	private static native int ECODE(int db_sid); // get error code
	private static native int GNSF(int db_sid); // get new sql flag
	private static native long LCT(int db_sid); // last call time
	private static native void LOGGING(int ecode, byte[] msg); // logging message
	private static native int NSS(); // the number of shared session
	private static native int MAXPS(); // the maximum number of private session
	private static native int ENCFILE(int db_sid, byte[] conf_file_path); 
	private static native byte[] GETKEY(int db_sid, byte[] enc_col_name);

	private static native String ENC(int db_sid, int enc_col_id, String src); // encrypt
	private static native String DEC(int db_sid, int enc_col_id, String src); // decrypt
	private static native int CRYPTFILE(int db_sid, byte[] param_string, byte[] intput_file_path, byte[] output_file_path);
	// added by chchung 2017.5.31 for stand alone session
	private static native byte[] GETKEYINFO(int db_sid, byte[] enc_col_name, byte[] passwd);
	// added by chchung 2017.5.31 for stand alone session
	private static native int PUTKEYINFO(byte[] key_info, byte[] passwd);
	private static native int ENCRYPTFILE(int db_sid, byte[] zone_name, byte[] intput_file_path, byte[] output_file_path, int num_using_core);
	private static native int DECRYPTFILE(int db_sid, byte[] zone_name, byte[] intput_file_path, byte[] output_file_path, int num_using_core);
	private static native int ENCF(int db_sid, byte[] key_name, byte[] intput_file_path, byte[] output_file_path);
	private static native int DECF(int db_sid, byte[] key_name, byte[] intput_file_path, byte[] output_file_path);
	private static native int CRC32CHECK(byte[] src);

	private static native byte[] REGENCRYPT(int db_sid, byte[] key_name, byte[] src, byte[] reg_name); // regEncrypt
	private static native byte[] REGDECRYPT(int db_sid, byte[] key_name, byte[] src); // regDecrypt

	private static native long GETORGSIZE(byte[] file_name); // getOrgSize
	private static native int GETDECBUFSIZE(byte[] key_name, byte[] file_name); // getDecBufSize
	private static native int GETHEADERSIZE(byte[] file_name); // getHeaderSize
	private static native int ISENCRYPTED(byte[] file_name); //check encrypted
	private static native int EXISTPTTNBUF(byte[] src, byte[] pattern_list); //check being pattern about src buffer
	private static native int EXISTPTTNBUFDETAIL(byte[] src, byte[] pattern_list, byte[] ret_buf); //check being pattern about src buffer
	private static native int EXISTPTTNFILE(byte[] file_name, byte[] pattern_list); //check being pattern about file
	private static native int EXISTPTTNFILEDETAIL(byte[] file_name, byte[] pattern_list, byte[] ret_buf); //check being pattern about file

	private static native int ENCLEN(int db_sid, byte[] enc_col_name, int src_len); // encrypt length

	private static native byte[] RSA_PUBLIC_ENCRYPT(byte[] file_path, byte[] src); // RSA encrypt oaep padding
	private static native byte[] RSA_PRIVATE_DECRYPT(byte[] file_path, byte[] enc_col_name, byte[] src); // RSA decrypt oaep padding
	private static native byte[] RSA_PUBLIC_ENCRYPT_PKCS(byte[] file_path, byte[] src); // RSA encrypt pkcs1 padding 
	private static native byte[] RSA_PRIVATE_DECRYPT_PKCS(byte[] file_path, byte[] enc_col_name, byte[] src); // RSA decrypt pkcs1 padding

	private static native byte[] HMAC_SHA1(byte[] key, byte[] src); // HMAC SHA1 by key
	private static native byte[] HMAC_SHA1_NM(byte[] key_name, byte[] src); // HMAC SHA1 by key name
	private static native String HMAC_SHA1_B64(byte[] key, byte[] src); // HMAC SHA1 base64 encode by key
	private static native String HMAC_SHA1_B64_NM(byte[] key_name, byte[] src); // HMAC SHA1 base64 encode by key name
	private static native byte[] HMAC_SHA256(byte[] key, byte[] src); // HMAC SHA256 by key
	private static native byte[] HMAC_SHA256_NM(byte[] key_name, byte[] src); // HMAC SHA256 by key name
	private static native String HMAC_SHA256_B64(byte[] key, byte[] src); // HMAC SHA256 base64 encode by key
	private static native String HMAC_SHA256_B64_NM(byte[] key_name, byte[] src); // HMAC SHA256 base64 encode by key name

	//added by shson 2018.12.12 for nh_bank
	private static native int PARAMCRYPTFILE(int db_sid, byte[] crypt_mode, byte[] param_name, byte[] input_file_path, byte[] output_file_path);

	private static native byte[] GETRSAKEY(int db_sid, byte[] key_name);

	public static void initialize(String conf_file_path, String credentials_password) throws PcaException
	{
		byte[]	cfp;
		if (conf_file_path != null) cfp = conf_file_path.getBytes();
		else cfp = "".getBytes();
		byte[]	cp = "".getBytes();
		if (credentials_password != null) cp = credentials_password.getBytes();
		else  cp = "".getBytes();
		int rtn = INIT(cfp, cp);
		if (rtn != 0) {
			throw new PcaException("initialize failed. error code[" + rtn + "]",rtn);
		}
	}

	public static int numSharedSession()
	{
		return NSS();
	}

	public static int maxPrivateSession()
	{
		return MAXPS();
	}

	public static String genHashKey(String client_ip, String user_id, String client_program)
	{
		return new String("ci="+client_ip+"ui="+user_id+"cp="+client_program);
	}

	public PcaSession(String client_ip, String user_id, String client_program) throws PcaException
	{
		HashKey = genHashKey(client_ip,user_id,client_program);
		if (client_ip == null) client_ip = new String("");
		if (user_id == null) user_id = new String("");
		if (client_program == null) client_program = new String("");
		if ((SID=OPN(0, "".getBytes(), "".getBytes(), client_ip.getBytes(), "".getBytes(), user_id.getBytes(), client_program.getBytes(), 0, user_id.getBytes(), "".getBytes())) < 0) {
			throw new PcaException("session open failed. error code[" + SID + "]",SID);
		}
	}

	public PcaSession() throws PcaException
        {
		if ((SID=OPN(0, "".getBytes(), "".getBytes(), "127.0.0.1".getBytes(), "".getBytes(), "".getBytes(), "".getBytes(), 0, "".getBytes(), "".getBytes())) < 0) {
			throw new PcaException("session open failed. error code[" + SID + "]",SID);
		}
        }

	public void setCharSet(String char_set)
	{
		byte[]	char_set_bytes = "".getBytes();
		if (char_set != null) char_set_bytes = char_set.getBytes();
		CCS(SID, char_set_bytes);
	}

	public byte[] encrypt(int eci, byte[] src) throws PcaException
	{
		if (src == null) src = "".getBytes();
		byte[]	encrypted_data;
		synchronized (this) {
			encrypted_data = ENC(SID, eci, src);
		}
		if (encrypted_data == null) {
			int	ErrCode = ECODE(SID);
			if (ErrCode != 0) {
				throw new PcaException("encryption failed, error code["+ErrCode+"]",ErrCode);
			}
		}
		return encrypted_data;
	}

	public byte[] encrypt(int eci, byte[] src, int sql_type) throws PcaException
        {
                if (src == null) src = "".getBytes();
                byte[]  encrypted_data;
                synchronized (this) {
                        encrypted_data = ENC(SID, eci, src, sql_type);
                }
                if (encrypted_data == null) {
                        int     ErrCode = ECODE(SID);
                        if (ErrCode != 0) {
								throw new PcaException("encryption failed, error code["+ErrCode+"]",ErrCode);
                        }
                }
                return encrypted_data;
        }

	public String encrypt(int eci, String src) throws PcaException
	{
		byte[]	src_bytes = null;
		if (src != null) src_bytes = src.getBytes();
		byte[]	encrypted_data = encrypt(eci, src_bytes);
		if (encrypted_data == null) return null;
		return new String(encrypted_data);
	}

	public String enc(int eci, String src) throws PcaException
        {
		if (src == null) src = new String("");
                String  encrypted_data;
                synchronized (this) {
                        encrypted_data = ENC(SID, eci, src);
                }
                if (encrypted_data == null) {
                        int     ErrCode = ECODE(SID);
                        if (ErrCode != 0) {
								throw new PcaException("encryption failed, error code["+ErrCode+"]",ErrCode);
                        }
                }
                return encrypted_data;
        }

	public String encrypt(int eci, String src, int sql_type) throws PcaException
        {
                byte[]  src_bytes = null;
                if (src != null) src_bytes = src.getBytes();
                byte[]  encrypted_data = encrypt(eci, src_bytes, sql_type);
                if (encrypted_data == null) return null;
                return new String(encrypted_data);
        }

	public byte[] encrypt(String ecn, byte[] src) throws PcaException
	{
		if (ecn == null) ecn = new String("");
		if (src == null) src = "".getBytes();
		byte[]	encrypted_data;
		synchronized (this) {
			encrypted_data = ENC_NM(SID, ecn.getBytes(), src);
		}
		if (encrypted_data == null) {
			int	ErrCode = ECODE(SID);
			if (ErrCode != 0) {
				throw new PcaException("encryption failed, error code["+ErrCode+"]",ErrCode);
			}
		}
		return encrypted_data;
	}

	//this api not using except IBK about rsa
	//only using IBK bank
	public byte[] encrypt(String ecn, byte[] src, byte[] set_key) throws PcaException
	{
		if (ecn == null) ecn = new String("");
		if (src == null) src = "".getBytes();
		byte[]	encrypted_data;
		synchronized (this) {
			encrypted_data = ENC_NM_SETKEY(SID, ecn.getBytes(), src, set_key);
		}
		if (encrypted_data == null) {
			int	ErrCode = ECODE(SID);
			if (ErrCode != 0) {
				throw new PcaException("encryption failed, error code["+ErrCode+"]",ErrCode);
			}
		}
		return encrypted_data;
	}

	public byte[] encrypt(String ecn, byte[] src, int sql_type, byte[] set_key, byte[] set_iv) throws PcaException
	{
		if (ecn == null) ecn = new String("");
		if (src == null) src = "".getBytes();
		byte[]	encrypted_data;
		synchronized (this) {
			encrypted_data = ENC_NM_SETKEYIV(SID, ecn.getBytes(), src, sql_type, set_key, set_iv);
		}
		if (encrypted_data == null) {
			int	ErrCode = ECODE(SID);
			if (ErrCode != 0) {
				throw new PcaException("encryption failed, error code["+ErrCode+"]",ErrCode);
			}
		}
		return encrypted_data;
	}

	public byte[] encryptLen(String ecn, byte[] src, int src_len) throws PcaException
	{
		if (ecn == null) ecn = new String("");
		if (src == null) src = "".getBytes();
		if (src_len == 0) return src;
		byte[]	src_data = new byte[src_len];
		System.arraycopy(src, 0, src_data,0 ,src_len);
		byte[]	encrypted_data;

		synchronized (this) {
			encrypted_data = ENC_NM(SID, ecn.getBytes(), src_data);
		}
		if (encrypted_data == null) {
			int	ErrCode = ECODE(SID);
			if (ErrCode != 0) {
				throw new PcaException("encryption failed, error code["+ErrCode+"]",ErrCode);
			}
		}
		return encrypted_data;
	}

	public byte[] encrypt(String ecn, byte[] src, int sql_type) throws PcaException
        {
                if (ecn == null) ecn = new String("");
                if (src == null) src = "".getBytes();
                byte[]  encrypted_data;
                synchronized (this) {
                        encrypted_data = ENC_NM(SID, ecn.getBytes(), src, sql_type);
                }
                if (encrypted_data == null) {
                        int     ErrCode = ECODE(SID);
                        if (ErrCode != 0) {
							throw new PcaException("encryption failed, error code["+ErrCode+"]",ErrCode);
                        }
                }
                return encrypted_data;
        }

	public String encrypt(String ecn, String src) throws PcaException
	{
		byte[]	src_bytes = null;
		if (src != null) src_bytes = src.getBytes();
		byte[]	encrypted_data = encrypt(ecn, src_bytes);
		if (encrypted_data == null) return null;
		return new String(encrypted_data);
	}

	public String encrypt(String ecn, String src, int sql_type) throws PcaException
        {
                byte[]  src_bytes = null;
                if (src != null) src_bytes = src.getBytes();
                byte[]  encrypted_data = encrypt(ecn, src_bytes, sql_type);
                if (encrypted_data == null) return null;
                return new String(encrypted_data);
        }

        public byte[] encrypt(byte[] src) throws PcaException
        {
                if (src == null) src = "".getBytes();
                byte[]  encrypted_data = encrypt(null, src);
                if (encrypted_data == null) return null;
                return encrypted_data;
        }

        public String encrypt(String src) throws PcaException
        {
                byte[]  src_bytes = null;
                if (src != null) src_bytes = src.getBytes();
                byte[]  encrypted_data = encrypt(null, src_bytes);
                if (encrypted_data == null) return null;
                return new String(encrypted_data);
        }

        public String encryptHash(String src) throws PcaException
        {
                byte[]  src_bytes = null;
                if (src != null) src_bytes = src.getBytes();
                byte[]  encrypted_data = encrypt(DefaultHashColName, src_bytes);
                if (encrypted_data == null) return null;
                return new String(encrypted_data);
	}

	public byte[] decrypt(int eci, byte[] src) throws PcaException
	{
		if (src == null) src = "".getBytes();
		byte[]	decrypted_data;
		synchronized (this) {
			decrypted_data = DEC(SID, eci, src);
		}
		if (decrypted_data == null) {
			int	ErrCode = ECODE(SID);
			if (ErrCode != 0) {
				throw new PcaException("decryption failed, error code["+ErrCode+"]",ErrCode);
			}
		}
		return decrypted_data;
	}

	public byte[] decrypt(int eci, byte[] src, int sql_type) throws PcaException
        {
                if (src == null) src = "".getBytes();
                byte[]  decrypted_data;
                synchronized (this) {
                        decrypted_data = DEC(SID, eci, src, sql_type);
                }
                if (decrypted_data == null) {
                        int     ErrCode = ECODE(SID);
                        if (ErrCode != 0) {
							throw new PcaException("decryption failed, error code["+ErrCode+"]",ErrCode);
                        }
                }
                return decrypted_data;
        }

	public String decrypt(int eci, String src) throws PcaException
	{
		byte[]	src_bytes = null;
		if (src != null) src_bytes = src.getBytes();
		byte[]	decrypted_data = decrypt(eci, src_bytes);
		if (decrypted_data == null) return null;
		return new String(decrypted_data);
	}

	public String decrypt(int eci, String src, int sql_type) throws PcaException
        {
                byte[]  src_bytes = null;
                if (src != null) src_bytes = src.getBytes();
                byte[]  decrypted_data = decrypt(eci, src_bytes, sql_type);
                if (decrypted_data == null) return null;
                return new String(decrypted_data);
        }

	public String dec(int eci, String src) throws PcaException
        {
                if (src == null) return null;
                String  decrypted_data;
                synchronized (this) {
                        decrypted_data = DEC(SID, eci, src);
                }
                if (decrypted_data == null) {
                        int     ErrCode = ECODE(SID);
                        if (ErrCode != 0) {
							throw new PcaException("decryption failed, error code["+ErrCode+"]",ErrCode);
                        }
                }
                return decrypted_data;
        }

	public byte[] decrypt(String ecn, byte[] src) throws PcaException
	{
		if (ecn == null) ecn = new String("");
		if (src == null) src = "".getBytes();
		byte[]	decrypted_data;
		synchronized (this) {
			decrypted_data = DEC_NM(SID, ecn.getBytes(), src);
		}
		if (decrypted_data == null) {
			int	ErrCode = ECODE(SID);
			if (ErrCode != 0) {
				throw new PcaException("decryption failed, error code["+ErrCode+"]",ErrCode);
			}
		}
		return decrypted_data;
	}

	//this api not using except IBK about rsa
	//only using IBK bank
	public byte[] decrypt(String ecn, byte[] src, byte[] set_key) throws PcaException
	{
		if (ecn == null) ecn = new String("");
		if (src == null) src = "".getBytes();
		byte[]	decrypted_data;
		synchronized (this) {
			decrypted_data = DEC_NM_SETKEY(SID, ecn.getBytes(), src, set_key);
		}
		if (decrypted_data == null) {
			int	ErrCode = ECODE(SID);
			if (ErrCode != 0) {
				throw new PcaException("decryption failed, error code["+ErrCode+"]",ErrCode);
			}
		}
		return decrypted_data;
	}

	public byte[] decrypt(String ecn, byte[] src, int sql_type, byte[] set_key, byte[] set_iv) throws PcaException
	{
		if (ecn == null) ecn = new String("");
		if (src == null) src = "".getBytes();
		byte[]	decrypted_data;
		synchronized (this) {
			decrypted_data = DEC_NM_SETKEYIV(SID, ecn.getBytes(), src, sql_type, set_key, set_iv);
		}
		if (decrypted_data == null) {
			int	ErrCode = ECODE(SID);
			if (ErrCode != 0) {
				throw new PcaException("decryption failed, error code["+ErrCode+"]",ErrCode);
			}
		}
		return decrypted_data;
	}

	public byte[] decryptLen(String ecn, byte[] src, int src_len) throws PcaException
	{
		if (ecn == null) ecn = new String("");
		if (src == null) src = "".getBytes();
		if (src_len == 0) return src;
		byte[]	src_data = new byte[src_len];
		System.arraycopy(src, 0, src_data,0 ,src_len);
		byte[]	decrypted_data;
		synchronized (this) {
			decrypted_data = DEC_NM(SID, ecn.getBytes(), src_data);
		}
		if (decrypted_data == null) {
			int	ErrCode = ECODE(SID);
			if (ErrCode != 0) {
				throw new PcaException("decryption failed, error code["+ErrCode+"]",ErrCode);
			}
		}
		return decrypted_data;
	}

	public byte[] decrypt(String ecn, byte[] src, int sql_type) throws PcaException
        {
                if (ecn == null) ecn = new String("");
                if (src == null) src = "".getBytes();
                byte[]  decrypted_data;
                synchronized (this) {
                        decrypted_data = DEC_NM(SID, ecn.getBytes(), src, sql_type);
                }
                if (decrypted_data == null) {
                        int     ErrCode = ECODE(SID);
                        if (ErrCode != 0) {
							throw new PcaException("decryption failed, error code["+ErrCode+"]",ErrCode);
                        }
                }
                return decrypted_data;
        }

	public String decrypt(String ecn, String src) throws PcaException
	{
		byte[]	src_bytes = null;
		if (src != null) src_bytes = src.getBytes();
		byte[]	decrypted_data = decrypt(ecn, src_bytes);
		if (decrypted_data == null) return null;
		return new String(decrypted_data);
	}

	public String decrypt(String ecn, String src, int sql_type) throws PcaException
        {
                byte[]  src_bytes = null;
                if (src != null) src_bytes = src.getBytes();
                byte[]  decrypted_data = decrypt(ecn, src_bytes, sql_type);
                if (decrypted_data == null) return null;
                return new String(decrypted_data);
        }

        public byte[] decrypt(byte[] src) throws PcaException
        {
                if (src == null) src = "".getBytes();
                byte[]  decrypted_data = decrypt(null, src);
                if (decrypted_data == null) return null;
                return decrypted_data;
        }

        public String decrypt(String src) throws PcaException
        {
                byte[]  src_bytes = null;
                if (src != null) src_bytes = src.getBytes();
                byte[]  decrypted_data = decrypt(null, src_bytes);
                if (decrypted_data == null) return null;
                return new String(decrypted_data);
        }

	public byte[] OPHUEK(int eci, byte[] src, int src_enc_flag) throws PcaException
	{
		if (src == null) src = "".getBytes();
		byte[]	hash_data;
		synchronized (this) {
			hash_data = OPHUEK(SID, eci, src, src_enc_flag);
		}
		if (hash_data == null) {
			throw new PcaException("ophuek failed, error code[" + ECODE(SID) + "]",ECODE(SID));
		}
		return hash_data;
	}

	public byte[] OPHUEK(String ecn, byte[] src, int src_enc_flag) throws PcaException
	{
		if (ecn == null) ecn = new String("");
		if (src == null) src = "".getBytes();
		byte[]	hash_data;
		synchronized (this) {
			hash_data = OPHUEK_NM(SID, ecn.getBytes(), src, src_enc_flag);
		}
		if (hash_data == null) {
			throw new PcaException("ophuek failed, error code[" + ECODE(SID) + "]",ECODE(SID));
		}
		return hash_data;
	}

	public byte[] encryptCpn(int eci, byte[] src) throws PcaException
	{
		if (src == null) src = "".getBytes();
		byte[]	coupon;
		synchronized (this) {
			coupon = ENC_CPN(SID, eci, src);
		}
		if (coupon == null) {
			int	ErrCode = ECODE(SID);
			if (ErrCode != 0) {
				throw new PcaException("encryption failed, error code["+ErrCode+"]",ErrCode);
			}
		}
		return coupon;
	}

	public byte[] encryptCpn(String ecn, byte[] src) throws PcaException
	{
		if (ecn == null) ecn = new String("");
		if (src == null) src = "".getBytes();
		byte[]	coupon;
		synchronized (this) {
			coupon = ENC_CPN_NM(SID, ecn.getBytes(), src);
		}
		if (coupon == null) {
			int	ErrCode = ECODE(SID);
			if (ErrCode != 0) {
				throw new PcaException("encryption failed, error code["+ErrCode+"]",ErrCode);
			}
		}
		return coupon;
	}

	public byte[] decryptCpn(int eci, byte[] coupon) throws PcaException
	{
		if (coupon == null) coupon = "".getBytes();
		byte[]	decrypted_data;
		synchronized (this) {
			decrypted_data = DEC_CPN(SID, eci, coupon);
		}
		if (decrypted_data == null) {
			int	ErrCode = ECODE(SID);
			if (ErrCode != 0) {
				throw new PcaException("decryption failed, error code["+ErrCode+"]",ErrCode);
			}
		}
		return decrypted_data;
	}

	public byte[] decryptCpn(String ecn, byte[] coupon) throws PcaException
	{
		if (ecn == null) ecn = new String("");
		if (coupon == null) coupon = "".getBytes();
		byte[]	decrypted_data;
		synchronized (this) {
			decrypted_data = DEC_CPN_NM(SID, ecn.getBytes(), coupon);
		}
		if (decrypted_data == null) {
			int	ErrCode = ECODE(SID);
			if (ErrCode != 0) {
				throw new PcaException("decryption failed, error code["+ErrCode+"]",ErrCode);
			}
		}
		return decrypted_data;
	}

	public int newSqlFlag()
	{
		return GNSF(SID);
	}

	public long lastCallTime()
	{
		return LCT(SID);
	}

	public void logCurrRequest(byte[] sql_hash, int sql_type)
	{
		if (sql_hash == null) sql_hash = "".getBytes();
		synchronized (this) {
			LCR(SID, sql_hash, sql_type);
		}
	}

	public void logCurrRequest(int sql_type, String api_program, String api_userid)
        {
                if (api_program == null) api_program = "";
                if (api_userid == null) api_userid = "";
                synchronized (this) {
                        LCR(SID, api_program.getBytes(), sql_type, api_userid.getBytes());
                }
        }

	public void closeSession()
	{
		synchronized (this) {
			if (SID >= 0) {
				CLS(SID);
				SID = -1;
			}
		}
	}

	public int encFile(String conf_file_path) throws PcaException
	{
		int ret=0;
		synchronized (this) {
			ret=ENCFILE(SID,conf_file_path.getBytes());
		}
		if (ret < 0) {
			throw new PcaException("samfile encrypt/decrypt failed[" + ret + "]",ret);
		}
		return ret;
		
	}

	public byte[] getKey(String ecn) throws PcaException
        {
                if (ecn == null) ecn = new String("");
                byte[]  key_data;
                synchronized (this) {
                        key_data = GETKEY(SID, ecn.getBytes());
                }
                if (key_data == null) {
                        int     ErrCode = ECODE(SID);
                        if (ErrCode != 0) {
							throw new PcaException("getKey failed, error code[" + ErrCode + "]",ErrCode);
                        }
                }
                return key_data;
        }

	public void cryptFile(String param_file_path) throws PcaException
	{
		int ret=0;
		synchronized (this) {
                        ret=CRYPTFILE(SID,param_file_path.getBytes(),"".getBytes(),"".getBytes());
                }
                if (ret < 0) {
			int     ErrCode = ECODE(SID);
                        throw new PcaException("file encrypt/decrypt failed[" + ret + "]",ret);
                }
	}

	public void cryptFile(String param_string, String input_file_path, String output_file_path) throws PcaException
	{
		int ret=0;
		if (input_file_path == null) input_file_path=new String("");
		if (output_file_path == null) output_file_path=new String("");
                synchronized (this) {
                        ret=CRYPTFILE(SID,param_string.getBytes(),input_file_path.getBytes(),output_file_path.getBytes());
                }
                if (ret < 0) {
			int     ErrCode = ECODE(SID);
                        throw new PcaException("file encrypt/decrypt failed[" + ret + "]",ret);
                }
	}

	public int isEncrypted(String file_name) throws PcaException
	{
		int ret=0;
		synchronized (this) {
                        ret=ISENCRYPTED(file_name.getBytes());
                }
		return ret;
	}

	public int encF(String key_name, String input_file_path, String output_file_path) throws PcaException
	{
		int ret=0;
		if (input_file_path == null) input_file_path=new String("");
		if (output_file_path == null) output_file_path=new String("");
		synchronized (this) {
			ret=ENCF(SID,key_name.getBytes(),input_file_path.getBytes(),output_file_path.getBytes());
		}
		if (ret < 0) {
			return ret;
		}
		return 0;
	}

	public int decF(String key_name, String input_file_path, String output_file_path) throws PcaException
	{
		int ret=0;
		if (input_file_path == null) input_file_path=new String("");
		if (output_file_path == null) output_file_path=new String("");
		synchronized (this) {
			ret=DECF(SID,key_name.getBytes(),input_file_path.getBytes(),output_file_path.getBytes());
		}
		if (ret < 0) {
			return ret;
		}
		return 0;
	}


	// added by chchung 2017.5.31 for stand alone session
	public String getKeyInfo(String ecn,String passwd) throws PcaException
        {
                if (ecn == null) ecn = new String("");
                if (passwd == null) passwd = new String("");
                byte[]  key_info;
                synchronized (this) {
                        key_info = GETKEYINFO(SID, ecn.getBytes(), passwd.getBytes());
                }
                if (key_info == null) {
                        int     ErrCode = ECODE(SID);
                        if (ErrCode != 0) {
							throw new PcaException("getKeyInfo failed, error code[" + ErrCode + "]",ErrCode);
                        }
                }
                return new String(key_info);
        }

	// added by chchung 2017.5.31 for stand alone session
	public static void putKeyInfo(String key_info,String passwd) throws PcaException
	{
		int ret=0;
                if (key_info == null) {
			throw new PcaException("key_info is null",-1);
		}
                if (passwd == null) passwd = new String("");
                ret = PUTKEYINFO(key_info.getBytes(), passwd.getBytes());
                if (ret < 0) {
					throw new PcaException("PUTKEYINFO failed[" + ret + "]",ret);
                }
	}

	public void encryptFile(String zone_name,String input_file_path,String output_file_path,int num_using_core) throws PcaException
	{
		int ret=0;
		if (zone_name == null) zone_name=new String("");
		if (input_file_path == null) input_file_path=new String("");
		if (output_file_path == null) output_file_path=new String("");
		synchronized (this) {
        	ret=ENCRYPTFILE(SID,zone_name.getBytes(),input_file_path.getBytes(),output_file_path.getBytes(),num_using_core);
		}
		if (ret < 0) {
			int ErrCode = ECODE(SID);
			throw new PcaException("file encrypt/decrypt failed[" + ret + "]",ret);
		}
	}

	public void decryptFile(String zone_name,String input_file_path,String output_file_path,int num_using_core) throws PcaException
	{
		int ret=0;
		if (zone_name == null) zone_name=new String("");
		if (input_file_path == null) input_file_path=new String("");
		if (output_file_path == null) output_file_path=new String("");
		synchronized (this) {
        	ret=DECRYPTFILE(SID,zone_name.getBytes(),input_file_path.getBytes(),output_file_path.getBytes(),num_using_core);
		}
		if (ret < 0) {
			int ErrCode = ECODE(SID);
			throw new PcaException("file encrypt/decrypt failed[" + ret + "]",ret);
		}
	}

	public int CRC32Check(String src)
        {
                int ret=0;
                if (src == null) return 0;
                synchronized (this) {
			ret=CRC32CHECK(src.getBytes());
                }
		return ret;
        }

	//byte[] (byte[] byte[] byte[]
	public byte[] regEncrypt(byte[] key_name, byte[] src, byte[] reg_name) throws PcaException
        {
                if (src == null) src = "".getBytes();
                byte[]  encrypted_data;
                synchronized (this) {
                        encrypted_data = REGENCRYPT(SID, key_name, src, reg_name);
                }
                if (encrypted_data == null) {
                        int     ErrCode = ECODE(SID);
                        if (ErrCode != 0) {
								throw new PcaException("regular encryption failed, error code["+ErrCode+"]",ErrCode);
                        }
                }
                return encrypted_data;
        }

	//byte[] (String byte[] String)
	public byte[] regEncrypt(String key_name, byte[] src, String reg_name) throws PcaException
        {
                if (src == null) src = "".getBytes();
                byte[]  encrypted_data = regEncrypt(key_name.getBytes(), src, reg_name.getBytes());
                if (encrypted_data == null) return null;
					return encrypted_data;
        }

	//String (String String String)
	public String regEncrypt(String key_name, String src, String reg_name) throws PcaException
        {
		byte[]  src_bytes = null; 
		if (src == null) src = "";
		if (src != null) src_bytes = src.getBytes(); 
                byte[]  encrypted_data = regEncrypt(key_name.getBytes(), src.getBytes(), reg_name.getBytes());
                if (encrypted_data == null) return null;
		return new String(encrypted_data);
        }

	//byte[] (byte[] byte[] byte[]
	public byte[] regDecrypt(byte[] key_name, byte[] src) throws PcaException
        {
                if (src == null) src = "".getBytes();
                byte[]  decrypted_data;
                synchronized (this) {
                        decrypted_data = REGDECRYPT(SID, key_name, src);
                }
                if (decrypted_data == null) {
                        int     ErrCode = ECODE(SID);
                        if (ErrCode != 0) {
								throw new PcaException("regular encryption failed, error code["+ErrCode+"]",ErrCode);
                        }
                }
                return decrypted_data;
        }

	//byte[] (String byte[])
	public byte[] regDecrypt(String key_name, byte[] src) throws PcaException
	{
                if (src == null) src = "".getBytes();
                byte[]  decrypted_data = regDecrypt(key_name.getBytes(), src);
                if (decrypted_data == null) return null;
		return decrypted_data;

	}

	//String (String String)
	public String regDecrypt(String key_name, String src) throws PcaException
	{
		byte[]  src_bytes = null; 
		if (src == null) src = "";
		if (src != null) src_bytes = src.getBytes(); 
                byte[]  decrypted_data = regDecrypt(key_name.getBytes(), src.getBytes());
                if (decrypted_data == null) return null;
		return new String(decrypted_data);

	}
	public long getOrgSize(String file_name) throws PcaException
	{
		long org_size = 0;
			org_size = GETORGSIZE(file_name.getBytes());
		return org_size;
	}

	public int getDecBufSize(String key_name, String file_name) throws PcaException
	{
		int dec_buf_size = 0;
			dec_buf_size = GETDECBUFSIZE(key_name.getBytes(), file_name.getBytes());
		return dec_buf_size;
	}

	public int getHeaderSize(String file_name) throws PcaException
	{
		int header_size = 0;
			header_size = GETHEADERSIZE(file_name.getBytes());
		return header_size;
	}

	public int existPttnBuf(String src, String pattern_list) throws PcaException
	{
		int rtn = 0;
		synchronized (this) {
			rtn= EXISTPTTNBUF(src.getBytes(), pattern_list.getBytes()); //check being pattern about src buffer
		}
		return rtn;
	}

	public int existPttnBufDetail(String src, String pattern_list, byte[] ret_buf) throws PcaException
	{
		int rtn = 0;
		synchronized (this) {
			rtn= EXISTPTTNBUFDETAIL(src.getBytes(), pattern_list.getBytes(), ret_buf); //check being pattern about src buffer
		}
		return rtn;
	}

	public int existPttnFile(String file_name, String pattern_list) throws PcaException
	{
		int rtn = 0;
		synchronized (this) {
			rtn= EXISTPTTNFILE(file_name.getBytes(), pattern_list.getBytes()); //check being pattern about src buffer
		}
		return rtn;
	}

	public int existPttnFileDetail(String file_name, String pattern_list, byte[] ret_buf) throws PcaException
	{
		int rtn = 0;
		synchronized (this) {
			rtn= EXISTPTTNFILEDETAIL(file_name.getBytes(), pattern_list.getBytes(), ret_buf); //check being pattern about src buffer
		}
		return rtn;
	}

	public int encryptLength(String key_name, int src_len) throws PcaException
	{
		int rtn = 0;
		synchronized (this) {
		rtn = ENCLEN(SID, key_name.getBytes(), src_len); // get encrypt length
		}
		return rtn;
	}

	public byte[] rsa_public_encrypt(String file_path, byte[] src) throws PcaException
        {
				byte[]  src_bytes = null; 
                if (src == null) src = "".getBytes();
                byte[]  encrypted_data = RSA_PUBLIC_ENCRYPT(file_path.getBytes(), src);
				if (encrypted_data == null) {
					throw new PcaException("rsa_public_encrypt failed, check petra_cipher_api.log");
				}
					return encrypted_data;
        }

	public byte[] rsa_private_decrypt(String file_path, String enc_col_name, byte[] src) throws PcaException
	{
				byte[]  src_bytes = null; 
                if (src == null) src = "".getBytes();
                byte[]  decrypted_data = RSA_PRIVATE_DECRYPT(file_path.getBytes(), enc_col_name.getBytes(), src);
				if (decrypted_data == null) {
					throw new PcaException("rsa_private_decrypt failed, check petra_cipher_api.log");
				}
					return decrypted_data;

	}

	public byte[] rsa_public_encrypt_pkcs(String file_path, byte[] src) throws PcaException
        {
				byte[]  src_bytes = null; 
                if (src == null) src = "".getBytes();
                byte[]  encrypted_data = RSA_PUBLIC_ENCRYPT_PKCS(file_path.getBytes(), src);
				if (encrypted_data == null) {
					throw new PcaException("rsa_public_encrypt failed, check petra_cipher_api.log");
				}
					return encrypted_data;
        }

	public byte[] rsa_private_decrypt_pkcs(String file_path, String enc_col_name, byte[] src) throws PcaException
	{
				byte[]  src_bytes = null; 
                if (src == null) src = "".getBytes();
                byte[]  decrypted_data = RSA_PRIVATE_DECRYPT_PKCS(file_path.getBytes(), enc_col_name.getBytes(), src);
				if (decrypted_data == null) {
					throw new PcaException("rsa_private_decrypt failed, check petra_cipher_api.log");
				}
					return decrypted_data;

	}

        public byte[] hmac_sha1(byte[] key, String src) throws PcaException
        {
                byte[]  src_bytes = null;
                if (src != null) src_bytes = src.getBytes();

                byte[]  dst_data = HMAC_SHA1(key, src_bytes);
                if (dst_data == null) {
                        throw new PcaException("hmac_sha1 failed, check petra_cipher_api.log");
                }
                return dst_data;
        }

        public byte[] hmac_sha1_nm(String key_name, String src) throws PcaException
        {
                byte[]  src_bytes = null;
                if (key_name == null) key_name = new String("");
                if (src != null) src_bytes = src.getBytes();

                byte[] dst_data = HMAC_SHA1_NM(key_name.getBytes(), src_bytes);
                if (dst_data == null) {
                        throw new PcaException("hmac_sha1_nm failed, check petra_cipher_api.log");
                }
                return dst_data;
        }

        public String hmac_sha1_b64(byte[] key, String src) throws PcaException
        {
                byte[]  src_bytes = null;
                if (src != null) src_bytes = src.getBytes();

                String dst_data = HMAC_SHA1_B64(key, src_bytes);
                if (dst_data == null) {
                        throw new PcaException("hmac_sha1_b64 failed, check petra_cipher_api.log");
                }
                return dst_data;
        }

        public String hmac_sha1_b64_nm(String key_name, String src) throws PcaException
        {
                byte[]  src_bytes = null;
                if (key_name == null) key_name = new String("");
                if (src != null) src_bytes = src.getBytes();

                String dst_data = HMAC_SHA1_B64_NM(key_name.getBytes(), src_bytes);
                if (dst_data == null) {
                        throw new PcaException("hmac_sha1_b64_nm failed, check petra_cipher_api.log");
                }
                return dst_data;
        }

        public byte[] hmac_sha256(byte[] key, String src) throws PcaException
        {
                byte[]  src_bytes = null;
                if (src != null) src_bytes = src.getBytes();

                byte[]  dst_data = HMAC_SHA256(key, src_bytes);
                if (dst_data == null) {
                        throw new PcaException("hmac_sha256 failed, check petra_cipher_api.log");
                }
                return dst_data;
        }

        public byte[] hmac_sha256_nm(String key_name, String src) throws PcaException
        {
                byte[]  src_bytes = null;
                if (key_name == null) key_name = new String("");
                if (src != null) src_bytes = src.getBytes();

                byte[] dst_data = HMAC_SHA256_NM(key_name.getBytes(), src_bytes);
                if (dst_data == null) {
                        throw new PcaException("hmac_sha256_nm failed, check petra_cipher_api.log");
                }
                return dst_data;
        }

        public String hmac_sha256_b64(byte[] key, String src) throws PcaException
        {
                byte[]  src_bytes = null;
                if (src != null) src_bytes = src.getBytes();

                String dst_data = HMAC_SHA256_B64(key, src_bytes);
                if (dst_data == null) {
                        throw new PcaException("hmac_sha256_b64 failed, check petra_cipher_api.log");
                }
                return dst_data;
        }

        public String hmac_sha256_b64_nm(String key_name, String src) throws PcaException
        {
                byte[]  src_bytes = null;
                if (key_name == null) key_name = new String("");
                if (src != null) src_bytes = src.getBytes();

                String dst_data = HMAC_SHA256_B64_NM(key_name.getBytes(), src_bytes);
                if (dst_data == null) {
                        throw new PcaException("hmac_sha256_b64_nm failed, check petra_cipher_api.log");
                }
                return dst_data;
        }

	public void paramCryptFile(String crypt_mode, String param_name, String input_file_path, String output_file_path) throws PcaException
	{
		int ret=0;
		if (input_file_path == null) input_file_path=new String("");
		if (output_file_path == null) output_file_path=new String("");
		synchronized (this) {
			ret=PARAMCRYPTFILE(SID,crypt_mode.getBytes(),param_name.getBytes(),input_file_path.getBytes(),output_file_path.getBytes());
		}
		if (ret < 0) {
			int	ErrCode = ECODE(SID);
			throw new PcaException("file Param encrypt/decrypt failed[" + ret + "]",ret);
		}
	}

        public String getRsaKey(String key_name) throws PcaException
        {
                byte[] key_data=null;
                synchronized (this) {
                        key_data=GETRSAKEY(SID,key_name.getBytes());
                }
                if (key_data == null) return null;
                return new String(key_data);
        }

	public String hashKey() { return HashKey; };
	public int sid() { return SID; }

	protected void finalize() throws Throwable
	{
		super.finalize();
	}

	private String HashKey;	// hash key
	private int SID; // client Session ID
	private static String DefaultHashColName = new String("__default__hash__column__"); // default hash column name
}

