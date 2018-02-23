//============================================================================
// Name        : TP.cpp
// Author      : Huseyin Kayahan
// Version     : 1.0
// Copyright   : All rights reserved. Do not distribute.
// Description : TP Program
//============================================================================

#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>
#include <cstdio>
#include "sslUtils.h"
#include "commonUtils.h"
#include <iostream>

using namespace std;
BIO *bio_err = 0;
typedef unsigned char byte;
static char *pass;
static int password_cb(char *buf,int num,
  int rwflag,void *userdata);

//store key and iv every time when the key exchange happens

static unsigned char key[32];
static unsigned char iv[16];
static SSL *ssl;

int berr_exit(const char *string) {
BIO_printf(bio_err, "%s\n", string);
ERR_print_errors(bio_err);
exit(0);
}
static int password_cb(char *buf,int num,
  int rwflag,void *userdata)
  {
	pass = "1234";
	//if(num<strlen(pass)+1)
    //  return(0);

    strcpy(buf,pass);
    return(strlen(pass));
  }
void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}
//=======================Implement the four functions below============================================

SSL *createSslObj(int role, int contChannel, char *certfile, char *keyfile, char *rootCApath ) {
/* In this function, you handle
* 1) The SSL handshake between the server and the client.
* 2) Authentication
* a) Both the server and the client rejects if the presented certificate is not signed by the trusted CA.
* b) Client rejects if the the server's certificate does not contain a pre-defined string of your choice in the common name (CN) in the subject.
*/

//SSL_METHOD *meth;
//SSL_CTX *contex;

//Initialize the library
if(!bio_err){
       /* Global system initialization*/
       SSL_library_init();
   SSL_load_error_strings();

/* An error write context */
bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);
}



if(role == 0){
	SSL_CTX * contex = SSL_CTX_new(SSLv23_server_method());

	/* Load keys and certificates*/
	if(!(SSL_CTX_use_certificate_file(contex, "/home/cdev/SSLCerts/srv.pem", SSL_FILETYPE_PEM))){
	berr_exit("Can’t load certificate file");
	}

	SSL_CTX_set_default_passwd_cb(contex, password_cb);

	if(!(SSL_CTX_use_PrivateKey_file(contex, "/home/cdev/SSLCerts/srv.key", SSL_FILETYPE_PEM))){
	berr_exit("Can’t read key file");
	}

	//check private and public keys
	if(!(SSL_CTX_check_private_key(contex))) {
	berr_exit("public / private keys don't match");
	}
	/* check if its sign by the root CA*/
	if(!(SSL_CTX_load_verify_locations(contex, "/home/cdev/SSLCerts/CA/rootCA.pem", NULL))){
	berr_exit("Can’t locate CA list");
	}

	//Configure how the context shall verify peer’s certificate
	SSL_CTX_set_verify(contex, SSL_VERIFY_PEER, NULL);


	ssl = SSL_new(contex);
	BIO *sbio;

	sbio = BIO_new_socket(contChannel, BIO_NOCLOSE);

	SSL_set_bio(ssl, sbio, sbio);
	   if((SSL_accept(ssl))<=0){
	    berr_exit("SSL accept error!");
	   }

	SSL_accept(ssl);

}
// For the client:
if(role == 1){

	SSL_CTX * contex = SSL_CTX_new(SSLv23_client_method());

/* Load keys and certificates*/
if(!(SSL_CTX_use_certificate_file(contex, "/home/cdev/SSLCerts/cli.pem", SSL_FILETYPE_PEM))){
berr_exit("Can’t load certificate file");
}

SSL_CTX_set_default_passwd_cb(contex,password_cb);

if(!(SSL_CTX_use_PrivateKey_file(contex, "/home/cdev/SSLCerts/cli.key", SSL_FILETYPE_PEM))){
berr_exit("Can’t read key file");
}
/*check private and public keys*/
if(!(SSL_CTX_check_private_key(contex))) {
berr_exit("public / private keys don't match");
}


if(!(SSL_CTX_load_verify_locations(contex, "/home/cdev/SSLCerts/CA/rootCA.pem", NULL))){
berr_exit("Can’t locate CA list");
}

SSL_CTX_set_verify(contex, SSL_VERIFY_PEER, NULL);
ssl = SSL_new(contex);
BIO *cbio;
cbio = BIO_new_socket(contChannel, BIO_NOCLOSE);
SSL_set_bio(ssl, cbio, cbio);
SSL_connect(ssl);
if(SSL_connect(ssl)<=0){
berr_exit("SSL connect error");
   }


//verify the Server CA's common name

X509 *peer;
    char peer_CN[256];


    if(SSL_get_verify_result(ssl)!=X509_V_OK){
    berr_exit("Certificate doesn't verify");
    }

    peer=SSL_get_peer_certificate(ssl);
    char *host = "TP Server jianij@kth.se yucong@kth.se";


    X509_NAME_get_text_by_NID (X509_get_subject_name(peer), NID_commonName, peer_CN, 256);
    if(strcasecmp(peer_CN,host)){
    berr_exit("Common name doesn't match host name");
    }

}

/*Check root CA common name*/
char root_CN[256];
char *root = "TP CA jianij@kth.se yucong@kth.se";
   X509 *peer2;
   peer2=SSL_get_peer_certificate(ssl);

   X509_NAME_get_text_by_NID(X509_get_issuer_name(peer2), NID_commonName, root_CN, 256);
   if(strcasecmp(root_CN,root)){
    berr_exit("Common name doesn't match root name");
   }

return ssl;
}

	void dataChannelKeyExchange(int role, SSL *ssl) {
		/* In this function, you handle
		 * 1) The generation of the key and the IV that is needed to symmetrically encrypt/decrypt the IP datagrams over UDP (data channel).
		 * 2) The exchange of the symmetric key and the IV over the control channel secured by the SSL object.
		 */
		//load cipher
		EVP_add_cipher(EVP_aes_256_cbc());

		if(role==0) {

			unsigned char createkey[32];
						unsigned char createiv[16];
			        srand(time(NULL));
					for(int a=0; a< 33; a++){
						createkey[a]=rand();
					}
					createkey[33] = '\0';
					for(int b=0; b<17; b++){
						createiv[b]=rand();
					}
					createiv[17]='\0';
						*key = *createkey;
						*iv = *createiv;

						std::cout<<"key "<<key<<std::endl;
						std::cout<<"iv "<<iv<<std::endl;

						SSL_write(ssl, key, sizeof(key));
						SSL_write(ssl, iv, sizeof(iv));
		}

		if(role==1) {

			int n;
					unsigned char keybuf[33];
					unsigned char ivbuf[17];
					 n =SSL_read(ssl, keybuf, sizeof(keybuf));
					 if(n<=0)
					 {berr_exit("key read fail");}
					n = SSL_read(ssl, ivbuf, sizeof(ivbuf));
		              if(n<=0)
		            	  berr_exit("iv read fail");
		          *key = * keybuf;
		          *iv = *ivbuf;
					std::cout<<"key "<<key<<std::endl;
					std::cout<<"iv "<<iv<<std::endl;
		}
	}
	int encrypt(unsigned char *plainText, int plainTextLen,
				unsigned char *cipherText) {
			/* In this function, you store the symmetrically encrypted form of the IP datagram at *plainText, into the memory at *cipherText.
			 * The memcpy below directly copies *plainText into *cipherText, therefore the tunnel works unencrypted. It is there for you to
			 * test if the tunnel works initially, so remove that line once you start implementing this function.
			 */
			//memcpy(cipherText, plainText, plainTextLen);
			 EVP_CIPHER_CTX *ctx;
				  int len;
				  int ciphertext_len;

				  /* Create and initialise the context */
				  if(!(ctx = EVP_CIPHER_CTX_new()))
					  handleErrors();

				  /* Initialise the encryption operation. IMPORTANT - ensure you use a key
				   * and IV size appropriate for your cipher
				   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
				   * IV size for *most* modes is the same as the block size. For AES this
				   * is 128 bits */
				  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
				    handleErrors();

				  /* Provide the message to be encrypted, and obtain the encrypted output.
				   * EVP_EncryptUpdate can be called multiple times if necessary
				   */
				  if(1 != EVP_EncryptUpdate(ctx, cipherText, &len, plainText, plainTextLen))
				    handleErrors();
				  ciphertext_len = len;

				  /* Finalise the encryption. Further ciphertext bytes may be written at
				   * this stage.
				   */
				  if(1 != EVP_EncryptFinal_ex(ctx, cipherText + len, &len))
					  handleErrors();
				  ciphertext_len += len;

				  /* Clean up */
				  EVP_CIPHER_CTX_free(ctx);

				  return ciphertext_len;
			//return plainTextLen;

		}

		int decrypt(unsigned char *cipherText, int cipherTextLen,
				unsigned char *plainText) {
			/* In this function, you symmetrically decrypt the data at *cipherText and store the output IP datagram at *plainText.
			 * The memcpy below directly copies *cipherText into *plainText, therefore the tunnel works unencrypted. It is there for you to
			 * test if the tunnel works initially, so remove that line once you start implementing this function.
			 */
			//memcpy(plainText, cipherText, cipherTextLen);
			if(cipherTextLen % 16 !=0){
					return 0;
				}

			EVP_CIPHER_CTX *ctx;

				  int len;

				  int plaintext_len;

				  /* Create and initialise the context */
				  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

				  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
				   * and IV size appropriate for your cipher
				   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
				   * IV size for *most* modes is the same as the block size. For AES this
				   * is 128 bits */
				  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
				    handleErrors();

				  /* Provide the message to be decrypted, and obtain the plaintext output.
				   * EVP_DecryptUpdate can be called multiple times if necessary
				   */
				  if(1 != EVP_DecryptUpdate(ctx, plainText, &len, cipherText, cipherTextLen))
				    handleErrors();
				  plaintext_len = len;

				  /* Finalise the decryption. Further plaintext bytes may be written at
				   * this stage.
				   */
				  if(1 != EVP_DecryptFinal_ex(ctx, plainText + len, &len)) handleErrors();
				  plaintext_len += len;

				  /* Clean up */
				  EVP_CIPHER_CTX_free(ctx);

				  return plaintext_len;
			//return cipherTextLen;

		}

