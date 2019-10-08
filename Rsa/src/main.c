#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "polarssl/base64.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"
#include "polarssl/rsa.h"

#define DEBUG_INFO(fmt, args...) printf("\033[33m[%s:%s:%d]\033[0m "#fmt"\r\n", __FILE__,__FUNCTION__, __LINE__, ##args)

#define KEY_SIZE 1024
#define BUFFER_SIZE 1024
#define EXPONENT 65537
//公钥
uint8_t rsa_n[BUFFER_SIZE];

uint8_t rsa_e[BUFFER_SIZE];
uint8_t rsa_d[BUFFER_SIZE];
uint8_t rsa_p[BUFFER_SIZE];
uint8_t rsa_q[BUFFER_SIZE];
uint8_t rsa_dp[BUFFER_SIZE];
uint8_t rsa_dq[BUFFER_SIZE];
uint8_t rsa_qp[BUFFER_SIZE];

//公钥长度
int RSA_N_Len; 

uint8_t PubKey[1024]; 
char PubPem[2048]={0};

//读取rsa key
int ReadRsaKey(void)
{
    int ret = 0;
    rsa_context rsa;
    FILE *fpriv;

    RSA_N_Len = 0;
	memset(rsa_n , 0 ,BUFFER_SIZE);
	memset(rsa_e , 0 ,BUFFER_SIZE);
	memset(rsa_d , 0 ,BUFFER_SIZE);
	memset(rsa_p , 0 ,BUFFER_SIZE);
	memset(rsa_q , 0 ,BUFFER_SIZE);
	memset(rsa_dp, 0 ,BUFFER_SIZE);
	memset(rsa_dq, 0 ,BUFFER_SIZE);
	memset(rsa_qp, 0 ,BUFFER_SIZE);
    
    rsa_init(&rsa, RSA_PKCS_V15, 0);
    if (( fpriv = fopen("./rsa_key.txt", "rb")) == NULL)  {
        DEBUG_INFO("fopen rsa file failed\n");
        ret = -1;
        goto exit;
    }
    
     if( ( ret = mpi_read_file( &rsa.N , 16, fpriv ) ) != 0 ||
        ( ret = mpi_read_file( &rsa.E , 16, fpriv) ) != 0 ||
        ( ret = mpi_read_file( &rsa.D , 16, fpriv) ) != 0 ||
        ( ret = mpi_read_file( &rsa.P , 16, fpriv ) ) != 0 ||
        ( ret = mpi_read_file( &rsa.Q , 16, fpriv ) ) != 0 ||
        ( ret = mpi_read_file( &rsa.DP, 16, fpriv ) ) != 0 ||
        ( ret = mpi_read_file( &rsa.DQ, 16, fpriv ) ) != 0 ||
        ( ret = mpi_read_file( &rsa.QP, 16, fpriv ) ) != 0 ) {
        DEBUG_INFO("read rsa file failed\n");
        ret = -1;
        goto exit;
    }

    mpi_write_binary(&rsa.N, rsa_n , BUFFER_SIZE);
	mpi_write_binary(&rsa.E, rsa_e , BUFFER_SIZE);
	mpi_write_binary(&rsa.D, rsa_d , BUFFER_SIZE);
	mpi_write_binary(&rsa.P, rsa_p , BUFFER_SIZE);
	mpi_write_binary(&rsa.Q, rsa_q , BUFFER_SIZE);
	mpi_write_binary(&rsa.DP, rsa_dp ,BUFFER_SIZE);
	mpi_write_binary(&rsa.DQ, rsa_dq, BUFFER_SIZE);
	mpi_write_binary(&rsa.QP, rsa_qp , BUFFER_SIZE);

    RSA_N_Len = (mpi_msb(&rsa.N)+7) >> 3;
	memset(PubKey , 0 , BUFFER_SIZE);	
	memcpy(PubKey , &rsa_n[1024-RSA_N_Len] , RSA_N_Len);
	int  n;
    #if 1
	for( n= 1024-RSA_N_Len; n< 1024 ;n++) {
		printf("%02x" , rsa_n[n]);
	}
	printf("\n");
    #endif
    
exit:
    if (fpriv) {
        fclose(fpriv);
    }
    rsa_free(&rsa);
    return ret;
}


//生成或者读取rsa公钥与私钥
int CreateRsaKey(void)
{
    int ret = -1;

    ret = ReadRsaKey();
    if (ret == 0) {
        DEBUG_INFO("ret=%d",ret);
        return ret;
    }

    DEBUG_INFO("ret=%d",ret);
    
	RSA_N_Len = 0;
	memset(rsa_n , 0 ,BUFFER_SIZE);
	memset(rsa_e , 0 ,BUFFER_SIZE);
	memset(rsa_d , 0 ,BUFFER_SIZE);
	memset(rsa_p , 0 ,BUFFER_SIZE);
	memset(rsa_q , 0 ,BUFFER_SIZE);
	memset(rsa_dp, 0 ,BUFFER_SIZE);
	memset(rsa_dq, 0 ,BUFFER_SIZE);
	memset(rsa_qp, 0 ,BUFFER_SIZE);
	rsa_context rsa;
	entropy_context entropy;
	ctr_drbg_context ctr_drbg;
	const char *pers = "rsa_genkey";
	entropy_init(&entropy);
	
	if((ret = ctr_drbg_init( &ctr_drbg, entropy_func, &entropy,(const unsigned char *) pers, strlen( pers))) != 0) {
   
        DEBUG_INFO( " failed ! ctr_drbg_init returned %d\n", ret );
        goto exit;
    }
	DEBUG_INFO( " ok  . Generating the RSA key [ %d-bit ]...\n", KEY_SIZE);
	rsa_init( &rsa, RSA_PKCS_V15, 0 );
	if ((ret = rsa_gen_key( &rsa, ctr_drbg_random, &ctr_drbg, KEY_SIZE, EXPONENT)) != 0) {
		DEBUG_INFO( " failed	! rsa_gen_key returned %d\n\n", ret );
		goto exit;
	}
	
	mpi_write_binary(&rsa.N, rsa_n , BUFFER_SIZE);
	mpi_write_binary(&rsa.E, rsa_e , BUFFER_SIZE);
	mpi_write_binary(&rsa.D, rsa_d , BUFFER_SIZE);
	mpi_write_binary(&rsa.P, rsa_p , BUFFER_SIZE);
	mpi_write_binary(&rsa.Q, rsa_q , BUFFER_SIZE);
	mpi_write_binary(&rsa.DP, rsa_dp ,BUFFER_SIZE);
	mpi_write_binary(&rsa.DQ, rsa_dq, BUFFER_SIZE);
	mpi_write_binary(&rsa.QP, rsa_qp , BUFFER_SIZE);
	RSA_N_Len = (mpi_msb(&rsa.N)+7) >> 3;
	memset(PubKey , 0 , BUFFER_SIZE);	
	memcpy(PubKey , &rsa_n[1024-RSA_N_Len] , RSA_N_Len);
	int  n;
	DEBUG_INFO("rsa.N: ");
	for( n= 1024-RSA_N_Len; n< 1024 ;n++) {
		printf("%02x" , rsa_n[n]);
	}
	printf("\n");
	FILE * fpriv = NULL;
	if ((fpriv = fopen("./rsa_key.txt", "wb+")) == NULL) {
        ret = 1;
        goto exit;
    }
	 if( ( ret = mpi_write_file( "N = " , &rsa.N , 16, fpriv ) ) != 0 ||
        ( ret = mpi_write_file( "E = " , &rsa.E , 16, fpriv ) ) != 0 ||
        ( ret = mpi_write_file( "D = " , &rsa.D , 16, fpriv ) ) != 0 ||
        ( ret = mpi_write_file( "P = " , &rsa.P , 16, fpriv ) ) != 0 ||
        ( ret = mpi_write_file( "Q = " , &rsa.Q , 16, fpriv ) ) != 0 ||
        ( ret = mpi_write_file( "DP = ", &rsa.DP, 16, fpriv ) ) != 0 ||
        ( ret = mpi_write_file( "DQ = ", &rsa.DQ, 16, fpriv ) ) != 0 ||
        ( ret = mpi_write_file( "QP = ", &rsa.QP, 16, fpriv ) ) != 0 )  {
        DEBUG_INFO( " failed  ! mpi_write_file returned %d\n", ret );
        goto exit;
    }
exit:
	if( fpriv != NULL ) {
        fclose( fpriv );
	}
	rsa_free( &rsa );
    ctr_drbg_free( &ctr_drbg );
    entropy_free( &entropy );
	return ret;
}

//rsa 用私钥解密
int RsaDecrypt(const unsigned      char *InBuf , unsigned char* OutBuf)
{
	int ret, c;
	size_t i;
	rsa_context rsa;
	entropy_context entropy;
	ctr_drbg_context ctr_drbg;
	const unsigned char *pers = "rsa_decrypt";
	ret = 1;
	entropy_init(&entropy);
	if(( ret = ctr_drbg_init( &ctr_drbg, entropy_func, &entropy, (const unsigned char *) pers,strlen(pers))) != 0)  {
        DEBUG_INFO( " failed\n  ! ctr_drbg_init returned %d\n", ret );
        goto exit;
    }
	rsa_init(&rsa , RSA_PKCS_V15 , 0);
	mpi_read_binary(&rsa.N , rsa_n , BUFFER_SIZE);
	mpi_read_binary(&rsa.E , rsa_e , BUFFER_SIZE);
	mpi_read_binary(&rsa.D , rsa_d , BUFFER_SIZE);
	mpi_read_binary(&rsa.P , rsa_p , BUFFER_SIZE);
	mpi_read_binary(&rsa.Q , rsa_q , BUFFER_SIZE);
	mpi_read_binary(&rsa.DP , rsa_dp , BUFFER_SIZE);
	mpi_read_binary(&rsa.DQ , rsa_dq , BUFFER_SIZE);
	mpi_read_binary(&rsa.QP , rsa_qp , BUFFER_SIZE);
	rsa.len = (mpi_msb(&rsa.N)+7) >> 3;
	DEBUG_INFO("rsa.len: %d\n", rsa.len);
	if( ( ret = rsa_pkcs1_decrypt( &rsa, ctr_drbg_random, &ctr_drbg, RSA_PRIVATE, &i, InBuf, OutBuf, 1024)) != 0 )
    {
        DEBUG_INFO( " failed\n  ! rsa_pkcs1_decrypt returned %d\n\n", ret );
        goto exit;
    }
    DEBUG_INFO( "The RSA decrypted OutBuf is: '%s'\n\n", OutBuf);
    
exit:
	rsa_free( &rsa );
    ctr_drbg_free( &ctr_drbg );
    entropy_free( &entropy );
	return ret;
}


//base64解码，rsa私钥解密
int Base64DeAndRsa(const unsigned char *Base64, unsigned char *OutBuf)
{
    int ret = -1;
	size_t num =0;
	char DataOut2[8000]={0};
	base64_decode(NULL , &num , Base64 , strlen(Base64));
	ret = base64_decode(DataOut2 , &num , Base64 , strlen(Base64));
	if (ret != 0) {
        DEBUG_INFO("base64 decode failed,ret=%d",ret);
        return ret;
    }
	
	ret = RsaDecrypt(DataOut2, OutBuf);
	return ret;
}


//公钥转换pkcs1输出
void RsaNToPkcs1(char * PemData)
{	 
	char DataOut[1024]={0};
	char PkcsANS[512]={0};
	uint8_t Head[]=  {
		0x30 , 0x81 ,0x9F ,0x30 ,0x0D ,0x06 , 0x09 ,0x2A ,
		0x86 ,0x48 ,0x86 ,0xF7 ,0x0D ,0x01 ,0x01 ,0x01,
		0x05 ,0x00 ,0x03 ,0x81 ,0x8D ,0x00 ,0x30 ,0x81,
		0x89 ,0x02 ,0x81 ,0x81, 0x00
	};
	uint8_t Last[]={0x02 ,0x03 ,0x01, 0x00, 0x01};
	memcpy(PkcsANS , Head , sizeof(Head));
	memcpy(&PkcsANS[sizeof(Head)], PubKey , RSA_N_Len);
	memcpy(&PkcsANS[sizeof(Head)+RSA_N_Len] , Last , sizeof(Last));
	int size = sizeof(Head) + RSA_N_Len + sizeof(Last);
	char Base64[1024]={0} ;
	size_t num = 0;
    //NULL ,num设为0 ，是为了获取num
	base64_encode(NULL , &num, PkcsANS, size);  
	//真正base64编码
	base64_encode(Base64 , &num,  PkcsANS, size); 	
	int n , i =0 ;
	for (n = 0 ; n<  num ; n++) {
	
		if (n!=0 && (n+1)%64 == 0) {
			DataOut[i] = '\n';
			i++;
		}
		DataOut[i]= Base64[n];
		i++;
	}
	sprintf( PemData ,"\n-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n" , DataOut);
	DEBUG_INFO("%s" , PemData);
}


//测试
void TestRsa(void)
{
  CreateRsaKey();
  RsaNToPkcs1(PubKey);

  //采用rsa公钥加密base64编码之后的密文，明文是12345678
  unsigned char buf[1024] = "qpkO85wYitHwZ/HTm3+DKZmfVm1jZkjwowMIY3rOsXnj6WMSNSKyCRX6aEOUqDHDX7JlqjPctzHYsMBGQyZ5jvKuiLIjIGDQsZtFWg29iXwSz09jhAdixCmiP6JqfMho9zek5FUydqM9tyMQppv8h3ilM8kiFCXRZ2+76PmhSg0=";
  unsigned char OutBuf[2048] = {0};
  //base64解码，rsa私钥解密
  Base64DeAndRsa(buf,OutBuf);
  //使用rsa私钥解密之后
  DEBUG_INFO("%s",OutBuf);
}

int main(void)
{
   TestRsa();
    
	return 0;
}
