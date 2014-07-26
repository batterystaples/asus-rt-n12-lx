#include "rsCertCommon.h"

static const char *cmd[]={
"usage: rsCert args\n",
"\n",
" -rst		- reset all cert files at running system and reset flash space for cert area (include cert area header, cert file header of user cert and root cert)\n",
" -wrAll		- store user cert and root cert\n",
" -wrUser		- store user cert\n",
" -wrRoot	- store root cert\n",
" -rd			- load user cert and root cert\n",
NULL
};

int main(int argc, char **argv)
{
	char badops;
	char **pp;
	char resetCert, storeAllCert, storeUserCert, storeRootCert, loadCert;
	unsigned char certFlag;
	char tmpFile[50];
	int offset;
	int ret;
	int toRet;

//	DEBUG("%s(%d): FLASH_SIZE(0x%x),KERNEL_IMAGE_OFFSET(0x%x), ROOT_IMAGE_OFFSET(0x%x) \n", __FUNCTION__,__LINE__,FLASH_SIZE,KERNEL_IMAGE_OFFSET,ROOT_IMAGE_OFFSET);//Added for test

	argc--;
	argv++;

	if(argc==0)
	{
		badops=1;
		goto bad;
	}
	
	while (argc >= 1)
	{
		if(strcmp(*argv,"-rst") == 0)
		{
			resetCert=1;
		}
		else if(strcmp(*argv,"-wrAll") == 0)
		{
			storeAllCert=1;
		}
		else if(strcmp(*argv,"-wrUser") == 0)
		{
			storeUserCert=1;
		}
		else if(strcmp(*argv,"-wrRoot") == 0)
		{
			storeRootCert=1;
		}
		else if(strcmp(*argv,"-rd") == 0)
		{
			loadCert=1;
		}
		else
		{
bad:
			ERR_PRINT("unknown option %s\n",*argv);
			badops=1;
			break;
		}
		argc--;
		argv++;	
	}

	if(badops==1)
	{
		for (pp=cmd; (*pp != NULL); pp++)
			ERR_PRINT("%s",*pp);
		toRet=FAILED;
		goto err;
	} 

	// initial
	certFlag=FLAG_NO_CERT;

	if(resetCert == 1)
	{
		//rm cert related first
		sprintf(tmpFile, "rm -f %s 2>/dev/null", RS_USER_CERT);
		system(tmpFile);

		sprintf(tmpFile, "rm -f %s 2>/dev/null", RS_ROOT_CERT);
		system(tmpFile);
	}

	ret=kernelImageOverSize();
	if((ret==FAILED)||(ret==1))
	{
		ERR_PRINT("%s(%d): can't use cert area, ret=%d\n",__FUNCTION__, __LINE__,ret);
		toRet=FAILED;
		goto err;
	}

	if(resetCert == 1)
	{
		//reset cert related at flash
		//Initial certAreaHeader
		certFlag=FLAG_NO_CERT;
		ret=updateCertAreaHeader(certFlag);
		if(ret==FAILED)
		{
			ERR_PRINT("%s(%d),updateCertAreaHeader failed!\n",__FUNCTION__,__LINE__);//Added for test
			toRet=FAILED;
			goto err;
		}

		//To initial user cert file header
		offset=USER_CERT_BASE;
		ret=storeFile(offset, RS_USER_CERT, 1);
		if(ret==FAILED)
		{
			ERR_PRINT("%s(%d),init flash offset(0x%x) failed!\n",__FUNCTION__,__LINE__, offset);//Added for test
			toRet=FAILED;
			goto err;
		}

		//To initial root cert file header
		offset=ROOT_CERT_BASE;
		ret=storeFile(offset, RS_ROOT_CERT , 1);
		if(ret==FAILED)
		{
			ERR_PRINT("%s(%d),init flash offset(0x%x) failed!\n",__FUNCTION__,__LINE__, offset);//Added for test
			toRet=FAILED;
			goto err;
		}
	}
	else if(storeAllCert == 1)
	{		
		//store user cert
		offset=USER_CERT_BASE;
		if(isFileExist(RS_USER_CERT))
		{
			ret=storeFile(offset, RS_USER_CERT, 0);
			if(ret==FAILED)
			{
				ERR_PRINT("%s(%d), store %s to 0x%x failed.\n",__FUNCTION__,__LINE__, RS_USER_CERT, offset);//Added for test
				toRet=FAILED;
				goto err;
			}

			certFlag |= FLAG_USER_CERT;
		}
		else
		{
			ERR_PRINT("%s(%d),%s not exist.\n",__FUNCTION__,__LINE__, RS_USER_CERT);//Added for test
			toRet=FAILED;
			//goto err;
		}

		//store root cert
		offset=ROOT_CERT_BASE;
		if(isFileExist(RS_ROOT_CERT))
		{
			ret=storeFile(offset, RS_ROOT_CERT, 0);
			if(ret==FAILED)
			{
				ERR_PRINT("%s(%d), store %s to 0x%x failed.\n",__FUNCTION__,__LINE__, RS_ROOT_CERT, offset);//Added for test
				toRet=FAILED;
				goto err;
			}

			certFlag |= FLAG_ROOT_CERT;
		}
		else
		{
			ERR_PRINT("%s(%d),%s not exist.\n",__FUNCTION__,__LINE__, RS_ROOT_CERT);//Added for test
			toRet=FAILED;
			//goto err;
		}

		if(certFlag != FLAG_NO_CERT)
		{
			//store cert area header
//			DEBUG("%s(%d): certFlag(0x%x) \n", __FUNCTION__,__LINE__,certFlag);//Added for test
			ret=updateCertAreaHeader(certFlag);
			if(ret==FAILED)
			{
				ERR_PRINT("%s(%d), updateCertAreaHeader certFlag(0x%x) failed.\n",__FUNCTION__,__LINE__, certFlag);//Added for test
				toRet=FAILED;
				goto err;
			}
		}
	}
	else if(storeUserCert == 1)
	{		
		//store user cert
		offset=USER_CERT_BASE;
		if(isFileExist(RS_USER_CERT))
		{
			ret=storeFile(offset, RS_USER_CERT, 0);
			if(ret==FAILED)
			{
				ERR_PRINT("%s(%d), store %s to 0x%x failed.\n",__FUNCTION__,__LINE__, RS_USER_CERT, offset);//Added for test
				toRet=FAILED;
				goto err;
			}

			certFlag |= FLAG_USER_CERT;
		}
		else
		{
			ERR_PRINT("%s(%d),%s not exist.\n",__FUNCTION__,__LINE__, RS_USER_CERT);//Added for test
			toRet=FAILED;
			//goto err;
		}

		if(certFlag != FLAG_NO_CERT)
		{
			//store cert area header
//			DEBUG("%s(%d): certFlag(0x%x) \n", __FUNCTION__,__LINE__,certFlag);//Added for test
			ret=updateCertAreaHeader(certFlag);
			if(ret==FAILED)
			{
				ERR_PRINT("%s(%d), updateCertAreaHeader certFlag(0x%x) failed.\n",__FUNCTION__,__LINE__, certFlag);//Added for test
				toRet=FAILED;
				goto err;
			}
		}
	}
	else if(storeRootCert == 1)
	{		
		//store root cert
		offset=ROOT_CERT_BASE;
		if(isFileExist(RS_ROOT_CERT))
		{
			ret=storeFile(offset, RS_ROOT_CERT, 0);
			if(ret==FAILED)
			{
				ERR_PRINT("%s(%d), store %s to 0x%x failed.\n",__FUNCTION__,__LINE__, RS_ROOT_CERT, offset);//Added for test
				toRet=FAILED;
				goto err;
			}

			certFlag |= FLAG_ROOT_CERT;
		}
		else
		{
			ERR_PRINT("%s(%d),%s not exist.\n",__FUNCTION__,__LINE__, RS_ROOT_CERT);//Added for test
			toRet=FAILED;
			//goto err;
		}

		if(certFlag != FLAG_NO_CERT)
		{
			//store cert area header
//			DEBUG("%s(%d): certFlag(0x%x) \n", __FUNCTION__,__LINE__,certFlag);//Added for test
			ret=updateCertAreaHeader(certFlag);
			if(ret==FAILED)
			{
				ERR_PRINT("%s(%d), updateCertAreaHeader certFlag(0x%x) failed.\n",__FUNCTION__,__LINE__, certFlag);//Added for test
				toRet=FAILED;
				goto err;
			}
		}
	}
	else if(loadCert == 1)
	{
		//load user cert
		offset=USER_CERT_BASE;
		ret=loadFile(RS_USER_CERT, offset);
		if(ret==FAILED)
		{
			ERR_PRINT("Warning: %s(%d), load no user cert.\n",__FUNCTION__,__LINE__);//Added for test
			toRet=FAILED;
			//goto err;
			
		}

		//load root cert
		offset=ROOT_CERT_BASE;
		ret=loadFile(RS_ROOT_CERT, offset);
		if(ret==FAILED)
		{
			ERR_PRINT("Warning: %s(%d), load no root cert.\n",__FUNCTION__,__LINE__);//Added for test
			toRet=FAILED;
			//goto err;
			
		}
	}

	toRet=SUCCESS;

err:
	return toRet;
}

