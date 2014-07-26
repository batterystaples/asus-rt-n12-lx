#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>


static void usage(char *prog, char *opt);
static char				*prog;
static void __usage(void)
{
	puts("\n"
			 "======================================================\n"	
	     "Usage: web_downsize [-f] [file list]\n\n"
	     "Example :\n"
	     "       step(1):ls > web_list.txt\n"
	     "       step(2):./web_downsize -f web_list.txt \n"
	     "======================================================\n"	
	     );
	     
	exit(0);
}
int str_index(char st[], char subst[]) {
    int st_start, sti, substi, limit, result, st_length, subst_length;
   
    result = -1;
    st_length = strlen(st);
    subst_length = strlen(subst);

    limit = st_length - subst_length;
    if (limit < 0) return -1;

    for (st_start = 0 ; st_start <= limit ; st_start++) {
        sti = st_start;
        substi = 0;

        while (st[sti] == subst[substi] && st[sti] != '\0') {
            sti++;
            substi++;
        }

        if (substi == subst_length) {
            result = st_start;
            break;
        }
    }
		
    return result;
}
int main ( int argc , char **argv )
{
    int	arg;
		char  path[FILENAME_MAX];
		
		if(getcwd(path,FILENAME_MAX)!=NULL){
		      printf("Current work directory is %s\n",path);
		 }	
    if(argc < 2)	
    		__usage();    		

		/* Parse the command line arguments */
		while ( ( arg = getopt ( argc , argv , "f:" ) ) != EOF ) {
			switch ( arg ) {
				case	'f':
					if (optarg)
					{
						parser(optarg);
					}
					else
					{
						printf("Please input file name\n");
						return;
					}
						break;		
				case	'?':
					usage ( prog , NULL );
					break;
				default	:
					__usage();
			}
		}
   
    return 0;
}
int parser(char *filename)
{
		int i,st_length;
		FILE *fptr_list;
		
		char line[200];
		char gif[]="gif";
		
		fptr_list=fopen(filename,"r");
    if(fptr_list==NULL ){
        printf("Can not open list file!\n");
        printf("Please make list file\n");
        return 0;
    }		
		while ((fscanf(fptr_list, "%s", line)) != EOF )
		{
				if (str_index(line, "htm") != -1) 
						web_downsize(line);
						
    		if (str_index(line, "html") != -1) 
						web_downsize(line);
						
				if (str_index(line, "asp") != -1) 
						web_downsize(line);
						
				if (str_index(line, "js") != -1) 
						web_downsize(line);						

		}			
    fclose(fptr_list);
    return 1;
	
}
void remove_char_start_speace(FILE *fptr_tmp, char *line)
{
	
	int st_length ,st_start,checkspace,check_start_space;
	st_length = strlen(line);
	
	check_start_space=0;

	for (st_start = 0 ; st_start <= st_length ; st_start++) 
	{
	
					if(line[st_start]==0x20||line[st_start]==0x09)
	        {
	           
	             if(check_start_space==1)
	             {
	             	
	             		if(line[st_start]==0x20 ||line[st_start]==0x09)
	             		{
	             				if(checkspace==1)
	             				{
//	             					fprintf(fptr_tmp, "");
	             				}
	             				else
	             				{
	             					fprintf(fptr_tmp, "%c", line[st_start]);
	             					//printf("%c", line[st_start]);
	             					checkspace=1;
	             				}
	             		}
	             		else
	             		{
	             				checkspace=0;
             						
	             				fprintf(fptr_tmp, "%c", line[st_start]);
	             				//printf("%c", line[st_start]);
	             		}
	             }
	            
	        }
	        else
	        {
	        		
	        		if(line[st_start]!=0x00)
	             		    fprintf(fptr_tmp, "%c", line[st_start]);
	             		    
	            check_start_space=1;
	            checkspace=0;
	        }
	}

}
void compression(FILE *fptr_tmp, char *line)
{
		
					int st_length ,st_start,checkspace;
					st_length = strlen(line);
					checkspace=0;
			    for (st_start = 0 ; st_start <= st_length ; st_start++) 
			    {
			        if(line[st_start]==' ')
			        {
			        		if(checkspace==0)
			        			fprintf(fptr_tmp, "\n", line[st_start]);
			            
			            checkspace=1;
			            
			        }
			        else
			        {
			        		checkspace=0;
			        		if(line[st_start]!='\n')
					            fprintf(fptr_tmp, "%c", line[st_start]);
			            //printf("%c",line[st_start]);
			        }
			    }
	
}
int web_downsize(char *filename)
{
		int i,j,k,l,checkinput,checkform,checkhtmltag,checkjavatag;
		int st_start,st_length;
		char line[3000];
		char line2[3000];
		char tempStr[160];
		char head[]="</head>";
		char head2[]="</HEAD>";
		char script[]="<script>";
		char script2[]="</script>";
		char script3[]="<SCRIPT>";
		char script4[]="</SCRIPT>";
		char input[]="<input";
		char htmltag[]=">";
		char javatag[]=";";
		char form[]="form";

		FILE *fptr;
		FILE *fptr_tmp;
		char *token;
		fptr=fopen(filename,"r");
		fptr_tmp=fopen("temp.htm","w");

    if(fptr==NULL ||fptr_tmp==NULL ){
        printf("Open file fail!");
        return 0;
    }

		while (fgets(line,3000,fptr)!=NULL)
    {
    	
    		remove_char_start_speace(fptr_tmp,line);
    }

		printf("Web Downsizing > %s\n",filename);
		sprintf(tempStr,"rm -rf %s",filename);
		system(tempStr);
			
		
		sprintf(tempStr,"mv temp.htm  %s",filename);
		system(tempStr);
		
    fclose(fptr);
    fclose(fptr_tmp);
}
static void usage(char *prog, char *opt)
{
	if (opt)
	{
		fprintf(stderr, "%s: %s\n", prog, opt);
	}

	__usage();
	exit(1);
}
