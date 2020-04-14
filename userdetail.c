#include<stdio.h>
#include<sys/types.h>
#include<pwd.h>
#include<shadow.h>
#include<unistd.h>
#include<stdlib.h>
#include<string.h>
#include<stdbool.h>

bool struct_check(struct passwd *pw){
	if((pw==NULL)||(strcmp(pw->pw_shell,"/bin/bash"))){
		return 0;
	}
	return 1;
}

void struct_print(struct passwd *s, struct spwd *shadowstruct){
	if(s==NULL){
		printf("user not exsist\n");
	}else if(s->pw_uid<1000&&s->pw_uid != 0){
		printf("Linux service user No Login\n");
	}
	else{
		printf("\n\nUser Account Detail\nUsername :\t%s\nPassword :\t%s\nUser Id :\t%d\nGroup Id :\t%d\nUser Infor :\t%s\nHome Dir :\t%s\nShell Prog :\t%s\n",s->pw_name,s->pw_passwd,s->pw_uid,s->pw_gid,s->pw_gecos,s->pw_dir,s->pw_shell);
	
		
			printf("\n\nShadow File Detail : \nName :\t%s\nPassword :\t%s\nLast Password change :\t%ld\nDays Until Allowed :\t%ld\nDays Before Required : \t%ld\nWarning :\t%ld\nAccount Inactive :\t%ld\nAccount expires :\t%ld\n",shadowstruct->sp_namp,shadowstruct->sp_pwdp,shadowstruct->sp_lstchg,shadowstruct->sp_min,shadowstruct->sp_max,shadowstruct->sp_warn,shadowstruct->sp_inact,shadowstruct->sp_expire);
		
	}
}



int main(int argc,char *argv){
	char *username = malloc(2*sizeof(char *)) , *password ,*enpasswd;
	struct spwd *shadowstruct; 
	struct passwd *pw ;
	printf("Enter UserName :");
	scanf("%s",username);
	pw = getpwnam(username);
	if(struct_check(pw)){
		password = getpass("Enter Password :");
 		shadowstruct = getspnam(pw->pw_name);
		if(shadowstruct ==NULL){
			printf("Please run Program as a Root\n");
			return 1;
		}
		enpasswd = crypt(password ,shadowstruct->sp_pwdp);

		(strcmp(shadowstruct->sp_pwdp,enpasswd))?printf("Incorrect Password\n") :struct_print(pw,shadowstruct);
	}
	else{
		printf("User Doesn't Exsist\n");
	}
	free(username);
	return 0;

}

