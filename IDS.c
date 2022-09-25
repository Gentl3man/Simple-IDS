/**
 * Simple Intrusion Detection System (IDS)
 * Analyzes all the packets from a file and generates alearts based on
 * provided rules
 * 
 * Rule format: 
 * <src IP address> <src port> <dst IP address> <dst port> "ALERT MESSAGE"
 * 
 *
 */

#include "IDS.h"
int custom_filter_file=0;
FILE *alert_file;

struct in_addr*            IDS_src_ip;       
unsigned int*              IDS_src_port;
struct in_addr*            IDS_dst_ip;
unsigned int*              IDS_dst_port;
char**                     alerts;

int *src_mask;
int *dst_mask;

int rule_counter = 0;

 int *my_src_ip_rule;
 int *my_dst_ip_rule;


void parse_rules(FILE** fp){
    char line[LINE_SIZE],c;
    int line_indx,isComment,i,j,curr_max_rules,last_was_letter;


    last_was_letter = 0;
    line_indx = 0;
    isComment = 0;
    c = getc(*fp);
    while ( c != EOF )
    {
        if ( line_indx == 0 && c == ' ' )
        {
            /* Ignore unessesary whitespaces at the begining*/
            c = getc(*fp);
            continue;
        }
        if ( line_indx == 0 && c == '#')
        {
            isComment = 1; /* Ignore comments */
        }
        if ( c == '\n' )
        {
            
            if ( line_indx != 0 )
            {
                line[line_indx] = '\0';
                
                
                setRule(line,line_indx);
                rule_counter++; //globl  
            }
            isComment = 0;
            line_indx = 0;
            c = getc(*fp);
            continue;
            /*
            line[line_indx] = '\0';
            setRule(line,line_indx);
            rule_count++; //globl
            isComment = 0;
            line_indx = 0;
            */
        }
        if( !isComment )
        {
            line[line_indx] = c;
            line_indx++;
        }
        c = getc(*fp);
    }    
}



void argument_check(int argc, char const *argv[]){
    if(argc<2){
        printf("Format: ./IDS <Filename> (pcapng file)\n");
        printf("./IDS -h [help]\n");
        exit(-1);
    }
    if(!strcmp(argv[1],"-h")||(!strcmp(argv[1],"h"))){
        printf("IDS by default reads the rules from a file called IDS_Filter_Rules\n");
        printf("You can pass a file of your choosing passing it as the third argument\n");
        printf("\nFormat: ./IDS <Filename> (pcapng file) <Rule_file> (filter file)\n");
        printf("\nThe filter file should be a text file and each line must contain ONE RULE, lines starting with \'#\' will be ignored\n");
        printf("Rule format:\n\t<src IP address> <src port> <dst IP address> <dst port> \"ALERT\"\n");
        printf("\nResults will be stored in the file \"alerts.txt\"\n");
        exit(0);
    }
    if(argc==3){
        custom_filter_file=1;   //filter file is passed as the 3rd argument
    }

}

//debug
void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet total length %d\n", packet_header.len);
    printf("\n");
}



void IDS_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    
    static int packet_count = 0 ;   //debug
    
    /* pointers to packet headers*/
    const struct sniff_ethernet *ethernet; /* The ethernet header */
    const struct sniff_ip       *ip;       /* The IP header */
    const struct sniff_tcp      *tcp;      /* The TCP header */
    //i dont need the payload
    int size_ip;
    int size_tcp;
    
    char* src_ip;
    char* dst_ip;
    uint16_t src_port;
    uint16_t dst_port;

    ethernet = (struct sniff_ethernet*)(packet);

    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
    
    if ( ip->ip_p != IPPROTO_TCP  )
        return;     //dn einai tcp den me endiaferei, den exw port den kanei alert
    
 
    
    /*
     * Its a tcp packet
     */

    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip );
    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20) //reminder tcp header is at least 20 Bytes
    {
        
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
    /* Get IP */
    src_ip = strdup( inet_ntoa(ip->ip_src) ); //get it raw string
    dst_ip = strdup( inet_ntoa(ip->ip_dst) );

    /* Get Port */
    src_port = ntohs(tcp->th_sport);
    dst_port = ntohs(tcp->th_dport);
    
    compare_with_rules (src_ip,dst_ip,src_port,dst_port); //pls doule4e

}

void setRule(const char* line,int size)
{
    int last_was_letter,i,k,j,i2,line_indx,tmp_count;
    short flag;
    char buffer[LINE_SIZE];
    char ip_buff[20],mask_buff[3],port_buff[20];
    char bytes_src[4],bytes_dst[4];

    char ip_buff_src[4],ip_buff_dst[4];

    ip_buff_src[3] = '\0';
    ip_buff_dst[3] = '\0';
    
    char* src_ip, *dst_ip;
    flag = IDS_SRC_IP;
    i=0;
    line_indx = 0;
    last_was_letter = 0;
    tmp_count = 0;
    mask_buff[2] = '\0';
    while ( line_indx < size )
    {

        switch ( flag )
        {
        case IDS_SRC_IP:
            while ( line[line_indx] != ' ' && line[line_indx] != '/' )
            {
                
                ip_buff[tmp_count] = line[line_indx];
                tmp_count++;
                line_indx++;
            }
            ip_buff[tmp_count] = '\0';
            tmp_count=0;
            line_indx++;
            /* example 192.168.1.0 */
            if( line[line_indx-1] == '/')
            {
                mask_buff[0] = line[line_indx+0];
                mask_buff[1] = line[line_indx+1];
                //mask_buff[0] = line[line_indx+1];
                //mask_buff[1] = line[line_indx+2];

                src_mask[rule_counter] = atoi(mask_buff);
                
                line_indx = line_indx + 2;
            }
            else
            {
                src_mask[rule_counter] = IDS_NO_MASK;
            }
            if ( inet_aton( ip_buff,&IDS_src_ip[rule_counter] ) == 0 )
            {
                /* Invalid IP, the rule shall be ignored */
                src_mask[rule_counter] = IDS_IGNORE_RULE;
                
                return;
            }
            /* ignore next whitespaces */
            while( line[line_indx] == ' ' )
            {
                line_indx++;
            }
            flag = IDS_SRC_PORT;   
            break;
        
        case IDS_SRC_PORT:
            i=0;
            while( line[line_indx] != ' ')
            {
                port_buff[i] = line[line_indx];
                line_indx++;
                i++;
            }
            port_buff[i] = '\0';
            IDS_src_port[rule_counter] = atoi(port_buff);

            while ( line[line_indx] == ' ' )
            {
                line_indx++; /* Ignore whitespaces */
            }
            flag = IDS_DST_IP;
            break;
        
        case IDS_DST_IP:
            tmp_count = 0;
            while ( line[line_indx] != ' ' && line[line_indx] != '/' )
            {
                
                ip_buff[tmp_count] = line[line_indx];
                tmp_count++;
                line_indx++;
            }
            ip_buff[tmp_count] = '\0';
            tmp_count=0;
            line_indx++;

            if( line[line_indx-1] == '/')
            {
                mask_buff[0] = line[line_indx+0];
                mask_buff[1] = line[line_indx+1];

                //mask_buff[0] = line[line_indx+1];
                //mask_buff[1] = line[line_indx+2];

                dst_mask[rule_counter] = atoi(mask_buff);
                
                line_indx = line_indx + 2;
            }
            else
            {
                dst_mask[rule_counter] = IDS_NO_MASK;
            }
            if ( inet_aton( ip_buff,&IDS_dst_ip[rule_counter] ) == 0 )
            {
                /* Invalid IP, the rule shall be ignored */
                dst_mask[rule_counter] = IDS_IGNORE_RULE;
                
                return;
            }
            /* ignore next whitespaces */
            while( line[line_indx] == ' ' )
            {
                line_indx++;

            }

            flag = IDS_DST_PORT;
            
 
            break;

        
        case IDS_DST_PORT:
            i = 0;
            while( line[line_indx] != ' ')
            {
                port_buff[i] = line[line_indx];
                line_indx++;
                i++;
            }
            port_buff[i] = '\0';
            IDS_dst_port[rule_counter] = atoi(port_buff);
            while ( line[line_indx] == ' ' )
            {
                line_indx++; /* Ignore whitespaces */
                
            }
            flag = IDS_ALERT;

            break;

        case IDS_ALERT:
            if ( line[line_indx] != '\"' )
            {
                /* Wrong format for alert */
                dst_mask[rule_counter] = IDS_IGNORE_RULE;
                src_mask[rule_counter] = IDS_IGNORE_RULE;
                return;
            }
            line_indx++;
            i = 0;
            while( line_indx < size && line[line_indx] != '\"' )
            {
                buffer[i] = line[line_indx];
                i++;
                line_indx++;
            }
            if ( line[line_indx] != '\"' )
            {
                /* Wrong format for alert, missing a '"' (ending one) */
                dst_mask[rule_counter] = IDS_IGNORE_RULE;
                src_mask[rule_counter] = IDS_IGNORE_RULE;
                return;
            }
            buffer[i] = '\0';
            alerts[rule_counter] = strdup(buffer);
            
            i = 0;
            i2 = 0;

            src_ip = strdup ( inet_ntoa (IDS_src_ip[rule_counter]) );
            dst_ip = strdup ( inet_ntoa (IDS_dst_ip[rule_counter]) );

            
            my_src_ip_rule[rule_counter] = 0;
            my_dst_ip_rule[rule_counter] = 0;
            for ( k = 0; k<4; k++)
            {
                j = 0;
                while ( src_ip[i] != '.' && src_ip[i] != '\0' )
                {
                    ip_buff_src[j] = src_ip[i];
                    i++;
                    j++;
                }
                i++;
                bytes_src[k] = atoi(ip_buff_src);
                my_src_ip_rule[rule_counter] += (int)bytes_src[k];

                if ( k < 3 )
                {
                   my_src_ip_rule[rule_counter] = my_src_ip_rule[rule_counter] << 8;
                }


                j = 0;
                while ( dst_ip[i2] != '.' && dst_ip[i2] != '\0')
                {
                    ip_buff_dst[j] = dst_ip[i2];
                    i2++;
                    j++;
                }
                i2++;
                bytes_dst[k] = atoi(ip_buff_dst);
                my_dst_ip_rule[rule_counter] += (int)bytes_dst[k];
                if ( k < 3)
                {
                    my_dst_ip_rule[rule_counter] = my_dst_ip_rule[rule_counter] << 8;
                }
            }
            
            return;
            break;
        default:
            break;
        }
    }
    return;
}

void init()
{
    /* space allocation for globl */

    IDS_src_ip = (struct in_addr*)malloc( sizeof(struct in_addr) * RULE_NUM_DEFAULT);
    IDS_dst_ip = (struct in_addr*)malloc( sizeof(struct in_addr) * RULE_NUM_DEFAULT);

    IDS_src_port = (int*)malloc( sizeof(int) * RULE_NUM_DEFAULT );
    IDS_dst_port = (int*)malloc( sizeof(int) * RULE_NUM_DEFAULT );

    src_mask = (int*)malloc( sizeof(int) * RULE_NUM_DEFAULT);
    dst_mask = (int*)malloc( sizeof(int) * RULE_NUM_DEFAULT);

    alerts = (char**)malloc( sizeof(char*) * RULE_NUM_DEFAULT );
    
    my_src_ip_rule = (int*)malloc( sizeof(int) * RULE_NUM_DEFAULT);
    my_dst_ip_rule = (int*)malloc( sizeof(int) * RULE_NUM_DEFAULT);
    
    return;
}

void compare_with_rules(char* src_ip, char* dst_ip, uint16_t src_port, uint16_t dst_port)
{
    int i2,i,j,k,curr_byte,bits_src,bits_dst;
    char bytes_src[4], bytes_dst[4] ,ip_buff_src[4], ip_buff_dst[4];
    int shifts;
    char *rule_src_ip,*rule_dst_ip;

    /* Sto read me gt einai etsi */
    int my_src_ip, my_dst_ip;
    unsigned int my_src_ip_temp; //ta arguments gia sugkrish
    unsigned int my_dst_ip_temp;

    unsigned int my_src_ip_rule_temp; //temp gia to rule
    unsigned int my_dst_ip_rule_temp;
    
    my_src_ip_rule_temp = 0;
    my_dst_ip_rule_temp = 0;

    my_src_ip = 0;
    my_dst_ip = 0;

    ip_buff_src[3] = '\0';
    ip_buff_dst[3] = '\0';
    i = 0;
    i2 = 0;
    for(k = 0; k<4; k++)
    {
        /* SRC poy epiase to packet */
        j = 0;
        while( src_ip[i] != '.' && src_ip[i] != '\0' )
        {
            ip_buff_src[j] = src_ip[i];
            i++;
            j++;
        }
        i++;
        /* pare to ascii vvalue kai vale to sto byte */
        bytes_src[k] = atoi(ip_buff_src);
        my_src_ip += (int)bytes_src[k];

        if( k < 3 )
        {
            my_src_ip = my_src_ip << 8;
        }
        

        j = 0;
        while (dst_ip[i2] != '.' && dst_ip[i2] != '\0' )
        {
            ip_buff_dst[j] = dst_ip[i2];
            i2++;
            j++;
        }
        i2++;
        bytes_dst[k] = atoi(ip_buff_dst);
        my_dst_ip += (int)bytes_dst[k];
        if( k < 3 )
        {
           my_dst_ip = my_dst_ip << 8;
        }
    }
        
    /* Check with every rule */

    

    
    for ( i = 0; i < rule_counter; i++)
    {
        

        my_src_ip_temp = my_src_ip; //assign gt 8a allazei ka8e fora analoga ta shifts
        
        if ( src_mask[i] == IDS_IGNORE_RULE || dst_mask[i] == IDS_IGNORE_RULE)
        {
            continue;
        }
        


        
        my_src_ip_rule_temp = my_src_ip_rule[i];   
        shifts = 0;
        if ( src_mask[i] != IDS_NO_MASK)
        {
            /* gia na kratas ta bit pou 8a ginei h sugkrish*/
            shifts = 32 - src_mask[i];
        }
        /* fae ta bits sta de3ia */
        my_src_ip_rule_temp = my_src_ip_rule_temp >> shifts;
        my_src_ip_temp = my_src_ip_temp      >> shifts;
        if(shifts != 0 )
        {
            my_src_ip_rule_temp--;
        }

        
        
        if ( my_src_ip_temp != my_src_ip_rule_temp )
        {
            /* IPs dont match go to the next rule */
            
            continue;
        }
        
        if ( (int)src_port != IDS_src_port[i])
        {
            /* Ports dont match, next rule */
            continue;
        }
        my_dst_ip_temp = my_dst_ip;
        my_dst_ip_rule_temp = my_dst_ip_rule[i];
        shifts = 0;
        if ( dst_mask[i] != IDS_NO_MASK )
        {
            shifts = 32 - dst_mask[i];
        }
        my_dst_ip_temp = my_dst_ip_temp >> shifts;
        my_dst_ip_rule_temp = my_dst_ip_rule_temp >> shifts;
        if( shifts != 0 )
        {
            //my_dst_ip_rule_temp--;
        }

        if ( my_dst_ip_temp != my_dst_ip_rule_temp )
        {
            continue;
        }

        if( (int)dst_port != IDS_dst_port[i] )
        {
            continue;
        }
        /* Einai ok kane print to message  antes */
        fprintf(alert_file,"ALERT: \'%s\'\n",alerts[i]);

    }
}



int main(int argc, char const *argv[])
{
    init();
    FILE *rule_file;    //or filter file idk

    char *device; //device name (eht0, wlan0)
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_input_file;   //pcapng file
    char **rules;
    int rule_count;
    char read_c;
    argument_check(argc, argv);
    
    /* Open file to read from */
    pcap_input_file = pcap_open_offline(argv[1], errbuf);

    if(pcap_input_file==NULL){
        printf("Error: %s\n",errbuf);
        exit(-1);
    }
    if(custom_filter_file){
        rule_file = fopen(argv[2],"r");
        if(!rule_file){
            printf("file: \'%s\' doesnt exists, exiting...\n", argv[2]);
            exit(-1);
        }
    }else{
        if( !(rule_file = fopen("IDS_Filter_Rules","r")) )
        {
            /* If the default file doesnt exit create a new one, and tell the user to import some rules */
            rule_file = fopen("IDS_Filter_Rules","w+");
            printf("Creating file: \'IDS_Filter_Rules\', import your rules to this file\n");
            printf("Rule format: <src IP address> <src port> <dst IP address> <dst port> \n");
            fprintf(rule_file,"#Rule format: <src IP address> <src port> <dst IP address> <dst port> \n");
            fclose(rule_file);
            exit(EXIT_FAILURE);        
        } 

    }
    alert_file = fopen("alerts.txt","w+");

    /* Parse the rules and store them in a way to make the comparisson easier */
    parse_rules(&rule_file);
    /*The file is no logner needed*/
    fclose(rule_file);

    //print_rules(); debug


    /* PCAP do your thing */
    pcap_loop(pcap_input_file,10,IDS_packet_handler,NULL);
    
    /* aight we're done bye */
    pcap_close(pcap_input_file);

    fclose(alert_file);
    /* idk */
    return 0;
}

//debug
void print_rules(){
    int i;
    int j;
    printf("\n\nprint rules\n");
    for ( i=0; i< rule_counter; i++){
        printf("RULE: %d\n",i);
        if ( src_mask[i] == IDS_IGNORE_RULE || dst_mask[i] == IDS_IGNORE_RULE)
        {
            printf("RULE IS INGORED, wrong format\n");
            printf("---------------------------\n");
            continue;
        }

        printf("IP src == %d aka %s\n",IDS_src_ip[i], inet_ntoa(IDS_src_ip[i]));
        printf("IP dst == %d aka %s\n",IDS_dst_ip[i], inet_ntoa(IDS_dst_ip[i]));
        printf("MY IPs src == %d\n",my_src_ip_rule[i]);
        printf("MY IPS dst == %d\n",my_dst_ip_rule[i]);
        
        printf("---------------------------\n");

    }
    j = my_src_ip_rule[i];
    printf("j = %d\n",j);
}