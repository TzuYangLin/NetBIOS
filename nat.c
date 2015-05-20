#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <string.h>
#include <sys/vfs.h>
#include <netinet/in.h>
#include "nat.h"
#include <fcntl.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>


static int put_nmb_name(char *buf,int offset,struct nmb_name *name)
{
    int ret,m;
    fstring buf1;
    char *p;

    if (name->name[0] == '*') {
        /* special case for wildcard name */
        bzero(buf1,20);
        buf1[0] = '*';
    } else {
        sprintf(buf1,"%-15.15s%c",name->name,name->name_type);
    }

    buf[offset] = 0x20;

    ret = 34;

    for (m=0;m<16;m++) {
        buf[offset+1+2*m] = 'A' + ((buf1[m]>>4)&0xF);
        buf[offset+2+2*m] = 'A' + (buf1[m]&0xF);
    }
    offset += 33;

    buf[offset] = 0;

    if (name->scope[0]) {
        /* XXXX this scope handling needs testing */
        ret += strlen(name->scope) + 1;
        strcpy(&buf[offset+1],name->scope);  

        p = &buf[offset+1];
        while ((p = strchr(p,'.'))) {
            buf[offset] = PTR_DIFF(p,&buf[offset]);
            offset += buf[offset];
            p = &buf[offset+1];
        }
        buf[offset] = strlen(&buf[offset+1]);
    }

    return(ret);
}

static int put_res_rec(char *buf,int offset,struct res_rec *recs,int count)
{
    int ret=0;
    int i;

    for (i=0;i<count;i++) {
        int l = put_nmb_name(buf,offset,&recs[i].rr_name);
        offset += l;
        ret += l;
        RSSVAL(buf,offset,recs[i].rr_type);
        RSSVAL(buf,offset+2,recs[i].rr_class);
        RSIVAL(buf,offset+4,recs[i].ttl);
        RSSVAL(buf,offset+8,recs[i].rdlength);
        memcpy(buf+offset+10,recs[i].rdata,recs[i].rdlength);
        offset += 10+recs[i].rdlength;
        ret += 10+recs[i].rdlength;
    }

    return(ret);
}

static int build_nmb(char *buf,struct packet_struct *p)
{
    struct nmb_packet *nmb = &p->packet.nmb;
    unsigned char *ubuf = (unsigned char *)buf;
    int offset=0;

    /* put in the header */
    RSSVAL(ubuf,offset,nmb->header.name_trn_id);
    ubuf[offset+2] = (nmb->header.opcode & 0xF) << 3;
      //printf("0x%02x 0x%02x\n", (char)ubuf[offset+2], (char)ubuf[offset+3]);
    if (nmb->header.response) ubuf[offset+2] |= (1<<7);
      //printf("0x%02x 0x%02x\n", (char)ubuf[offset+2], (char)ubuf[offset+3]);
    if (nmb->header.nm_flags.authoritative) ubuf[offset+2] |= 0x4;
      //printf("0x%02x 0x%02x\n", (char)ubuf[offset+2], (char)ubuf[offset+3]);
    if (nmb->header.nm_flags.trunc) ubuf[offset+2] |= 0x2;
      //printf("0x%02x 0x%02x\n", (char)ubuf[offset+2], (char)ubuf[offset+3]);
    if (nmb->header.nm_flags.recursion_desired) ubuf[offset+2] |= 0x1;
      //printf("0x%02x 0x%02x\n", (char)ubuf[offset+2], (char)ubuf[offset+3]);
    if (nmb->header.nm_flags.recursion_available) ubuf[offset+3] |= 0x80;
      //printf("0x%02x 0x%02x\n", (char)ubuf[offset+2], (char)ubuf[offset+3]);
    if (nmb->header.nm_flags.bcast) ubuf[offset+3] |= 0x10;
      //printf("0x%02x 0x%02x\n", (char)ubuf[offset+2], (char)ubuf[offset+3]);
    ubuf[offset+3] |= (nmb->header.rcode & 0xF);
    RSSVAL(ubuf,offset+4,nmb->header.qdcount);
    RSSVAL(ubuf,offset+6,nmb->header.ancount);
    RSSVAL(ubuf,offset+8,nmb->header.nscount);
    RSSVAL(ubuf,offset+10,nmb->header.arcount);

    offset += 12;
    if (nmb->header.qdcount) {
      /* XXXX this doesn't handle a qdcount of > 1 */
      offset += put_nmb_name((char *)ubuf,offset,&nmb->question.question_name);
      RSSVAL(ubuf,offset,nmb->question.question_type);
      RSSVAL(ubuf,offset+2,nmb->question.question_class);
      offset += 4;
    }

    if (nmb->header.ancount)
      offset += put_res_rec((char *)ubuf,offset,nmb->answers,
                nmb->header.ancount);

    if (nmb->header.nscount)
      offset += put_res_rec((char *)ubuf,offset,nmb->nsrecs,
                nmb->header.nscount);

    if (nmb->header.arcount)
      offset += put_res_rec((char *)ubuf,offset,nmb->additional,
                nmb->header.arcount);  

    return(offset);
}

static BOOL send_udp(int fd,char *buf,int len,struct in_addr ip,int port)
{
    BOOL ret;
    struct sockaddr_in sock_out;

    /* set the address and port */
    bzero((char *)&sock_out,sizeof(sock_out));
    putip((char *)&sock_out.sin_addr,(char *)&ip);
    sock_out.sin_port = htons( port );
    sock_out.sin_family = PF_INET;

    printf("sending a packet of len %d to (%s) on port %d\n", len, inet_ntoa(ip), port);

    ret = (sendto(fd,buf,len,0,(struct sockaddr *)&sock_out,
          sizeof(sock_out)) >= 0);

    if (!ret)
        printf("Packet send failed to %s(%d) ERRNO=%s\n", inet_ntoa(ip), port, strerror(errno));

    if (ret)
        num_good_sends++;

    return(ret);
}

BOOL send_packet(struct packet_struct *p)
{
    char buf[1024];
    int len=0, i;

    bzero(buf,sizeof(buf));

    len = build_nmb(buf,p);

    if (!len) return(False);
    for (i=0; i<len; i++) {
        if( (i % 32) == 0)
            printf("\n");
        printf("0x%02x ",(unsigned char)buf[i]);
    }

    return (send_udp(p->fd,buf,len,p->ip,p->port));
}

static void free_nmb_packet(struct nmb_packet *nmb)
{  
    SAFE_FREE(nmb->answers);
    SAFE_FREE(nmb->nsrecs);
    SAFE_FREE(nmb->additional);
}

void free_packet(struct packet_struct *packet)
{  
    if (packet->locked) 
        return;

    free_nmb_packet(&packet->packet.nmb);

    ZERO_STRUCTPN(packet);
    SAFE_FREE(packet);
}

static BOOL handle_name_ptrs(unsigned char *ubuf,int *offset,int length,
                 BOOL *got_pointer,int *ret)
{
    int loop_count=0;

    while ((ubuf[*offset] & 0xC0) == 0xC0) {
        if (!*got_pointer)
            (*ret) += 2;
        (*got_pointer)=True;
        (*offset) = ((ubuf[*offset] & ~0xC0)<<8) | ubuf[(*offset)+1];
        if (loop_count++ == 10 || (*offset) < 0 || (*offset)>(length-2)) {
            return(False);
        }
    }

    return(True);
}

static int parse_nmb_name(char *inbuf,int ofs,int length, struct nmb_name *name)
{
    int m,n=0;
    unsigned char *ubuf = (unsigned char *)inbuf;
    int ret = 0;
    BOOL got_pointer=False;
    int loop_count=0;
    int offset = ofs;

    if (length - offset < 2)
        return(0);  

    /* handle initial name pointers */
    if (!handle_name_ptrs(ubuf,&offset,length,&got_pointer,&ret))
        return(0);

    m = ubuf[offset];

    if (!m)
        return(0);
    if ((m & 0xC0) || offset+m+2 > length)
        return(0);

    memset((char *)name,'\0',sizeof(*name));

    /* the "compressed" part */
    if (!got_pointer)
        ret += m + 2;
    offset++;
    while (m > 0) {
        unsigned char c1,c2;
        c1 = ubuf[offset++]-'A';
        c2 = ubuf[offset++]-'A';
        if ((c1 & 0xF0) || (c2 & 0xF0) || (n > sizeof(name->name)-1))
            return(0);
        name->name[n++] = (c1<<4) | c2;
        m -= 2;
    }
    name->name[n] = 0;

    if (n==MAX_NETBIOSNAME_LEN) {
        /* parse out the name type, its always in the 16th byte of the name */
        name->name_type = ((unsigned char)name->name[15]) & 0xff;

        /* remove trailing spaces */
        name->name[15] = 0;
        n = 14;
        while (n && name->name[n]==' ')
            name->name[n--] = 0;  
    }

    /* now the domain parts (if any) */
    n = 0;
    while (ubuf[offset]) {
        /* we can have pointers within the domain part as well */
        if (!handle_name_ptrs(ubuf,&offset,length,&got_pointer,&ret))
            return(0);

        m = ubuf[offset];
        /*
         * Don't allow null domain parts.
         */
        if (!m)
            return(0);
        if (!got_pointer)
            ret += m+1;
        if (n)
            name->scope[n++] = '.';
        if (m+2+offset>length || n+m+1>sizeof(name->scope))
            return(0);
        offset++;
        while (m--)
            name->scope[n++] = (char)ubuf[offset++];

        /*
         * Watch for malicious loops.
         */
        if (loop_count++ == 10)
            return 0;
    }
    name->scope[n++] = 0;  

    return(ret);
}

static BOOL parse_alloc_res_rec(char *inbuf,int *offset,int length,
                struct res_rec **recs, int count)
{
    int i;

    *recs = (struct res_rec *)malloc(sizeof(**recs)*count);
    if (!*recs)
        return(False);

    memset((char *)*recs,'\0',sizeof(**recs)*count);

    for (i=0;i<count;i++) {
        int l = parse_nmb_name(inbuf,*offset,length,&(*recs)[i].rr_name);
        (*offset) += l;
        if (!l || (*offset)+10 > length) {
            SAFE_FREE(*recs);
            return(False);
        }
        (*recs)[i].rr_type = RSVAL(inbuf,(*offset));
        (*recs)[i].rr_class = RSVAL(inbuf,(*offset)+2);
        (*recs)[i].ttl = RIVAL(inbuf,(*offset)+4);
        (*recs)[i].rdlength = RSVAL(inbuf,(*offset)+8);
        (*offset) += 10;
        if ((*recs)[i].rdlength>sizeof((*recs)[i].rdata) || 
                (*offset)+(*recs)[i].rdlength > length) {
            SAFE_FREE(*recs);
            return(False);
        }
        memcpy((*recs)[i].rdata,inbuf+(*offset),(*recs)[i].rdlength);
        (*offset) += (*recs)[i].rdlength;    
    }
    return(True);
}

static BOOL parse_nmb(char *inbuf,int length,struct nmb_packet *nmb)
{
    int nm_flags,offset;

    memset((char *)nmb,'\0',sizeof(*nmb));

    if (length < 12)
        return(False);

    /* parse the header */
    nmb->header.name_trn_id = RSVAL(inbuf,0);

    //printf("parse_nmb: packet id = %d\n", nmb->header.name_trn_id);

    nmb->header.opcode = (CVAL(inbuf,2) >> 3) & 0xF;
    nmb->header.response = ((CVAL(inbuf,2)>>7)&1)?True:False;
    nm_flags = ((CVAL(inbuf,2) & 0x7) << 4) + (CVAL(inbuf,3)>>4);
    nmb->header.nm_flags.bcast = (nm_flags&1)?True:False;
    nmb->header.nm_flags.recursion_available = (nm_flags&8)?True:False;
    nmb->header.nm_flags.recursion_desired = (nm_flags&0x10)?True:False;
    nmb->header.nm_flags.trunc = (nm_flags&0x20)?True:False;
    nmb->header.nm_flags.authoritative = (nm_flags&0x40)?True:False;  
    nmb->header.rcode = CVAL(inbuf,3) & 0xF;
    nmb->header.qdcount = RSVAL(inbuf,4);
    nmb->header.ancount = RSVAL(inbuf,6);
    nmb->header.nscount = RSVAL(inbuf,8);
    nmb->header.arcount = RSVAL(inbuf,10);

    if (nmb->header.qdcount) {
        offset = parse_nmb_name(inbuf,12,length,&nmb->question.question_name);
        if (!offset)
            return(False);
        if (length - (12+offset) < 4)
            return(False);
        nmb->question.question_type = RSVAL(inbuf,12+offset);
        nmb->question.question_class = RSVAL(inbuf,12+offset+2);

        offset += 12+4;
    } else {
        offset = 12;
    }

    /* and any resource records */
    if (nmb->header.ancount && !parse_alloc_res_rec(inbuf,&offset,length,&nmb->answers,
                    nmb->header.ancount))
        return(False);

    if (nmb->header.nscount && !parse_alloc_res_rec(inbuf,&offset,length,&nmb->nsrecs,
                    nmb->header.nscount))
        return(False);

    if (nmb->header.arcount && !parse_alloc_res_rec(inbuf,&offset,length,&nmb->additional,
                    nmb->header.arcount))
        return(False);

    return(True);
}

struct packet_struct *parse_packet(char *buf,int length)
{
    extern struct in_addr lastip;
    extern int lastport;
    struct packet_struct *p;
    BOOL ok=False;

    p = (struct packet_struct *)malloc(sizeof(*p));
    if (!p)
        return(NULL);

    p->next = NULL;
    p->prev = NULL;
    p->ip = lastip;
    p->port = lastport;
    p->locked = False;
    p->timestamp = time(NULL);
    p->packet_type = NMB_PACKET;

    ok = parse_nmb(buf,length,&p->packet.nmb);

    if (!ok) {
        free_packet(p);
        return NULL;
    }

    return p;
}

void reply_netbios_packet(struct packet_struct *orig_packet, int rcode, int opcode,
                          int ttl)
{
    struct packet_struct packet;
    struct nmb_packet *nmb = NULL;
    struct res_rec answers;
    struct nmb_packet *orig_nmb = &orig_packet->packet.nmb;
    BOOL loopback_this_packet = False;
    const char *packet_type = "unknown";


    if (/*ismyip(orig_packet->ip) && */(orig_packet->port == global_nmb_port))
        loopback_this_packet = True;

    nmb = &packet.packet.nmb;

    packet = *orig_packet;
    packet.locked = False;
    nmb->answers = NULL;
    nmb->nsrecs = NULL;
    nmb->additional = NULL;

    packet_type = "nmb_query";
    nmb->header.nm_flags.recursion_desired = True;
    nmb->header.nm_flags.recursion_available = True;

    printf("reply_netbios_packet: sending a reply of packet type: %s %s to ip %s \
            for id %hu\n", packet_type, &orig_nmb->question.question_name.name,
            inet_ntoa(packet.ip), orig_nmb->header.name_trn_id);

    nmb->header.name_trn_id = orig_nmb->header.name_trn_id;
    nmb->header.opcode = opcode;
    nmb->header.response = True;
    nmb->header.nm_flags.bcast = False;
    nmb->header.nm_flags.trunc = False;
    nmb->header.nm_flags.authoritative = True;

    nmb->header.rcode = rcode;
    nmb->header.qdcount = 0;
    nmb->header.ancount = 1;
    nmb->header.nscount = 0;
    nmb->header.arcount = 0;

    memset((char*)&nmb->question,'\0',sizeof(nmb->question));

    nmb->answers = &answers;
    memset((char*)nmb->answers,'\0',sizeof(*nmb->answers));

    nmb->answers->rr_name  = orig_nmb->question.question_name;
    nmb->answers->rr_type  = orig_nmb->question.question_type;
    nmb->answers->rr_class = orig_nmb->question.question_class;
    nmb->answers->ttl      = ttl;

    //  if (data && len) {
    //      nmb->answers->rdlength = len;
    //      memcpy(nmb->answers->rdata, data, len);
    //  }
    nmb->answers->rdlength = 6;
    {
        char data[6];
        memset(data, 0, sizeof(data));
        data[2] = 0xc0;
        data[3] = 0xa8;
        data[4] = 0x01;
        data[5] = 0x22;
        memcpy(nmb->answers->rdata, data, 6);
    }

    packet.packet_type = NMB_PACKET;
    /* Ensure we send out on the same fd that the original
        packet came in on to give the correct source IP address. */
    packet.fd = orig_packet->fd;
    packet.timestamp = time(NULL);

    send_packet(&packet);
}

int main(void)
{
    int sockfd, one=1, i, ret;
    struct sockaddr_in my_addr; // my address information
    struct sockaddr_in their_addr; // connector's address information
    socklen_t addr_len = sizeof(their_addr);
    fd_set readfd;
    struct timeval wait;
    int numbytes;
    char buf[MAX_DGRAM_SIZE];
    struct packet_struct *packet;
    char *nam_names = "DANIEL_TEST";

    //struct hostent *hp;

    /*
    if ((hp = Get_Hostbyname("192.168.1.34")) == 0) {
      printf( "Get_Hostbyname: Unknown host. %s\n","192.168.1.34");
    }

    putip((char *)&lastip,(char *)hp->h_addr);
    */
    global_nmb_port = NMB_PORT;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("socket");
        exit(1);
    }

    fcntl(sockfd, F_GETFL, 0);

    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof(one));

    my_addr.sin_family = AF_INET;        // host byte order
    my_addr.sin_addr.s_addr = INADDR_ANY; // automatically fill with my IP
    my_addr.sin_port = htons(NMB_PORT);  // short, network byte order
    memset(&(my_addr.sin_zero), '\0', 8); // zero the rest of the struct

    if (bind(sockfd, (struct sockaddr *)&my_addr,
        sizeof(struct sockaddr)) == -1) {
        perror("bind");
        exit(1);
    }

    while (1) 
    {
        FD_ZERO(&readfd);
        FD_SET(sockfd, &readfd);
        wait.tv_sec = 1;
        wait.tv_usec = 0;
        if ((numbytes = select(sockfd+1, &readfd, (fd_set *)0, (fd_set *)0, &wait)) <= 0)
            continue;

        if (!FD_ISSET(sockfd, &readfd))
            continue;

        memset(buf, 0, sizeof(buf));
        if ((numbytes = recvfrom(sockfd, buf, MAX_DGRAM_SIZE-1 , 0, (struct sockaddr *)&their_addr, &addr_len)) <= 0)
            continue;

        lastip = their_addr.sin_addr;
        lastport = ntohs(their_addr.sin_port);
        printf("lastip = %s\n", inet_ntoa(lastip));

        if (numbytes < MIN_DGRAM_SIZE)
            continue;
        
        printf("get a name service request (%d)\n", numbytes);
        
        for (i=0; i<numbytes; i++) {
            if( (i % 16) == 0)
                printf("\n");
            printf("0x%02x ",(unsigned char)buf[i]);
        }
        printf("\n\n");
        
        packet = parse_packet(buf, numbytes);
        if (!packet)
            continue;

        printf("name = %s\n", packet->packet.nmb.question.question_name.name);
        if ((ret = strncmp(nam_names, packet->packet.nmb.question.question_name.name, strlen(nam_names))) != 0) {
            free_packet(packet);
            continue;
        }
        

        packet->fd = sockfd;
        printf("\n================= NetBIOS Name service ===================\n");
        printf("Received a packet of len %d from (%s) port %d\n", numbytes, inet_ntoa(packet->ip), packet->port);

        {
            reply_netbios_packet(packet, 0, NMB_NAME_QUERY_OPCODE, 0);
        }
        free_packet(packet);
    }

    close(sockfd);

    return 0;
}