#define MAX_DGRAM_SIZE 576
#define MIN_DGRAM_SIZE 12

#define NMB_PORT 137
#define DGRAM_PORT 138
#define SMB_PORT 139

typedef char pstring[1024];
typedef char fstring[128];
typedef fstring string;
typedef int BOOL;

int samba_nb_type = 0; /* samba's NetBIOS name type */

#define putip(dest,src) memcpy(dest,src,4)

enum name_source {LMHOSTS, REGISTER, SELF, DNS, DNSFAIL};
enum node_type {B_NODE=0, P_NODE=1, M_NODE=2, NBDD_NODE=3};
enum packet_type {NMB_PACKET, DGRAM_PACKET};

/* a netbios name structure */
struct nmb_name {
    char name[17];
    char scope[64];
    int name_type;
};

/* this is the structure used for the local netbios name list */
struct name_record
{
    struct name_record *next;
    struct name_record *prev;
    struct nmb_name name;
    time_t death_time;
    struct in_addr ip;
    BOOL unique;
    enum name_source source;
};

/* this is used by the list of domains */
struct domain_record
{
    struct domain_record *next;
    struct domain_record *prev;
    fstring name;
    time_t lastannounce_time;
    int announce_interval;
    struct in_addr bcast_ip;
};

/* this is used to hold the list of servers in my domain */
struct server_record
{
    struct server_record *next;
    struct server_record *prev;
    fstring name;
    fstring comment;
    int servertype;
    time_t death_time;  
};

/* a resource record */
struct res_rec {
    struct nmb_name rr_name;
    int rr_type;
    int rr_class;
    int ttl;
    int rdlength;
    char rdata[MAX_DGRAM_SIZE];
};

/* define a nmb packet. */
struct nmb_packet
{
    struct {
        int name_trn_id;
        int opcode;
        BOOL response;
        struct {
            BOOL bcast;
            BOOL recursion_available;
            BOOL recursion_desired;
            BOOL trunc;
            BOOL authoritative;
        } nm_flags;
        int rcode;
        int qdcount;
        int ancount;
        int nscount;
        int arcount;
    } header;

    struct {
        struct nmb_name question_name;
        int question_type;
        int question_class;
    } question;

    struct res_rec *answers;
    struct res_rec *nsrecs;
    struct res_rec *additional;
};


/* a datagram - this normally contains SMB data in the data[] array */
struct dgram_packet {
    struct {
        int msg_type;
        struct {
            enum node_type node_type;
            BOOL first;
            BOOL more;
        } flags;
        int dgm_id;
        struct in_addr source_ip;
        int source_port;
        int dgm_length;
        int packet_offset;
    } header;
    struct nmb_name source_name;
    struct nmb_name dest_name;
    int datasize;
    char data[MAX_DGRAM_SIZE];
};

/* define a structure used to queue packets. this will be a linked
 list of nmb packets */
struct packet_struct
{
    struct packet_struct *next;
    struct packet_struct *prev;
    BOOL locked;
    struct in_addr ip;
    int port;
    int fd;
    time_t timestamp;
    enum packet_type packet_type;
    union {
        struct nmb_packet nmb;
        struct dgram_packet dgram;
    } packet;
};


/* this defines a list of network interfaces */
struct net_interface {
    struct net_interface *next;
    struct in_addr ip;
    struct in_addr bcast;
    struct in_addr netmask;
};

#define        const
#define        uid_t           int
#define        gid_t           int
#define        mode_t          int
#define        ptrdiff_t       int

#define NMB_PORT 137
#define DGRAM_PORT 138

#define MAX_NETBIOSNAME_LEN 16

#define NMB_NAME_QUERY_OPCODE   0x0

#define LOCAL_TO_GMT 1
#define GMT_TO_LOCAL (-1)

#define NMB_PACKET      0

#define False (0)
#define True (1)

#define BOOLSTR(b) ((b) ? "Yes" : "No")
#define BITSETB(ptr,bit) ((((char *)ptr)[0] & (1<<(bit)))!=0)
#define BITSETW(ptr,bit) ((SVAL(ptr,0) & (1<<(bit)))!=0)
#define PTR_DIFF(p1,p2) ((ptrdiff_t)(((char *)(p1)) - (char *)(p2)))

#define CVAL(buf,pos) (((unsigned char *)(buf))[pos])
#define PVAL(buf,pos) ((unsigned)CVAL(buf,pos))
#define SCVAL(buf,pos,val) (CVAL(buf,pos) = (val))


/* this handles things for architectures like the 386 that can handle
   alignment errors */
/*
   WARNING: This section is dependent on the length of int16 and int32
   being correct 
*/
#define SVAL(buf,pos) (*(int *)((char *)(buf) + (pos)))
#define IVAL(buf,pos) (*(int *)((char *)(buf) + (pos)))
#define SVALS(buf,pos) (*(int *)((char *)(buf) + (pos)))
#define IVALS(buf,pos) (*(int *)((char *)(buf) + (pos)))
#define SSVAL(buf,pos,val) SVAL(buf,pos)=((int)(val))
#define SIVAL(buf,pos,val) IVAL(buf,pos)=((int)(val))
#define SSVALS(buf,pos,val) SVALS(buf,pos)=((int)(val))
#define SIVALS(buf,pos,val) IVALS(buf,pos)=((int)(val))


/* now the reverse routines - these are used in nmb packets (mostly) */
#define SREV(x) ((((x)&0xFF)<<8) | (((x)>>8)&0xFF))
#define IREV(x) ((SREV(x)<<16) | (SREV((x)>>16)))

#define RSVAL(buf,pos) SREV(SVAL(buf,pos))
#define RIVAL(buf,pos) IREV(IVAL(buf,pos))
#define RSSVAL(buf,posal) SSVAL(buf,pos,SREV(val))
#define RSIVAL(buf,pos,val) SIVAL(buf,pos,IREV(val))

#define SAFE_FREE(x) do { if ((x) != NULL) {free(x); x=NULL;} } while(0)
#define SAFE_FREE(x) do { if ((x) != NULL) {free(x); x=NULL;} } while(0)
#define ZERO_STRUCTPN(x) memset((char *)(x), 0, sizeof(*(x)))

int num_good_sends=0;
static int name_trn_id = 0;
struct in_addr dest_ip;
struct in_addr lastip;
int lastport, global_nmb_port;

int ClientNMB, ClientDGRAM;