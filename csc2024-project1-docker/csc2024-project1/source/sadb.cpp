#include "sadb.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <linux/ip.h>
#include <sys/un.h>

#include <iomanip>
#include <iostream>
#include <string>

// globle variable
uint32_t           spi;

uint8_t            auth_alg;
uint8_t            enc_alg;

std::string        src_address;
std::string        dst_address;

std::vector<uint8_t> auth_key;
std::vector<uint8_t> enc_key;

void print_sadb_msg(struct sadb_msg *msg, int msglen);
void sa_print(struct sadb_ext *ext);
const char * get_sa_state(int state);
const char * get_auth_alg(int alg);
const char * get_encrypt_alg(int alg);
const char * get_sadb_msg_type(int type);
const char * get_sadb_satype(int type);
void lifetime_print(struct sadb_ext *ext);
void key_print(struct sadb_ext *ext);
void address_print(struct sadb_ext *ext);
char * sock_ntop(const struct sockaddr *sa, socklen_t salen);
void supported_print(struct sadb_ext *ext);
const char * get_sadb_alg_type(int alg, int authenc);

std::optional<ESPConfig> getConfigFromSADB() {
  std::vector<uint8_t> message(65536);
  sadb_msg msg{};
  // TODO: Fill sadb_msg
  msg.sadb_msg_version = PF_KEY_V2;
  msg.sadb_msg_type    = SADB_DUMP;
  msg.sadb_msg_satype  = SADB_SATYPE_ESP;
  msg.sadb_msg_len     = sizeof(sadb_msg) / 8;
  msg.sadb_msg_pid     = getpid();

  // TODO: Create a PF_KEY_V2 socket and write msg to it
  // Then read from socket to get SADB information
  int sock = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
  write(sock, &msg, sizeof(msg));

  bool gotEOF = false;
  int  msglen = 0;

  while (!gotEOF) {
    msglen = read(sock, message.data(), message.size());
    struct sadb_msg *msgp = (struct sadb_msg*)message.data();
    if (msgp->sadb_msg_seq == 0) {
      gotEOF = true;
      print_sadb_msg(msgp, msglen);
    }
  }

  // TODO: Set size to number of bytes in response message
  int size = msglen;
  // Has SADB entry
  if (size != sizeof(sadb_msg)) {
    ESPConfig config{};
    
    // TODO: Parse SADB message
    config.spi = spi;
    config.aalg = std::make_unique<ESP_AALG>(auth_alg, std::span<uint8_t>{auth_key});
    config.ealg = std::make_unique<ESP_EALG>(enc_alg,  std::span<uint8_t>{enc_key});

    // Source address:
    config.local  = src_address;//ipToString(src_address.c_str());
    config.remote = dst_address;//ipToString(dst_address.c_str());

    return config;
  }

  std::cerr << "SADB entry not found." << std::endl;
  return std::nullopt;
}

std::ostream &operator<<(std::ostream &os, const ESPConfig &config) {
  os << "------------------------------------------------------------" << std::endl;
  os << "AALG  : ";
  if (!config.aalg->empty()) {
    os << std::left << std::setw(30) << std::setfill(' ') << config.aalg->name();
    os << "HWACCEL: " << config.aalg->provider() << std::endl;
  } else {
    os << "NONE" << std::endl;
  }
  os << "EALG  : ";
  if (!config.ealg->empty()) {
    os << std::left << std::setw(30) << std::setfill(' ') << config.ealg->name();
    os << "HWACCEL: " << config.aalg->provider() << std::endl;
  } else {
    os << "NONE" << std::endl;
  }
  os << "Local : " << config.local << std::endl;
  os << "Remote: " << config.remote << std::endl;
  os << "------------------------------------------------------------";
  return os;
}

void print_sadb_msg(struct sadb_msg *msg, int msglen) {
	struct sadb_ext *ext;

	if (msglen != msg->sadb_msg_len * 8) {
		printf("SADB Message length (%d) doesn't match msglen (%d)\n", msg->sadb_msg_len * 8, msglen);
		return;
	}

	if (msg->sadb_msg_version != PF_KEY_V2) {
		printf("SADB Message version not PF_KEY_V2\n");
		return;
	}

	printf("SADB Message %s, errno %d, satype %s, seq %d, pid %d\n", get_sadb_msg_type(msg->sadb_msg_type), msg->sadb_msg_errno, get_sadb_satype(msg->sadb_msg_satype), msg->sadb_msg_seq, msg->sadb_msg_pid);
	if (msg->sadb_msg_errno != 0)
		printf(" errno %s\n", strerror(msg->sadb_msg_errno));

	if (msglen == sizeof(struct sadb_msg))
		return;	/* no extensions */

	msglen -= sizeof(struct sadb_msg);
	ext    = (struct sadb_ext *)(msg + 1);

	while (msglen > 0) {
		switch (ext->sadb_ext_type) {
			case SADB_EXT_RESERVED:	
				printf(" Reserved Extension\n");break;
			case SADB_EXT_SA:	    
				sa_print(ext);                  break;
			case SADB_EXT_LIFETIME_CURRENT:
				lifetime_print(ext);            break;
			case SADB_EXT_LIFETIME_HARD:
				lifetime_print(ext);            break;
			case SADB_EXT_LIFETIME_SOFT:
				lifetime_print(ext);            break;
			case SADB_EXT_ADDRESS_SRC:
				address_print(ext);             break;
			case SADB_EXT_ADDRESS_DST:
				address_print(ext);             break;
			case SADB_EXT_ADDRESS_PROXY:
				address_print(ext);             break;
			case SADB_EXT_KEY_AUTH:
				key_print(ext);                 break;
			case SADB_EXT_KEY_ENCRYPT:
				key_print(ext);                 break;
			case SADB_EXT_IDENTITY_SRC:
				printf(" [identity...]\n");     break;
			case SADB_EXT_IDENTITY_DST:
				printf(" [identity...]\n");     break;
			case SADB_EXT_SENSITIVITY:
				printf(" [sensitivity...]\n");  break;
			case SADB_EXT_PROPOSAL:
				printf(" [proposal...]\n");     break;
			case SADB_EXT_SUPPORTED_AUTH:
				supported_print(ext);           break;
			case SADB_EXT_SUPPORTED_ENCRYPT:
				supported_print(ext);           break;
			case SADB_EXT_SPIRANGE:
				printf(" [spirange...]\n");     break;
			default:	
				printf(" [unknown extension %d]\n", ext->sadb_ext_type);
		}
		msglen -= ext->sadb_ext_len << 3;
		ext = (struct sadb_ext*)((char *)ext + (ext->sadb_ext_len << 3));
	}
}

void sa_print(struct sadb_ext *ext) { 
	struct sadb_sa *sa = (struct sadb_sa *)ext;
    spi      = ntohl(sa->sadb_sa_spi);
    auth_alg = sa->sadb_sa_auth;
    enc_alg  = sa->sadb_sa_encrypt;

	printf("SA: SPI = %d Replay Window = %d State = %s\n", spi, sa->sadb_sa_replay, get_sa_state(sa->sadb_sa_state));
	printf("Authentication Algorithm: %s\n", get_auth_alg(sa->sadb_sa_auth));
	printf("Encryption Algorithm:     %s\n", get_encrypt_alg(sa->sadb_sa_encrypt));
	if (sa->sadb_sa_flags & SADB_SAFLAGS_PFS)
		printf("Perfect Forward Secrecy\n");
}

const char * get_sa_state(int state) {
	static char buf[100];
	switch (state) {
		case SADB_SASTATE_LARVAL:	return "Larval";
		case SADB_SASTATE_MATURE:	return "Mature";
		case SADB_SASTATE_DYING:	return "Dying";
		case SADB_SASTATE_DEAD:		return "Dead";
		default:					sprintf(buf, "[Unknown SA state %d]", state);
		
		return buf;
	}
}

const char * get_auth_alg(int alg) {
	static char buf[100];
	switch (alg) {
		case SADB_AALG_NONE:		return "None";
		case SADB_AALG_MD5HMAC:		return "HMAC-MD5";
		case SADB_AALG_SHA1HMAC:	return "HMAC-SHA-1";
#ifdef SADB_X_AALG_MD5
		case SADB_X_AALG_MD5:		return "Keyed MD5";
#endif
#ifdef SADB_X_AALG_SHA
		case SADB_X_AALG_SHA:		return "Keyed SHA-1";
#endif
#ifdef SADB_X_AALG_NULL
		case SADB_X_AALG_NULL:		return "Null";
#endif
#ifdef SADB_X_AALG_SHA2_256
		case SADB_X_AALG_SHA2_256:	return "SHA2-256";
#endif
#ifdef SADB_X_AALG_SHA2_384
		case SADB_X_AALG_SHA2_384:	return "SHA2-384";
#endif
#ifdef SADB_X_AALG_SHA2_512
		case SADB_X_AALG_SHA2_512:	return "SHA2-512";
#endif
		default:					sprintf(buf, "[Unknown authentication algorithm %d]", alg);
		
		return buf;
	}
}

const char * get_encrypt_alg(int alg) {
	static char buf[100];
	switch (alg) {
		case SADB_EALG_NONE:		return "None";
		case SADB_EALG_DESCBC:		return "DES-CBC";
		case SADB_EALG_3DESCBC:		return "3DES-CBC";
		case SADB_EALG_NULL:		return "Null";
#ifdef SADB_X_EALG_CAST128CBC
		case SADB_X_EALG_CAST128CBC:	return "CAST128-CBC";
#endif
#ifdef SADB_X_EALG_BLOWFISHCBC
		case SADB_X_EALG_BLOWFISHCBC:	return "Blowfish-CBC";
#endif
#ifdef SADB_X_EALG_AES
		case SADB_X_EALG_AES:			return "AES";
#endif
		default:					sprintf(buf, "[Unknown encryption algorithm %d]", alg);
		
		return buf;
	}
}

const char * get_sadb_msg_type(int type) {
	static char buf[100];
	switch (type) {
		case SADB_RESERVED:	return "Reserved";
		case SADB_GETSPI:	return "Get SPI";
		case SADB_UPDATE:	return "Update";
		case SADB_ADD:		return "Add";
		case SADB_DELETE:	return "Delete";
		case SADB_GET:		return "Get";
		case SADB_ACQUIRE:	return "Acquire";
		case SADB_REGISTER:	return "Register";
		case SADB_EXPIRE:	return "Expire";
		case SADB_FLUSH:	return "Flush";
		case SADB_DUMP:		return "Dump";
		default:			sprintf(buf, "[Unknown type %d]", type);
		
		return buf;
	}
}

const char * get_sadb_satype(int type) {
	static char buf[100];
	switch (type) {
		case SADB_SATYPE_UNSPEC:	return "Unspecified";
		case SADB_SATYPE_AH:		return "IPsec AH";
		case SADB_SATYPE_ESP:		return "IPsec ESP";
		case SADB_SATYPE_RSVP:		return "RSVP";
		case SADB_SATYPE_OSPFV2:	return "OSPFv2";
		case SADB_SATYPE_RIPV2:		return "RIPv2";
		case SADB_SATYPE_MIP:		return "Mobile IP";
		default:					sprintf(buf, "[Unknown satype %d]", type);
		
		return buf;
	}
}

void lifetime_print(struct sadb_ext *ext) {
	struct sadb_lifetime *life = (struct sadb_lifetime *)ext;

	printf(" %s lifetime:\n", life->sadb_lifetime_exttype == SADB_EXT_LIFETIME_CURRENT ? "Current" : life->sadb_lifetime_exttype == SADB_EXT_LIFETIME_HARD ? "Hard" : "Soft");
	printf(" %d allocations, %d bytes", life->sadb_lifetime_allocations, life->sadb_lifetime_bytes);

	if (life->sadb_lifetime_exttype == SADB_EXT_LIFETIME_CURRENT) {
		time_t t;
		struct tm *tm;
		char buf[100];

		t = life->sadb_lifetime_addtime;
		tm = localtime(&t);
		strftime(buf, sizeof(buf), "%c", tm);
		printf("\n  added at %s, ", buf);

		if (life->sadb_lifetime_usetime == 0) {
			printf("never used\n");
		} 
		else {
			t = life->sadb_lifetime_usetime;
			tm = localtime(&t);
			strftime(buf, sizeof(buf), "%c", tm);
			printf("first used at %s\n", buf);
		}
	} 
	else {
		printf("%d addtime, %d usetime\n", life->sadb_lifetime_addtime, life->sadb_lifetime_usetime);
	}
}

void key_print(struct sadb_ext *ext) {
	struct sadb_key *key = (struct sadb_key *)ext;
	int bits;
	unsigned char *p;

	printf(" %s key, %d bits: 0x", key->sadb_key_exttype == SADB_EXT_KEY_AUTH ? "Authentication" : "Encryption", key->sadb_key_bits);
	
	if (key->sadb_key_exttype == SADB_EXT_KEY_AUTH) {
		for (p = (unsigned char *)(key + 1), bits = key->sadb_key_bits; bits > 0; p++, bits -= 8) {
			printf("%02x", *p);
			auth_key.push_back(static_cast<uint8_t>(*p));
		} 
	}

  	else {
		for (p = (unsigned char *)(key + 1), bits = key->sadb_key_bits; bits > 0; p++, bits -= 8) {
			printf("%02x", *p);
			enc_key.push_back(static_cast<uint8_t>(*p));
		}
  	}
	printf("\n");
}

void address_print(struct sadb_ext *ext) {
	struct sadb_address *addr = (struct sadb_address *)ext;
	struct sockaddr *sa;
	printf(" %s address: ", addr->sadb_address_exttype == SADB_EXT_ADDRESS_SRC ? "Source" : addr->sadb_address_exttype == SADB_EXT_ADDRESS_DST ? "Dest" : "Proxy");
	sa = (struct sockaddr *)(addr + 1);

  	char* ip_address = sock_ntop(sa, addr->sadb_address_len * 8 - sizeof(*addr));
  	if (addr->sadb_address_exttype == SADB_EXT_ADDRESS_SRC) {
    	src_address = ip_address;
  	} 
	else if (addr->sadb_address_exttype == SADB_EXT_ADDRESS_DST) {
		dst_address = ip_address;
	}

	printf("  %s", ip_address);

	if (addr->sadb_address_prefixlen == 0)
		printf(" ");
	else
		printf("/%d ", addr->sadb_address_prefixlen);

	switch (addr->sadb_address_proto) {
		case IPPROTO_UDP:	printf("(UDP)"); break;
		case IPPROTO_TCP:	printf("(TCP)"); break;
		case 0:				break;
		default:			printf("(IP proto %d)", addr->sadb_address_proto);
		break;
	}
	printf("\n");
}

char * sock_ntop(const struct sockaddr *sa, socklen_t salen) {
    char		portstr[7];
    static char str[128];		/* Unix domain is largest */

	switch (sa->sa_family) {
		case AF_INET: {
			struct sockaddr_in	*sin = (struct sockaddr_in *) sa;

			if (inet_ntop(AF_INET, &sin->sin_addr, str, sizeof(str)) == NULL)
				return(NULL);
			if (ntohs(sin->sin_port) != 0) {
				snprintf(portstr, sizeof(portstr), ".%d", ntohs(sin->sin_port));
				strcat(str, portstr);
			}
			return(str);
		}
/* end sock_ntop */

#ifdef	IPV6
		case AF_INET6: {
			struct sockaddr_in6	*sin6 = (struct sockaddr_in6 *) sa;

			if (inet_ntop(AF_INET6, &sin6->sin6_addr, str, sizeof(str)) == NULL)
				return(NULL);
			if (ntohs(sin6->sin6_port) != 0) {
				snprintf(portstr, sizeof(portstr), ".%d", ntohs(sin6->sin6_port));
				strcat(str, portstr);
			}
			return(str);
		}
#endif

#ifdef	AF_UNIX
		case AF_UNIX: {
			struct sockaddr_un	*unp = (struct sockaddr_un *) sa;

				/* OK to have no pathname bound to the socket: happens on
				every connect() unless client calls bind() first. */
			if (unp->sun_path[0] == 0)
				strcpy(str, "(no pathname bound)");
			else
				snprintf(str, sizeof(str), "%s", unp->sun_path);
			return(str);
		}
#endif

#ifdef	HAVE_SOCKADDR_DL_STRUCT
		case AF_LINK: {
			struct sockaddr_dl	*sdl = (struct sockaddr_dl *) sa;

			if (sdl->sdl_nlen > 0)
				snprintf(str, sizeof(str), "%*s",
						sdl->sdl_nlen, &sdl->sdl_data[0]);
			else
				snprintf(str, sizeof(str), "AF_LINK, index=%d", sdl->sdl_index);
			return(str);
		}
#endif

		default:
			snprintf(str, sizeof(str), "sock_ntop: unknown AF_xxx: %d, len %d", sa->sa_family, salen);
			return(str);
	}

    return (NULL);
}

void supported_print(struct sadb_ext *ext) {
	struct sadb_supported *sup = (struct sadb_supported *)ext;
	struct sadb_alg *alg;
	int len;

	printf(" Supported %s algorithms:\n", sup->sadb_supported_exttype == SADB_EXT_SUPPORTED_AUTH ? "authentication" : "encryption");
	len = sup->sadb_supported_len * 8;
	len -= sizeof(*sup);

	if (len == 0) {
		printf("  None\n");
		return;
	}
	for (alg = (struct sadb_alg *)(sup + 1); len>0; len -= sizeof(*alg), alg++) {
		printf("  %s ivlen %d bits %d-%d\n", get_sadb_alg_type(alg->sadb_alg_id, sup->sadb_supported_exttype), alg->sadb_alg_ivlen, alg->sadb_alg_minbits, alg->sadb_alg_maxbits);
	}
}

const char * get_sadb_alg_type(int alg, int authenc) {
	if (authenc == SADB_EXT_SUPPORTED_AUTH) {
		return get_auth_alg(alg);
	} 
	else {
		return get_encrypt_alg(alg);
	}
}
