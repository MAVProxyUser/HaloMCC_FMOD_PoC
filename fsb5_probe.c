/*
 * fsb5_probe.c  --  FMOD FSB5 crash/fix bisection harness
 *
 * Opens a crafted FSB5 bank through an arbitrary libfmod.dylib (loaded at
 * runtime via dlopen) using the exact code path MCC's halo3.dll exercises:
 *   System::create -> setOutput(NOSOUND) -> init -> createSound(path, mode) -> release
 * No playback, no audio device required.
 *
 * Distinguishing outcomes:
 *   - clean FMOD_RESULT (even an error like FMOD_ERR_FORMAT) => process exits 0
 *     and prints "RESULT=<n> <name>".  A clean error return == the parser
 *     rejected the file safely == FIXED/not-vulnerable on this build.
 *   - SIGSEGV / SIGBUS / SIGABRT => the process dies with that signal (the OS
 *     terminates it); the wrapper sees exit code 128+signo == VULNERABLE.
 *
 * Usage: fsb5_probe <libfmod.dylib> <bank.fsb> [mode_hex] [version_hex]
 *   mode_hex    default 0x2080  (FMOD_OPENONLY|FMOD_CREATESTREAM), matches the
 *               in-game createStream(...,0x2080,NULL) call in halo3.dll.
 *   version_hex optional value passed as System_Create's 2nd argument. Harmless
 *               on builds whose System_Create takes only one argument (the extra
 *               register is ignored under the C ABI); required on builds that
 *               version-check there. 0 (default) means "don't care".
 *
 * Build (no link against fmod; pure dlopen):
 *   cc -O0 -g -o fsb5_probe fsb5_probe.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

typedef int FMOD_RESULT;

/* FMOD_RESULT enum names, in definition order (FMOD only appends, so the low
 * indices are identical across 1.10 -> 2.03). Index == numeric value. */
static const char *RESULT_NAMES[] = {
    "FMOD_OK","FMOD_ERR_BADCOMMAND","FMOD_ERR_CHANNEL_ALLOC","FMOD_ERR_CHANNEL_STOLEN",
    "FMOD_ERR_DMA","FMOD_ERR_DSP_CONNECTION","FMOD_ERR_DSP_DONTPROCESS","FMOD_ERR_DSP_FORMAT",
    "FMOD_ERR_DSP_INUSE","FMOD_ERR_DSP_NOTFOUND","FMOD_ERR_DSP_RESERVED","FMOD_ERR_DSP_SILENCE",
    "FMOD_ERR_DSP_TYPE","FMOD_ERR_FILE_BAD","FMOD_ERR_FILE_COULDNOTSEEK","FMOD_ERR_FILE_DISKEJECTED",
    "FMOD_ERR_FILE_EOF","FMOD_ERR_FILE_ENDOFDATA","FMOD_ERR_FILE_NOTFOUND","FMOD_ERR_FORMAT",
    "FMOD_ERR_HEADER_MISMATCH","FMOD_ERR_HTTP","FMOD_ERR_HTTP_ACCESS","FMOD_ERR_HTTP_PROXY_AUTH",
    "FMOD_ERR_HTTP_SERVER_ERROR","FMOD_ERR_HTTP_TIMEOUT","FMOD_ERR_INITIALIZATION","FMOD_ERR_INITIALIZED",
    "FMOD_ERR_INTERNAL","FMOD_ERR_INVALID_FLOAT","FMOD_ERR_INVALID_HANDLE","FMOD_ERR_INVALID_PARAM",
    "FMOD_ERR_INVALID_POSITION","FMOD_ERR_INVALID_SPEAKER","FMOD_ERR_INVALID_SYNCPOINT","FMOD_ERR_INVALID_THREAD",
    "FMOD_ERR_INVALID_VECTOR","FMOD_ERR_MAXAUDIBLE","FMOD_ERR_MEMORY","FMOD_ERR_MEMORY_CANTPOINT",
    "FMOD_ERR_NEEDS3D","FMOD_ERR_NEEDSHARDWARE","FMOD_ERR_NET_CONNECT","FMOD_ERR_NET_SOCKET_ERROR",
    "FMOD_ERR_NET_URL","FMOD_ERR_NET_WOULD_BLOCK","FMOD_ERR_NOTREADY","FMOD_ERR_OUTPUT_ALLOCATED",
    "FMOD_ERR_OUTPUT_CREATEBUFFER","FMOD_ERR_OUTPUT_DRIVERCALL","FMOD_ERR_OUTPUT_FORMAT","FMOD_ERR_OUTPUT_INIT",
    "FMOD_ERR_OUTPUT_NODRIVERS","FMOD_ERR_PLUGIN","FMOD_ERR_PLUGIN_MISSING","FMOD_ERR_PLUGIN_RESOURCE",
    "FMOD_ERR_PLUGIN_VERSION","FMOD_ERR_RECORD","FMOD_ERR_REVERB_CHANNELGROUP","FMOD_ERR_REVERB_INSTANCE",
    "FMOD_ERR_SUBSOUNDS","FMOD_ERR_SUBSOUND_ALLOCATED","FMOD_ERR_SUBSOUND_CANTMOVE","FMOD_ERR_TAGNOTFOUND",
    "FMOD_ERR_TOOMANYCHANNELS","FMOD_ERR_TRUNCATED","FMOD_ERR_UNIMPLEMENTED","FMOD_ERR_UNINITIALIZED",
    "FMOD_ERR_UNSUPPORTED","FMOD_ERR_VERSION","FMOD_ERR_EVENT_ALREADY_LOADED","FMOD_ERR_EVENT_LIVEUPDATE_BUSY",
    "FMOD_ERR_EVENT_LIVEUPDATE_MISMATCH","FMOD_ERR_EVENT_LIVEUPDATE_TIMEOUT","FMOD_ERR_EVENT_NOTFOUND",
    "FMOD_ERR_STUDIO_UNINITIALIZED","FMOD_ERR_STUDIO_NOT_LOADED","FMOD_ERR_INVALID_STRING",
    "FMOD_ERR_ALREADY_LOCKED","FMOD_ERR_NOT_LOCKED","FMOD_ERR_RECORD_DISCONNECTED","FMOD_ERR_TOOMANYSAMPLES",
};
static const int N_RESULT_NAMES = (int)(sizeof(RESULT_NAMES)/sizeof(RESULT_NAMES[0]));

static const char *rname(FMOD_RESULT r){
    if (r >= 0 && r < N_RESULT_NAMES) return RESULT_NAMES[r];
    return "FMOD_ERR_<unknown>";
}

typedef FMOD_RESULT (*pfn_create)(void **system, unsigned int headerversion);
typedef FMOD_RESULT (*pfn_setoutput)(void *system, int output);
typedef FMOD_RESULT (*pfn_init)(void *system, int maxchannels, unsigned int flags, void *extra);
typedef FMOD_RESULT (*pfn_createsound)(void *system, const char *name, unsigned int mode, void *exinfo, void **sound);
typedef FMOD_RESULT (*pfn_sound_release)(void *sound);
typedef FMOD_RESULT (*pfn_sys_release)(void *system);
/* FMOD 2.03+ changed getVersion to (version, buildnumber); older takes (version) only.
   Declaring/passing two out-params is safe for both (the 1-arg callee ignores the extra reg). */
typedef FMOD_RESULT (*pfn_getversion)(void *system, unsigned int *version, unsigned int *build);

#define FMOD_OUTPUTTYPE_NOSOUND 2

static void *must(void *h, const char *sym){
    void *p = dlsym(h, sym);
    if(!p){ fprintf(stderr, "PROBE: missing symbol %s: %s\n", sym, dlerror()); exit(97); }
    return p;
}

int main(int argc, char **argv){
    if(argc < 3){
        fprintf(stderr,"usage: %s <libfmod.dylib> <bank.fsb> [mode_hex=0x2080] [ver_hex=0]\n", argv[0]);
        return 96;
    }
    const char *libpath = argv[1];
    const char *bank    = argv[2];
    unsigned int mode   = (argc>3)? (unsigned int)strtoul(argv[3],0,16) : 0x2080u;
    unsigned int ver    = (argc>4)? (unsigned int)strtoul(argv[4],0,16) : 0u;

    void *h = dlopen(libpath, RTLD_NOW|RTLD_LOCAL);
    if(!h){ fprintf(stderr,"PROBE: dlopen failed: %s\n", dlerror()); return 95; }

    pfn_create       f_create   = (pfn_create)      must(h,"FMOD_System_Create");
    pfn_setoutput    f_output   = (pfn_setoutput)   must(h,"FMOD_System_SetOutput");
    pfn_init         f_init     = (pfn_init)        must(h,"FMOD_System_Init");
    pfn_createsound  f_cs       = (pfn_createsound) must(h,"FMOD_System_CreateSound");
    pfn_sound_release f_srel    = (pfn_sound_release)must(h,"FMOD_Sound_Release");
    pfn_sys_release  f_rel      = (pfn_sys_release) must(h,"FMOD_System_Release");
    pfn_getversion   f_ver      = (pfn_getversion)  dlsym(h,"FMOD_System_GetVersion");

    void *sys = 0;
    FMOD_RESULT r = f_create(&sys, ver);
    fprintf(stderr,"PROBE: System_Create -> %d %s\n", r, rname(r));
    if(r != 0){ fprintf(stderr,"PROBE: cannot create system (try passing ver_hex)\n"); dlclose(h); return 94; }

    if(f_ver){
        unsigned int v=0, build=0; f_ver(sys,&v,&build);
        fprintf(stderr,"PROBE: lib reports version 0x%08x (build %u)\n", v, build);
    }

    r = f_output(sys, FMOD_OUTPUTTYPE_NOSOUND);
    fprintf(stderr,"PROBE: SetOutput(NOSOUND) -> %d %s\n", r, rname(r));

    r = f_init(sys, 32, 0 /*FMOD_INIT_NORMAL*/, 0);
    fprintf(stderr,"PROBE: Init -> %d %s\n", r, rname(r));
    if(r != 0){ fprintf(stderr,"PROBE: init failed\n"); f_rel(sys); dlclose(h); return 93; }

    void *sound = 0;
    fprintf(stderr,"PROBE: calling CreateSound(\"%s\", mode=0x%x) ...\n", bank, mode);
    fflush(stderr);
    r = f_cs(sys, bank, mode, 0, &sound);           /* <-- the FSB5 parser runs here */
    fprintf(stderr,"PROBE: CreateSound -> %d %s  (RESULT=%d)\n", r, rname(r), r);

    if(r == 0 && sound) f_srel(sound);
    f_rel(sys);
    dlclose(h);
    /* Reaching here at all == no crash. Print the machine-readable verdict. */
    printf("VERDICT=CLEAN RESULT=%d %s\n", r, rname(r));
    return 0;
}
