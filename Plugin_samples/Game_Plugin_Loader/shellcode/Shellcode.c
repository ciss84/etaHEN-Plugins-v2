#include <stdint.h>

// Ce shellcode charge le PRX dès le PREMIER appel à scePadReadState
// sans attendre qu'une manette soit connectée

#define ORBIS_PAD_PORT_TYPE_STANDARD 0
#define ORBIS_PAD_PORT_TYPE_SPECIAL 2

#define ORBIS_PAD_DEVICE_CLASS_PAD 0
#define ORBIS_PAD_DEVICE_CLASS_GUITAR 1
#define ORBIS_PAD_DEVICE_CLASS_DRUMS 2

#define ORBIS_PAD_CONNECTION_TYPE_STANDARD 0
#define ORBIS_PAD_CONNECTION_TYPE_REMOTE 2

enum OrbisPadButton {
  ORBIS_PAD_BUTTON_L3 = 0x0002,
    ORBIS_PAD_BUTTON_R3 = 0x0004,
    ORBIS_PAD_BUTTON_OPTIONS = 0x0008,
    ORBIS_PAD_BUTTON_UP = 0x0010,
    ORBIS_PAD_BUTTON_RIGHT = 0x0020,
    ORBIS_PAD_BUTTON_DOWN = 0x0040,
    ORBIS_PAD_BUTTON_LEFT = 0x0080,

    ORBIS_PAD_BUTTON_L2 = 0x0100,
    ORBIS_PAD_BUTTON_R2 = 0x0200,
    ORBIS_PAD_BUTTON_L1 = 0x0400,
    ORBIS_PAD_BUTTON_R1 = 0x0800,

    ORBIS_PAD_BUTTON_TRIANGLE = 0x1000,
    ORBIS_PAD_BUTTON_CIRCLE = 0x2000,
    ORBIS_PAD_BUTTON_CROSS = 0x4000,
    ORBIS_PAD_BUTTON_SQUARE = 0x8000,

    ORBIS_PAD_BUTTON_TOUCH_PAD = 0x100000
};

#define ORBIS_PAD_MAX_TOUCH_NUM 2
#define ORBIS_PAD_MAX_DATA_NUM 0x40

typedef struct vec_float3 {
  float x;
  float y;
  float z;
}
vec_float3;

typedef struct vec_float4 {
  float x;
  float y;
  float z;
  float w;
}
vec_float4;

typedef struct stick {
  uint8_t x;
  uint8_t y;
}
stick;

typedef struct analog {
  uint8_t l2;
  uint8_t r2;
}
analog;

typedef struct OrbisPadTouch {
  uint16_t x, y;
  uint8_t finger;
  uint8_t pad[3];
}
OrbisPadTouch;

typedef struct OrbisPadTouchData {
  uint8_t fingers;
  uint8_t pad1[3];
  uint32_t pad2;
  OrbisPadTouch touch[ORBIS_PAD_MAX_TOUCH_NUM];
}
OrbisPadTouchData;

typedef struct OrbisPadData {
  uint32_t buttons;
  stick leftStick;
  stick rightStick;
  analog analogButtons;
  uint16_t padding;
  vec_float4 quat;
  vec_float3 vel;
  vec_float3 acell;
  OrbisPadTouchData touch;
  uint8_t connected;
  uint64_t timestamp;
  uint8_t ext[16];
  uint8_t count;
  uint8_t unknown[15];
} OrbisPadData;

typedef struct {
  int (*scePadReadState)(int handle, OrbisPadData *pData);
  int (*sceKernelDebugOutText)(int channel, const char *txt);
  int (*sceKernelLoadStartModule)(const char *moduleFileName, int args, const void *argp, int flags, void *opt, int *pRes);
  int (*sceKernelDlsym)(int handle, const char *symbol, void **addrp);
  uint64_t ASLR_Base;
  char prx_path[256];
  int loaded;

} GameExtraStuff;


// VERSION MODIFIÉE: Charge au premier appel sans conditions
static int __attribute__((used)) scePadReadState_Hook(int handle, OrbisPadData *pData, GameExtraStuff *restrict stuff){

    volatile unsigned long long Hello_Game[2];
    Hello_Game[0] = 0x7266206f6c6c6548; // "Hello fr"
    Hello_Game[1] = 0x0000364f42206d6f; // "om BO6"

    // Appeler la fonction originale d'abord
    int ret = stuff->scePadReadState(handle, pData);

    // ===================================================================
    // MODIFICATION PRINCIPALE: Charger dès le premier appel
    // On ne vérifie PLUS si la manette est connectée ou si ret == 0
    // ===================================================================
    if (!stuff->loaded)
    {
        // Message de debug
        stuff->sceKernelDebugOutText(0, "[PRX-LOADER] First call detected, loading PRX...\n");
        
        // Charger le PRX
        int res = stuff->sceKernelLoadStartModule(stuff->prx_path, 0, 0, 0, 0, 0);
        
        // Logger le résultat
        char result_msg[128];
        if (res > 0) {
            // Succès
            stuff->sceKernelDebugOutText(0, (const char*)Hello_Game);
            stuff->sceKernelDebugOutText(0, "[PRX-LOADER] PRX loaded successfully!\n");
        } else {
            // Échec
            stuff->sceKernelDebugOutText(0, "[PRX-LOADER] PRX load failed!\n");
        }
        
        // Marquer comme chargé même si échec pour éviter de réessayer
        stuff->loaded = 1;
    }
    
    return ret;
}


// VERSION ALTERNATIVE: Charge uniquement si succès mais sans vérifier la manette
static int __attribute__((used)) scePadReadState_Hook_Alt(int handle, OrbisPadData *pData, GameExtraStuff *restrict stuff){

    // Appeler la fonction originale
    int ret = stuff->scePadReadState(handle, pData);

    // Charger si scePadReadState a réussi et pas encore chargé
    // (plus robuste que la version qui charge inconditionnellement)
    if (ret == 0 && !stuff->loaded)
    {
        stuff->sceKernelDebugOutText(0, "[PRX-LOADER] Loading PRX on first successful call...\n");
        
        int res = stuff->sceKernelLoadStartModule(stuff->prx_path, 0, 0, 0, 0, 0);
        
        if (res > 0) {
            stuff->sceKernelDebugOutText(0, "[PRX-LOADER] PRX loaded!\n");
        }
        
        stuff->loaded = 1;
    }
    
    return ret;
}


// VERSION DEBUG: Affiche tous les appels pour diagnostic
static int __attribute__((used)) scePadReadState_Hook_Debug(int handle, OrbisPadData *pData, GameExtraStuff *restrict stuff){

    static int call_count = 0;
    call_count++;

    // Logger chaque appel
    char debug_msg[256];
    int len = 0;
    
    // Construire le message manuellement (pas de snprintf disponible)
    debug_msg[len++] = '[';
    debug_msg[len++] = 'C';
    debug_msg[len++] = 'A';
    debug_msg[len++] = 'L';
    debug_msg[len++] = 'L';
    debug_msg[len++] = ' ';
    
    // Ajouter le numéro d'appel (simple conversion)
    if (call_count < 10) {
        debug_msg[len++] = '0' + call_count;
    } else {
        debug_msg[len++] = '0' + (call_count / 10);
        debug_msg[len++] = '0' + (call_count % 10);
    }
    
    debug_msg[len++] = ']';
    debug_msg[len++] = '\n';
    debug_msg[len] = '\0';
    
    stuff->sceKernelDebugOutText(0, debug_msg);

    // Appeler la fonction originale
    int ret = stuff->scePadReadState(handle, pData);

    // Logger le résultat
    const char* result_msg = (ret == 0) ? 
        "[SUCCESS] handle=%d, connected=%d\n" : 
        "[FAILED] ret=%d\n";
    stuff->sceKernelDebugOutText(0, result_msg);

    // Charger au premier appel réussi
    if (ret == 0 && !stuff->loaded)
    {
        stuff->sceKernelDebugOutText(0, "[PRX-LOADER] !!! LOADING PRX NOW !!!\n");
        
        int res = stuff->sceKernelLoadStartModule(stuff->prx_path, 0, 0, 0, 0, 0);
        
        if (res > 0) {
            stuff->sceKernelDebugOutText(0, "[PRX-LOADER] >>> SUCCESS! PRX IS LOADED! <<<\n");
        } else {
            stuff->sceKernelDebugOutText(0, "[PRX-LOADER] >>> FAILED! ERROR LOADING PRX! <<<\n");
        }
        
        stuff->loaded = 1;
    }
    
    return ret;
}