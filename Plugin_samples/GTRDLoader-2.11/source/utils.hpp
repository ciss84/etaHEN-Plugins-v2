#include <stddef.h>
#include <stdio.h>
#include <sys/_pthreadtypes.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include "dbg.hpp"
#include "dbg/dbg.hpp"
#include "elf/elf.hpp"
#include "hijacker/hijacker.hpp"
#include "notify.hpp"
#include "backtrace.hpp"

#define ORBIS_PAD_PORT_TYPE_STANDARD 0
#define ORBIS_PAD_PORT_TYPE_SPECIAL 2

#define ORBIS_PAD_DEVICE_CLASS_PAD 0
#define ORBIS_PAD_DEVICE_CLASS_GUITAR 1
#define ORBIS_PAD_DEVICE_CLASS_DRUMS 2

#define ORBIS_PAD_CONNECTION_TYPE_STANDARD 0
#define ORBIS_PAD_CONNECTION_TYPE_REMOTE 2

	enum OrbisPadButton
	{
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

	typedef struct vec_float3
	{
		float x;
		float y;
		float z;
	} vec_float3;

	typedef struct vec_float4
	{
		float x;
		float y;
		float z;
		float w;
	} vec_float4;

	typedef struct stick
	{
		uint8_t x;
		uint8_t y;
	} stick;

	typedef struct analog
	{
		uint8_t l2;
		uint8_t r2;
	} analog;

	typedef struct OrbisPadTouch
	{
		uint16_t x, y;
		uint8_t finger;
		uint8_t pad[3];
	} OrbisPadTouch;

	typedef struct OrbisPadTouchData
	{
		uint8_t fingers;
		uint8_t pad1[3];
		uint32_t pad2;
		OrbisPadTouch touch[ORBIS_PAD_MAX_TOUCH_NUM];
	} OrbisPadTouchData;

	// The ScePadData Structure contains data polled from the DS4 controller. This includes button states, analogue
	// positional data, and touchpad related data.
	typedef struct OrbisPadData
	{
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

	// The PadColor structure contains RGBA for the DS4 controller lightbar.
	typedef struct OrbisPadColor
	{
		uint8_t r;
		uint8_t g;
		uint8_t b;
		uint8_t a;
	} OrbisPadColor;

	typedef struct OrbisPadVibeParam
	{
		uint8_t lgMotor;
		uint8_t smMotor;
	} OrbisPadVibeParam;

	// Vendor information about which controller to open for scePadOpenExt
	typedef struct _OrbisPadExtParam
	{
		uint16_t vendorId;
		uint16_t productId;
		uint16_t productId_2; // this is in here twice?
		uint8_t unknown[10];
	} OrbisPadExtParam;

	typedef struct _OrbisPadInformation
	{
		float touchpadDensity;
		uint16_t touchResolutionX;
		uint16_t touchResolutionY;
		uint8_t stickDeadzoneL;
		uint8_t stickDeadzoneR;
		uint8_t connectionType;
		uint8_t count;
		int32_t connected;
		int32_t deviceClass;
		uint8_t unknown[8];
	} OrbisPadInformation;

struct GameStuff {
  uintptr_t scePadReadState;        // +0x00
  uintptr_t debugout;                // +0x08
  uintptr_t sceKernelLoadStartModule; // +0x10
  uintptr_t sceKernelDlsym;          // +0x18
  uint64_t ASLR_Base = 0;            // +0x20
  char prx_path[256];                 // +0x28
  int loaded = 0;                     // +0x128
  uint64_t game_hash = 0;            // +0x12C (padding fait que c'est à +0x130)
  int frame_delay = 300;             // +0x138
  int frame_counter = 0;             // +0x13C

  GameStuff(Hijacker &hijacker) noexcept
      : debugout(hijacker.getLibKernelAddress(nid::sceKernelDebugOutText)), 
        sceKernelLoadStartModule(hijacker.getLibKernelAddress(nid::sceKernelLoadStartModule)),
        sceKernelDlsym(hijacker.getLibKernelAddress(nid::sceKernelDlsym)) {}
};

struct GameBuilder {
  static constexpr size_t SHELLCODE_SIZE = 137;
  static constexpr size_t SHELLCODE_SIZE_AUTO = 125; // Taille correcte pour auto-load avec frame delay
  static constexpr size_t EXTRA_STUFF_ADDR_OFFSET = 2;

  uint8_t shellcode[SHELLCODE_SIZE];

  void setExtraStuffAddr(uintptr_t addr) noexcept {
    *reinterpret_cast<uintptr_t *>(shellcode + EXTRA_STUFF_ADDR_OFFSET) = addr;
  }
};

// Standard shellcode (waits for controller input)
static constexpr GameBuilder BUILDER_TEMPLATE {
    0x48, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MOV RDX, [GameStuff addr]
    0x55, 0x41, 0x57, 0x41, 0x56, 0x53, 0x48, 0x83, 0xec, 0x18, 0x48, 0xb8, 0x48, 0x65, 0x6c, 0x6c,
    0x6f, 0x20, 0x66, 0x72, 0x48, 0x89, 0xd3, 0x49, 0x89, 0xf6, 0x41, 0x89, 0xff, 0x48, 0x89, 0x04,
    0x24, 0x48, 0xb8, 0x6f, 0x6d, 0x20, 0x42, 0x4f, 0x36, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x08,
    0xff, 0x12, 0x89, 0xc5, 0x45, 0x85, 0xff, 0x7e, 0x39, 0x85, 0xed, 0x75, 0x35, 0x41, 0x80, 0x7e,
    0x4c, 0x00, 0x74, 0x2e, 0x83, 0xbb, 0x28, 0x01, 0x00, 0x00, 0x00, 0x75, 0x25, 0x48, 0x8d, 0x7b,
    0x28, 0x31, 0xf6, 0x31, 0xd2, 0x31, 0xc9, 0x45, 0x31, 0xc0, 0x45, 0x31, 0xc9, 0xff, 0x53, 0x10,
    0x48, 0x89, 0xe6, 0x31, 0xff, 0xff, 0x53, 0x08, 0xc7, 0x83, 0x28, 0x01, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x89, 0xe8, 0x48, 0x83, 0xc4, 0x18, 0x5b, 0x41, 0x5e, 0x41, 0x5f, 0x5d, 0xc3
};

// Auto-load shellcode avec frame delay (loads after specified frame delay)
// Équivalent assembleur de la fonction C dans Shellcode.c
static constexpr GameBuilder BUILDER_TEMPLATE_AUTO {
    // Prologue - MOV RDX avec adresse GameStuff (patché par setExtraStuffAddr)
    0x48, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MOV RDX, [GameStuff addr]
    
    // Save registers
    0x55,                                                       // PUSH RBP
    0x41, 0x57,                                                 // PUSH R15
    0x41, 0x56,                                                 // PUSH R14
    0x53,                                                       // PUSH RBX
    0x48, 0x83, 0xec, 0x18,                                    // SUB RSP, 0x18
    
    // Save GameStuff pointer and arguments
    0x48, 0x89, 0xd3,                                           // MOV RBX, RDX (save GameStuff to RBX)
    0x49, 0x89, 0xf6,                                           // MOV R14, RSI (save arg2)
    0x41, 0x89, 0xff,                                           // MOV R15D, EDI (save arg1)
    
    // Call scePadReadState
    0xff, 0x12,                                                 // CALL QWORD PTR [RDX] (scePadReadState)
    0x89, 0xc5,                                                 // MOV EBP, EAX (save return value)
    
    // Check if already loaded: if (stuff->loaded) return ret;
    0x83, 0xbb, 0x28, 0x01, 0x00, 0x00, 0x00,                  // CMP DWORD PTR [RBX+0x128], 0 (loaded)
    0x75, 0x34,                                                 // JNE skip_load (jump to end if loaded)
    
    // Increment frame_counter: stuff->frame_counter++
    0x8b, 0x83, 0x3c, 0x01, 0x00, 0x00,                        // MOV EAX, [RBX+0x13C] (frame_counter)
    0xff, 0xc0,                                                 // INC EAX
    0x89, 0x83, 0x3c, 0x01, 0x00, 0x00,                        // MOV [RBX+0x13C], EAX (save frame_counter)
    
    // Compare with frame_delay: if (frame_counter < frame_delay) return ret;
    0x3b, 0x83, 0x38, 0x01, 0x00, 0x00,                        // CMP EAX, [RBX+0x138] (frame_delay)
    0x7c, 0x22,                                                 // JL skip_load (jump if less)
    
    // Load the PRX: sceKernelLoadStartModule(prx_path, 0, 0, 0, 0, 0)
    0x48, 0x8d, 0x7b, 0x28,                                    // LEA RDI, [RBX+0x28] (prx_path)
    0x31, 0xf6,                                                 // XOR ESI, ESI (args = 0)
    0x31, 0xd2,                                                 // XOR EDX, EDX (argp = 0)
    0x31, 0xc9,                                                 // XOR ECX, ECX (flags = 0)
    0x45, 0x31, 0xc0,                                           // XOR R8D, R8D (opt = 0)
    0x45, 0x31, 0xc9,                                           // XOR R9D, R9D (pRes = 0)
    0xff, 0x53, 0x10,                                           // CALL QWORD PTR [RBX+0x10] (sceKernelLoadStartModule)
    
    // Mark as loaded: stuff->loaded = 1
    0xc7, 0x83, 0x28, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // MOV DWORD PTR [RBX+0x128], 1
    
    // skip_load: restore and return
    0x89, 0xe8,                                                 // MOV EAX, EBP (restore return value)
    0x48, 0x83, 0xc4, 0x18,                                    // ADD RSP, 0x18
    0x5b,                                                       // POP RBX
    0x41, 0x5e,                                                 // POP R14
    0x41, 0x5f,                                                 // POP R15
    0x5d,                                                       // POP RBP
    0xc3                                                        // RET
};


extern "C" int sceSystemServiceKillApp(int, int, int, int);
extern "C" int sceSystemServiceGetAppId(const char *);
extern "C" int _sceApplicationGetAppId(int pid, int *appId);
void plugin_log(const char* fmt, ...);
bool Is_Game_Running(int &BigAppid, const char* title_id);
bool HookGame(UniquePtr<Hijacker> &hijacker, uint64_t alsr_b, const char* prx_path, bool auto_load, int frame_delay = 300);
