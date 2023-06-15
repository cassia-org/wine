/*
 * Android driver initialisation functions
 *
 * Copyright 1996, 2013, 2017 Alexandre Julliard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#if 0
#pragma makedep unix
#endif

#define NONAMELESSSTRUCT
#define NONAMELESSUNION
#include "config.h"

#include <stdarg.h>
#include <string.h>
#include <dlfcn.h>
#include <link.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winreg.h"
#include "android.h"
#include "wine/server.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(android);

// TODO not this
unsigned int screen_width = 1920;
unsigned int screen_height = 1080;
RECT virtual_screen_rect = { 0, 0, 1920, 1080 };

static const unsigned int screen_bpp = 32;  /* we don't support other modes */


static RECT monitor_rc_work;
static BOOL force_display_devices_refresh;

PNTAPCFUNC register_window_callback;

typedef struct
{
    struct gdi_physdev dev;
} ANDROID_PDEVICE;

static const struct user_driver_funcs android_drv_funcs;

NTSTATUS android_register_window( void *arg ) { return STATUS_SUCCESS; }
NTSTATUS android_dispatch_ioctl( void *arg ) { return STATUS_SUCCESS; }

static void android_resize_desktop(void)
{
    RECT virtual_rect = NtUserGetVirtualScreenRect();
    NtUserSetWindowPos(NtUserGetDesktopWindow(), 0,
                       virtual_rect.left, virtual_rect.top,
                       virtual_rect.right - virtual_rect.left,
                       virtual_rect.bottom - virtual_rect.top,
                       SWP_NOZORDER | SWP_NOACTIVATE | SWP_DEFERERASE);
}


/******************************************************************************
 *           create_android_physdev
 */
static ANDROID_PDEVICE *create_android_physdev(void)
{
    ANDROID_PDEVICE *physdev;

    if (!(physdev = calloc( 1, sizeof(*physdev) ))) return NULL;
    return physdev;
}


/**********************************************************************
 *           ANDROID_CreateDC
 */
static BOOL ANDROID_CreateDC( PHYSDEV *pdev, LPCWSTR device, LPCWSTR output, const DEVMODEW *initData )
{
    ANDROID_PDEVICE *physdev = create_android_physdev();

    if (!physdev) return FALSE;

    push_dc_driver( pdev, &physdev->dev, &android_drv_funcs.dc_funcs );
    return TRUE;
}


/**********************************************************************
 *           ANDROID_CreateCompatibleDC
 */
static BOOL ANDROID_CreateCompatibleDC( PHYSDEV orig, PHYSDEV *pdev )
{
    ANDROID_PDEVICE *physdev = create_android_physdev();

    if (!physdev) return FALSE;

    push_dc_driver( pdev, &physdev->dev, &android_drv_funcs.dc_funcs );
    return TRUE;
}


/**********************************************************************
 *           ANDROID_DeleteDC
 */
static BOOL ANDROID_DeleteDC( PHYSDEV dev )
{
    free( dev );
    return TRUE;
}

/**********************************************************************
 *           WAYLAND_DesktopWindowProc
 */
LRESULT ANDROID_DesktopWindowProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
    case WM_DISPLAYCHANGE:
        android_resize_desktop();
        break;
    }

    return NtUserMessageCall(hwnd, msg, wp, lp, 0, NtUserDefWindowProc, FALSE);
}



/***********************************************************************
 *           ANDROID_ChangeDisplaySettings
 */
LONG ANDROID_ChangeDisplaySettings( LPDEVMODEW displays, LPCWSTR primary_name, HWND hwnd, DWORD flags, LPVOID lpvoid )
{
    FIXME( "(%p,%s,%p,0x%08x,%p)\n", displays, debugstr_w(primary_name), hwnd, (int)flags, lpvoid );
    return DISP_CHANGE_SUCCESSFUL;
}


/***********************************************************************
 *           ANDROID_UpdateDisplayDevices
 */
BOOL ANDROID_UpdateDisplayDevices( const struct gdi_device_manager *device_manager, BOOL force, void *param )
{
    if (force || force_display_devices_refresh)
    {
        static const struct gdi_gpu gpu;
        static const struct gdi_adapter adapter =
        {
            .state_flags = DISPLAY_DEVICE_ATTACHED_TO_DESKTOP | DISPLAY_DEVICE_PRIMARY_DEVICE | DISPLAY_DEVICE_VGA_COMPATIBLE,
        };
        struct gdi_monitor gdi_monitor =
        {
            .rc_monitor = virtual_screen_rect,
            .rc_work = monitor_rc_work,
            .state_flags = DISPLAY_DEVICE_ACTIVE | DISPLAY_DEVICE_ATTACHED,
        };
        const DEVMODEW mode =
        {
            .dmFields = DM_DISPLAYORIENTATION | DM_PELSWIDTH | DM_PELSHEIGHT | DM_BITSPERPEL |
                        DM_DISPLAYFLAGS | DM_DISPLAYFREQUENCY | DM_POSITION,
            .dmBitsPerPel = screen_bpp, .dmPelsWidth = screen_width, .dmPelsHeight = screen_height, .dmDisplayFrequency = 60,
        };
        device_manager->add_gpu( &gpu, param );
        device_manager->add_adapter( &adapter, param );
        device_manager->add_monitor( &gdi_monitor, param );
        device_manager->add_mode( &mode, TRUE, param );
        force_display_devices_refresh = FALSE;
    }

    return TRUE;
}


/***********************************************************************
 *           ANDROID_GetCurrentDisplaySettings
 */
BOOL ANDROID_GetCurrentDisplaySettings( LPCWSTR name, BOOL is_primary, LPDEVMODEW devmode )
{
    devmode->u2.dmDisplayFlags = 0;
    devmode->u1.s2.dmPosition.x = 0;
    devmode->u1.s2.dmPosition.y = 0;
    devmode->u1.s2.dmDisplayOrientation = 0;
    devmode->u1.s2.dmDisplayFixedOutput = 0;
    devmode->dmPelsWidth = screen_width;
    devmode->dmPelsHeight = screen_height;
    devmode->dmBitsPerPel = screen_bpp;
    devmode->dmDisplayFrequency = 60;
    devmode->dmFields = DM_POSITION | DM_DISPLAYORIENTATION | DM_PELSWIDTH | DM_PELSHEIGHT |
                        DM_BITSPERPEL | DM_DISPLAYFLAGS | DM_DISPLAYFREQUENCY;
    TRACE( "current mode -- %dx%d %d bpp @%d Hz\n",
           (int)devmode->dmPelsWidth, (int)devmode->dmPelsHeight,
           (int)devmode->dmBitsPerPel, (int)devmode->dmDisplayFrequency );
    return TRUE;
}

/**********************************************************************
 *           ANDROID_WindowMessage
 */
LRESULT ANDROID_WindowMessage(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
    default:
        FIXME("got window msg %x hwnd %p wp %lx lp %lx\n", msg, hwnd, (long)wp, lp);
        return 0;
    }
}

/**********************************************************************
 *           ANDROID_wine_get_vulkan_driver
 */
static const struct vulkan_funcs *ANDROID_wine_get_vulkan_driver( UINT version )
{
    return get_vulkan_driver( version );
}

static const struct user_driver_funcs android_drv_funcs =
{
    .dc_funcs.pCreateCompatibleDC = ANDROID_CreateCompatibleDC,
    .dc_funcs.pCreateDC = ANDROID_CreateDC,
    .dc_funcs.pDeleteDC = ANDROID_DeleteDC,
    .dc_funcs.priority = GDI_PRIORITY_GRAPHICS_DRV,

    .pGetKeyNameText = NULL,
    .pMapVirtualKeyEx = NULL,
    .pVkKeyScanEx = NULL,
    .pSetCursor = NULL,
    .pChangeDisplaySettings = ANDROID_ChangeDisplaySettings,
    .pGetCurrentDisplaySettings = ANDROID_GetCurrentDisplaySettings,
    .pUpdateDisplayDevices = ANDROID_UpdateDisplayDevices,
    .pCreateDesktop = NULL,
    .pCreateWindow = NULL,
    .pDesktopWindowProc = ANDROID_DesktopWindowProc,
    .pDestroyWindow = NULL,
    .pProcessEvents = NULL,
    .pSetCapture = NULL,
    .pSetLayeredWindowAttributes = NULL,
    .pSetParent = NULL,
    .pSetWindowRgn = NULL,
    .pSetWindowStyle = NULL,
    .pShowWindow = NULL,
    .pUpdateLayeredWindow = NULL,
    .pWindowMessage = ANDROID_WindowMessage,
    .pWindowPosChanging = NULL,
    .pWindowPosChanged = NULL,
    .pwine_get_wgl_driver = NULL,
    .pwine_get_vulkan_driver = ANDROID_wine_get_vulkan_driver,

};

static HRESULT android_init( void *arg )
{
    struct init_params *params = arg;
    void *ntdll;

    if (!(ntdll = dlopen( "ntdll.so", RTLD_NOW ))) return STATUS_UNSUCCESSFUL;

    register_window_callback = params->register_window_callback;

    __wine_set_user_driver( &android_drv_funcs, WINE_GDI_DRIVER_VERSION );
    return STATUS_SUCCESS;
}

const unixlib_entry_t __wine_unix_call_funcs[] =
{
    android_dispatch_ioctl,
    android_init,
    android_register_window,
};


C_ASSERT( ARRAYSIZE(__wine_unix_call_funcs) == unix_funcs_count );

#ifdef _WIN64

static NTSTATUS wow64_android_dispatch_ioctl( void *args )
{
    struct params_layout
    {
        UINT_PTR irp;
        DWORD client_id;
    } const *params32 = args;

    struct ioctl_params params =
    {
        ULongToPtr(params32->irp),
        params32->client_id
    };

    return android_dispatch_ioctl( &params );
}

const unixlib_entry_t __wine_unix_call_wow64_funcs[] =
{
    wow64_android_dispatch_ioctl,
    android_init,
    android_register_window,
};

#endif  /* _WIN64 */
