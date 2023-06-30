/* Android Vulkan implementation
 *
 * Copyright 2017 Roderick Colenbrander
 * Copyright 2023 Billy Laws
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

/* NOTE: If making changes here, consider whether they should be reflected in
 * the other drivers. */

#if 0
#pragma makedep unix
#endif

#include "config.h"

#include <stdarg.h>
#include <stdio.h>
#include <dlfcn.h>
#include <errno.h>
#include <string.h>
#include <android/hardware_buffer.h>
#include <android/sync.h>
#include <adrenotools/driver.h>

#include "windef.h"
#include "winbase.h"

#include "wine/debug.h"
#include "android.h"

#include "ipc_client.h"

#define VK_NO_PROTOTYPES
#define WINE_VK_HOST

#include "wine/vulkan.h"
#include "wine/vulkan_driver.h"

WINE_DEFAULT_DEBUG_CHANNEL(vulkan);
#ifdef SONAME_LIBVULKAN

#define VK_EXTERNAL_MEMORY_HANDLE_TYPE_ANDROID_HARDWARE_BUFFER_BIT_ANDROID 0x00000400

#define VK_STRUCTURE_TYPE_IMPORT_ANDROID_HARDWARE_BUFFER_INFO_ANDROID 1000129003

typedef struct VkImportAndroidHardwareBufferInfoANDROID {
    VkStructureType            sType;
    const void*                pNext;
    struct AHardwareBuffer*    buffer;
} VkImportAndroidHardwareBufferInfoANDROID;

#define VK_STRUCTURE_TYPE_IMPORT_SEMAPHORE_FD_INFO_KHR 1000079000

typedef struct VkImportSemaphoreFdInfoKHR {
    VkStructureType                          sType;
    const void*                              pNext;
    VkSemaphore                              semaphore;
    VkSemaphoreImportFlags                   flags;
    VkExternalSemaphoreHandleTypeFlagBits    handleType;
    int                                      fd;
} VkImportSemaphoreFdInfoKHR;

#define VK_STRUCTURE_TYPE_SEMAPHORE_GET_FD_INFO_KHR 1000079001

typedef struct VkSemaphoreGetFdInfoKHR {
    VkStructureType                          sType;
    const void*                              pNext;
    VkSemaphore                              semaphore;
    VkExternalSemaphoreHandleTypeFlagBits    handleType;
} VkSemaphoreGetFdInfoKHR;

#define VK_STRUCTURE_TYPE_IMPORT_FENCE_FD_INFO_KHR 1000115000

typedef struct VkImportFenceFdInfoKHR {
    VkStructureType                      sType;
    const void*                          pNext;
    VkFence                              fence;
    VkFenceImportFlags                   flags;
    VkExternalFenceHandleTypeFlagBits    handleType;
    int                                  fd;
} VkImportFenceFdInfoKHR;

struct wine_vk_surface {
    HWND hwnd;
};

struct wine_vk_swapchain {
    cassia_compositor_swapchain_handle cassia_handle;
    unsigned int image_count;
    AHardwareBuffer **hardware_buffers;
    VkImage *images;
    VkDeviceMemory *image_memory;
};

static pthread_mutex_t cassia_wsi_mutex = PTHREAD_MUTEX_INITIALIZER;
static int cassia_wsi_socket = -1;

static VkResult (*pvkCreateInstance)(const VkInstanceCreateInfo *, const VkAllocationCallbacks *, VkInstance *);
static void (*pvkDestroyInstance)(VkInstance, const VkAllocationCallbacks *);
static VkResult (*pvkEnumerateInstanceExtensionProperties)(const char *, uint32_t *, VkExtensionProperties *);
static VkResult (*pvkCreateDevice)(VkPhysicalDevice, const VkDeviceCreateInfo *, const VkAllocationCallbacks *, VkDevice *);
static void * (*pvkGetDeviceProcAddr)(VkDevice, const char *);
static void * (*pvkGetInstanceProcAddr)(VkInstance, const char *);
static VkResult (*pvkCreateImage)(VkDevice, const VkImageCreateInfo *, const VkAllocationCallbacks *, VkImage *);
static void (*pvkGetImageMemoryRequirements)(VkDevice, VkImage, VkMemoryRequirements *);
static VkResult (*pvkAllocateMemory)(VkDevice, const VkMemoryAllocateInfo *, const VkAllocationCallbacks *, VkDeviceMemory *);
static VkResult (*pvkBindImageMemory)(VkDevice, VkImage, VkDeviceMemory, VkDeviceSize);
static void (*pvkFreeMemory)(VkDevice, VkDeviceMemory, const VkAllocationCallbacks *);
static void (*pvkDestroyImage)(VkDevice, VkImage, const VkAllocationCallbacks *);

static pthread_mutex_t vk_device_funcs_init_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool vk_device_funcs_initialised = false;
static VkResult (*pvkImportSemaphoreFdKHR)(VkDevice, const VkImportSemaphoreFdInfoKHR *);
static VkResult (*pvkGetSemaphoreFdKHR)(VkDevice, const VkSemaphoreGetFdInfoKHR *, int *);
static VkResult (*pvkImportFenceFdKHR)(VkDevice, const VkImportFenceFdInfoKHR *);

static void *ANDROID_get_vk_device_proc_addr(const char *name);
static void *ANDROID_get_vk_instance_proc_addr(VkInstance instance, const char *name);

static void *vulkan_handle;
static void *adrenotools_mapping_handle;

static void wine_vk_init(void)
{
    char *hook_lib_dir = getenv("ADRENOTOOLS_HOOK_LIB_DIR");
    char *custom_driver_dir = getenv("ADRENOTOOLS_CUSTOM_DRIVER_DIR");
    char *custom_driver_name = getenv("ADRENOTOOLS_CUSTOM_DRIVER_NAME");
    char *file_redirect_dir = getenv("ADRENOTOOLS_FILE_REDIRECT_DIR");
    int adrenotools_flags = ADRENOTOOLS_DRIVER_GPU_MAPPING_IMPORT;
    if (file_redirect_dir)
        adrenotools_flags |= ADRENOTOOLS_DRIVER_FILE_REDIRECT;

    if (custom_driver_dir)
        adrenotools_flags |= ADRENOTOOLS_DRIVER_CUSTOM;

    if (hook_lib_dir)
        vulkan_handle = adrenotools_open_libvulkan(RTLD_NOW, adrenotools_flags, NULL, hook_lib_dir,
                                                   custom_driver_dir, custom_driver_name, file_redirect_dir, &adrenotools_mapping_handle);
    else
        WARN("ADRENOTOOLS_HOOK_LIB_DIR is not set! adrenotools will not be used");

    if (!vulkan_handle) {
        ERR("Failed to load adrenotools: %s.\n", strerror(errno));
        if (!(vulkan_handle = dlopen(SONAME_LIBVULKAN, RTLD_NOW)))
        {
            ERR("Failed to load %s.\n", SONAME_LIBVULKAN);
            return;
        }
    }

#define LOAD_FUNCPTR(f) if (!(p##f = dlsym(vulkan_handle, #f))) goto fail
#define LOAD_OPTIONAL_FUNCPTR(f) p##f = dlsym(vulkan_handle, #f)
    LOAD_FUNCPTR(vkCreateInstance);
    LOAD_FUNCPTR(vkDestroyInstance);
    LOAD_FUNCPTR(vkEnumerateInstanceExtensionProperties);
    LOAD_FUNCPTR(vkCreateDevice);
    LOAD_FUNCPTR(vkGetDeviceProcAddr);
    LOAD_FUNCPTR(vkGetInstanceProcAddr);
    LOAD_FUNCPTR(vkCreateImage);
    LOAD_FUNCPTR(vkGetImageMemoryRequirements);
    LOAD_FUNCPTR(vkAllocateMemory);
    LOAD_FUNCPTR(vkBindImageMemory);
    LOAD_FUNCPTR(vkFreeMemory);
    LOAD_FUNCPTR(vkDestroyImage);
#undef LOAD_FUNCPTR
#undef LOAD_OPTIONAL_FUNCPTR

    cassia_wsi_socket = cassiaclt_connect();
    if (cassia_wsi_socket == -1)
    {
        ERR("Could not connect to cassia server\n");
        goto fail;
    }

    return;

fail:
    dlclose(vulkan_handle);
    vulkan_handle = NULL;
}

static void wine_vk_device_funcs_init(VkDevice device)
{
    if (vk_device_funcs_initialised)
        return;

    pthread_mutex_lock(&vk_device_funcs_init_mutex);
    if (vk_device_funcs_initialised)
        return;

    pvkImportSemaphoreFdKHR = pvkGetDeviceProcAddr(device, "vkImportSemaphoreFdKHR");
    pvkGetSemaphoreFdKHR = pvkGetDeviceProcAddr(device, "vkGetSemaphoreFdKHR");
    pvkImportFenceFdKHR = pvkGetDeviceProcAddr(device, "vkImportFenceFdKHR");

    vk_device_funcs_initialised = true;
    pthread_mutex_unlock(&vk_device_funcs_init_mutex);

    if (!pvkImportSemaphoreFdKHR || !pvkGetSemaphoreFdKHR || !pvkImportFenceFdKHR)
        ERR("Failed to load external semaphore/fence functions\n");
}

static VkResult ANDROID_vkAcquireNextImage2KHR(VkDevice device, const VkAcquireNextImageInfoKHR *acquire_info,
     uint32_t *image_index) {
    struct wine_vk_swapchain *wine_swapchain = (struct wine_vk_swapchain *)acquire_info->swapchain;
    VkResult result;
    int fence_fd;
    bool ret;
    VkImportSemaphoreFdInfoKHR semaphoreImportInfo;
    VkImportFenceFdInfoKHR fenceImportInfo;

    TRACE("%p %p %p\n", device, acquire_info, image_index);

    if (acquire_info->pNext)
    {
        ERR("Unsupported pNext");
        return VK_ERROR_DEVICE_LOST;
    }

    pthread_mutex_lock(&cassia_wsi_mutex);
    ret = cassiaclt_compositor_command_dequeue(cassia_wsi_socket, wine_swapchain->cassia_handle,
                                               acquire_info->timeout, &result, image_index, &fence_fd);
    pthread_mutex_unlock(&cassia_wsi_mutex);

    if (!ret)
    {
        ERR("Lost connection to cassia server!\n");
        return VK_ERROR_DEVICE_LOST;
    }


    if (result != VK_SUCCESS)
        return result;

    wine_vk_device_funcs_init(device);

    if (acquire_info->semaphore) {
        semaphoreImportInfo.sType = VK_STRUCTURE_TYPE_IMPORT_SEMAPHORE_FD_INFO_KHR;
        semaphoreImportInfo.pNext = NULL;
        semaphoreImportInfo.semaphore = acquire_info->semaphore;
        semaphoreImportInfo.flags = VK_SEMAPHORE_IMPORT_TEMPORARY_BIT;
        semaphoreImportInfo.handleType = VK_EXTERNAL_SEMAPHORE_HANDLE_TYPE_SYNC_FD_BIT;
        semaphoreImportInfo.fd = dup(fence_fd);
        result = pvkImportSemaphoreFdKHR(device, &semaphoreImportInfo);
        if (result != VK_SUCCESS)
            goto end;
    }


    if (acquire_info->fence) {
        fenceImportInfo.sType = VK_STRUCTURE_TYPE_IMPORT_FENCE_FD_INFO_KHR;
        fenceImportInfo.pNext = NULL;
        fenceImportInfo.fence = acquire_info->fence;
        fenceImportInfo.flags = VK_SEMAPHORE_IMPORT_TEMPORARY_BIT;
        fenceImportInfo.handleType = VK_EXTERNAL_FENCE_HANDLE_TYPE_SYNC_FD_BIT;
        fenceImportInfo.fd = dup(fence_fd);
        result = pvkImportFenceFdKHR(device, &fenceImportInfo);
    }

end:
    close(fence_fd);
    return result;
}

static VkResult ANDROID_vkAcquireNextImageKHR(VkDevice device, VkSwapchainKHR swapchain, uint64_t timeout,
     VkSemaphore semaphore, VkFence fence, uint32_t *image_index) {
    VkAcquireNextImageInfoKHR acquire_info;
    acquire_info.sType = VK_STRUCTURE_TYPE_ACQUIRE_NEXT_IMAGE_INFO_KHR;
    acquire_info.pNext = NULL;
    acquire_info.swapchain = swapchain;
    acquire_info.timeout = timeout;
    acquire_info.semaphore = semaphore;
    acquire_info.fence = fence;
    acquire_info.deviceMask = 1;

    return ANDROID_vkAcquireNextImage2KHR(device, &acquire_info, image_index);
}

/* Helper function for converting between win32 and X11 compatible VkInstanceCreateInfo.
 * Caller is responsible for allocation and cleanup of 'dst'.
 */
static VkResult wine_vk_device_convert_create_info(const VkDeviceCreateInfo *src,
        VkDeviceCreateInfo *dst)
{
    const char **enabled_extensions = NULL;

    memcpy(dst, src, sizeof(VkDeviceCreateInfo));

    if (src->enabledExtensionCount > 0)
    {
        dst->ppEnabledExtensionNames = NULL;
        dst->enabledExtensionCount = src->enabledExtensionCount + 6;

        enabled_extensions = calloc(dst->enabledExtensionCount,
                                    sizeof(*dst->ppEnabledExtensionNames));
        if (!enabled_extensions)
        {
            ERR("Failed to allocate memory for enabled extensions\n");
            return VK_ERROR_OUT_OF_HOST_MEMORY;
        }

        memcpy(enabled_extensions, src->ppEnabledExtensionNames,
               sizeof(*src->ppEnabledExtensionNames) * src->enabledExtensionCount);

        enabled_extensions[src->enabledExtensionCount + 0] = "VK_ANDROID_external_memory_android_hardware_buffer";
        enabled_extensions[src->enabledExtensionCount + 1] = "VK_KHR_external_semaphore";
        enabled_extensions[src->enabledExtensionCount + 2] = "VK_KHR_external_semaphore_fd";
        enabled_extensions[src->enabledExtensionCount + 3] = "VK_KHR_external_fence";
        enabled_extensions[src->enabledExtensionCount + 4] = "VK_KHR_external_fence_fd";
        enabled_extensions[src->enabledExtensionCount + 5] = "VK_KHR_external_memory";

        dst->ppEnabledExtensionNames = enabled_extensions;
    }

    return VK_SUCCESS;
}


static VkResult ANDROID_vkCreateDevice(VkPhysicalDevice physical_device, const VkDeviceCreateInfo *create_info,
     const VkAllocationCallbacks *allocator, VkDevice *device)
{
    VkDeviceCreateInfo create_info_host;
    VkResult res;
    TRACE("create_info %p, allocator %p, device %p\n", create_info, allocator, device);

    if (allocator)
        FIXME("Support for allocation callbacks not implemented yet\n");

    res = wine_vk_device_convert_create_info(create_info, &create_info_host);
    if (res != VK_SUCCESS)
    {
        ERR("Failed to convert device create info, res=%d\n", res);
        return res;
    }

    res = pvkCreateDevice(physical_device, &create_info_host, NULL /* allocator */, device);

    free((void *)create_info_host.ppEnabledExtensionNames);
    return res;
}

/* Helper function for converting between win32 and android compatible VkInstanceCreateInfo.
 * Caller is responsible for allocation and cleanup of 'dst'.
 */
static VkResult wine_vk_instance_convert_create_info(const VkInstanceCreateInfo *src,
        VkInstanceCreateInfo *dst)
{
    unsigned int i;
    const char **enabled_extensions = NULL;
    int win32_surface_idx = -1;

    dst->sType = src->sType;
    dst->flags = src->flags;
    dst->pApplicationInfo = src->pApplicationInfo;
    dst->pNext = NULL;
    dst->enabledLayerCount = 0;
    dst->ppEnabledLayerNames = NULL;
    dst->enabledExtensionCount = 0;
    dst->ppEnabledExtensionNames = NULL;

    if (src->enabledExtensionCount > 0)
    {
        for (i = 0; i < src->enabledExtensionCount; i++)
            if (!strcmp(src->ppEnabledExtensionNames[i], "VK_KHR_win32_surface"))
                win32_surface_idx = i;

        dst->enabledExtensionCount = src->enabledExtensionCount + win32_surface_idx == -1 ? 0 : 2;

        enabled_extensions = calloc(dst->enabledExtensionCount,
                                    sizeof(*src->ppEnabledExtensionNames));
        if (!enabled_extensions)
        {
            ERR("Failed to allocate memory for enabled extensions\n");
            return VK_ERROR_OUT_OF_HOST_MEMORY;
        }

        memcpy(enabled_extensions, src->ppEnabledExtensionNames,
               sizeof(*src->ppEnabledExtensionNames) * src->enabledExtensionCount);

        if (win32_surface_idx != -1)
        {
            enabled_extensions[win32_surface_idx] = "VK_KHR_external_memory_capabilities";
            enabled_extensions[src->enabledExtensionCount] = "VK_KHR_external_semaphore_capabilities";
            enabled_extensions[src->enabledExtensionCount + 1] = "VK_KHR_external_fence_capabilities";
        }

        dst->ppEnabledExtensionNames = enabled_extensions;
    }

    return VK_SUCCESS;
}


static VkResult ANDROID_vkCreateInstance(const VkInstanceCreateInfo *create_info,
        const VkAllocationCallbacks *allocator, VkInstance *instance)
{
    VkInstanceCreateInfo create_info_host;
    VkResult res;
    TRACE("create_info %p, allocator %p, instance %p %p\n", create_info, allocator, instance, pvkCreateInstance);

    if (allocator)
        FIXME("Support for allocation callbacks not implemented yet\n");

    res = wine_vk_instance_convert_create_info(create_info, &create_info_host);
    if (res != VK_SUCCESS)
    {
        ERR("Failed to convert instance create info, res=%d\n", res);
        return res;
    }

    res = pvkCreateInstance(&create_info_host, NULL /* allocator */, instance);

    free((void *)create_info_host.ppEnabledExtensionNames);
    return res;
}

static void ANDROID_vkDestroySwapchainKHR(VkDevice device, VkSwapchainKHR swapchain,
        const VkAllocationCallbacks *allocator);

static VkResult ANDROID_vkCreateSwapchainKHR(VkDevice device,
        const VkSwapchainCreateInfoKHR *create_info,
        const VkAllocationCallbacks *allocator, VkSwapchainKHR *swapchain)
{
    VkResult result = VK_SUCCESS;
    struct wine_vk_swapchain *wine_swapchain = NULL;
    VkImageCreateInfo imageCreateInfo;
    VkExternalMemoryImageCreateInfoKHR externalMemoryImageCreateInfo;
    VkMemoryRequirements imageMemoryRequirements;
    VkMemoryAllocateInfo memoryAllocateInfo;
    VkImportAndroidHardwareBufferInfoANDROID importHardwareBufferInfo;
    unsigned int i;
    bool ret;

    TRACE("%p %p %p %p %u\n", device, create_info, allocator, swapchain, create_info->minImageCount);

    if (allocator)
        FIXME("Support for allocation callbacks not implemented yet\n");

    wine_swapchain = calloc(1, sizeof(struct wine_vk_swapchain));
    if (!wine_swapchain)
    {
        ERR("Failed to allocate memory for swapchain\n");
        result = VK_ERROR_OUT_OF_HOST_MEMORY;
        goto err;
    }

    wine_swapchain->image_count = create_info->minImageCount;
    wine_swapchain->hardware_buffers = calloc(wine_swapchain->image_count, sizeof(AHardwareBuffer *));
    wine_swapchain->images = calloc(wine_swapchain->image_count, sizeof(VkImage));
    wine_swapchain->image_memory = calloc(wine_swapchain->image_count, sizeof(VkDeviceMemory));

    if (!wine_swapchain->hardware_buffers || !wine_swapchain->images || !wine_swapchain->image_memory)
     {
        ERR("Failed to allocate memory for swapchain images\n");
        result = VK_ERROR_OUT_OF_HOST_MEMORY;
        goto err;
    }

    // TODO: maybe return the usage flags in the response (or maybe whole create info struct)
    // TODO: replace 0 with something better after we have actual windows
    pthread_mutex_lock(&cassia_wsi_mutex);
    ret = cassiaclt_compositor_allocate_swapchain(cassia_wsi_socket, 0, create_info->imageFormat,
                                                  create_info->imageExtent, create_info->imageUsage,
                                                  create_info->compositeAlpha, wine_swapchain->image_count,
                                                  &result, &wine_swapchain->cassia_handle,
                                                  wine_swapchain->hardware_buffers);

    pthread_mutex_unlock(&cassia_wsi_mutex);

    if (!ret)
    {
        ERR("Lost connection to cassia server!\n");
        result = VK_ERROR_DEVICE_LOST;
        goto err;
    }

    externalMemoryImageCreateInfo.sType = VK_STRUCTURE_TYPE_EXTERNAL_MEMORY_IMAGE_CREATE_INFO;
    externalMemoryImageCreateInfo.pNext = NULL;
    externalMemoryImageCreateInfo.handleTypes = VK_EXTERNAL_MEMORY_HANDLE_TYPE_ANDROID_HARDWARE_BUFFER_BIT_ANDROID;

    imageCreateInfo.sType = VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO;
    imageCreateInfo.pNext = &externalMemoryImageCreateInfo;
    imageCreateInfo.flags = 0;
    imageCreateInfo.imageType = VK_IMAGE_TYPE_2D;
    imageCreateInfo.format = create_info->imageFormat;
    imageCreateInfo.extent.width = create_info->imageExtent.width;
    imageCreateInfo.extent.height = create_info->imageExtent.height;
    imageCreateInfo.extent.depth = 1;
    imageCreateInfo.mipLevels = 1;
    imageCreateInfo.arrayLayers = 1;
    imageCreateInfo.samples = VK_SAMPLE_COUNT_1_BIT;
    imageCreateInfo.tiling = VK_IMAGE_TILING_OPTIMAL;
    imageCreateInfo.usage = create_info->imageUsage | VK_IMAGE_USAGE_TRANSFER_DST_BIT;
    imageCreateInfo.queueFamilyIndexCount = 0;
    imageCreateInfo.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
    imageCreateInfo.initialLayout = VK_IMAGE_LAYOUT_UNDEFINED;

    for (i = 0; i < wine_swapchain->image_count; i++)
    {
        result = pvkCreateImage(device, &imageCreateInfo, NULL, &wine_swapchain->images[i]);
        if (result != VK_SUCCESS) {
            ERR("Failed to create swapchain image");
            goto err;
        }

        pvkGetImageMemoryRequirements(device, wine_swapchain->images[i], &imageMemoryRequirements);

        importHardwareBufferInfo.sType = VK_STRUCTURE_TYPE_IMPORT_ANDROID_HARDWARE_BUFFER_INFO_ANDROID;
        importHardwareBufferInfo.pNext = NULL;
        importHardwareBufferInfo.buffer = wine_swapchain->hardware_buffers[i];

        memoryAllocateInfo.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
        memoryAllocateInfo.pNext = &importHardwareBufferInfo;
        memoryAllocateInfo.memoryTypeIndex = 0; // TODO use hwb ext to get this
        memoryAllocateInfo.allocationSize = imageMemoryRequirements.size;
        result = pvkAllocateMemory(device, &memoryAllocateInfo, NULL, &wine_swapchain->image_memory[i]);
        if (result != VK_SUCCESS) {

            ERR("Failed to import swapchain image memory\n");
            goto err;
        }

        result = pvkBindImageMemory(device, wine_swapchain->images[i], wine_swapchain->image_memory[i], 0);
        if (result != VK_SUCCESS) {
            ERR("Failed to bind imported swapchain image memory\n");
            goto err;
        }
    }

    *swapchain = (VkSwapchainKHR)wine_swapchain;

    return result;

err:
    ANDROID_vkDestroySwapchainKHR(device, (VkSwapchainKHR)swapchain, NULL);

    return result;
}

static VkResult ANDROID_vkCreateWin32SurfaceKHR(VkInstance instance,
        const VkWin32SurfaceCreateInfoKHR *create_info,
        const VkAllocationCallbacks *allocator, VkSurfaceKHR *surface)
{
    struct wine_vk_surface *wine_surface;
    TRACE("%p %p %p %p\n", instance, create_info, allocator, surface);

    if (allocator)
        FIXME("Support for allocation callbacks not implemented yet\n");

    /* TODO: support child window rendering. */
    if (create_info->hwnd && NtUserGetAncestor(create_info->hwnd, GA_PARENT) != NtUserGetDesktopWindow())
    {
        FIXME("Application requires child window rendering, which is not implemented yet!\n");
        return VK_ERROR_INCOMPATIBLE_DRIVER;
    }

    wine_surface = malloc(sizeof(struct wine_vk_surface));
    if (!wine_surface)
    {
        ERR("Failed to allocate memory for surface\n");
        return VK_ERROR_OUT_OF_HOST_MEMORY;
    }

    wine_surface->hwnd = create_info->hwnd;

    /* TODO WE NEED TO HAVE SOME SORT OF HWND TO CASSIA WINDOW MAPPING HERE */

    *surface = (VkSurfaceKHR)wine_surface;

    return VK_SUCCESS;
}

static void ANDROID_vkDestroyInstance(VkInstance instance, const VkAllocationCallbacks *allocator)
{
    TRACE("%p %p\n", instance, allocator);

    if (allocator)
        FIXME("Support for allocation callbacks not implemented yet\n");

    pvkDestroyInstance(instance, NULL /* allocator */);
}

static void ANDROID_vkDestroySurfaceKHR(VkInstance instance, VkSurfaceKHR surface,
        const VkAllocationCallbacks *allocator)
{
    TRACE("%p 0x%s %p\n", instance, wine_dbgstr_longlong(surface), allocator);

    if (allocator)
        FIXME("Support for allocation callbacks not implemented yet\n");

    free((struct wine_vk_surface*)surface);
}

static void ANDROID_vkDestroySwapchainKHR(VkDevice device, VkSwapchainKHR swapchain,
         const VkAllocationCallbacks *allocator)
{
    struct wine_vk_swapchain *wine_swapchain = (struct wine_vk_swapchain *)swapchain;
    unsigned int i;

    TRACE("%p, 0x%s %p\n", device, wine_dbgstr_longlong(swapchain), allocator);

    if (allocator)
        FIXME("Support for allocation callbacks not implemented yet\n");

    if (!wine_swapchain)
        return;

    if (wine_swapchain->images && wine_swapchain->hardware_buffers && wine_swapchain->image_memory)
    {
        for (i = 0; i < wine_swapchain->image_count; i++)
        {
            if (wine_swapchain->images[i])
                pvkDestroyImage(device, wine_swapchain->images[i], NULL);

            if (wine_swapchain->image_memory[i])
                pvkFreeMemory(device, wine_swapchain->image_memory[i], NULL);

            if (wine_swapchain->hardware_buffers[i])
                AHardwareBuffer_release(wine_swapchain->hardware_buffers[i]);
        }
    }

    free(wine_swapchain->image_memory);
    free(wine_swapchain->images);
    free(wine_swapchain->hardware_buffers);

    // TODO: cassasrvfree swapchain

    free(wine_swapchain);
}

static VkResult ANDROID_vkEnumerateInstanceExtensionProperties(const char *layer_name,
        uint32_t *count, VkExtensionProperties* properties)
{
    unsigned int i;
    VkResult res;

    TRACE("layer_name %s, count %p, properties %p\n", debugstr_a(layer_name), count, properties);

    /* This shouldn't get called with layer_name set, the ICD loader prevents it. */
    if (layer_name)
    {
        ERR("Layer enumeration not supported from ICD.\n");
        return VK_ERROR_LAYER_NOT_PRESENT;
    }

    /* We will return the same number of instance extensions reported by the host back to
     * winevulkan. Along the way we may replace android extensions with their win32 equivalents.
     * Winevulkan will perform more detailed filtering as it knows whether it has thunks
     * for a particular extension.
     */
    res = pvkEnumerateInstanceExtensionProperties(layer_name, count, properties);
    if (!properties || res < 0)
        return res;

    for (i = 0; i < *count; i++)
    {
        /* For now the only android extension we need to fixup. Long-term we may need an array. */
        if (!strcmp(properties[i].extensionName, "VK_KHR_android_surface"))
        {
            TRACE("Substituting VK_KHR_android_surface for VK_KHR_win32_surface\n");

            snprintf(properties[i].extensionName, sizeof(properties[i].extensionName),
                    VK_KHR_WIN32_SURFACE_EXTENSION_NAME);
            properties[i].specVersion = VK_KHR_WIN32_SURFACE_SPEC_VERSION;
        }
    }

    TRACE("Returning %u extensions.\n", *count);
    return res;
}

static VkResult ANDROID_vkGetDeviceGroupPresentCapabilitiesKHR(VkDevice device,
        VkDeviceGroupPresentCapabilitiesKHR *capabilities)
{
    capabilities->sType = VK_STRUCTURE_TYPE_DEVICE_GROUP_PRESENT_CAPABILITIES_KHR;
    capabilities->pNext = NULL;
    capabilities->presentMask[0] = 1;
    capabilities->modes = VK_DEVICE_GROUP_PRESENT_MODE_LOCAL_BIT_KHR;
    return VK_SUCCESS;
}

static VkResult ANDROID_vkGetDeviceGroupSurfacePresentModesKHR(VkDevice device,
        VkSurfaceKHR surface, VkDeviceGroupPresentModeFlagsKHR *flags)
{
    TRACE("%p, 0x%s, %p\n", device, wine_dbgstr_longlong(surface), flags);

    *flags = VK_DEVICE_GROUP_PRESENT_MODE_LOCAL_BIT_KHR;
    return VK_SUCCESS;
}

static void *ANDROID_vkGetDeviceProcAddr(VkDevice device, const char *name)
{
    void *proc_addr;

    TRACE("%p, %s\n", device, debugstr_a(name));

    if ((proc_addr = ANDROID_get_vk_device_proc_addr(name)))
        return proc_addr;

    return pvkGetDeviceProcAddr(device, name);
}

static void *ANDROID_vkGetInstanceProcAddr(VkInstance instance, const char *name)
{
    void *proc_addr;

    TRACE("%p, %s\n", instance, debugstr_a(name));

    if ((proc_addr = ANDROID_get_vk_instance_proc_addr(instance, name)))
        return proc_addr;

    return pvkGetInstanceProcAddr(instance, name);
}

static VkResult ANDROID_vkGetPhysicalDevicePresentRectanglesKHR(VkPhysicalDevice phys_dev,
        VkSurfaceKHR surface, uint32_t *count, VkRect2D *rects)
{
    if (!rects)
    {
        *count = 1;
        return VK_SUCCESS;
    }

    if (*count < 1) {
        *count = 0;
        return VK_INCOMPLETE;
    }


    // TODO: query window size from cassia!
    rects[0].offset.x = 0;
    rects[0].offset.y = 0;

    // rects[0].extent.width = ...
    // rects[0].extent.height = ...

    *count = 1;
    ERR("ANDROID_vkGetPhysicalDevicePresentRectanglesKHR is unimplemented!\n");
    return VK_ERROR_DEVICE_LOST;
}

static VkResult ANDROID_vkGetPhysicalDeviceSurfaceCapabilitiesKHR(VkPhysicalDevice phys_dev,
        VkSurfaceKHR surface, VkSurfaceCapabilitiesKHR *capabilities)
{

    capabilities->minImageCount = 3;
    capabilities->maxImageCount = 0;

    // TODO: query window size from cassia!
    capabilities->currentExtent.width = 1920;
    capabilities->currentExtent.height = 1080;

    capabilities->minImageExtent.width = 1;
    capabilities->minImageExtent.height = 1;

    // TODO: is this fine?
    capabilities->maxImageExtent.width = 4096;
    capabilities->maxImageExtent.height = 4096;

    capabilities->maxImageArrayLayers = 1;
    capabilities->supportedTransforms = VK_SURFACE_TRANSFORM_IDENTITY_BIT_KHR;
    capabilities->currentTransform = VK_SURFACE_TRANSFORM_IDENTITY_BIT_KHR;
    capabilities->supportedCompositeAlpha = VK_COMPOSITE_ALPHA_OPAQUE_BIT_KHR |
                                            VK_COMPOSITE_ALPHA_PRE_MULTIPLIED_BIT_KHR |
                                            VK_COMPOSITE_ALPHA_POST_MULTIPLIED_BIT_KHR |
                                            VK_COMPOSITE_ALPHA_INHERIT_BIT_KHR;

    capabilities->supportedUsageFlags = VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT |
                                        VK_IMAGE_USAGE_TRANSFER_DST_BIT |
                                        VK_IMAGE_USAGE_STORAGE_BIT;

    return VK_SUCCESS;
}

static VkResult ANDROID_vkGetPhysicalDeviceSurfaceCapabilities2KHR(VkPhysicalDevice phys_dev,
        const VkPhysicalDeviceSurfaceInfo2KHR *surface_info, VkSurfaceCapabilities2KHR *capabilities)
{
    if (surface_info->pNext)
    {
        ERR("Unsupported pNext structs");
        return VK_ERROR_DEVICE_LOST;
    }

    capabilities->sType = VK_STRUCTURE_TYPE_SURFACE_CAPABILITIES_2_KHR;
    capabilities->pNext = NULL;

    return ANDROID_vkGetPhysicalDeviceSurfaceCapabilitiesKHR(phys_dev, surface_info->surface,
                                                             &capabilities->surfaceCapabilities);

}

// TODO: investigate bgra (needs opaque fd as ahwb doesn't support)
static VkResult ANDROID_vkGetPhysicalDeviceSurfaceFormats2KHR(VkPhysicalDevice phys_dev,
        const VkPhysicalDeviceSurfaceInfo2KHR *surface_info, uint32_t *count, VkSurfaceFormat2KHR *formats)
{
    if (!formats) {
        *count = 2/*4*/;
        return VK_SUCCESS;
    }

    if (*count < 2/*4*/) {
        *count = 0;
        return VK_INCOMPLETE;
    }


    formats[0].sType = VK_STRUCTURE_TYPE_SURFACE_FORMAT_2_KHR;
    formats[0].pNext = NULL;
    formats[0].surfaceFormat.format = VK_FORMAT_R8G8B8A8_UNORM;
    formats[0].surfaceFormat.colorSpace = VK_COLOR_SPACE_SRGB_NONLINEAR_KHR;

    formats[1].sType = VK_STRUCTURE_TYPE_SURFACE_FORMAT_2_KHR;
    formats[1].pNext = NULL;
    formats[1].surfaceFormat.format = VK_FORMAT_R8G8B8A8_SRGB;
    formats[1].surfaceFormat.colorSpace = VK_COLOR_SPACE_SRGB_NONLINEAR_KHR;

    formats[2].sType = VK_STRUCTURE_TYPE_SURFACE_FORMAT_2_KHR;
    formats[2].pNext = NULL;
    formats[2].surfaceFormat.format = VK_FORMAT_B8G8R8A8_UNORM;
    formats[2].surfaceFormat.colorSpace = VK_COLOR_SPACE_SRGB_NONLINEAR_KHR;

    formats[3].sType = VK_STRUCTURE_TYPE_SURFACE_FORMAT_2_KHR;
    formats[3].pNext = NULL;
    formats[3].surfaceFormat.format = VK_FORMAT_B8G8R8A8_SRGB;
    formats[3].surfaceFormat.colorSpace = VK_COLOR_SPACE_SRGB_NONLINEAR_KHR;

    *count = 2;//4;

    return VK_SUCCESS;
}

static VkResult ANDROID_vkGetPhysicalDeviceSurfaceFormatsKHR(VkPhysicalDevice phys_dev,
        VkSurfaceKHR surface, uint32_t *count, VkSurfaceFormatKHR *formats)
{
    if (!formats) {
        *count = 2/*4*/;
        return VK_SUCCESS;
    }

    if (*count < 2/*4*/) {
        *count = 0;
        return VK_INCOMPLETE;
    }


    formats[0].format = VK_FORMAT_R8G8B8A8_UNORM;
    formats[0].colorSpace = VK_COLOR_SPACE_SRGB_NONLINEAR_KHR;
    formats[1].format = VK_FORMAT_R8G8B8A8_SRGB;
    formats[1].colorSpace = VK_COLOR_SPACE_SRGB_NONLINEAR_KHR;
    formats[2].format = VK_FORMAT_B8G8R8A8_UNORM;
    formats[2].colorSpace = VK_COLOR_SPACE_SRGB_NONLINEAR_KHR;
    formats[3].format = VK_FORMAT_B8G8R8A8_SRGB;
    formats[3].colorSpace = VK_COLOR_SPACE_SRGB_NONLINEAR_KHR;

    *count = 2;//4;

    return VK_SUCCESS;
}


// TODO: mailbox/immediatr
static VkResult ANDROID_vkGetPhysicalDeviceSurfacePresentModesKHR(VkPhysicalDevice phys_dev,
        VkSurfaceKHR surface, uint32_t *count, VkPresentModeKHR *modes)
{
    if (!modes) {
        *count = 1;
        return VK_SUCCESS;
    }

    if (*count < 1)
        return VK_INCOMPLETE;


    modes[0] = VK_PRESENT_MODE_FIFO_KHR;

    *count = 1;

    return VK_SUCCESS;
}

static VkResult ANDROID_vkGetPhysicalDeviceSurfaceSupportKHR(VkPhysicalDevice phys_dev,
        uint32_t index, VkSurfaceKHR surface, VkBool32 *supported)
{
    *supported = true;
    return VK_SUCCESS;
}

static VkBool32 ANDROID_vkGetPhysicalDeviceWin32PresentationSupportKHR(VkPhysicalDevice phys_dev,
        uint32_t index)
{
    return true;
}

static VkResult ANDROID_vkGetSwapchainImagesKHR(VkDevice device,
        VkSwapchainKHR swapchain, uint32_t *count, VkImage *images)
{
    struct wine_vk_swapchain *wine_swapchain = (struct wine_vk_swapchain *)swapchain;

    if (!images) {
        *count = wine_swapchain->image_count;
        return VK_SUCCESS;
    }

    if (*count < wine_swapchain->image_count) {
        *count = 0;
        return VK_INCOMPLETE;
    }

    memcpy(images, wine_swapchain->images, wine_swapchain->image_count * sizeof(VkImage));
    *count = wine_swapchain->image_count;
    return VK_SUCCESS;
}

static VkResult ANDROID_vkQueuePresentKHR(VkQueue queue, const VkPresentInfoKHR *present_info)
{
    int tmp_queue_semaphore, old_master_queue_semaphore, master_queue_semaphore = -1;
    VkSemaphoreGetFdInfoKHR semaphoreGetFdInfo;
    struct wine_vk_swapchain *wine_swapchain;
    bool ret;
    unsigned int i;
    VkResult result = VK_SUCCESS;

    if (present_info->pNext)
    {
        ERR("pNext is not supported");
        return VK_ERROR_DEVICE_LOST;
    }

    semaphoreGetFdInfo.sType = VK_STRUCTURE_TYPE_SEMAPHORE_GET_FD_INFO_KHR;
    semaphoreGetFdInfo.pNext = NULL;
    semaphoreGetFdInfo.handleType = VK_EXTERNAL_SEMAPHORE_HANDLE_TYPE_SYNC_FD_BIT;

    if (present_info->waitSemaphoreCount >= 1) {
        semaphoreGetFdInfo.semaphore = present_info->pWaitSemaphores[0];
        result = pvkGetSemaphoreFdKHR((VkDevice)NULL, &semaphoreGetFdInfo, &master_queue_semaphore);
        if (result != VK_SUCCESS)
            return result;
    }


    // For any further semaphores, need to merge them sequentially into a single fence fd
    for (i = 1; i < present_info->waitSemaphoreCount; i++)
    {
        semaphoreGetFdInfo.semaphore = present_info->pWaitSemaphores[i];
        // TODO, not cheat here and pass an actual device
        result = pvkGetSemaphoreFdKHR((VkDevice)NULL, &semaphoreGetFdInfo, &tmp_queue_semaphore);
        if (tmp_queue_semaphore == 0)
        {
            ERR("QCOM QUIRK %d\n", result);
            tmp_queue_semaphore = -1;
        }
        if (result != VK_SUCCESS) {
            close(master_queue_semaphore);
            return result;
        }

        old_master_queue_semaphore = master_queue_semaphore;
        master_queue_semaphore = sync_merge("queue_wait", tmp_queue_semaphore, old_master_queue_semaphore);
        close(tmp_queue_semaphore);
        close(old_master_queue_semaphore);
    }

    for (i = 0; i < present_info->swapchainCount; i++)
    {
        wine_swapchain = (struct wine_vk_swapchain *)present_info->pSwapchains[i];

        pthread_mutex_lock(&cassia_wsi_mutex);
        ret = cassiaclt_compositor_command_queue(cassia_wsi_socket, wine_swapchain->cassia_handle,
                                                 present_info->pImageIndices[i], master_queue_semaphore,
                                                 &result);
        pthread_mutex_unlock(&cassia_wsi_mutex);

        if (!ret)
        {
            ERR("Lost connection to cassia server!");
            result = VK_ERROR_DEVICE_LOST;
        }

        if (present_info->pResults)
            present_info->pResults[i] = result;

        if (result != VK_SUCCESS)
            goto end;
    }

end:
    close(master_queue_semaphore);
    return result;

}

static VkSurfaceKHR ANDROID_wine_get_native_surface(VkSurfaceKHR surface)
{
    return surface;
}

static void *ANDROID_wine_get_adrenotools_mapping_handle(void)
{
    return adrenotools_mapping_handle;
}

static const struct vulkan_funcs vulkan_funcs =
{
    ANDROID_vkAcquireNextImage2KHR,
    ANDROID_vkAcquireNextImageKHR,
    ANDROID_vkCreateDevice,
    ANDROID_vkCreateInstance,
    ANDROID_vkCreateSwapchainKHR,
    ANDROID_vkCreateWin32SurfaceKHR,
    ANDROID_vkDestroyInstance,
    ANDROID_vkDestroySurfaceKHR,
    ANDROID_vkDestroySwapchainKHR,
    ANDROID_vkEnumerateInstanceExtensionProperties,
    ANDROID_vkGetDeviceGroupPresentCapabilitiesKHR,
    ANDROID_vkGetDeviceGroupSurfacePresentModesKHR,
    ANDROID_vkGetDeviceProcAddr,
    ANDROID_vkGetInstanceProcAddr,
    ANDROID_vkGetPhysicalDevicePresentRectanglesKHR,
    ANDROID_vkGetPhysicalDeviceSurfaceCapabilities2KHR,
    ANDROID_vkGetPhysicalDeviceSurfaceCapabilitiesKHR,
    ANDROID_vkGetPhysicalDeviceSurfaceFormats2KHR,
    ANDROID_vkGetPhysicalDeviceSurfaceFormatsKHR,
    ANDROID_vkGetPhysicalDeviceSurfacePresentModesKHR,
    ANDROID_vkGetPhysicalDeviceSurfaceSupportKHR,
    ANDROID_vkGetPhysicalDeviceWin32PresentationSupportKHR,
    ANDROID_vkGetSwapchainImagesKHR,
    ANDROID_vkQueuePresentKHR,

    ANDROID_wine_get_native_surface,
    ANDROID_wine_get_adrenotools_mapping_handle,
};

static void *ANDROID_get_vk_device_proc_addr(const char *name)
{
    return get_vulkan_driver_device_proc_addr(&vulkan_funcs, name);
}

static void *ANDROID_get_vk_instance_proc_addr(VkInstance instance, const char *name)
{
    return get_vulkan_driver_instance_proc_addr(&vulkan_funcs, instance, name);
}

const struct vulkan_funcs *get_vulkan_driver(UINT version)
{
    static pthread_once_t init_once = PTHREAD_ONCE_INIT;

    if (version != WINE_VULKAN_DRIVER_VERSION)
    {
        ERR("version mismatch, vulkan wants %u but driver has %u\n", version, WINE_VULKAN_DRIVER_VERSION);
        return NULL;
    }

    pthread_once(&init_once, wine_vk_init);
    if (vulkan_handle)
        return &vulkan_funcs;

    return NULL;
}

#else /* No vulkan */

const struct vulkan_funcs *get_vulkan_driver(UINT version)
{
    ERR("Wine was built without Vulkan support.\n");
    return NULL;
}

#endif /* SONAME_LIBVULKAN */
