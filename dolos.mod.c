#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0x975feced, "module_layout" },
	{ 0x5ac24451, "unregister_kprobe" },
	{ 0x85acb812, "register_kprobe" },
	{ 0xb238d2c0, "kmalloc_caches" },
	{ 0x97255bdf, "strlen" },
	{ 0x1e6d26a8, "strstr" },
	{ 0x9d669763, "memcpy" },
	{ 0x167f43ae, "kmem_cache_alloc_trace" },
	{ 0xe68d4180, "fget" },
	{ 0x99bb8806, "memmove" },
	{ 0x2cfde9a2, "warn_slowpath_fmt" },
	{ 0x5f754e5a, "memset" },
	{ 0x51a910c0, "arm_copy_to_user" },
	{ 0x37a0cba, "kfree" },
	{ 0xe2d5255a, "strcmp" },
	{ 0xae353d77, "arm_copy_from_user" },
	{ 0x2d6fcc06, "__kmalloc" },
	{ 0x3c3ff9fd, "sprintf" },
	{ 0xc5850110, "printk" },
	{ 0xb1ad28e0, "__gnu_mcount_nc" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "4ED22439F664135A2C1A622");
