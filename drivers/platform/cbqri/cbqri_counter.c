/*
 * DO NOT MERGE
 * Simple test driver to set CBQRI monitoring counter values
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sysfs.h>
#include <asm/qos.h>

static struct kobject *cbqri_counter_kobj;

/* Sysfs file read function */
static ssize_t cbqri_counter_value_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct task_struct *task = current;
	u32 cbqri_counter;

	//cbqri_counter = READ_ONCE(task->thread.sqoscfg);
	//trace_printk("DEBUG %s(): task->pid=%d cbqri_counter=%d", __func__, task->pid, cbqri_counter);

	return sprintf(buf, "%d\n", cbqri_counter);
}

/* Sysfs file write function */
static ssize_t cbqri_counter_value_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
	struct task_struct *task = current;
	u32 cbqri_counter;
	u32 old_cbqri_counter;
	int value;

	if (kstrtoint(buf, 10, &value) < 0)
		return -EINVAL;
	trace_printk("DEBUG %s(): task->pid=%d value=%d [0x%x]", __func__, task->pid, value, value);

	//old_cbqri_counter = READ_ONCE(task->thread.sqoscfg);
	//trace_printk("DEBUG %s(): old_thread.sqoscfg=0x%x", __func__, old_cbqri_counter);

	//trace_printk("DEBUG %s(): write value to thread.sqoscfg=0x%x for pid=%d", __func__, value, task->pid);
	//WRITE_ONCE(task->thread.sqoscfg, value);

	////cbqri_counter = READ_ONCE(task->thread.sqoscfg);
	trace_printk("DEBUG %s(): read thread.sqoscfg=%d for pid=%d", __func__, cbqri_counter, task->pid);

	return count;
}

/* Sysfs attributes */
static struct kobj_attribute cbqri_counter_value_attr = __ATTR(cbqri_counter_value, 0660, cbqri_counter_value_show, cbqri_counter_value_store);

/* Initialize the module */
static int __init cbqri_counter_init(void)
{
	int error = 0;

	/* Create a kobject */
	cbqri_counter_kobj = kobject_create_and_add("cbqri_counter", kernel_kobj);
	if (!cbqri_counter_kobj)
		return -ENOMEM;

	/* Create sysfs file attributes */
	error = sysfs_create_file(cbqri_counter_kobj, &cbqri_counter_value_attr.attr);
	if (error) {
		kobject_put(cbqri_counter_kobj);
		return error;
	}

	return 0;
}

/* Cleanup the module */
static void __exit cbqri_counter_exit(void)
{
	/* Remove sysfs file attributes */
	sysfs_remove_file(cbqri_counter_kobj, &cbqri_counter_value_attr.attr);

	/* Remove the kobject */
	kobject_put(cbqri_counter_kobj);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Drew Fustini");
MODULE_DESCRIPTION("Test sysfs module for RISC-V CBQRI monitoring counter values");
module_init(cbqri_counter_init);
module_exit(cbqri_counter_exit);

