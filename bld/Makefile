
KERNEL_VERSION=$(shell uname -r)

KOBJ := /lib/modules/$(KERNEL_VERSION)/build

ifneq (,$(findstring 3.2.,$(KERNEL_VERSION)))
VERSION_FILE := $(KOBJ)/include/linux/version.h
else
ifneq (,$(findstring 2.6.32,$(KERNEL_VERSION)))
VERSION_FILE := $(KOBJ)/include/linux/version.h
else
VERSION_FILE := $(KOBJ)/include/generated/uapi/linux/version.h
endif
endif
ifeq (,$(wildcard $(VERSION_FILE)))
  $(error Linux kernel source not configured - missing version.h)
endif

BLD=$(PWD)
ORIG_SRC=$(PWD)/../net/openvswitch
OBJCOPY=objcopy
IOVISOR_ROOT=$(BLD)/../

MOD_ALLOC=$(shell sudo grep -w module_alloc /boot/System.map-$(KERNEL_VERSION) | cut -f1 -d' ')
GIT_VERSION=$(shell cd $(ORIG_SRC);git describe;cd - > /dev/null)
# "debianize" the tag name: remove the leading 'v' and use a tilde as rc separator.
# We use a tilde because of the ordering rules in:
# http://www.debian.org/doc/debian-policy/ch-controlfields.html#s-f-Version
ifeq (,$(wildcard /etc/redhat-release))
PKG_GIT_VERSION=$(shell echo $(GIT_VERSION) | sed 's:^v::' | sed 's:-rc:~rc:')
else
RHEL := 1
PKG_GIT_VERSION=$(shell echo $(GIT_VERSION) | sed 's:^v::' | sed 's:-rc:~rc:' | sed 's:-:_:g')
endif

NOSTDINC_FLAGS += -I$(BLD)/../include -I$(BLD)/../compat -I$(BLD)/../compat/include

EXTRA_CFLAGS += -I$(BLD)/../net/openvswitch -g \
 -include $(BLD)/../compat/kcompat.h -DMOD_ALLOC=0x$(MOD_ALLOC) -DGIT_VERSION=\"$(GIT_VERSION)\"

obj-m += iovisor.o
iovisor-objs := actions.o datapath.o dp_notify.o flow.o vport.o vport-gre.o vport-internal_dev.o \
	vport-netdev.o vport-vxlan.o dp_bpf.o bpf_plum.o bpf_table.o bpf_replicator.o \
	bpf_callbacks.o radix-tree.o bpf_run.o bpf_check.o bpf2_jit_comp.o

ifneq (,$(findstring 2.6.32,$(KERNEL_VERSION)))
iovisor-objs += genetlink-openvswitch.o gre.o exthdrs_core.o ip_tunnels_core.o gso.o \
	checksum.o vxlan.o vlan.o netdevice.o net_namespace.o offloads.o
endif
ifneq (,$(findstring 3.2.,$(KERNEL_VERSION)))
iovisor-objs += genetlink-openvswitch.o gre.o exthdrs_core.o ip_tunnels_core.o gso.o \
	checksum.o vxlan.o vlan.o offloads.o
endif
ifneq (,$(findstring 3.10.,$(KERNEL_VERSION)))
iovisor-objs += gre.o vxlan.o ip_tunnels_core.o gso.o
endif
ifneq (,$(findstring 3.12.,$(KERNEL_VERSION)))
endif

all:
	ln -sf $(BLD)/../compat/*.c .
	ln -sf $(ORIG_SRC)/*.c .
	$(MAKE) -C $(KOBJ) M=$(BLD) modules

install:
#	$(MAKE) -C $(KOBJ) M=$(BLD) modules_install
	mkdir -p /lib/modules/`uname -r`/updates/dkms/
	cp iovisor.ko /lib/modules/`uname -r`/updates/dkms/
	depmod `uname -r`

packages:
ifeq (,$(RHEL))
	[ $(shell dpkg-query -l dkms|grep -c 'ii.*dkms') = 1 ] || sudo apt-get install -y dkms
	[ $(shell dpkg-query -l debhelper|grep -c 'ii.*debhelper') = 1 ] || sudo apt-get install -y debhelper
else
	[ $(shell yum list installed|grep -c 'rpm-build') = 1 ] || sudo yum install -y rpm-build
endif

IOVISOR_VERSION=$(PKG_GIT_VERSION)
DKMS_DIR=$(IOVISOR_ROOT)/dkms/iovisor-$(IOVISOR_VERSION)/
dkms: packages
	rm -rf $(IOVISOR_ROOT)/dkms/
	cp -r $(IOVISOR_ROOT)/dkms_tmpl/ $(IOVISOR_ROOT)/dkms/
	find $(IOVISOR_ROOT)/dkms/ -type f | xargs sed -i "s/__REPLACE_GIT_VERSION__/$(PKG_GIT_VERSION)/g"
	mkdir -p $(DKMS_DIR)/bld/
	cat $(BLD)/Makefile |sed 's/^GIT_VERSION=.*/GIT_VERSION=$(GIT_VERSION)/' > $(DKMS_DIR)/bld/Makefile
	cp -r $(IOVISOR_ROOT)/net $(DKMS_DIR)
	cp -r $(IOVISOR_ROOT)/compat $(DKMS_DIR)
	cp -r $(IOVISOR_ROOT)/include $(DKMS_DIR)
	mv $(IOVISOR_ROOT)/dkms/dkms.conf $(DKMS_DIR)
ifeq (,$(RHEL))
	cd $(IOVISOR_ROOT)/dkms/;dpkg-buildpackage -rfakeroot -d -b -us -uc
else
	mkdir -p $(IOVISOR_ROOT)/dkms/{BUILD,RPMS,SRPMS,SPECS,SOURCES}
	mv $(IOVISOR_ROOT)/dkms/iovisor.spec $(IOVISOR_ROOT)/dkms/SPECS/
	tar -czvf $(IOVISOR_ROOT)/dkms/SOURCES/iovisor-$(PKG_GIT_VERSION)-src.tar.gz -C $(DKMS_DIR) .
	cd $(IOVISOR_ROOT)/dkms/SPECS;rpmbuild --define "_topdir $(IOVISOR_ROOT)/dkms" -ba iovisor.spec
	cp $(IOVISOR_ROOT)/dkms/RPMS/noarch/iovisor-$(PKG_GIT_VERSION)-1dkms.noarch.rpm $(IOVISOR_ROOT)
endif
	rm -rf $(IOVISOR_ROOT)/dkms/

clean:
	$(MAKE) -C $(KOBJ) M=$(BLD) clean
	rm -f *.c
	rm -f iovisor.dbg
