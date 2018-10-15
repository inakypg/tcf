FIXME: this is an experiment and it is not yet complete


PENDING

- how to open the firewall upon installation
  
- SELinux

- httpd: service started (depend on it)
  
- drop /etc/httpd/conf.d/ttbd.conf which configures
  /home/ttbd/boot_files or whatever it is
  
    Alias "/~ttbd" "/home/ttbd/public_html"

    <Directory "/home/ttbd/public_html">
        AllowOverride FileInfo AuthConfig Limit Indexes
        Options MultiViews Indexes SymLinksIfOwnerMatch IncludesNoExec
        Require method GET POST OPTIONS
    </Directory>

  change the ~ttbd to ttbd-PREFIX

  Drop one for -staging, -production? etc

- RPM dependencies:

  - tftp: set configs to dir upthere, indicate service is needed
    started, open firewall need perms to create
    /var/lib/tftpboot/ttbd-staging as ttbd:nobody

    - add a /etc/systemd/system/ttbd@.service.d/afapli.conf which adds a::
        
    ExecStartPre = /usr/bin/install -vv -d --mode 2775 --owner ttbd --group ttbd /var/lib/tftpboot/ttbd-%i
    
- dhcpd: service not started, we do our own config, open firewall
- nfs: server started, fixme how to place images?
- syslinux: 
- https server to serve images, it is way faster than tftp

- nfs server serving images for service domain, easier than trusting
  the local setup

- will use properties as source of things needed to boot

- set

- QEMU not netbooting

- support no initramfs, no ip setting?

- local boot has to be implemeted with !syslinux, so syslinux
  chainloads grub or whatever. Reason? that way we make sure there
  is a local way to boot the system.

- we also want to use tftp as the swithcing mechanism as it doesn't
  need to reload config files (DHCPD does)--so it is easy to switch
  state.



Timings:

- first deployment of F27 to #6: 13s, complete 1.1m prompt failed




FIXME:

 - autoconfiguration of firewall and dependencies for the daemon

 - set the root device to be passed from here

 - clear -- terminals in single mode do not do sulogin? why? sulogin
   just takes whatever; works in Fedora--is it done by initrd?
   sulogin spawns for each?

Dependencies:

Ensure daemons are started: tftp, nfs-server, rpc-info, httpd rsync

cd /home/images
sudo rsync --daemon --no-detach --config rsyncd.conf

nfs-server:
- add --udp to /etc/sysconfig/nfs:RPCNFSDARGS
- systemctl enable nfs-server
- systemctl restart nfs-server

firewall has open: http, ttps, dhcp dhcpv6 ssh rsnc

sudo rsync --daemon --config rsyncd.conf  --no-detach -v

 FIXME SUDO so the images can have it all -- need to button down so it treats only as RO and gets permissions properly

boot manager has to ensure ipv4 boot is always the first


TARGET SETUP

- Set to:
  
  - UEFI boot to network IPv4 as primary boot source
    
  - remove any other boot methods (TCF will tell it to boot to local
    disk via the network boot) [USB, Optical, etc]
    
  - Power on after AC power loss / power failure

  - NUCL Devices/Advanced-Config: extract the MAC address

- TCF config, add tags:

  - add 'boot_interconnect' tag pointing to which interconncet it uses
    for booting (useful?)
  
  - add 'boot_domain_dev' tag pointing to which interconncet it uses
    for booting (useful?)

- once in cloud:

  FIXME: do a forced partition reinitialization

  FIXME: partition script do checks to see if things are all right

- by hand now -- do prep script that setups

  FIXME: create script that initializes

  DEVICE=%(bd_root_dev) ./parts.py

  FIXME: mke2fs.ext4 parts
  
COMMON PITFALLS:

- firewall up on rsync, ssh, apache, DHCP, TFTP
- serial line up? boot the service OS on monitor, verify the /dev/ttyUSB0 or whatever is set to 115200n8r

- Serial consoles on the target's USB (console=ttyUSB0) are useless
  for early boot -- they only get started once the kernel has booted

- service OS issues
  
  - Service OS boots but then when starting, NFS timeouts are reported
    and never finishes booting; seems the machine is out of the
    network because it doesn't ping from the server.
    - connect machine to a monitor
    - power up and keep a hold loop on it::
        while tcf acquire NW TARGET; do sleep 10s; done
    - add to command line [append]
      /var/lib/tftpboot/ttbd-INSTANCE/pxelinux.cfg/01-MAC::

        systemd.log_level=debug
        systemd.log_target=console
        console=ttyUSB0,115200

      all in the same line

    - manually power cycle the target

IMAGE SETUP

- tcf-live
  
  - Remove hardcoded configuration::

      rm -f tcf-live/etc/systemd/network/nuc-*.conf

    otherwise we are screwed with some settings it does for MAC
    addresses; this will go away at some point

ARCHITECTURAL CALLS
    
- can't really use single in the boot because it doesn't enable the
  serial console getty and sometimes it does not pick it from the
  console command line parameters;

  -  I suspect because it takes time to enumerate USB ones

  - also, we need to force BPS to 115200, sometimes it gets stuck at
    9600

  tcf-live is handling it pretty good (dhcp.py extra_kopts)

- MODIFY SOS image to do agetty on /dev/tty(USB0|S0)
    
  modify serial-getty@ to fix baud rate at 115200, remove
  --keep-baud -- note when you edit do not edit the symlink in
  IMAGE/etc/systemd/system/getty.target.wants, since that'll get you
  to edit the system's -- edit manually the 
